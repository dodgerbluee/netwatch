"""OIDC HTTP routes.

Public:
  GET  /auth/oidc/providers           list enabled providers for login page
  GET  /auth/oidc/login               start authorize redirect (?provider=name&next=/)
  GET  /auth/oidc/callback            IdP returns here with ?code & ?state

Admin (require is_admin):
  GET    /settings/sso                 render Settings SSO panel (htmx fragment)
  POST   /settings/sso                 create provider
  POST   /settings/sso/{id}            update provider
  POST   /settings/sso/{id}/delete     delete provider
  POST   /settings/sso/test            try discovery against a candidate issuer
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select

from netwatch.auth.deps import current_user
from netwatch.auth.oidc import registry as oidc_registry
from netwatch.auth.oidc.discovery import fetch_discovery, invalidate_cache
from netwatch.auth.oidc.providers import OIDCError
from netwatch.auth.sessions import create_session
from netwatch.config import Settings
from netwatch.db.models import (
    OAuthProvider as OAuthProviderRow,
)
from netwatch.db.models import (
    OAuthProviderKind,
    OAuthState,
    User,
    UserSource,
)
from netwatch.db.session import session_scope
from netwatch.logging import get_logger

log = get_logger(__name__)

OIDC_STATE_TTL = timedelta(minutes=10)


def _now() -> datetime:
    return datetime.now(UTC)


def _callback_url(request: Request, settings: Settings) -> str:
    """Compute the redirect_uri the IdP must POST/GET back to.

    Prefers `auth.external_url` if configured (production behind a proxy);
    otherwise derives from the incoming request scheme + host.
    """

    if settings.auth.external_url:
        return settings.auth.external_url.rstrip("/") + "/auth/oidc/callback"
    return str(request.url_for("oidc_callback"))


def build_router(*, settings: Settings, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()
    cookie = settings.auth.cookie_name

    # ----- public: providers list ---------------------------------------

    @router.get("/auth/oidc/providers")
    async def list_providers() -> JSONResponse:
        return JSONResponse({"providers": oidc_registry.list_public()})

    # ----- public: kick off login --------------------------------------

    @router.get("/auth/oidc/login")
    async def oidc_login(request: Request, provider: str, next: str = "/") -> RedirectResponse:
        prov = oidc_registry.get(provider)
        if prov is None:
            raise HTTPException(404, f"unknown provider: {provider}")

        redirect_uri = _callback_url(request, settings)
        try:
            auth_start = await prov.begin_authorization(redirect_uri=redirect_uri)
        except Exception as exc:  # noqa: BLE001
            log.warning("oidc.login.start_failed", provider=provider, error=repr(exc))
            raise HTTPException(502, f"OIDC discovery failed: {exc}") from exc

        async with session_scope() as s:
            s.add(
                OAuthState(
                    state=auth_start.state,
                    provider_name=provider,
                    code_verifier=auth_start.code_verifier,
                    nonce=auth_start.nonce,
                    redirect_uri=redirect_uri,
                    next_url=next or "/",
                )
            )

        return RedirectResponse(auth_start.url, status_code=status.HTTP_302_FOUND)

    # ----- public: IdP callback ----------------------------------------

    @router.get("/auth/oidc/callback", name="oidc_callback")
    async def oidc_callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> RedirectResponse:
        if error:
            log.info("oidc.callback.error_from_idp", error=error, desc=error_description)
            return RedirectResponse(
                "/login?error=" + (error_description or error)[:200], status_code=303
            )
        if not code or not state:
            return RedirectResponse("/login?error=missing_code_or_state", status_code=303)

        async with session_scope() as s:
            state_row = await s.get(OAuthState, state)
            if state_row is None:
                return RedirectResponse("/login?error=unknown_state", status_code=303)
            # Same-row read; capture fields then delete to make state single-use.
            provider_name = state_row.provider_name
            code_verifier = state_row.code_verifier
            nonce = state_row.nonce
            redirect_uri = state_row.redirect_uri
            next_url = state_row.next_url
            created_at = state_row.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            await s.delete(state_row)

        if _now() - created_at > OIDC_STATE_TTL:
            return RedirectResponse("/login?error=state_expired", status_code=303)

        prov = oidc_registry.get(provider_name)
        if prov is None:
            return RedirectResponse("/login?error=provider_unavailable", status_code=303)

        try:
            tokens = await prov.exchange_code(
                code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
            )
            id_token = tokens.get("id_token")
            if not id_token:
                raise OIDCError("token response missing id_token")
            claims = await prov.verify_id_token(id_token=id_token, nonce=nonce)
        except (OIDCError, Exception) as exc:  # noqa: BLE001
            log.warning(
                "oidc.callback.exchange_failed",
                provider=provider_name,
                error=repr(exc),
            )
            return RedirectResponse(
                "/login?error=" + str(exc)[:200].replace(" ", "_"), status_code=303
            )

        identity = prov.to_identity(claims)
        if not identity.subject or not identity.username:
            return RedirectResponse("/login?error=incomplete_claims", status_code=303)

        # Resolve or auto-provision the user, then mint a session.
        async with session_scope() as s:
            # 1. Existing OIDC user with same provider+subject?
            res = await s.execute(
                select(User).where(
                    User.oidc_provider == provider_name,
                    User.oidc_subject == identity.subject,
                )
            )
            user = res.scalar_one_or_none()

            # 2. Try to link by email (e.g. someone first logged in locally).
            if user is None and identity.email:
                res = await s.execute(
                    select(User).where(User.email == identity.email)
                )
                user = res.scalar_one_or_none()

            # 3. Try to link by username.
            if user is None and identity.username:
                res = await s.execute(
                    select(User).where(User.username == identity.username)
                )
                user = res.scalar_one_or_none()

            # If we matched an existing user (step 2 or 3), link the OIDC identity.
            if user is not None and not user.oidc_subject:
                user.oidc_provider = provider_name
                user.oidc_subject = identity.subject
                if not user.password_hash:
                    user.source = UserSource.OIDC

            # 4. Auto-register if allowed.
            if user is None:
                if not prov.auto_register:
                    return RedirectResponse(
                        "/login?error=auto_register_disabled", status_code=303
                    )
                # Ensure username uniqueness; suffix if taken.
                base = identity.username
                candidate = base
                i = 2
                while True:
                    res = await s.execute(
                        select(User).where(User.username == candidate)
                    )
                    if res.scalar_one_or_none() is None:
                        break
                    candidate = f"{base}-{i}"
                    i += 1
                user = User(
                    username=candidate,
                    display_name=identity.display_name or candidate,
                    email=identity.email,
                    source=UserSource.OIDC,
                    oidc_provider=provider_name,
                    oidc_subject=identity.subject,
                    is_admin=prov.default_admin,
                )
                s.add(user)
                await s.flush()
                log.info("oidc.user.provisioned", username=user.username)

            if user.is_disabled:
                return RedirectResponse("/login?error=user_disabled", status_code=303)

            # Keep claims fresh.
            if identity.display_name and identity.display_name != user.display_name:
                user.display_name = identity.display_name
            if identity.email and identity.email != user.email:
                user.email = identity.email

            session_row = await create_session(
                s,
                user=user,
                lifetime=timedelta(days=settings.auth.session_lifetime_days),
                user_agent=request.headers.get("User-Agent", ""),
                ip=request.client.host if request.client else "",
            )
            token = session_row.token
            log.info(
                "oidc.login.ok",
                provider=provider_name,
                username=user.username,
            )

        resp = RedirectResponse(next_url or "/", status_code=303)
        resp.set_cookie(
            key=cookie,
            value=token,
            max_age=settings.auth.session_lifetime_days * 86400,
            httponly=True,
            secure=settings.auth.cookie_secure,
            samesite=settings.auth.cookie_samesite,
            path="/",
        )
        return resp

    # ----- admin: render Settings SSO panel (htmx fragment) -------------

    @router.get("/settings/sso", response_class=HTMLResponse)
    async def settings_sso(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        async with session_scope() as s:
            res = await s.execute(
                select(OAuthProviderRow).order_by(OAuthProviderRow.name)
            )
            providers = list(res.scalars().all())
        return templates.TemplateResponse(
            request,
            "_settings_sso.html",
            {"providers": providers, "OAuthProviderKind": OAuthProviderKind},
        )

    # ----- admin: test discovery against a candidate issuer -------------

    @router.post("/settings/sso/test", response_class=HTMLResponse)
    async def settings_sso_test(
        issuer_url: Annotated[str, Form()],
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        try:
            disc = await fetch_discovery(issuer_url.strip())
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">discovery failed: {exc}</span>'
            )
        finally:
            invalidate_cache(issuer_url.strip())
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">'
            f'OK · issuer={disc.issuer}</span>'
        )

    # ----- admin: create provider --------------------------------------

    @router.post("/settings/sso", response_class=HTMLResponse)
    async def settings_sso_create(
        admin: Annotated[User, Depends(current_user)],
        name: Annotated[str, Form(min_length=2, max_length=64)],
        display_name: Annotated[str, Form(min_length=1, max_length=128)],
        kind: Annotated[str, Form()],
        client_id: Annotated[str, Form()],
        client_secret: Annotated[str, Form()],
        issuer_url: Annotated[str, Form()],
        scopes: Annotated[str, Form()] = "openid,profile,email",
        auto_register: Annotated[bool, Form()] = True,
        default_admin: Annotated[bool, Form()] = False,
        enabled: Annotated[bool, Form()] = True,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        try:
            kind_enum = OAuthProviderKind(kind)
        except ValueError:
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">invalid kind</span>', status_code=400
            )
        async with session_scope() as s:
            res = await s.execute(
                select(OAuthProviderRow).where(OAuthProviderRow.name == name.strip())
            )
            if res.scalar_one_or_none() is not None:
                return HTMLResponse(
                    '<span class="text-rose-300 text-xs">name already exists</span>',
                    status_code=400,
                )
            s.add(
                OAuthProviderRow(
                    name=name.strip(),
                    display_name=display_name.strip(),
                    kind=kind_enum,
                    client_id=client_id.strip(),
                    client_secret=client_secret,
                    issuer_url=issuer_url.strip(),
                    scopes=scopes.strip(),
                    auto_register=auto_register,
                    default_admin=default_admin,
                    enabled=enabled,
                )
            )
        await oidc_registry.reload()
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">provider created</span>'
            "<script>htmx.trigger(document.body, 'sso:refresh')</script>"
        )

    # ----- admin: update provider --------------------------------------

    @router.post("/settings/sso/{provider_id}", response_class=HTMLResponse)
    async def settings_sso_update(
        provider_id: int,
        admin: Annotated[User, Depends(current_user)],
        display_name: Annotated[str, Form()] = "",
        kind: Annotated[str, Form()] = "",
        client_id: Annotated[str, Form()] = "",
        client_secret: Annotated[str, Form()] = "",
        issuer_url: Annotated[str, Form()] = "",
        scopes: Annotated[str, Form()] = "",
        auto_register: Annotated[bool, Form()] = False,
        default_admin: Annotated[bool, Form()] = False,
        enabled: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        async with session_scope() as s:
            row = await s.get(OAuthProviderRow, provider_id)
            if row is None:
                raise HTTPException(404)
            if display_name:
                row.display_name = display_name.strip()
            if kind:
                try:
                    row.kind = OAuthProviderKind(kind)
                except ValueError:
                    pass
            if client_id:
                row.client_id = client_id.strip()
            # Only overwrite the secret if a new one was actually entered.
            if client_secret and client_secret != "__unchanged__":
                row.client_secret = client_secret
            if issuer_url:
                row.issuer_url = issuer_url.strip()
            if scopes:
                row.scopes = scopes.strip()
            row.auto_register = auto_register
            row.default_admin = default_admin
            row.enabled = enabled
        await oidc_registry.reload()
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">saved</span>'
            "<script>htmx.trigger(document.body, 'sso:refresh')</script>"
        )

    # ----- admin: delete provider --------------------------------------

    @router.post("/settings/sso/{provider_id}/delete", response_class=HTMLResponse)
    async def settings_sso_delete(
        provider_id: int,
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        async with session_scope() as s:
            row = await s.get(OAuthProviderRow, provider_id)
            if row is None:
                raise HTTPException(404)
            await s.delete(row)
        await oidc_registry.reload()
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">deleted</span>'
            "<script>htmx.trigger(document.body, 'sso:refresh')</script>"
        )

    return router


# ---------------------------------------------------------------------------
# Background: purge expired state rows
# ---------------------------------------------------------------------------


async def purge_expired_states() -> int:
    cutoff = _now() - OIDC_STATE_TTL
    async with session_scope() as s:
        res = await s.execute(delete(OAuthState).where(OAuthState.created_at < cutoff))
        return int(res.rowcount or 0)
