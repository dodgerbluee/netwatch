"""HTTP routes for authentication + first-run setup + settings page."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from netwatch.auth.deps import current_user, current_user_optional
from netwatch.auth.passwords import hash_password, needs_rehash, verify_password
from netwatch.auth.sessions import (
    create_session,
    purge_expired,
    revoke_all_for_user,
    revoke_session,
)
from netwatch.config import Settings
from netwatch.db.models import User, UserSource
from netwatch.db.session import session_scope
from netwatch.logging import get_logger

log = get_logger(__name__)


def build_router(*, settings: Settings, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()
    cookie = settings.auth.cookie_name

    # ----- Setup wizard -------------------------------------------------

    @router.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request) -> HTMLResponse:
        if await _has_users():
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(request, "setup.html", {"error": ""})

    @router.post("/setup", response_class=HTMLResponse)
    async def setup_submit(
        request: Request,
        username: Annotated[str, Form(min_length=2, max_length=64)],
        password: Annotated[str, Form(min_length=8)],
        password_confirm: Annotated[str, Form()],
        display_name: Annotated[str, Form(max_length=128)] = "",
    ) -> HTMLResponse:
        if await _has_users():
            return RedirectResponse("/login", status_code=303)
        if password != password_confirm:
            return templates.TemplateResponse(
                request, "setup.html",
                {"error": "Passwords don't match", "username": username},
                status_code=400,
            )
        try:
            phash = hash_password(password)
        except ValueError as exc:
            return templates.TemplateResponse(
                request, "setup.html",
                {"error": str(exc), "username": username},
                status_code=400,
            )

        async with session_scope() as s:
            user = User(
                username=username.strip().lower(),
                display_name=(display_name or username).strip(),
                source=UserSource.LOCAL,
                password_hash=phash,
                is_admin=True,
            )
            s.add(user)
            await s.flush()
            session_row = await create_session(
                s,
                user=user,
                lifetime=timedelta(days=settings.auth.session_lifetime_days),
                user_agent=request.headers.get("User-Agent", ""),
                ip=request.client.host if request.client else "",
            )
            log.info("auth.setup.admin_created", username=user.username)
            token = session_row.token

        resp = RedirectResponse("/", status_code=303)
        _set_session_cookie(resp, token, settings)
        return resp

    # ----- Login --------------------------------------------------------

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(
        request: Request,
        next: str = "/",
        error: str = "",
        user: Annotated[User | None, Depends(current_user_optional)] = None,
    ) -> HTMLResponse:
        if not await _has_users():
            return RedirectResponse("/setup", status_code=303)
        if user is not None:
            return RedirectResponse(next or "/", status_code=303)
        return templates.TemplateResponse(
            request, "login.html", {"next": next, "error": error.replace("_", " ") if error else ""}
        )

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        next: Annotated[str, Form()] = "/",
        remember: Annotated[bool, Form()] = True,
    ) -> HTMLResponse:
        if not await _has_users():
            return RedirectResponse("/setup", status_code=303)

        uname = username.strip().lower()
        async with session_scope() as s:
            res = await s.execute(select(User).where(User.username == uname))
            user = res.scalar_one_or_none()

            if (
                user is None
                or user.is_disabled
                or user.source != UserSource.LOCAL
                or not verify_password(password, user.password_hash)
            ):
                # Constant-ish-time response. Don't tell the user which part
                # failed.
                log.info("auth.login.failed", username=uname)
                return templates.TemplateResponse(
                    request, "login.html",
                    {"next": next, "error": "Invalid username or password"},
                    status_code=401,
                )

            # Opportunistic rehash if params bumped.
            if needs_rehash(user.password_hash):
                try:
                    user.password_hash = hash_password(password)
                except ValueError:
                    pass

            lifetime = timedelta(
                days=settings.auth.session_lifetime_days if remember else 1
            )
            session_row = await create_session(
                s,
                user=user,
                lifetime=lifetime,
                user_agent=request.headers.get("User-Agent", ""),
                ip=request.client.host if request.client else "",
            )
            token = session_row.token
            log.info("auth.login.ok", username=uname, remember=remember)

        resp = RedirectResponse(next or "/", status_code=303)
        _set_session_cookie(resp, token, settings, remember=remember)
        return resp

    # ----- Logout -------------------------------------------------------

    @router.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        token = request.cookies.get(cookie, "")
        if token:
            async with session_scope() as s:
                await revoke_session(s, token)
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(cookie, path="/")
        return resp

    # ----- Settings page ------------------------------------------------

    @router.get("/settings", response_class=HTMLResponse)
    async def settings_page(
        request: Request,
        user: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        async with session_scope() as s:
            res = await s.execute(select(User).order_by(User.created_at))
            users = list(res.scalars().all())
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "me": user,
                "users": users,
                "auth_settings": settings.auth,
                "settings": settings,
            },
        )

    @router.post("/settings/password", response_class=HTMLResponse)
    async def change_password(
        request: Request,
        current_password: Annotated[str, Form()],
        new_password: Annotated[str, Form(min_length=8)],
        new_password_confirm: Annotated[str, Form()],
        user: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if user.source != UserSource.LOCAL:
            return HTMLResponse(
                '<span class="text-amber-300 text-xs">'
                'SSO users manage passwords at their identity provider.</span>',
                status_code=400,
            )
        if not verify_password(current_password, user.password_hash):
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">Current password incorrect.</span>',
                status_code=401,
            )
        if new_password != new_password_confirm:
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">New passwords don\'t match.</span>',
                status_code=400,
            )
        try:
            new_hash = hash_password(new_password)
        except ValueError as exc:
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">{exc}</span>',
                status_code=400,
            )
        async with session_scope() as s:
            db_user = await s.get(User, user.id)
            assert db_user is not None
            db_user.password_hash = new_hash
            # Logout other devices for safety.
            await revoke_all_for_user(
                s, user.id, except_token=request.cookies.get(cookie, "")
            )
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">'
            'Password changed; other sessions logged out.</span>'
        )

    @router.post("/settings/users", response_class=HTMLResponse)
    async def create_user(
        request: Request,
        username: Annotated[str, Form(min_length=2, max_length=64)],
        password: Annotated[str, Form(min_length=8)],
        display_name: Annotated[str, Form(max_length=128)] = "",
        is_admin: Annotated[bool, Form()] = False,
        admin: Annotated[User, Depends(current_user)] = None,  # type: ignore[assignment]
    ) -> HTMLResponse:
        if not admin.is_admin:
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">Admin required.</span>',
                status_code=403,
            )
        uname = username.strip().lower()
        try:
            phash = hash_password(password)
        except ValueError as exc:
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">{exc}</span>',
                status_code=400,
            )
        async with session_scope() as s:
            res = await s.execute(select(User).where(User.username == uname))
            if res.scalar_one_or_none() is not None:
                return HTMLResponse(
                    '<span class="text-rose-300 text-xs">Username taken.</span>',
                    status_code=400,
                )
            s.add(
                User(
                    username=uname,
                    display_name=(display_name or uname).strip(),
                    source=UserSource.LOCAL,
                    password_hash=phash,
                    is_admin=is_admin,
                )
            )
        return HTMLResponse(
            f'<span class="text-emerald-300 text-xs">User {uname} created.</span>'
            '<script>setTimeout(() => location.reload(), 800)</script>'
        )

    @router.post("/settings/users/{user_id}/disable", response_class=HTMLResponse)
    async def disable_user(
        user_id: int,
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if admin.id == user_id:
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">Refusing to disable yourself.</span>',
                status_code=400,
            )
        async with session_scope() as s:
            u = await s.get(User, user_id)
            if u is None:
                raise HTTPException(404)
            u.is_disabled = True
            await revoke_all_for_user(s, user_id)
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">User disabled.</span>'
            '<script>setTimeout(() => location.reload(), 800)</script>'
        )

    @router.post("/settings/users/{user_id}/enable", response_class=HTMLResponse)
    async def enable_user(
        user_id: int,
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        async with session_scope() as s:
            u = await s.get(User, user_id)
            if u is None:
                raise HTTPException(404)
            u.is_disabled = False
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">User enabled.</span>'
            '<script>setTimeout(() => location.reload(), 800)</script>'
        )

    @router.post("/settings/users/{user_id}/delete", response_class=HTMLResponse)
    async def delete_user(
        user_id: int,
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if admin.id == user_id:
            return HTMLResponse(
                '<span class="text-rose-300 text-xs">Refusing to delete yourself.</span>',
                status_code=400,
            )
        async with session_scope() as s:
            u = await s.get(User, user_id)
            if u is None:
                raise HTTPException(404)
            await revoke_all_for_user(s, user_id)
            await s.delete(u)
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">User deleted.</span>'
            '<script>setTimeout(() => location.reload(), 800)</script>'
        )

    @router.post("/settings/sessions/purge", response_class=HTMLResponse)
    async def purge_sessions(
        admin: Annotated[User, Depends(current_user)],
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        async with session_scope() as s:
            n = await purge_expired(s)
        return HTMLResponse(
            f'<span class="text-emerald-300 text-xs">Purged {n} expired session(s).</span>'
        )

    # ----- Config save endpoints ----------------------------------------

    @router.post("/settings/config/general", response_class=HTMLResponse)
    async def save_general(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
        enforcement_enabled: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        await settings.save_section("general", {
            "enforcement_enabled": enforcement_enabled,
        })
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">General settings saved.</span>'
        )

    @router.post("/settings/config/unifi", response_class=HTMLResponse)
    async def save_unifi(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
        host: Annotated[str, Form()] = "",
        site: Annotated[str, Form()] = "default",
        username: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
        verify_tls: Annotated[bool, Form()] = False,
        bootstrap_grace_seconds: Annotated[int, Form()] = 120,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        # Preserve existing password if placeholder sent.
        if password == "__unchanged__" and settings.unifi.password:
            password = settings.unifi.password
        from netwatch.config import UniFiConfig

        cfg = UniFiConfig(
            host=host.strip(),
            site=site.strip() or "default",
            username=username.strip(),
            password=password,
            verify_tls=verify_tls,
            bootstrap_grace_seconds=bootstrap_grace_seconds,
        )
        await settings.save_section("unifi", cfg.to_dict())
        supervisor = request.app.state.supervisor
        await supervisor.restart_task("unifi-listener")
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">UniFi settings saved. Service restarting.</span>'
        )

    @router.post("/settings/config/mqtt", response_class=HTMLResponse)
    async def save_mqtt(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
        host: Annotated[str, Form()] = "",
        port: Annotated[int, Form()] = 1883,
        username: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
        discovery_prefix: Annotated[str, Form()] = "homeassistant",
        base_topic: Annotated[str, Form()] = "netwatch",
        client_id: Annotated[str, Form()] = "netwatch",
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if password == "__unchanged__" and settings.mqtt.password:
            password = settings.mqtt.password
        from netwatch.config import MQTTConfig

        cfg = MQTTConfig(
            host=host.strip(),
            port=port,
            username=username.strip(),
            password=password,
            discovery_prefix=discovery_prefix.strip() or "homeassistant",
            base_topic=base_topic.strip() or "netwatch",
            client_id=client_id.strip() or "netwatch",
        )
        await settings.save_section("mqtt", cfg.to_dict())
        supervisor = request.app.state.supervisor
        await supervisor.restart_task("mqtt-bridge")
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">MQTT settings saved. Service restarting.</span>'
        )

    @router.post("/settings/config/opnsense", response_class=HTMLResponse)
    async def save_opnsense(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
        host: Annotated[str, Form()] = "",
        api_key: Annotated[str, Form()] = "",
        api_secret: Annotated[str, Form()] = "",
        verify_tls: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if api_secret == "__unchanged__" and settings.opnsense.api_secret:
            api_secret = settings.opnsense.api_secret
        from netwatch.config import OPNsenseConfig

        cfg = OPNsenseConfig(
            host=host.strip(),
            api_key=api_key.strip(),
            api_secret=api_secret,
            verify_tls=verify_tls,
        )
        await settings.save_section("opnsense", cfg.to_dict())
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">OPNsense settings saved.</span>'
        )

    @router.post("/settings/config/auth", response_class=HTMLResponse)
    async def save_auth(
        request: Request,
        admin: Annotated[User, Depends(current_user)],
        session_lifetime_days: Annotated[int, Form()] = 30,
        cookie_secure: Annotated[bool, Form()] = True,
        cookie_samesite: Annotated[str, Form()] = "lax",
        external_url: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        from netwatch.config import AuthConfig

        cfg = AuthConfig(
            session_lifetime_days=max(1, min(365, session_lifetime_days)),
            cookie_secure=cookie_secure,
            cookie_samesite=cookie_samesite if cookie_samesite in ("lax", "strict", "none") else "lax",
            external_url=external_url.strip(),
        )
        await settings.save_section("auth", cfg.to_dict())
        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">Auth settings saved.</span>'
        )

    # ----- Connection test endpoints ------------------------------------

    @router.post("/settings/config/unifi/test", response_class=HTMLResponse)
    async def test_unifi(
        admin: Annotated[User, Depends(current_user)],
        host: Annotated[str, Form()] = "",
        username: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
        verify_tls: Annotated[bool, Form()] = False,
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if password == "__unchanged__" and settings.unifi.password:
            password = settings.unifi.password
        from netwatch.config import UniFiConfig
        from netwatch.unifi.client import UnifiClient

        cfg = UniFiConfig(
            host=host.strip(),
            username=username.strip(),
            password=password,
            verify_tls=verify_tls,
        )
        try:
            async with UnifiClient(cfg) as client:
                clients = await client.list_active_clients()
            return HTMLResponse(
                f'<span class="text-emerald-300 text-xs">'
                f'Connected. {len(clients)} active client(s) found.</span>'
            )
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">Failed: {exc}</span>'
            )

    @router.post("/settings/config/mqtt/test", response_class=HTMLResponse)
    async def test_mqtt(
        admin: Annotated[User, Depends(current_user)],
        host: Annotated[str, Form()] = "",
        port: Annotated[int, Form()] = 1883,
        username: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        if not admin.is_admin:
            raise HTTPException(403)
        if password == "__unchanged__" and settings.mqtt.password:
            password = settings.mqtt.password
        import aiomqtt

        try:
            async with aiomqtt.Client(
                hostname=host.strip(),
                port=port,
                username=username.strip() or None,
                password=password or None,
                identifier="netwatch-test",
            ):
                pass
            return HTMLResponse(
                '<span class="text-emerald-300 text-xs">Connected successfully.</span>'
            )
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">Failed: {exc}</span>'
            )

    return router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _has_users() -> bool:
    async with session_scope() as s:
        res = await s.execute(select(func.count(User.id)))
        return int(res.scalar_one()) > 0


def _set_session_cookie(
    response,
    token: str,
    settings: Settings,
    *,
    remember: bool = True,
) -> None:
    max_age = (
        settings.auth.session_lifetime_days * 86400 if remember else None
    )
    response.set_cookie(
        key=settings.auth.cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.auth.cookie_secure,
        samesite=settings.auth.cookie_samesite,
        path="/",
    )
