"""FastAPI app factory.

Mounted endpoints:
  GET  /                  device list (htmx page)
  GET  /devices           same as / but paged JSON for the htmx swap target
  GET  /policies          SSID policy editor
  POST /devices/{mac}     mutate device (approve / flag / rename / allowed_ssids)
  POST /devices/{mac}/unblock
  GET  /history           recent decisions + sightings
  GET  /healthz           liveness (no deps)
  GET  /readyz            readiness (checks DB)
  GET  /export            stream a consistent SQLite snapshot
  POST /import            restore an uploaded SQLite snapshot
"""

from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator, Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from netwatch import __version__
from netwatch.auth.deps import (
    _RedirectToLogin,
    current_user,
    current_user_optional,
    install_redirect_handler,
)
from netwatch.auth.routes import build_router as build_auth_router
from netwatch.auth.sessions import get_active_session
from netwatch.config import Settings
from sqlalchemy import update

from netwatch.db.models import Device, DeviceKind, DeviceStatus, User
from netwatch.db.repository import (
    list_devices,
    list_policies,
    recent_sightings,
    set_known,
    set_status,
    upsert_policy,
)
from netwatch.db.session import get_engine, session_scope
from netwatch.logging import get_logger
from netwatch.policy.engine import PolicyEngine

log = get_logger(__name__)

PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
STATIC_DIR = PACKAGE_ROOT / "static"


# Paths that NEVER require auth. Everything else does.
PUBLIC_PATHS = {
    "/healthz",
    "/readyz",
    "/setup",
    "/login",
    "/logout",
    "/favicon.ico",
    "/auth/oidc/providers",
    "/auth/oidc/login",
    "/auth/oidc/callback",
}
PUBLIC_PREFIXES = ("/static/",)


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(p) for p in PUBLIC_PREFIXES)


def _install_auth_middleware(app: FastAPI, settings: Settings) -> None:
    """Block unauthenticated access to every non-public path.

    Resolution: forward-auth headers first, then cookie session. On miss,
    either redirect (HTML) or 401 (htmx/JSON).
    """

    from sqlalchemy import func, select

    from netwatch.db.models import User as UserModel

    @app.middleware("http")
    async def auth_middleware(request, call_next):
        path = request.url.path
        if _is_public(path):
            return await call_next(request)

        # If there are no users at all, push everyone to setup.
        async with session_scope() as s:
            res = await s.execute(select(func.count(UserModel.id)))
            user_count = int(res.scalar_one())
        if user_count == 0:
            from fastapi.responses import RedirectResponse

            return RedirectResponse("/setup", status_code=303)

        # Cookie session lookup
        token = request.cookies.get(settings.auth.cookie_name, "")
        if token:
            async with session_scope() as s:
                found = await get_active_session(s, token)
            if found is not None:
                _, user = found
                request.state.user = user
                return await call_next(request)

        # No auth -> bounce
        from fastapi.responses import JSONResponse, RedirectResponse

        is_htmx = request.headers.get("HX-Request", "").lower() == "true"
        accept = request.headers.get("Accept", "")
        wants_html = "text/html" in accept or accept in ("", "*/*")
        if is_htmx:
            return JSONResponse(
                {"error": "login required"},
                status_code=401,
                headers={"HX-Redirect": "/login"},
            )
        if wants_html:
            from urllib.parse import quote

            return RedirectResponse(
                f"/login?next={quote(path, safe='/')}", status_code=303
            )
        return JSONResponse({"error": "login required"}, status_code=401)


def _localtime_filter(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone().strftime(fmt)


def create_app(
    *,
    settings: Settings,
    lifespan: Callable[[FastAPI], AsyncIterator[None]] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="netwatch",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.settings = settings

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["localtime"] = _localtime_filter
    app.state.templates = templates

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    install_redirect_handler(app)
    _install_auth_middleware(app, settings)
    app.include_router(build_auth_router(settings=settings, templates=templates))
    from netwatch.auth.oidc_routes import build_router as build_oidc_router

    app.include_router(build_oidc_router(settings=settings, templates=templates))
    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _register_routes(app: FastAPI) -> None:
    templates: Jinja2Templates = app.state.templates
    settings: Settings = app.state.settings

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> dict[str, str]:
        # Ping DB to verify init_db ran and engine is responsive.
        try:
            engine = get_engine()
            async with engine.connect() as conn:
                await conn.exec_driver_sql("SELECT 1")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"status": "ready"}    # ----- HTML pages ----------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request, status: str | None = None) -> HTMLResponse:
        effective = status if status is not None else "unapproved"
        async with session_scope() as session:
            devices = await list_devices(
                session,
                status=DeviceStatus(effective) if effective else None,
            )
            policies = await list_policies(session)
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "devices": devices,
                "policies": policies,
                "filter_status": effective,
                "settings": settings,
                "DeviceKind": DeviceKind,
                "DeviceStatus": DeviceStatus,
            },
        )

    @app.get("/policies", response_class=HTMLResponse)
    async def policies_page(request: Request) -> HTMLResponse:
        async with session_scope() as session:
            policies = await list_policies(session)
        return templates.TemplateResponse(
            request,
            "policies.html",
            {"policies": policies, "settings": settings},
        )

    @app.get("/history", response_class=HTMLResponse)
    async def history_page(request: Request, mac: str | None = None) -> HTMLResponse:
        async with session_scope() as session:
            sightings = await recent_sightings(session, mac=mac, limit=200)
        return templates.TemplateResponse(
            request,
            "history.html",
            {"sightings": sightings, "filter_mac": mac or ""},
        )

    # ----- Device mutations ---------------------------------------------

    @app.post("/devices/{mac}/approve", response_class=HTMLResponse)
    async def approve(
        mac: str,
        request: Request,
        owner: str = Form(""),
        kind: str = Form("personal"),
        allowed_ssids: str = Form(""),
        name: str = Form(""),
    ) -> HTMLResponse:
        ssids = [s.strip() for s in allowed_ssids.split(",") if s.strip()]
        async with session_scope() as session:
            await set_known(
                session,
                mac,
                kind=DeviceKind(kind),
                owner=owner,
                allowed_ssids=ssids,
                name=name or None,
            )
        return await _device_row(request, mac, templates)

    @app.post("/devices/{mac}/rename", response_class=HTMLResponse)
    async def rename(mac: str, request: Request, name: str = Form("")) -> HTMLResponse:
        new_name = name.strip()
        if not new_name:
            raise HTTPException(400, "name is required")
        async with session_scope() as session:
            await session.execute(
                update(Device).where(Device.mac == mac.lower()).values(name=new_name)
            )
        if settings.unifi.configured:
            from netwatch.unifi.client import UnifiClient
            try:
                async with UnifiClient(settings.unifi) as unifi:
                    await unifi.rename_client(mac, new_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("ui.rename.unifi_failed", mac=mac, error=repr(exc))
        return await _device_row(request, mac, templates)

    @app.post("/devices/{mac}/unapprove", response_class=HTMLResponse)
    async def unapprove(mac: str, request: Request) -> HTMLResponse:
        async with session_scope() as session:
            await session.execute(
                update(Device)
                .where(Device.mac == mac.lower())
                .values(
                    status=DeviceStatus.UNAPPROVED,
                    kind=DeviceKind.UNKNOWN,
                    owner="",
                    allowed_ssids=[],
                )
            )
        return await _device_row(request, mac, templates)

    @app.post("/devices/{mac}/flag", response_class=HTMLResponse)
    async def flag(mac: str, request: Request) -> HTMLResponse:
        async with session_scope() as session:
            await set_status(session, mac, DeviceStatus.FLAGGED)
        return await _device_row(request, mac, templates)

    @app.post("/devices/{mac}/block", response_class=HTMLResponse)
    async def block(mac: str, request: Request) -> HTMLResponse:
        async with session_scope() as session:
            await set_status(session, mac, DeviceStatus.BLOCKED)
        engine = PolicyEngine(settings)
        # Best-effort actual block at UniFi
        from netwatch.unifi.client import UnifiClient

        try:
            async with UnifiClient(settings.unifi) as unifi:
                await unifi.block_client(mac)
        except Exception as exc:  # noqa: BLE001
            log.warning("ui.block.failed", mac=mac, error=repr(exc))
        return await _device_row(request, mac, templates)

    @app.post("/devices/{mac}/unblock", response_class=HTMLResponse)
    async def unblock(mac: str, request: Request) -> HTMLResponse:
        engine = PolicyEngine(settings)
        await engine.unblock(mac)
        return await _device_row(request, mac, templates)

    # ----- Policies CRUD -------------------------------------------------

    @app.post("/policies/{ssid:path}", response_class=JSONResponse)
    async def update_policy(
        ssid: str,
        internal_name: str = Form(""),
        vlan: int | None = Form(None),
        allow_kinds: str = Form(""),
        allow_owners: str = Form(""),
        auto_block_unknown: bool = Form(True),
        description: str = Form(""),
    ) -> JSONResponse:
        async with session_scope() as session:
            policy = await upsert_policy(
                session,
                ssid=ssid,
                internal_name=internal_name,
                vlan=vlan,
                allow_kinds=[s.strip() for s in allow_kinds.split(",") if s.strip()],
                allow_owners=[s.strip() for s in allow_owners.split(",") if s.strip()],
                auto_block_unknown=auto_block_unknown,
                description=description,
            )
        return JSONResponse({"ssid": policy.ssid, "ok": True})

    # ----- Sync ----------------------------------------------------------

    @app.post("/sync/unifi-aliases", response_class=HTMLResponse)
    async def sync_aliases() -> HTMLResponse:
        from netwatch.unifi.alias_sync import full_sync

        try:
            r = await full_sync(settings)
        except Exception as exc:  # noqa: BLE001
            log.warning("ui.sync.failed", error=repr(exc))
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">sync failed: {exc}</span>'
            )
        parts = []
        if r.aliases_updated:
            parts.append(f"{r.aliases_updated} name{'s' if r.aliases_updated != 1 else ''}")
        if r.online_marked:
            parts.append(f"{r.online_marked} online")
        if r.offline_marked:
            parts.append(f"{r.offline_marked} offline")
        if r.blocked_synced:
            parts.append(f"{r.blocked_synced} blocked")
        summary = ", ".join(parts) if parts else "everything up to date"
        return HTMLResponse(
            f'<span class="text-emerald-300 text-xs">synced: {summary}</span>'
        )

    # ----- Export / Import ----------------------------------------------

    @app.get("/export", response_class=FileResponse)
    async def export_db() -> FileResponse:
        """Stream a consistent SQLite snapshot to the browser."""

        from netwatch.db.backup import export_snapshot

        tmpdir = Path(tempfile.mkdtemp(prefix="netwatch-export-"))
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        snapshot = tmpdir / f"netwatch-{timestamp}.db"
        try:
            await export_snapshot(settings, snapshot)
        except Exception as exc:  # noqa: BLE001
            log.warning("ui.export.failed", error=repr(exc))
            raise HTTPException(500, f"export failed: {exc}") from exc

        return FileResponse(
            path=snapshot,
            filename=snapshot.name,
            media_type="application/vnd.sqlite3",
            # FileResponse will close the file but not delete it; clean up
            # in a background task once the response is fully sent.
            background=_cleanup_dir(tmpdir),
        )

    @app.post("/import", response_class=HTMLResponse)
    async def import_db(
        request: Request,
        snapshot: UploadFile = File(...),
        confirm: str = Form(""),
    ) -> HTMLResponse:
        """Replace the live DB with the uploaded snapshot.

        Requires `confirm=REPLACE` form field to guard against accidental
        clicks. Returns a status fragment for htmx to swap into the
        import area.
        """

        from netwatch.db.backup import restore_snapshot

        if confirm != "REPLACE":
            return HTMLResponse(
                '<span class="text-amber-300 text-xs">'
                'Refusing to import: type REPLACE to confirm.</span>',
                status_code=400,
            )

        tmpdir = Path(tempfile.mkdtemp(prefix="netwatch-import-"))
        upload_path = tmpdir / "uploaded.db"
        with upload_path.open("wb") as fh:
            while chunk := await snapshot.read(1 << 20):
                fh.write(chunk)

        try:
            await restore_snapshot(settings, upload_path)
        except ValueError as exc:
            log.warning("ui.import.rejected", error=str(exc))
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">rejected: {exc}</span>',
                status_code=400,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("ui.import.failed", error=repr(exc))
            return HTMLResponse(
                f'<span class="text-rose-300 text-xs">import failed: {exc}</span>',
                status_code=500,
            )
        finally:
            # restore_snapshot moves the file into place on success, but on
            # failure it stays in tmpdir.
            if tmpdir.exists():
                import shutil as _sh

                _sh.rmtree(tmpdir, ignore_errors=True)

        return HTMLResponse(
            '<span class="text-emerald-300 text-xs">'
            'imported successfully — refreshing…</span>'
            '<script>setTimeout(() => location.reload(), 800)</script>'
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _device_row(request: Request, mac: str, templates: Jinja2Templates) -> HTMLResponse:
    """Return just the table row for htmx to swap in."""

    from netwatch.db.repository import get_device

    async with session_scope() as session:
        device = await get_device(session, mac)
    if device is None:
        log.warning("ui.device_row.not_found", mac=mac)
        raise HTTPException(404, f"no such device: {mac}")
    # Template uses `d` as the loop variable in index.html so we pass it as `d`
    # here too. Keeps a single _device_row.html partial for both pages.
    return templates.TemplateResponse(
        request, "_device_row.html", {"d": device}
    )


def _cleanup_dir(path: Path):
    """Return a starlette BackgroundTask that removes `path` after response."""

    from starlette.background import BackgroundTask

    def _rm() -> None:
        import shutil as _sh

        _sh.rmtree(path, ignore_errors=True)

    return BackgroundTask(_rm)
