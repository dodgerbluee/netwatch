"""FastAPI dependencies for auth.

Two endpoints into the auth system:

  - `current_user(required=True)` — for protected routes; raises 401/redirects
    if no auth could be resolved.
  - `current_user_optional()` — returns User or None; used by /login, /setup
    to redirect already-authenticated users away.

Resolution: cookie session only. OIDC providers (configured via Settings)
mint sessions through the standard /login/callback flow; once a session
exists it's no different from a local login.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from starlette.responses import Response

from netwatch.auth.sessions import get_active_session
from netwatch.config import Settings
from netwatch.db.models import User
from netwatch.db.session import session_scope


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("Accept", "")
    return "text/html" in accept or "*/*" in accept or accept == ""


async def current_user_optional(request: Request) -> User | None:
    """Best-effort resolution; never raises."""

    settings: Settings = request.app.state.settings

    # Cookie session
    token = request.cookies.get(settings.auth.cookie_name, "")
    if not token:
        return None
    async with session_scope() as s:
        found = await get_active_session(s, token)
    if found is None:
        return None
    _, user = found
    return user


async def current_user(
    request: Request,
    user: Annotated[User | None, Depends(current_user_optional)] = None,
) -> User:
    """Required auth. Behavior on failure depends on request type:
      - htmx requests get a 401 with an `HX-Redirect` header.
      - JSON / API requests get a 401.
      - HTML page loads get a 302 to /login?next=...
    """

    if user is not None:
        return user

    if _is_htmx(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"HX-Redirect": "/login"},
            detail="login required",
        )
    if _wants_html(request):
        # FastAPI's HTTPException can't redirect; raise a special exception
        # that the app's exception handler converts to a RedirectResponse.
        raise _RedirectToLogin(next_url=str(request.url.path))
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "login required")


class _RedirectToLogin(Exception):
    def __init__(self, next_url: str) -> None:
        self.next_url = next_url


def install_redirect_handler(app) -> None:
    """Wire up the redirect exception once during app creation."""

    @app.exception_handler(_RedirectToLogin)
    async def _handle(_request: Request, exc: _RedirectToLogin) -> Response:
        # quote the next URL minimally; only path is allowed in
        from urllib.parse import quote

        url = "/login"
        if exc.next_url and exc.next_url != "/":
            url += f"?next={quote(exc.next_url, safe='/')}"
        return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
