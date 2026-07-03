"""Server-side sessions.

We don't use signed cookies as the source of truth — the cookie holds an
opaque random token, the DB holds the actual session row. Lets us revoke
individual sessions (logout from one device, log out everywhere) without
fiddling with cookie expiry.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netwatch.db.models import Session, User
from netwatch.logging import get_logger

log = get_logger(__name__)

TOKEN_BYTES = 32  # 256 bits


def _now() -> datetime:
    return datetime.now(UTC)


async def create_session(
    session: AsyncSession,
    *,
    user: User,
    lifetime: timedelta,
    user_agent: str = "",
    ip: str = "",
) -> Session:
    """Mint a new session row + return it. Token is the row's primary key."""

    token = secrets.token_urlsafe(TOKEN_BYTES)
    row = Session(
        token=token,
        user_id=user.id,
        expires_at=_now() + lifetime,
        user_agent=user_agent[:255],
        ip=ip[:45],
    )
    session.add(row)
    user.last_login_at = _now()
    await session.flush()
    return row


async def get_active_session(
    session: AsyncSession, token: str
) -> tuple[Session, User] | None:
    """Lookup by token. Returns (session, user) or None.

    Touches `last_seen_at` for active sessions so the UI can show
    "last used" timestamps. Expired sessions are deleted lazily here so
    we don't need a cron job.
    """

    if not token:
        return None
    row = await session.get(Session, token)
    if row is None:
        return None

    now = _now()
    # SQLite drops the tzinfo when round-tripping; coerce both sides to UTC
    # so comparisons are consistent.
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= now:
        await session.delete(row)
        return None

    user = await session.get(User, row.user_id)
    if user is None or user.is_disabled:
        await session.delete(row)
        return None

    # Cheap "touch" — only update if it's been more than a minute since
    # the last update, to avoid a write on every request.
    last_seen = row.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    if (now - last_seen).total_seconds() > 60:
        row.last_seen_at = now
    return row, user


async def revoke_session(session: AsyncSession, token: str) -> None:
    await session.execute(delete(Session).where(Session.token == token))


async def revoke_all_for_user(
    session: AsyncSession, user_id: int, *, except_token: str | None = None
) -> int:
    """Useful for 'log out everywhere'. Returns count removed."""

    stmt = delete(Session).where(Session.user_id == user_id)
    if except_token:
        stmt = stmt.where(Session.token != except_token)
    res = await session.execute(stmt)
    return int(res.rowcount or 0)


async def purge_expired(session: AsyncSession) -> int:
    """Periodic cleanup; safe to call on any schedule."""

    res = await session.execute(delete(Session).where(Session.expires_at <= _now()))
    return int(res.rowcount or 0)
