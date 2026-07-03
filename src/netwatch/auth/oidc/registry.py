"""In-memory provider registry.

Loaded from the DB at app startup. Admin CRUD calls `reload()` after
writing so the running process picks up the change without a restart.

Discovery is cached separately (see `discovery.py`); changing `issuer_url`
on an existing provider invalidates its discovery entry.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import select

from netwatch.auth.oidc.discovery import invalidate_cache
from netwatch.auth.oidc.providers import BaseOIDCProvider, build_provider
from netwatch.db.models import OAuthProvider as OAuthProviderRow
from netwatch.db.session import session_scope
from netwatch.logging import get_logger

log = get_logger(__name__)


_providers: dict[str, BaseOIDCProvider] = {}
_lock = asyncio.Lock()


async def reload() -> None:
    """Re-read all enabled providers from the DB."""

    async with _lock:
        async with session_scope() as session:
            res = await session.execute(
                select(OAuthProviderRow).where(OAuthProviderRow.enabled.is_(True))
            )
            rows = list(res.scalars().all())

        new: dict[str, BaseOIDCProvider] = {}
        for row in rows:
            try:
                new[row.name] = build_provider(row)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "oidc.provider.invalid", name=row.name, error=repr(exc)
                )

        # Invalidate discovery cache for any issuer that disappeared or changed.
        old_issuers = {p.issuer_url for p in _providers.values()}
        new_issuers = {p.issuer_url for p in new.values()}
        for stale in old_issuers - new_issuers:
            invalidate_cache(stale)

        _providers.clear()
        _providers.update(new)
        log.info("oidc.providers.reloaded", count=len(_providers))


def get(name: str) -> BaseOIDCProvider | None:
    return _providers.get(name)


def list_public() -> list[dict[str, str]]:
    """Public-facing list used by the login page (no secrets)."""

    return [
        {"name": p.name, "display_name": p.display_name, "kind": p.kind.value}
        for p in _providers.values()
    ]


def count() -> int:
    return len(_providers)
