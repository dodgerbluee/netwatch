"""UniFi -> netwatch alias synchronization.

Pulls friendly client names from UniFi's `/rest/user` endpoint and applies
them to netwatch's Device rows. UniFi-always-wins: any alias set in UniFi
overwrites the netwatch `name` field.

Used in three places:
  - bootstrap (once at startup, after the active-client snapshot)
  - daily background task (catches aliases you add in UniFi later)
  - manual POST /sync/unifi-aliases from the web UI
"""

from __future__ import annotations

from dataclasses import dataclass

from netwatch.config import Settings
from netwatch.db.repository import sync_unifi_alias
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.unifi.client import UnifiClient

log = get_logger(__name__)


@dataclass(slots=True)
class SyncResult:
    fetched: int           # how many user records UniFi returned
    candidates: int        # how many had a non-empty alias
    updated: int           # how many netwatch rows actually changed
    missing: int           # alias existed but device not yet in netwatch DB


async def sync_unifi_aliases(settings: Settings) -> SyncResult:
    """Run one sync pass. Safe to call concurrently — each call gets its own
    UniFi session and its own DB transaction."""

    async with UnifiClient(settings.unifi) as unifi:
        users = await unifi.list_known_clients()

    candidates = [u for u in users if (u.get("name") or "").strip()]
    updated = 0
    missing = 0

    async with session_scope() as session:
        for u in candidates:
            mac = (u.get("mac") or "").lower()
            if not mac:
                continue
            changed = await sync_unifi_alias(
                session,
                mac=mac,
                alias=(u.get("name") or "").strip(),
                hostname=(u.get("hostname") or "").strip(),
            )
            if changed:
                updated += 1
            else:
                # No-op either because alias matched or device row missing.
                # Distinguish for telemetry purposes.
                from netwatch.db.models import Device

                if await session.get(Device, mac) is None:
                    missing += 1

    result = SyncResult(
        fetched=len(users),
        candidates=len(candidates),
        updated=updated,
        missing=missing,
    )
    log.info(
        "unifi.alias_sync.done",
        fetched=result.fetched,
        candidates=result.candidates,
        updated=result.updated,
        missing=result.missing,
    )
    return result
