"""UniFi -> netwatch synchronization.

Pulls client data from UniFi and applies it to netwatch's Device rows:
  - Friendly names (aliases) from /rest/user
  - Online/offline status from /stat/sta (active clients)
  - Blocked status from /rest/user (blocked flag)
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import update

from netwatch.config import Settings
from netwatch.db.models import Device, DeviceStatus
from netwatch.db.repository import sync_unifi_alias
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.unifi.client import UnifiClient

log = get_logger(__name__)


@dataclass(slots=True)
class SyncResult:
    fetched: int = 0
    aliases_updated: int = 0
    missing: int = 0
    online_marked: int = 0
    offline_marked: int = 0
    blocked_synced: int = 0


async def sync_unifi_aliases(settings: Settings) -> SyncResult:
    """Legacy entry point — calls full_sync."""
    return await full_sync(settings)


async def full_sync(settings: Settings) -> SyncResult:
    """Run a full sync pass: names, online/offline, and blocked status."""

    async with UnifiClient(settings.unifi) as unifi:
        known_clients = await unifi.list_known_clients()
        active_clients = await unifi.list_active_clients()

    active_macs = {(c.get("mac") or "").lower() for c in active_clients if c.get("mac")}
    blocked_macs = {
        (u.get("mac") or "").lower()
        for u in known_clients
        if u.get("blocked")
    }
    log.debug("unifi.sync.blocked_from_unifi", count=len(blocked_macs), macs=list(blocked_macs)[:10])

    result = SyncResult(fetched=len(known_clients))

    async with session_scope() as session:
        # 1. Sync aliases
        candidates = [u for u in known_clients if (u.get("name") or "").strip()]
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
                result.aliases_updated += 1
            elif await session.get(Device, mac) is None:
                result.missing += 1

        # 2. Sync online/offline status
        from sqlalchemy import select

        all_devices = (await session.execute(select(Device))).scalars().all()
        for device in all_devices:
            is_active = device.mac in active_macs
            if device.is_online != is_active:
                device.is_online = is_active
                if is_active:
                    result.online_marked += 1
                else:
                    result.offline_marked += 1

        # 3. Sync blocked status (bidirectional)
        # Pull: UniFi blocked -> netwatch blocked.
        # UniFi is the authority — if a device is blocked there, the app
        # reflects it. (Approve unblocks at UniFi, so no false conflicts.)
        existing_macs = {d.mac for d in all_devices}
        for device in all_devices:
            if device.mac in blocked_macs and device.status != DeviceStatus.BLOCKED:
                device.status = DeviceStatus.BLOCKED
                result.blocked_synced += 1

        # Create device rows for blocked clients not yet in DB
        known_by_mac = {(u.get("mac") or "").lower(): u for u in known_clients}
        for mac in blocked_macs - existing_macs:
            u = known_by_mac.get(mac, {})
            device = Device(
                mac=mac,
                name=(u.get("name") or "").strip() or mac,
                hostname=(u.get("hostname") or "").strip(),
                oui=(u.get("oui") or "").strip(),
                status=DeviceStatus.BLOCKED,
                is_online=False,
            )
            session.add(device)
            result.blocked_synced += 1

    # Push: netwatch blocked -> UniFi blocked (only when enforcement is on)
    if settings.enforcement_enabled:
        async with session_scope() as session:
            from sqlalchemy import select
            res = await session.execute(
                select(Device.mac).where(Device.status == DeviceStatus.BLOCKED)
            )
            netwatch_blocked = {row[0] for row in res.all()}

        to_block_in_unifi = netwatch_blocked - blocked_macs
        if to_block_in_unifi:
            async with UnifiClient(settings.unifi) as unifi:
                for mac in to_block_in_unifi:
                    try:
                        await unifi.block_client(mac)
                        result.blocked_synced += 1
                    except Exception as exc:  # noqa: BLE001
                        log.warning("unifi.sync.block_push_failed", mac=mac, error=repr(exc))

    log.info(
        "unifi.full_sync.done",
        fetched=result.fetched,
        aliases=result.aliases_updated,
        online=result.online_marked,
        offline=result.offline_marked,
        blocked=result.blocked_synced,
    )
    return result
