"""High-level data-access helpers.

Centralizes the queries used by the policy engine, UniFi listener, and
web UI. Keeps SQL out of those modules.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netwatch.db.models import (
    Action,
    ActionKind,
    ActionResult,
    Device,
    DeviceKind,
    DeviceStatus,
    Policy,
    Sighting,
    SightingEvent,
)


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


async def get_device(session: AsyncSession, mac: str) -> Device | None:
    mac = mac.lower()
    return await session.get(Device, mac)


async def list_devices(
    session: AsyncSession,
    *,
    status: DeviceStatus | None = None,
    online_only: bool = False,
    limit: int = 500,
) -> list[Device]:
    stmt = select(Device).order_by(Device.last_seen_at.desc().nullslast())
    if status is not None:
        stmt = stmt.where(Device.status == status)
    if online_only:
        stmt = stmt.where(Device.is_online.is_(True))
    stmt = stmt.limit(limit)
    res = await session.execute(stmt)
    return list(res.scalars().all())


async def upsert_device_from_sighting(
    session: AsyncSession,
    *,
    mac: str,
    ssid: str,
    ip: str,
    ap_mac: str,
    hostname: str,
    oui: str,
) -> tuple[Device, bool]:
    """Insert-or-update a device row from a fresh sighting.

    Returns (device, created) so callers can tell first-seen vs returning.
    """

    mac = mac.lower()
    now = datetime.now(UTC)

    existing = await session.get(Device, mac)
    if existing is None:
        device = Device(
            mac=mac,
            name=hostname or oui or mac,
            hostname=hostname,
            oui=oui,
            kind=DeviceKind.UNKNOWN,
            status=DeviceStatus.UNAPPROVED,
            allowed_ssids=[],
            last_ssid=ssid,
            last_ip=ip,
            last_ap_mac=ap_mac,
            last_seen_at=now,
            first_seen_at=now,
            is_online=True,
        )
        session.add(device)
        await session.flush()
        return device, True

    existing.last_ssid = ssid or existing.last_ssid
    existing.last_ip = ip or existing.last_ip
    existing.last_ap_mac = ap_mac or existing.last_ap_mac
    existing.last_seen_at = now
    existing.is_online = True
    if hostname and not existing.hostname:
        existing.hostname = hostname
    if oui and not existing.oui:
        existing.oui = oui
    await session.flush()
    return existing, False


async def mark_offline(session: AsyncSession, mac: str) -> None:
    await session.execute(
        update(Device).where(Device.mac == mac.lower()).values(is_online=False)
    )


async def set_status(session: AsyncSession, mac: str, status: DeviceStatus) -> None:
    await session.execute(
        update(Device).where(Device.mac == mac.lower()).values(status=status)
    )


async def set_known(
    session: AsyncSession,
    mac: str,
    *,
    kind: DeviceKind,
    owner: str,
    allowed_ssids: list[str],
    name: str | None = None,
) -> None:
    values: dict[str, Any] = {
        "status": DeviceStatus.KNOWN,
        "kind": kind,
        "owner": owner,
        "allowed_ssids": allowed_ssids,
    }
    if name:
        values["name"] = name
    await session.execute(update(Device).where(Device.mac == mac.lower()).values(**values))


async def sync_unifi_alias(
    session: AsyncSession,
    *,
    mac: str,
    alias: str,
    hostname: str = "",
) -> bool:
    """Apply a UniFi friendly alias to a device row. UniFi-always-wins.

    Returns True if the row was changed, False if no-op (alias unchanged or
    device doesn't exist yet in netwatch). We deliberately don't create a
    new Device row here — sightings are the source of new rows so we don't
    pollute the DB with every MAC UniFi has ever seen.
    """

    mac = mac.lower()
    device = await session.get(Device, mac)
    if device is None:
        return False
    changed = False
    if alias and device.name != alias:
        device.name = alias
        changed = True
    if hostname and device.hostname != hostname:
        device.hostname = hostname
        changed = True
    return changed


# ---------------------------------------------------------------------------
# Sightings
# ---------------------------------------------------------------------------


async def record_sighting(
    session: AsyncSession,
    *,
    mac: str,
    event: SightingEvent,
    ssid: str,
    ip: str,
    ap_mac: str,
    rssi: int | None,
    raw: dict[str, Any],
) -> Sighting:
    sighting = Sighting(
        mac=mac.lower(),
        event=event,
        ssid=ssid,
        ip=ip,
        ap_mac=ap_mac,
        rssi=rssi,
        raw=raw,
    )
    session.add(sighting)
    await session.flush()
    return sighting


async def recent_sightings(
    session: AsyncSession,
    *,
    mac: str | None = None,
    since: timedelta | None = None,
    limit: int = 200,
) -> list[Sighting]:
    from sqlalchemy.orm import selectinload

    stmt = (
        select(Sighting)
        .options(selectinload(Sighting.device))
        .order_by(Sighting.observed_at.desc())
        .limit(limit)
    )
    if mac is not None:
        stmt = stmt.where(Sighting.mac == mac.lower())
    if since is not None:
        cutoff = datetime.now(UTC) - since
        stmt = stmt.where(Sighting.observed_at >= cutoff)
    res = await session.execute(stmt)
    return list(res.scalars().all())


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


async def get_policy(session: AsyncSession, ssid: str) -> Policy | None:
    res = await session.execute(select(Policy).where(Policy.ssid == ssid))
    return res.scalar_one_or_none()


async def list_policies(session: AsyncSession) -> list[Policy]:
    res = await session.execute(select(Policy).order_by(Policy.ssid))
    return list(res.scalars().all())


async def upsert_policy(
    session: AsyncSession,
    *,
    ssid: str,
    internal_name: str,
    vlan: int | None,
    allow_kinds: list[str],
    allow_owners: list[str],
    auto_block_unknown: bool,
    description: str = "",
) -> Policy:
    policy = await get_policy(session, ssid)
    if policy is None:
        policy = Policy(
            ssid=ssid,
            internal_name=internal_name,
            vlan=vlan,
            allow_kinds=allow_kinds,
            allow_owners=allow_owners,
            auto_block_unknown=auto_block_unknown,
            description=description,
        )
        session.add(policy)
    else:
        policy.internal_name = internal_name
        policy.vlan = vlan
        policy.allow_kinds = allow_kinds
        policy.allow_owners = allow_owners
        policy.auto_block_unknown = auto_block_unknown
        policy.description = description
    await session.flush()
    return policy


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


async def record_action(
    session: AsyncSession,
    *,
    mac: str,
    ssid: str,
    kind: ActionKind,
    result: ActionResult,
    reason: str,
    context: dict[str, Any] | None = None,
) -> Action:
    action = Action(
        mac=mac.lower(),
        ssid=ssid,
        kind=kind,
        result=result,
        reason=reason,
        context=context or {},
    )
    session.add(action)
    await session.flush()
    return action
