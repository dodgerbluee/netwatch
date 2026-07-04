"""UniFi event listener task.

Long-running coroutine that:
  1. Connects to the UniFi WebSocket.
  2. Normalizes each event.
  3. Hands it to the policy engine.
  4. Records the sighting + any resulting action.

Also runs a periodic reconciler (every 60s) that queries the REST endpoint
for the active client list and creates synthetic CONNECTED sightings for
anything we haven't seen via WS — covers the case where the websocket
dropped events during a reconnect.
"""

from __future__ import annotations

import asyncio
import time

import structlog

from netwatch.config import Settings
from netwatch.db.models import SightingEvent
from netwatch.db.repository import (
    mark_offline,
    record_sighting,
    upsert_device_from_sighting,
)
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.policy.engine import PolicyEngine
from netwatch.unifi.alias_sync import sync_unifi_aliases
from netwatch.unifi.client import UnifiClient
from netwatch.unifi.events import NetworkEvent, normalize

log = get_logger(__name__)


async def run_unifi_listener(settings: Settings) -> None:
    """Entry point used by the Supervisor."""

    bootstrap_until = time.monotonic() + settings.unifi.bootstrap_grace_seconds
    engine = PolicyEngine(settings)

    async with UnifiClient(settings.unifi) as unifi:
        await _seed_active_clients(unifi, bootstrap_until)

    # Pull friendly aliases right after the snapshot so the UI shows good
    # names from the very first page load. Uses its own UniFi session so
    # we don't share the long-lived WebSocket client.
    try:
        await sync_unifi_aliases(settings)
    except Exception as exc:  # noqa: BLE001
        log.warning("unifi.alias_sync.bootstrap_failed", error=repr(exc))

    async with UnifiClient(settings.unifi) as unifi:
        await asyncio.gather(
            _ws_loop(unifi, engine, bootstrap_until),
            _reconcile_loop(settings, bootstrap_until, interval=60),
            _alias_resync_loop(settings, interval_seconds=86400),
        )


# ---------------------------------------------------------------------------
# Initial fill: snapshot existing associations so we don't lose state on
# every restart, but don't notify about devices that were already there.
# ---------------------------------------------------------------------------


async def _seed_active_clients(unifi: UnifiClient, bootstrap_until: float) -> None:
    log.info("unifi.bootstrap.start")
    clients = await unifi.list_active_clients()
    async with session_scope() as session:
        for c in clients:
            mac = (c.get("mac") or "").lower()
            if not mac:
                continue
            ssid = c.get("essid") or ""
            await upsert_device_from_sighting(
                session,
                mac=mac,
                ssid=ssid,
                ip=c.get("ip") or "",
                ap_mac=(c.get("ap_mac") or "").lower(),
                hostname=c.get("hostname") or c.get("name") or "",
                oui=c.get("oui") or "",
            )
            await record_sighting(
                session,
                mac=mac,
                event=SightingEvent.CONNECTED,
                ssid=ssid,
                ip=c.get("ip") or "",
                ap_mac=(c.get("ap_mac") or "").lower(),
                rssi=c.get("rssi") if isinstance(c.get("rssi"), int) else None,
                raw={"source": "bootstrap", **c},
            )
    log.info(
        "unifi.bootstrap.done",
        count=len(clients),
        grace_remaining=int(bootstrap_until - time.monotonic()),
    )


# ---------------------------------------------------------------------------
# WebSocket consumer
# ---------------------------------------------------------------------------


async def _ws_loop(
    unifi: UnifiClient, engine: PolicyEngine, bootstrap_until: float
) -> None:
    async for raw in unifi.stream_events():
        evt = normalize(raw)
        if evt is None:
            continue
        await _handle_event(evt, engine, bootstrap_until)


# ---------------------------------------------------------------------------
# Reconciler: safety net against missed events
# ---------------------------------------------------------------------------


async def _reconcile_loop(
    settings: Settings,
    bootstrap_until: float,
    *,
    interval: int,
) -> None:
    from sqlalchemy import select

    from netwatch.db.models import Device

    while True:
        await asyncio.sleep(interval)
        try:
            async with UnifiClient(settings.unifi) as unifi:
                clients = await unifi.list_active_clients()
        except Exception as exc:  # noqa: BLE001
            log.warning("unifi.reconcile.failed", error=repr(exc))
            continue

        seen_macs: set[str] = set()
        for c in clients:
            mac = (c.get("mac") or "").lower()
            if not mac:
                continue
            seen_macs.add(mac)

        async with session_scope() as session:
            res = await session.execute(
                select(Device.mac).where(Device.is_online.is_(True))
            )
            online_macs = {row[0] for row in res.all()}
            for mac in online_macs - seen_macs:
                await mark_offline(session, mac)


# ---------------------------------------------------------------------------
# Daily alias resync: catches names you add in UniFi after netwatch started
# ---------------------------------------------------------------------------


async def _alias_resync_loop(settings: Settings, *, interval_seconds: int) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await sync_unifi_aliases(settings)
        except Exception as exc:  # noqa: BLE001
            log.warning("unifi.alias_sync.periodic_failed", error=repr(exc))


# ---------------------------------------------------------------------------
# Per-event handler
# ---------------------------------------------------------------------------


async def _handle_event(
    evt: NetworkEvent, engine: PolicyEngine, bootstrap_until: float
) -> None:
    in_grace = time.monotonic() < bootstrap_until
    structlog.contextvars.bind_contextvars(mac=evt.mac, ssid=evt.ssid, event=str(evt.event))
    try:
        async with session_scope() as session:
            if evt.event == SightingEvent.DISCONNECTED:
                await record_sighting(
                    session,
                    mac=evt.mac,
                    event=evt.event,
                    ssid=evt.ssid,
                    ip=evt.ip,
                    ap_mac=evt.ap_mac,
                    rssi=evt.rssi,
                    raw=evt.raw,
                )
                await mark_offline(session, evt.mac)
                return

            device, created = await upsert_device_from_sighting(
                session,
                mac=evt.mac,
                ssid=evt.ssid,
                ip=evt.ip,
                ap_mac=evt.ap_mac,
                hostname=evt.hostname,
                oui=evt.oui,
            )

            await record_sighting(
                session,
                mac=evt.mac,
                event=evt.event,
                ssid=evt.ssid,
                ip=evt.ip,
                ap_mac=evt.ap_mac,
                rssi=evt.rssi,
                raw=evt.raw,
            )

        # Policy evaluation happens outside the DB scope to avoid holding the
        # transaction open across network I/O (UniFi block calls, MQTT publish).
        if in_grace:
            log.debug("event.skip.bootstrap_grace")
            return

        await engine.evaluate(event=evt, device_created=created)
    finally:
        structlog.contextvars.unbind_contextvars("mac", "ssid", "event")
