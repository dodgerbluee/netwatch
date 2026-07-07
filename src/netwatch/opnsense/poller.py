"""OPNsense wired-device poller.

Periodically polls the ARP table and DHCP leases to detect wired devices
connecting and disconnecting. Creates Device + Sighting rows the same way
the UniFi listener does for wireless devices.

Wired-only: any MAC also seen via UniFi (wireless) is skipped so we don't
double-count devices.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from netwatch.config import Settings
from netwatch.db.models import ConnectionType, Device, SightingEvent
from netwatch.db.repository import (
    mark_offline,
    record_sighting,
    upsert_device_from_sighting,
)
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.mac import normalize_mac
from netwatch.opnsense.client import OPNsenseClient

log = get_logger(__name__)

# MACs to always ignore (broadcast, multicast, gateway).
_IGNORE_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33:")


def _is_ignorable(mac: str) -> bool:
    return any(mac.startswith(p) for p in _IGNORE_PREFIXES)


async def run_opnsense_poller(settings: Settings) -> None:
    """Entry point for the supervisor."""
    interval = 30
    previous_macs: set[str] = set()

    while True:
        try:
            current_macs, hostname_map, ip_map = await _poll_once(settings)
            new = current_macs - previous_macs
            gone = previous_macs - current_macs

            if new:
                await _handle_connected(new, hostname_map, ip_map)
            if gone:
                await _handle_disconnected(gone)

            previous_macs = current_macs
        except Exception as exc:  # noqa: BLE001
            log.warning("opnsense.poll.failed", error=repr(exc))

        await asyncio.sleep(interval)


async def _poll_once(
    settings: Settings,
) -> tuple[set[str], dict[str, str], dict[str, str]]:
    """Poll ARP + DHCP, return (active_macs, hostname_map, ip_map).

    Filters out wireless MACs (already tracked by UniFi).
    """
    async with OPNsenseClient(settings.opnsense) as client:
        arp_entries = await client.get_arp_table()
        dhcp_leases = await client.get_dhcp_leases()

    # Build hostname lookup from DHCP leases.
    hostname_map: dict[str, str] = {}
    for lease in dhcp_leases:
        mac = normalize_mac(lease.get("mac") or "")
        hostname = (lease.get("hostname") or "").strip()
        if mac and hostname:
            hostname_map[mac] = hostname

    # Active wired MACs from ARP (only completed entries).
    active_macs: set[str] = set()
    ip_map: dict[str, str] = {}
    for entry in arp_entries:
        mac = normalize_mac(entry.get("mac") or "")
        ip = entry.get("ip") or ""
        if not mac or mac == "(incomplete)" or _is_ignorable(mac):
            continue
        active_macs.add(mac)
        if ip:
            ip_map[mac] = ip

    # Filter out wireless MACs already tracked by UniFi.
    wifi_macs = await _get_wifi_macs()
    wired_only = active_macs - wifi_macs

    log.debug(
        "opnsense.poll",
        arp_total=len(active_macs),
        wired_only=len(wired_only),
        dhcp_leases=len(dhcp_leases),
    )
    return wired_only, hostname_map, ip_map


async def _get_wifi_macs() -> set[str]:
    """Return MACs of devices with a non-empty last_ssid (i.e., wireless)."""
    from sqlalchemy import select

    async with session_scope() as session:
        res = await session.execute(
            select(Device.mac).where(Device.last_ssid != "")
        )
        return {row[0] for row in res.all()}


async def _handle_connected(
    macs: set[str],
    hostname_map: dict[str, str],
    ip_map: dict[str, str],
) -> None:
    async with session_scope() as session:
        for mac in macs:
            hostname = hostname_map.get(mac, "")
            ip = ip_map.get(mac, "")

            device, created = await upsert_device_from_sighting(
                session,
                mac=mac,
                ssid="",
                ip=ip,
                ap_mac="",
                hostname=hostname,
                oui="",
                connection_type=ConnectionType.WIRED,
            )
            await record_sighting(
                session,
                mac=mac,
                event=SightingEvent.CONNECTED,
                ssid="",
                ip=ip,
                ap_mac="",
                rssi=None,
                raw={"source": "opnsense-arp"},
            )
            log.info(
                "opnsense.device.connected",
                mac=mac,
                hostname=hostname,
                ip=ip,
                new=created,
            )


async def _handle_disconnected(macs: set[str]) -> None:
    async with session_scope() as session:
        for mac in macs:
            await record_sighting(
                session,
                mac=mac,
                event=SightingEvent.DISCONNECTED,
                ssid="",
                ip="",
                ap_mac="",
                rssi=None,
                raw={"source": "opnsense-arp"},
            )
            await mark_offline(session, mac)
            log.info("opnsense.device.disconnected", mac=mac)
