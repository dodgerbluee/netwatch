"""Normalized event types our pipeline operates on.

UniFi's raw events have many shapes (`EVT_WU_Connected`, `EVT_LU_Connected`,
syslog-ish strings, and the websocket-only `sta:join` form on newer OS
versions). We translate all of them into a single `NetworkEvent` so the
rest of the codebase doesn't have to care.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netwatch.db.models import SightingEvent
from netwatch.mac import normalize_mac

# Raw UniFi event keys we care about. Anything else is dropped at the
# normalizer level so log noise stays sane.
_CONNECT_KEYS = {
    "EVT_WU_Connected",
    "EVT_WG_Connected",  # guest
    "EVT_LU_Connected",  # wired (we still record so we know it's wired)
    "EVT_WU_Roam",
    "EVT_WU_RoamRadio",
    "sta:join",
}

_DISCONNECT_KEYS = {
    "EVT_WU_Disconnected",
    "EVT_WG_Disconnected",
    "EVT_LU_Disconnected",
    "sta:leave",
}


@dataclass(slots=True)
class NetworkEvent:
    """One normalized association/disassociation event."""

    mac: str
    event: SightingEvent
    ssid: str = ""
    hostname: str = ""
    oui: str = ""
    ip: str = ""
    ap_mac: str = ""
    rssi: int | None = None
    is_wired: bool = False
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_wifi(self) -> bool:
        return not self.is_wired


def normalize(raw: dict[str, Any]) -> NetworkEvent | None:
    """Translate a single raw UniFi event dict to a NetworkEvent.

    Returns None if the event isn't one we track.
    """

    key = raw.get("key") or raw.get("event") or raw.get("meta", {}).get("message", "")
    mac = normalize_mac(raw.get("user") or raw.get("mac") or raw.get("client_mac") or "")
    if not mac:
        return None

    if key in _CONNECT_KEYS:
        event = SightingEvent.CONNECTED
    elif key in _DISCONNECT_KEYS:
        event = SightingEvent.DISCONNECTED
    else:
        return None

    return NetworkEvent(
        mac=mac,
        event=event,
        ssid=raw.get("ssid") or raw.get("essid") or "",
        hostname=raw.get("hostname") or raw.get("name") or "",
        oui=raw.get("oui") or "",
        ip=raw.get("ip") or raw.get("ipAddress") or "",
        ap_mac=normalize_mac(raw.get("ap") or raw.get("ap_mac") or ""),
        rssi=raw.get("rssi") if isinstance(raw.get("rssi"), int) else None,
        is_wired=bool(raw.get("is_wired") or key.startswith("EVT_LU_")),
        raw=raw,
    )
