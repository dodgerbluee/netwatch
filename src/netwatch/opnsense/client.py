"""OPNsense API client.

Uses API key + secret authentication to poll:
  - ARP table (currently reachable L2 neighbours → wired devices)
  - DHCP leases (historical + active → hostname + lease metadata)

Only tracks ethernet/wired devices — anything also seen on Wi-Fi
via UniFi is ignored so there's a single source of truth per MAC.
"""

from __future__ import annotations

from typing import Any

import httpx

from netwatch.config import OPNsenseConfig
from netwatch.logging import get_logger

log = get_logger(__name__)


class OPNsenseClient:
    def __init__(self, settings: OPNsenseConfig) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> OPNsenseClient:
        self._client = httpx.AsyncClient(
            base_url=self._settings.host,
            verify=self._settings.verify_tls,
            timeout=httpx.Timeout(15.0, connect=5.0),
            auth=(self._settings.api_key, self._settings.api_secret),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_arp_table(self) -> list[dict[str, Any]]:
        """Return ARP entries from diagnostics/interface."""
        assert self._client is not None
        resp = await self._client.get("/api/diagnostics/interface/getArp")
        resp.raise_for_status()
        data = resp.json()
        log.debug("opnsense.arp.raw_type", type=type(data).__name__,
                  keys=list(data.keys()) if isinstance(data, dict) else f"list[{len(data)}]")
        if isinstance(data, list):
            return data
        return list(data.get("rows", data.get("arp", [])))

    async def get_dhcp_leases(self) -> list[dict[str, Any]]:
        """Return all DHCPv4 leases (active + expired)."""
        assert self._client is not None
        resp = await self._client.get(
            "/api/dhcpv4/leases/searchLease"
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return list(data.get("rows", []))

    async def get_interfaces(self) -> dict[str, Any]:
        """Return interface list (to identify LAN vs WAN)."""
        assert self._client is not None
        resp = await self._client.get("/api/diagnostics/interface/getInterfaceNames")
        resp.raise_for_status()
        return resp.json()
