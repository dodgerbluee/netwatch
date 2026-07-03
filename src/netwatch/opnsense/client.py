"""OPNsense API client — phase 2.

This module is stubbed intentionally; it's wired up so the rest of the
codebase compiles, but it doesn't do anything until you enable it.

Implementation plan when you're ready:
  1. Use API key + secret (`OPNsense -> System -> Access -> Users -> +API key`).
  2. Endpoints we'll need:
       GET  /api/firewall/alias/get
       POST /api/firewall/alias/setItem/<uuid>
       POST /api/firewall/alias/reconfigure
     Maintain two MAC aliases (`netwatch_allowed_macs`, `netwatch_blocked_macs`)
     and rebuild them from the netwatch DB on every change.
  3. Trigger: a new asyncio task subscribes to the in-process bus (same
     pattern as mqtt.publisher) and queues a sync after N seconds of
     quiet (debounce).
  4. Optional: feed a separate alias for "kids devices" so OPNsense can
     enforce per-MAC schedules independent of WiFi.
"""

from __future__ import annotations

from netwatch.config import OPNsenseConfig
from netwatch.logging import get_logger

log = get_logger(__name__)


class OPNsenseClient:
    """Stub. Methods raise NotImplementedError until wired up."""

    def __init__(self, settings: OPNsenseConfig) -> None:
        self._settings = settings

    async def sync_macs(
        self, *, allowed: list[str], blocked: list[str]
    ) -> None:  # pragma: no cover
        if not self._settings.enabled:
            log.debug("opnsense.disabled")
            return
        raise NotImplementedError("OPNsense sync is phase 2; see TODO in module docstring")
