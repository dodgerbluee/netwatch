"""Per-MAC cooldowns for alerts and re-block attempts.

In-memory on purpose: netwatch is a single process, restarts already get
the bootstrap grace period, and persisting notification state would be
over-engineering for a home deployment. Keys are namespaced per purpose
("alert:<mac>", "reblock:<mac>") so one MAC carries independent cooldowns
for notifications and block re-enforcement.
"""

from __future__ import annotations

import time

ALERT_COOLDOWN_SECONDS = 3600.0

_last_fired: dict[str, float] = {}


def alert_key(mac: str) -> str:
    return f"alert:{mac}"


def reblock_key(mac: str) -> str:
    return f"reblock:{mac}"


def ready(key: str, cooldown: float = ALERT_COOLDOWN_SECONDS) -> bool:
    """True if `key` hasn't fired within `cooldown` seconds; marks it fired.

    Check-and-mark is combined so callers can't forget the mark step.
    """

    now = time.monotonic()
    last = _last_fired.get(key)
    if last is not None and now - last < cooldown:
        return False
    _last_fired[key] = now
    return True


def clear(mac: str) -> None:
    """Re-arm every cooldown for a MAC. Called on status changes so a
    just-flagged or just-unapproved device alerts immediately."""

    suffix = f":{mac}"
    for key in [k for k in _last_fired if k.endswith(suffix)]:
        del _last_fired[key]


def reset() -> None:
    """Drop all cooldown state (tests only)."""

    _last_fired.clear()
