"""MAC address normalization helpers."""

from __future__ import annotations


def normalize_mac(mac: str) -> str:
    """Return a lowercase colon-separated MAC when possible."""

    cleaned = "".join(c for c in mac.strip().lower() if c in "0123456789abcdef")
    if len(cleaned) != 12:
        return mac.strip().lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
