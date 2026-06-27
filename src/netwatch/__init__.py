"""netwatch — WiFi device watcher service.

A long-running service that:

1. Subscribes to UniFi OS events (associations, disassociations, etc.).
2. Persists every sighting + a "first seen" record per MAC to SQLite.
3. Evaluates each event against the policy engine:
   - unknown MAC                -> block + notify
   - known device on wrong SSID -> notify
   - flagged MAC                -> block + critical notify
4. Publishes everything to Home Assistant via MQTT discovery so HA gets
   sensors, binary sensors, and actionable notification buttons for free.
5. Exposes a small htmx web UI on :8099 for human review/maintenance.

The package is small enough to read end-to-end; entrypoints live in
`netwatch.main`.
"""

from __future__ import annotations

__version__ = "0.1.0"
