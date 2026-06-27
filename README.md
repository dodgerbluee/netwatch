# netwatch

WiFi device watcher. Subscribes to UniFi OS events in real time, persists
every sighting to a local SQLite database, applies a policy engine to
decide whether to block + notify, and publishes everything to Home
Assistant via MQTT auto-discovery.

Designed to answer two questions reliably:

1. Has anyone connected a device I haven't seen before?
2. Is any known device on a WiFi network it shouldn't be on?

Built for households with multiple SSIDs (adults / kids / IoT / cameras /
guest). The kids network gets the strictest policy — only the approved
kid devices may join, everything else is auto-blocked until explicitly
approved from a phone notification or the web UI.

## Status

`v0.1` — feature-complete for single-controller homes. OPNsense sync is
stubbed for a future phase. License is **TBD** — decide before pushing
the repo public.

## What's in the box

| Path | What it is |
|---|---|
| `src/netwatch/` | The Python service. |
| `Dockerfile` | Multi-stage build that produces a ~150 MB image. |
| `compose.yaml` | Local-dev compose with an optional Mosquitto sidecar. |
| `addon/` | Home Assistant add-on wrapper around the same image. |
| `.github/workflows/` | CI (lint + test + build) and release (multi-arch GHCR push). |
| `tests/` | Pure-function tests for the policy engine + event normalizer. |

## Architecture

```
                    UniFi WebSocket   (real-time events)
                            │
                            ▼
       ┌─────────────────────────────────────────────┐
       │              netwatch service               │
       │                                             │
       │   normalizer  ───►  policy engine           │
       │       │                  │                  │
       │       │              UniFi API   ◄────── block / unblock
       │       │                  │                  │
       │       ▼                  ▼                  │
       │   SQLite (devices / sightings / actions)    │
       │       │                  │                  │
       │       │                  ▼                  │
       │       │            MQTT publisher  ────► Home Assistant
       │       │                  │                  │       (discovery)
       │       ▼                  ▼                  │
       │   web UI (htmx)    HA action callbacks      │
       └─────────────────────────────────────────────┘
```

## Quickstart (Docker)

```bash
cp .env.example .env
$EDITOR .env                 # UniFi + MQTT credentials
docker compose up --build
```

Web UI at <http://localhost:8099>. The service waits 120 seconds after
startup before alerting, so the initial UniFi snapshot doesn't generate
a flood. During that grace period, open the UI and approve the devices
you recognize.

Once the device list looks right, set `NETWATCH_ENFORCEMENT_ENABLED=true`
and restart. Now any new MAC connecting will be blocked at UniFi until
you approve it.

## Quickstart (HA add-on)

See `addon/README.md`.

## Default SSID policy

Pre-seeded on first DB creation; edit freely in the web UI under
**Policies**.

| SSID | Internal | VLAN | Allowed |
|---|---|---|---|
| `thingernet` | IoT | 50 | kind: iot |
| `lan of the free` | Security | 60 | kind: camera |
| `blistering supersonic tsunami` | Trusted | 20 | personal devices of `greg`, `zac` |
| `pretty fly for a wifi` | Guest | 80 | — (everything new prompts approval) |
| `kidnapped bandwidth` | Kids | 40 | personal devices of `natalie`, `gregory`, `noah`, `hayden` |

## Home Assistant integration

The service publishes the following entities via MQTT auto-discovery —
no YAML on the HA side required:

| Entity | What |
|---|---|
| `sensor.netwatch_status` | `running` / `down` (LWT) |
| `sensor.netwatch_known_count` | count of approved devices |
| `sensor.netwatch_flagged_count` | count of watchlisted MACs |
| `sensor.netwatch_unapproved_count` | count of devices awaiting approval |
| `sensor.netwatch_blocked_count` | count of currently blocked MACs |
| `sensor.netwatch_last_event` | JSON of the most recent decision |
| `binary_sensor.netwatch_alert` | flips on when an alert is pending |

For notifications, write a simple HA automation that triggers on
`binary_sensor.netwatch_alert` -> on, pulls the JSON from
`sensor.netwatch_last_event` attributes, and pushes to your phone. The
HA notification can include "Approve" / "Keep blocked" buttons that
publish to:

```
netwatch/cmd/unblock    {"mac": "aa:bb:cc:11:22:33"}
netwatch/cmd/approve    {"mac": "...", "owner": "noah", "kind": "personal", "allowed_ssids": ["kidnapped bandwidth"]}
netwatch/cmd/flag       {"mac": "..."}
```

Example HA automation YAML lives in the `examples/` folder once added.

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check . && mypy src
```

## Roadmap

- [ ] Decide license (currently TBD)
- [ ] OPNsense sync (`src/netwatch/opnsense/client.py` has the plan)
- [ ] Example HA automations (`examples/`)
- [ ] Per-owner schedule policies (e.g. kid device blocked after 10pm)
- [ ] Web-push directly from netwatch (skip MQTT roundtrip)
- [ ] Multi-controller support
