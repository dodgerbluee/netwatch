# netwatch

WiFi device watcher for UniFi networks. Subscribes to UniFi OS events in
real time, persists every device sighting to SQLite, applies a per-SSID
policy engine to decide whether to block and notify, and publishes
everything to Home Assistant via MQTT auto-discovery.

Built to answer two questions:

1. **Has anyone connected a device I haven't seen before?**
2. **Is any known device on a WiFi network it shouldn't be on?**

Designed for households with multiple SSIDs (adults / kids / IoT / cameras /
guest). Strict SSIDs like a kids network only allow pre-approved devices —
everything else is auto-blocked until explicitly approved from a phone
notification or the web UI.

## How it works

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

The service connects to the UniFi controller's WebSocket for real-time
client connect/disconnect/roam events. Each event is normalized, recorded
as a sighting in the database, and fed to the policy engine. The engine
checks the device against the SSID's policy rules and decides whether to
allow, notify, or block (via UniFi's REST API). All decisions are published
to MQTT so Home Assistant can trigger notifications and expose actionable
buttons.

A periodic reconciler polls the UniFi active client list every 60 seconds
to catch any events missed during WebSocket reconnects.

## Features

- **Real-time monitoring** — WebSocket connection to UniFi OS for instant
  connect/disconnect/roam events
- **Per-SSID policy engine** — define which device kinds and owners are
  allowed on each SSID, with optional auto-block for unknown devices
- **Automatic enforcement** — block unauthorized devices at the UniFi
  controller and restrict approved devices to their allowed SSIDs
- **Home Assistant integration** — MQTT auto-discovery publishes sensors,
  alerts, and per-device unblock buttons with no YAML required on the HA side
- **Web UI** — htmx-based dashboard with device list, policy editor,
  sighting history, and full settings management (UniFi, MQTT, auth)
- **Authentication** — local username/password or SSO via OIDC (Authentik,
  generic OIDC providers) with PKCE
- **DB backup/restore** — export a consistent SQLite snapshot or import one
  to migrate between instances
- **Supervised tasks** — background tasks (UniFi listener, MQTT bridge,
  OPNsense poller) restart with exponential backoff; the web UI stays up
  even if the UniFi controller is unreachable
- **HA add-on** — installable as a Home Assistant add-on with ingress support

## Quickstart (Docker)

```bash
docker compose up --build
```

The web UI is at `http://localhost:8099`. On first launch you'll create an
admin account, then configure UniFi and MQTT credentials through the
Settings page.

The service waits 120 seconds after startup before alerting, so the initial
UniFi device snapshot doesn't generate a flood of notifications. During
that grace period, open the UI and approve the devices you recognize.

Once the device list looks right, enable enforcement in Settings. Now any
new MAC connecting to a strict SSID will be blocked at UniFi until you
approve it.

## Quickstart (Home Assistant add-on)

See [`addon/README.md`](addon/README.md).

## Policy engine

Each SSID has a policy row defining:

| Field | Purpose |
|---|---|
| `allow_kinds` | Device kinds permitted (e.g. `iot`, `camera`, `personal`) |
| `allow_owners` | Device owners permitted (e.g. `greg`, `natalie`) |
| `auto_block_unknown` | Whether unknown devices get blocked or just flagged |

When a device connects, the engine walks this decision tree:

1. **Flagged** — always notify (block if enforcement is on)
2. **Unapproved** — notify; block if the SSID policy has `auto_block_unknown`
3. **Known, wrong SSID** — notify (the device isn't in its `allowed_ssids`
   and the SSID policy doesn't implicitly match its kind/owner)
4. **Blocked, re-associated** — re-issue the block
5. **Otherwise** — allow silently

Approved devices can also be restricted to specific SSIDs. If a device
connects to an SSID not in its allowed list, it gets flagged but not
blocked (wrong-SSID is a warning, not a hard enforcement).

## Home Assistant integration

The service publishes these entities via MQTT auto-discovery:

| Entity | What |
|---|---|
| `sensor.netwatch_status` | `running` / `down` (LWT) |
| `sensor.netwatch_known_count` | Count of approved devices |
| `sensor.netwatch_flagged_count` | Count of watchlisted MACs |
| `sensor.netwatch_unapproved_count` | Count of devices awaiting approval |
| `sensor.netwatch_blocked_count` | Count of currently blocked MACs |
| `sensor.netwatch_last_event` | JSON of the most recent decision |
| `binary_sensor.netwatch_alert` | Flips on when an alert is pending |

For phone notifications, trigger on the MQTT topic `netwatch/event/alert`.
It is published **non-retained** and at most once per device per cooldown
window (one hour), so automations won't replay stale alerts on broker
reconnect or re-fire on every reconnect/roam of the same device. Approving,
flagging, or unblocking a device re-arms its cooldown. The payload carries
`mac`, `name`, `hostname`, `ssid`, `verdict`, `severity`, `reason`, and
`blocked`:

```yaml
triggers:
  - trigger: mqtt
    topic: netwatch/event/alert
actions:
  - action: notify.mobile_app_your_phone
    data:
      title: Network Alert
      message: >-
        {{ trigger.payload_json.name or trigger.payload_json.mac }} joined
        {{ trigger.payload_json.ssid }}
```

Do **not** trigger notifications on `netwatch/last_event` — that topic is
retained state for the `sensor.netwatch_last_event` entity and gets
republished on every decision, including allowed reconnects.

Notifications can include actionable buttons that publish MQTT commands:

```
netwatch/cmd/unblock    {"mac": "aa:bb:cc:11:22:33"}
netwatch/cmd/approve    {"mac": "...", "owner": "noah", "kind": "personal", "allowed_ssids": ["kidnapped bandwidth"]}
netwatch/cmd/flag       {"mac": "..."}
```

## Configuration

Boot-time settings load from environment variables (all optional, sane defaults):

| Variable | Default | Purpose |
|---|---|---|
| `NETWATCH_LOG_LEVEL` | `INFO` | Log verbosity |
| `NETWATCH_HTTP_HOST` | `0.0.0.0` | Bind address |
| `NETWATCH_HTTP_PORT` | `8099` | Web UI port |
| `NETWATCH_DATA_DIR` | `/data` | SQLite database location |

Everything else — UniFi credentials, MQTT broker, OPNsense, enforcement
toggle, auth settings, OIDC providers — is configured through the web UI
under Settings and stored in the database.

## Project layout

| Path | What |
|---|---|
| `src/netwatch/` | Python service (FastAPI + async tasks) |
| `src/netwatch/policy/` | Decision logic (`rules.py`) and side-effect orchestration (`engine.py`) |
| `src/netwatch/unifi/` | UniFi WebSocket listener, REST client, alias sync |
| `src/netwatch/mqtt/` | MQTT publisher, HA auto-discovery payloads, command bus |
| `src/netwatch/web/` | FastAPI routes, Jinja2 templates, static assets |
| `src/netwatch/auth/` | Local auth, OIDC/SSO, session management |
| `src/netwatch/db/` | SQLAlchemy models, repository, config store, backup |
| `Dockerfile` | Multi-stage build (~150 MB image) |
| `compose.yaml` | Local-dev compose with optional Mosquitto sidecar |
| `addon/` | Home Assistant add-on wrapper |
| `.github/workflows/` | CI (lint + test + build) and release (multi-arch GHCR push) |
| `tests/` | Policy engine, event normalizer, MQTT discovery, and auth tests |

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check . && mypy src
```

## Status

`v0.1` — feature-complete for single-controller homes. OPNsense sync is
stubbed for a future phase.

## Roadmap

- [ ] OPNsense firewall sync
- [ ] Example HA automations
- [ ] Per-owner schedule policies (e.g. kid devices blocked after 10pm)
- [ ] Web-push directly from netwatch (skip the MQTT roundtrip for notifications)
- [ ] Multi-controller support
