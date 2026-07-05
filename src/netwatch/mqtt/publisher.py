"""MQTT bridge — publishes state + listens for HA commands."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiomqtt
from sqlalchemy import func, select

from netwatch.config import Settings
from netwatch.db.models import Device, DeviceStatus
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.mqtt.bus import subscribe_decisions
from netwatch.mqtt.discovery import binary_sensor, sensor
from netwatch.policy.engine import PolicyEngine
from netwatch.policy.rules import Verdict

log = get_logger(__name__)


def _topic(base: str, *parts: str) -> str:
    return "/".join([base, *parts])


async def run_mqtt_bridge(settings: Settings) -> None:
    """Connect to MQTT, publish discovery + state, subscribe to commands."""

    mqtt_cfg = settings.mqtt
    base_url = f"http://{settings.http_host}:{settings.http_port}"
    base = mqtt_cfg.base_topic
    discovery = mqtt_cfg.discovery_prefix

    while True:
        try:
            async with aiomqtt.Client(
                hostname=mqtt_cfg.host,
                port=mqtt_cfg.port,
                username=mqtt_cfg.username or None,
                password=mqtt_cfg.password or None,
                identifier=mqtt_cfg.client_id,
                will=aiomqtt.Will(
                    topic=_topic(base, "status"),
                    payload=b"down",
                    qos=1,
                    retain=True,
                ),
            ) as client:
                log.info("mqtt.connected", host=mqtt_cfg.host, port=mqtt_cfg.port)

                # 1. Discovery payloads (retained so HA re-creates entities on
                #    restart without us re-publishing).
                await _publish_discovery(client, base, discovery, base_url)

                # 2. Set status online.
                await client.publish(
                    _topic(base, "status"), b"running", qos=1, retain=True
                )

                # 3. Clear stale retained messages on non-retained topics.
                for t in ("last_event", "last_event/summary"):
                    await client.publish(
                        _topic(base, t), b"", qos=1, retain=True
                    )

                # 4. Publish initial counts.
                await _publish_counts(client, base)

                # 5. Subscribe to commands.
                await client.subscribe(_topic(base, "cmd/+"), qos=1)

                # 6. Run pub + sub loops concurrently.
                engine = PolicyEngine(settings)
                await asyncio.gather(
                    _decision_loop(client, base),
                    _command_loop(client, base, engine),
                    _periodic_counts_loop(client, base),
                )
        except aiomqtt.MqttError as exc:
            log.warning("mqtt.disconnected", error=repr(exc), retry_in=5)
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def _publish_discovery(
    client: aiomqtt.Client, base: str, discovery: str, base_url: str
) -> None:
    entities: list[tuple[str, dict[str, Any]]] = []

    entities.append(
        (
            f"{discovery}/sensor/netwatch/status/config",
            sensor(
                unique_id="netwatch_status",
                name="Netwatch Status",
                state_topic=_topic(base, "status"),
                icon="mdi:shield-account",
                base_url=base_url,
            ),
        )
    )
    for status in (DeviceStatus.KNOWN, DeviceStatus.FLAGGED, DeviceStatus.UNAPPROVED, DeviceStatus.BLOCKED):
        entities.append(
            (
                f"{discovery}/sensor/netwatch/{status}_count/config",
                sensor(
                    unique_id=f"netwatch_{status}_count",
                    name=f"Netwatch {status.title()} Devices",
                    state_topic=_topic(base, "counts", status.value),
                    icon="mdi:devices",
                    unit_of_measurement="devices",
                    base_url=base_url,
                ),
            )
        )
    entities.append(
        (
            f"{discovery}/sensor/netwatch/last_event/config",
            sensor(
                unique_id="netwatch_last_event",
                name="Netwatch Last Event",
                state_topic=_topic(base, "last_event/summary"),
                json_attributes_topic=_topic(base, "last_event"),
                icon="mdi:bell-ring",
                base_url=base_url,
            ),
        )
    )
    entities.append(
        (
            f"{discovery}/binary_sensor/netwatch/alert/config",
            binary_sensor(
                unique_id="netwatch_alert",
                name="Netwatch Alert",
                state_topic=_topic(base, "alert"),
                base_url=base_url,
                icon="mdi:alert",
            ),
        )
    )
    entities.append(
        (
            f"{discovery}/sensor/netwatch/last_blocked/config",
            sensor(
                unique_id="netwatch_last_blocked",
                name="Netwatch Last Blocked",
                state_topic=_topic(base, "event/blocked/summary"),
                json_attributes_topic=_topic(base, "event/blocked"),
                icon="mdi:shield-off",
                base_url=base_url,
            ),
        )
    )

    for topic, payload in entities:
        await client.publish(
            topic, json.dumps(payload).encode(), qos=1, retain=True
        )
    log.info("mqtt.discovery.published", count=len(entities))


# ---------------------------------------------------------------------------
# Pub loops
# ---------------------------------------------------------------------------


async def _decision_loop(client: aiomqtt.Client, base: str) -> None:
    async for de in subscribe_decisions():
        payload = {
            "mac": de.event.mac,
            "ssid": de.event.ssid,
            "hostname": de.event.hostname,
            "ip": de.event.ip,
            "ap_mac": de.event.ap_mac,
            "verdict": str(de.decision.verdict),
            "severity": de.decision.severity,
            "reason": de.decision.reason,
            "blocked": de.decision.should_block,
            "observed_at": de.event.observed_at.isoformat(),
        }
        await client.publish(
            _topic(base, "last_event"),
            json.dumps(payload).encode(),
            qos=1,
            retain=False,
        )
        summary = (
            f"{de.decision.verdict}: {de.event.hostname or de.event.mac} "
            f"-> {de.event.ssid or '?'}"
        )
        await client.publish(
            _topic(base, "last_event/summary"),
            summary.encode(),
            qos=1,
            retain=False,
        )
        # Alert binary sensor flips on for any non-allow decision.
        alert_state = "on" if de.decision.verdict != Verdict.ALLOW else "off"
        await client.publish(
            _topic(base, "alert"), alert_state.encode(), qos=1, retain=True
        )

        # Dedicated blocked event — only fires on first-time blocks.
        if de.first_block:
            device_label = de.device_name or de.event.hostname or de.event.mac
            blocked_payload = {
                "mac": de.event.mac,
                "name": device_label,
                "ssid": de.event.ssid,
                "ip": de.event.ip,
                "reason": de.decision.reason,
                "observed_at": de.event.observed_at.isoformat(),
            }
            await client.publish(
                _topic(base, "event/blocked"),
                json.dumps(blocked_payload).encode(),
                qos=1,
                retain=False,
            )
            await client.publish(
                _topic(base, "event/blocked/summary"),
                f"Blocked: {device_label} on {de.event.ssid or '?'}".encode(),
                qos=1,
                retain=False,
            )


async def _periodic_counts_loop(client: aiomqtt.Client, base: str) -> None:
    while True:
        await asyncio.sleep(30)
        await _publish_counts(client, base)


async def _publish_counts(client: aiomqtt.Client, base: str) -> None:
    async with session_scope() as session:
        counts: dict[DeviceStatus, int] = {}
        for status in DeviceStatus:
            res = await session.execute(
                select(func.count(Device.mac)).where(Device.status == status)
            )
            counts[status] = int(res.scalar_one())
    for status, n in counts.items():
        await client.publish(
            _topic(base, "counts", status.value), str(n).encode(), qos=1, retain=True
        )


# ---------------------------------------------------------------------------
# Command subscription
# ---------------------------------------------------------------------------


async def _command_loop(
    client: aiomqtt.Client, base: str, engine: PolicyEngine
) -> None:
    """Handle incoming `netwatch/cmd/<verb>` messages."""

    async for msg in client.messages:
        topic = str(msg.topic)
        try:
            verb = topic.rsplit("/", 1)[-1]
            payload = json.loads(msg.payload.decode() or "{}")
        except Exception as exc:  # noqa: BLE001
            log.warning("mqtt.cmd.bad_payload", topic=topic, error=repr(exc))
            continue

        mac = (payload.get("mac") or "").lower()
        log.info("mqtt.cmd", verb=verb, mac=mac, payload=payload)
        if not mac:
            continue

        if verb == "unblock":
            await engine.unblock(mac)
        elif verb == "approve":
            from netwatch.db.models import DeviceKind
            from netwatch.db.repository import set_known

            async with session_scope() as session:
                await set_known(
                    session,
                    mac,
                    kind=DeviceKind(payload.get("kind", "personal")),
                    owner=payload.get("owner", ""),
                    allowed_ssids=list(payload.get("allowed_ssids", [])),
                    name=payload.get("name"),
                )
            try:
                await engine.unblock(mac)
            except Exception:  # noqa: BLE001
                pass
        elif verb == "flag":
            await _set_flagged(mac)
        else:
            log.warning("mqtt.cmd.unknown", verb=verb)


async def _set_flagged(mac: str) -> None:
    from netwatch.db.repository import set_status

    async with session_scope() as session:
        await set_status(session, mac, DeviceStatus.FLAGGED)
