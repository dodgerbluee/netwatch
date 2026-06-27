"""MQTT discovery payload tests."""

from __future__ import annotations

import json

from netwatch.mqtt.discovery import binary_sensor, sensor


def test_sensor_payload_shape():
    payload = sensor(
        unique_id="netwatch_known_count",
        name="Netwatch Known Devices",
        state_topic="netwatch/counts/known",
        unit_of_measurement="devices",
        base_url="http://netwatch:8099",
    )
    # Round-trip JSON to confirm it's serializable.
    serialized = json.loads(json.dumps(payload))
    assert serialized["unique_id"] == "netwatch_known_count"
    assert serialized["state_topic"] == "netwatch/counts/known"
    assert serialized["device"]["identifiers"] == ["netwatch"]
    assert serialized["device"]["configuration_url"] == "http://netwatch:8099"


def test_binary_sensor_defaults_to_problem_class():
    payload = binary_sensor(
        unique_id="netwatch_alert",
        name="Netwatch Alert",
        state_topic="netwatch/alert",
        base_url="http://x",
    )
    assert payload["device_class"] == "problem"
    assert payload["payload_on"] == "on"
    assert payload["payload_off"] == "off"
