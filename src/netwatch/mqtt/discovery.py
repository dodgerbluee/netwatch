"""Home Assistant MQTT discovery payloads.

We expose:
  - sensor.netwatch_status            (running / degraded / down)
  - sensor.netwatch_known_count
  - sensor.netwatch_flagged_count
  - sensor.netwatch_unapproved_count
  - sensor.netwatch_last_event        (JSON of the most recent decision)
  - binary_sensor.netwatch_alert      (on whenever there's an unhandled alert)
  - button.netwatch_unblock_<mac>     (created lazily when an alert fires)

Each entity gets a `device` block so HA groups them together under one
"netwatch" device card.
"""

from __future__ import annotations

from typing import Any

from netwatch import __version__


def device_block(base_url: str) -> dict[str, Any]:
    """The shared `device` block used by every discovery payload."""

    return {
        "identifiers": ["netwatch"],
        "name": "Netwatch",
        "manufacturer": "dodgerbluee",
        "model": "netwatch",
        "sw_version": __version__,
        "configuration_url": base_url,
    }


def sensor(
    *,
    unique_id: str,
    name: str,
    state_topic: str,
    icon: str | None = None,
    unit_of_measurement: str | None = None,
    value_template: str | None = None,
    json_attributes_topic: str | None = None,
    base_url: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "unique_id": unique_id,
        "object_id": unique_id,
        "state_topic": state_topic,
        "device": device_block(base_url),
    }
    if icon:
        payload["icon"] = icon
    if unit_of_measurement:
        payload["unit_of_measurement"] = unit_of_measurement
    if value_template:
        payload["value_template"] = value_template
    if json_attributes_topic:
        payload["json_attributes_topic"] = json_attributes_topic
    return payload


def binary_sensor(
    *,
    unique_id: str,
    name: str,
    state_topic: str,
    base_url: str,
    device_class: str | None = "problem",
    icon: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "unique_id": unique_id,
        "object_id": unique_id,
        "state_topic": state_topic,
        "payload_on": "on",
        "payload_off": "off",
        "device": device_block(base_url),
    }
    if device_class:
        payload["device_class"] = device_class
    if icon:
        payload["icon"] = icon
    return payload


def button(
    *,
    unique_id: str,
    name: str,
    command_topic: str,
    payload_press: str,
    base_url: str,
    icon: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "unique_id": unique_id,
        "object_id": unique_id,
        "command_topic": command_topic,
        "payload_press": payload_press,
        "device": device_block(base_url),
    }
    if icon:
        payload["icon"] = icon
    return payload
