"""Shared pytest fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from netwatch.db.models import Device, DeviceKind, DeviceStatus, Policy
from netwatch.db.models import SightingEvent
from netwatch.unifi.events import NetworkEvent


@pytest.fixture(autouse=True)
def _reset_cooldowns():
    from netwatch.policy import cooldown

    cooldown.reset()
    yield
    cooldown.reset()


@pytest.fixture
def mac() -> str:
    return "aa:bb:cc:11:22:33"


@pytest.fixture
def make_event(mac: str):
    def _factory(
        *,
        ssid: str = "kidnapped bandwidth",
        event: SightingEvent = SightingEvent.CONNECTED,
        hostname: str = "test-host",
    ) -> NetworkEvent:
        return NetworkEvent(
            mac=mac,
            event=event,
            ssid=ssid,
            hostname=hostname,
            oui="Apple",
            ip="10.40.0.10",
            ap_mac="cc:dd:ee:00:11:22",
            rssi=-50,
            is_wired=False,
            observed_at=datetime.now(UTC),
            raw={},
        )

    return _factory


@pytest.fixture
def make_device(mac: str):
    def _factory(
        *,
        status: DeviceStatus = DeviceStatus.UNAPPROVED,
        kind: DeviceKind = DeviceKind.UNKNOWN,
        owner: str = "",
        allowed_ssids: list[str] | None = None,
        name: str = "test",
    ) -> Device:
        return Device(
            mac=mac,
            name=name,
            hostname=name,
            kind=kind,
            owner=owner,
            status=status,
            allowed_ssids=allowed_ssids or [],
        )

    return _factory


@pytest.fixture
def make_policy():
    def _factory(
        *,
        ssid: str = "kidnapped bandwidth",
        allow_kinds: list[str] | None = None,
        allow_owners: list[str] | None = None,
        auto_block_unknown: bool = True,
    ) -> Policy:
        return Policy(
            ssid=ssid,
            internal_name="Kids",
            vlan=40,
            allow_kinds=allow_kinds or ["personal"],
            allow_owners=allow_owners or ["natalie", "gregory", "noah", "hayden"],
            auto_block_unknown=auto_block_unknown,
        )

    return _factory
