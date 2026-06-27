"""Event normalization tests."""

from __future__ import annotations

from netwatch.db.models import SightingEvent
from netwatch.unifi.events import normalize


def test_normalize_wireless_connect():
    evt = normalize(
        {
            "key": "EVT_WU_Connected",
            "user": "AA:BB:CC:11:22:33",
            "ssid": "blistering supersonic tsunami",
            "ap": "cc:dd:ee:00:11:22",
            "ip": "10.20.0.5",
            "hostname": "ZacIphone",
            "oui": "Apple",
            "rssi": -45,
        }
    )
    assert evt is not None
    assert evt.mac == "aa:bb:cc:11:22:33"  # lowercased
    assert evt.event == SightingEvent.CONNECTED
    assert evt.ssid == "blistering supersonic tsunami"
    assert evt.is_wifi is True


def test_normalize_disconnect():
    evt = normalize(
        {
            "key": "EVT_WU_Disconnected",
            "user": "aa:bb:cc:11:22:33",
            "ssid": "kidnapped bandwidth",
        }
    )
    assert evt is not None
    assert evt.event == SightingEvent.DISCONNECTED


def test_normalize_wired_uses_lu_keys():
    evt = normalize(
        {
            "key": "EVT_LU_Connected",
            "user": "aa:bb:cc:11:22:33",
        }
    )
    assert evt is not None
    assert evt.is_wired is True


def test_normalize_ignores_unrelated_events():
    assert normalize({"key": "EVT_AD_Login", "user": "aa:bb:cc:11:22:33"}) is None
    assert normalize({}) is None
    assert normalize({"key": "EVT_WU_Connected"}) is None  # no MAC


def test_normalize_handles_modern_sta_join_form():
    evt = normalize(
        {
            "key": "sta:join",
            "mac": "AA:BB:CC:11:22:33",
            "essid": "thingernet",
            "ap_mac": "cc:dd:ee:00:11:22",
            "ipAddress": "10.50.0.7",
        }
    )
    assert evt is not None
    assert evt.event == SightingEvent.CONNECTED
    assert evt.ssid == "thingernet"
    assert evt.ip == "10.50.0.7"
