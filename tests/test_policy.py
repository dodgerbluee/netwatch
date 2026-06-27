"""Pure decision logic tests — no DB, no network."""

from __future__ import annotations

import pytest

from netwatch.db.models import DeviceKind, DeviceStatus
from netwatch.policy.rules import Verdict, decide


def test_unknown_device_auto_blocks_when_enforcement_on(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(status=DeviceStatus.UNAPPROVED),
        policy=make_policy(auto_block_unknown=True),
        event=make_event(),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.NOTIFY_UNKNOWN
    assert decision.should_block is True
    assert decision.severity == "warning"


def test_unknown_device_notifies_only_when_enforcement_off(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(status=DeviceStatus.UNAPPROVED),
        policy=make_policy(auto_block_unknown=True),
        event=make_event(),
        enforcement_enabled=False,
    )
    assert decision.verdict == Verdict.NOTIFY_UNKNOWN
    assert decision.should_block is False


def test_unknown_device_notifies_only_when_policy_says_so(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(status=DeviceStatus.UNAPPROVED),
        policy=make_policy(auto_block_unknown=False),
        event=make_event(),
        enforcement_enabled=True,
    )
    assert decision.should_block is False


def test_flagged_device_always_critical(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(status=DeviceStatus.FLAGGED),
        policy=make_policy(),
        event=make_event(),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.NOTIFY_FLAGGED
    assert decision.severity == "critical"
    assert decision.should_block is True


def test_known_device_on_allowed_ssid_is_silent(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(
            status=DeviceStatus.KNOWN,
            kind=DeviceKind.PERSONAL,
            owner="natalie",
            allowed_ssids=["kidnapped bandwidth"],
        ),
        policy=make_policy(),
        event=make_event(ssid="kidnapped bandwidth"),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.ALLOW


def test_known_device_on_wrong_ssid_notifies(make_event, make_device, make_policy):
    decision = decide(
        device=make_device(
            status=DeviceStatus.KNOWN,
            kind=DeviceKind.PERSONAL,
            owner="natalie",
            allowed_ssids=["kidnapped bandwidth"],
        ),
        policy=make_policy(
            ssid="blistering supersonic tsunami",
            allow_kinds=["personal"],
            allow_owners=["greg", "zac"],
        ),
        event=make_event(ssid="blistering supersonic tsunami"),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.NOTIFY_WRONG_SSID
    assert decision.should_block is False


def test_policy_implicitly_allows_kind_and_owner(make_event, make_device, make_policy):
    """Adult on Trusted with policy.allow_owners=[greg,zac] is allowed even if
    allowed_ssids on the device entry is empty."""

    decision = decide(
        device=make_device(
            status=DeviceStatus.KNOWN,
            kind=DeviceKind.PERSONAL,
            owner="greg",
            allowed_ssids=[],
        ),
        policy=make_policy(
            ssid="blistering supersonic tsunami",
            allow_kinds=["personal"],
            allow_owners=["greg", "zac"],
        ),
        event=make_event(ssid="blistering supersonic tsunami"),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.ALLOW


def test_kid_owner_blocked_on_trusted(make_event, make_device, make_policy):
    """The whole point of the system: kid's known device showing up on the
    Trusted SSID must fire NOTIFY_WRONG_SSID."""

    decision = decide(
        device=make_device(
            status=DeviceStatus.KNOWN,
            kind=DeviceKind.PERSONAL,
            owner="gregory",
            allowed_ssids=["kidnapped bandwidth"],
        ),
        policy=make_policy(
            ssid="blistering supersonic tsunami",
            allow_kinds=["personal"],
            allow_owners=["greg", "zac"],  # gregory NOT in here
        ),
        event=make_event(ssid="blistering supersonic tsunami"),
        enforcement_enabled=True,
    )
    assert decision.verdict == Verdict.NOTIFY_WRONG_SSID
