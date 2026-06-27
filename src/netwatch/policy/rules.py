"""Pure-function policy decision logic.

Kept separate from the engine that drives side effects so it's trivial to
unit-test: feed in a Device + Policy + NetworkEvent, get back a Decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from netwatch.db.models import Device, DeviceStatus, Policy
from netwatch.unifi.events import NetworkEvent


class Verdict(StrEnum):
    ALLOW = "allow"                  # do nothing
    NOTIFY_UNKNOWN = "notify_unknown"
    NOTIFY_WRONG_SSID = "notify_wrong_ssid"
    NOTIFY_FLAGGED = "notify_flagged"


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    should_block: bool
    severity: str        # "info" | "warning" | "critical"
    reason: str


def decide(
    *,
    device: Device,
    policy: Policy | None,
    event: NetworkEvent,
    enforcement_enabled: bool,
) -> Decision:
    """Compute the policy decision for a single connect event.

    The caller is responsible for actually performing the side effects
    (block, notify, log).
    """

    # ---- 1. Flagged trumps everything ----------------------------------
    if device.status == DeviceStatus.FLAGGED:
        return Decision(
            verdict=Verdict.NOTIFY_FLAGGED,
            should_block=enforcement_enabled,
            severity="critical",
            reason=f"flagged MAC {device.mac} appeared on {event.ssid!r}",
        )

    # ---- 2. Unknown device --------------------------------------------
    if device.status == DeviceStatus.UNAPPROVED:
        auto_block = bool(policy and policy.auto_block_unknown)
        return Decision(
            verdict=Verdict.NOTIFY_UNKNOWN,
            should_block=enforcement_enabled and auto_block,
            severity="warning",
            reason=(
                f"unknown device {device.mac} joined {event.ssid!r}"
                + (" (auto-block)" if auto_block else " (notify-only)")
            ),
        )

    # ---- 3. Known device — check SSID compliance ----------------------
    if device.status == DeviceStatus.KNOWN:
        if event.ssid and event.ssid not in (device.allowed_ssids or []):
            # Cross-check the SSID policy too: if the SSID's policy
            # accepts the device's kind/owner, we treat it as allowed
            # implicitly (e.g., a personal device of an allowed owner).
            if not _policy_implicitly_allows(policy, device):
                return Decision(
                    verdict=Verdict.NOTIFY_WRONG_SSID,
                    should_block=False,
                    severity="warning",
                    reason=(
                        f"known device {device.mac} ({device.name}) joined "
                        f"{event.ssid!r}, allowed: {device.allowed_ssids}"
                    ),
                )

    # ---- 4. Already-blocked device that somehow associated ------------
    if device.status == DeviceStatus.BLOCKED:
        # Re-issue the block; UniFi may have lost the rule across a
        # firmware restore or a manual unblock.
        return Decision(
            verdict=Verdict.NOTIFY_UNKNOWN,
            should_block=enforcement_enabled,
            severity="warning",
            reason=f"blocked device {device.mac} re-associated to {event.ssid!r}",
        )

    return Decision(
        verdict=Verdict.ALLOW,
        should_block=False,
        severity="info",
        reason="ok",
    )


def _policy_implicitly_allows(policy: Policy | None, device: Device) -> bool:
    """Return True if the SSID policy already accepts this device.

    e.g., a personal device owned by an adult on the Trusted SSID — we
    don't really need to enumerate it in allowed_ssids when the SSID
    policy already lists `kind=personal, owner in (greg, zac)`.
    """

    if policy is None:
        return False
    kind_ok = bool(policy.allow_kinds) and device.kind in policy.allow_kinds
    owner_ok = bool(policy.allow_owners) and device.owner in policy.allow_owners
    # Require both lists to match (intersection of constraints).
    if policy.allow_kinds and policy.allow_owners:
        return kind_ok and owner_ok
    if policy.allow_kinds:
        return kind_ok
    if policy.allow_owners:
        return owner_ok
    return False
