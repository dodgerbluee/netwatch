"""Engine that ties policy decisions to side effects.

Side effects:
  - UniFi block / unblock
  - DB action audit row
  - MQTT publish (so HA gets a notification + state update)

The engine is intentionally thin — all decision logic lives in `rules.py`,
so this module is mostly orchestration.
"""

from __future__ import annotations

from netwatch.config import Settings
from netwatch.db.models import (
    ActionKind,
    ActionResult,
    DeviceStatus,
)
from netwatch.db.repository import (
    get_device,
    get_policy,
    record_action,
    set_status,
)
from netwatch.db.session import session_scope
from netwatch.logging import get_logger
from netwatch.mac import normalize_mac
from netwatch.mqtt.bus import publish_decision
from netwatch.policy.rules import Decision, Verdict, decide
from netwatch.unifi.client import UnifiClient
from netwatch.unifi.events import NetworkEvent

log = get_logger(__name__)


class PolicyEngine:
    """Stateless per-event evaluator."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def evaluate(
        self, *, event: NetworkEvent, device_created: bool
    ) -> Decision | None:
        """Evaluate a single event and dispatch any required side effects."""

        from netwatch.db.config_store import get_config

        general_cfg = await get_config("general")
        enforcement = bool(general_cfg.get("enforcement_enabled", False))

        async with session_scope() as session:
            device = await get_device(session, event.mac)
            policy = await get_policy(session, event.ssid) if event.ssid else None
            if device is None:
                log.warning("policy.no_device", mac=event.mac)
                return None

            device_name = device.name or ""
            was_blocked = device.status == DeviceStatus.BLOCKED

            decision = decide(
                device=device,
                policy=policy,
                event=event,
                enforcement_enabled=enforcement,
            )

        # Short-circuit allow.
        if decision.verdict == Verdict.ALLOW and not device_created:
            return decision

        log.info(
            "policy.decision",
            mac=event.mac,
            verdict=str(decision.verdict),
            block=decision.should_block,
            reason=decision.reason,
        )

        # --- side effects -------------------------------------------------
        first_block = False
        if decision.should_block:
            blocked = await self._block(event)
            async with session_scope() as session:
                await record_action(
                    session,
                    mac=event.mac,
                    ssid=event.ssid,
                    kind=ActionKind.BLOCK,
                    result=ActionResult.OK if blocked else ActionResult.FAILED,
                    reason=decision.reason,
                    context={"verdict": str(decision.verdict)},
                )
                if blocked:
                    await set_status(session, event.mac, DeviceStatus.BLOCKED)
                    first_block = not was_blocked
        else:
            async with session_scope() as session:
                await record_action(
                    session,
                    mac=event.mac,
                    ssid=event.ssid,
                    kind=ActionKind.NOTIFY,
                    result=ActionResult.OK,
                    reason=decision.reason,
                    context={"verdict": str(decision.verdict)},
                )

        await publish_decision(
            event=event,
            decision=decision,
            device_name=device_name,
            first_block=first_block,
        )
        return decision

    async def _block(self, event: NetworkEvent) -> bool:
        try:
            async with UnifiClient(self._settings.unifi) as unifi:
                return await unifi.block_client(event.mac)
        except Exception as exc:  # noqa: BLE001
            log.warning("policy.block.failed", mac=event.mac, error=repr(exc))
            return False

    async def unblock(self, mac: str) -> bool:
        """Manual unblock path used by the HA actionable button + web UI."""

        mac = normalize_mac(mac)
        try:
            async with UnifiClient(self._settings.unifi) as unifi:
                ok = await unifi.unblock_client(mac)
        except Exception as exc:  # noqa: BLE001
            log.warning("policy.unblock.failed", mac=mac, error=repr(exc))
            ok = False

        async with session_scope() as session:
            await record_action(
                session,
                mac=mac,
                ssid="",
                kind=ActionKind.UNBLOCK,
                result=ActionResult.OK if ok else ActionResult.FAILED,
                reason="manual unblock",
            )
            if ok:
                await set_status(session, mac, DeviceStatus.KNOWN)
        return ok
