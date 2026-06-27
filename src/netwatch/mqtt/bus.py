"""In-process pub/sub bus.

The policy engine emits "decisions" and the MQTT publisher subscribes to
them. Decoupling lets us test the engine without spinning up a real
broker, and lets a future module (e.g., OPNsense sync) hook in too.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass

from netwatch.policy.rules import Decision
from netwatch.unifi.events import NetworkEvent


@dataclass(frozen=True, slots=True)
class DecisionEvent:
    event: NetworkEvent
    decision: Decision


_queue: asyncio.Queue[DecisionEvent] = asyncio.Queue(maxsize=1024)


async def publish_decision(*, event: NetworkEvent, decision: Decision) -> None:
    """Non-blocking publish. Drops oldest if the queue overflows so we
    never stall the policy engine on a slow broker."""

    try:
        _queue.put_nowait(DecisionEvent(event=event, decision=decision))
    except asyncio.QueueFull:
        try:
            _ = _queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        _queue.put_nowait(DecisionEvent(event=event, decision=decision))


async def subscribe_decisions() -> AsyncIterator[DecisionEvent]:
    while True:
        yield await _queue.get()
