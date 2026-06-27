"""Async task supervisor.

Owns the long-running background tasks (UniFi listener, MQTT bridge,
reconciler). Restarts them with exponential backoff on failure, but never
crashes the whole process — netwatch should keep serving the web UI even
if the UniFi controller is unreachable, so the operator can still see
state and make decisions.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from netwatch.config import Settings
from netwatch.logging import get_logger

log = get_logger(__name__)

TaskFactory = Callable[[Settings], Awaitable[None]]


@dataclass
class _SupervisedTask:
    name: str
    factory: TaskFactory
    backoff_initial: float = 1.0
    backoff_max: float = 60.0
    task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)


class Supervisor:
    """Runs each registered task in its own retry loop."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tasks: list[_SupervisedTask] = []
        self._stop_event = asyncio.Event()

    # ----- registration --------------------------------------------------

    def register(self, name: str, factory: TaskFactory) -> None:
        self._tasks.append(_SupervisedTask(name=name, factory=factory))

    # ----- lifecycle -----------------------------------------------------

    async def start(self) -> None:
        # Lazy import so circular dependencies are avoided.
        from netwatch.mqtt.publisher import run_mqtt_bridge
        from netwatch.unifi.listener import run_unifi_listener

        self.register("unifi-listener", run_unifi_listener)
        self.register("mqtt-bridge", run_mqtt_bridge)

        for t in self._tasks:
            t.task = asyncio.create_task(self._run_with_backoff(t), name=t.name)
            log.info("task.started", task=t.name)

    async def stop(self) -> None:
        self._stop_event.set()
        for t in self._tasks:
            if t.task and not t.task.done():
                t.task.cancel()
        # Best-effort wait; don't hang shutdown on a misbehaving task.
        for t in self._tasks:
            if t.task is None:
                continue
            try:
                await asyncio.wait_for(t.task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                log.warning("task.shutdown.forced", task=t.name)

    # ----- internals -----------------------------------------------------

    async def _run_with_backoff(self, t: _SupervisedTask) -> None:
        backoff = t.backoff_initial
        while not self._stop_event.is_set():
            try:
                await t.factory(self._settings)
                # Clean return -> task completed; don't restart.
                log.info("task.exited.clean", task=t.name)
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "task.crashed",
                    task=t.name,
                    error=repr(exc),
                    backoff_seconds=backoff,
                )
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                    return  # stop requested during backoff
                except TimeoutError:
                    pass
                backoff = min(backoff * 2, t.backoff_max)
