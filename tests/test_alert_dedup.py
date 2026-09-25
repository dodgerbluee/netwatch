"""Regression tests: repeated sightings must not re-alert.

Covers the alert-storm defect where every reconnect/roam of the same
unapproved device — and every association retry of a blocked device —
re-published a notify verdict and re-fired HA notifications.

Enforcement stays off (no "general" config row) so the engine never
touches the UniFi API and no mocking is needed.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from netwatch.config import Settings
from netwatch.db import session as db_session
from netwatch.db.models import Base, DeviceStatus
from netwatch.db.repository import set_status, upsert_device_from_sighting
from netwatch.mqtt import bus
from netwatch.policy.engine import PolicyEngine
from netwatch.policy.rules import Verdict
from netwatch.unifi.events import NetworkEvent


@pytest.fixture
async def db(tmp_path):
    """Point the process-wide session factory at a throwaway database.

    Deliberately bypasses init_db(): it drags in policy seeding, cookie
    secrets, and OIDC registry reload that these tests don't need.
    """

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db_session._engine = engine
    db_session._session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _drain_bus()
    yield
    _drain_bus()
    await engine.dispose()
    db_session._engine = None
    db_session._session_factory = None


def _drain_bus() -> list[bus.DecisionEvent]:
    out: list[bus.DecisionEvent] = []
    while True:
        try:
            out.append(bus._queue.get_nowait())
        except asyncio.QueueEmpty:
            return out


async def _seed_device(event: NetworkEvent) -> None:
    async with db_session.session_scope() as session:
        await upsert_device_from_sighting(
            session,
            mac=event.mac,
            ssid=event.ssid,
            ip=event.ip,
            ap_mac=event.ap_mac,
            hostname=event.hostname,
            oui=event.oui,
        )


async def test_unknown_device_alerts_once_within_cooldown(db, make_event):
    event = make_event()
    await _seed_device(event)
    engine = PolicyEngine(Settings())

    first = await engine.evaluate(event=event, device_created=True)
    second = await engine.evaluate(event=event, device_created=False)

    assert first is not None and first.verdict == Verdict.NOTIFY_UNKNOWN
    assert second is not None and second.verdict == Verdict.NOTIFY_UNKNOWN
    published = _drain_bus()
    assert [de.notify for de in published] == [True, False]


async def test_blocked_device_retry_never_alerts(db, make_event):
    event = make_event()
    await _seed_device(event)
    async with db_session.session_scope() as session:
        await set_status(session, event.mac, DeviceStatus.BLOCKED)
    engine = PolicyEngine(Settings())

    for _ in range(3):
        decision = await engine.evaluate(event=event, device_created=False)
        assert decision is not None and decision.verdict == Verdict.REBLOCK

    published = _drain_bus()
    assert len(published) == 3
    assert all(de.notify is False for de in published)


async def test_status_change_rearms_alerting(db, make_event):
    event = make_event()
    await _seed_device(event)
    engine = PolicyEngine(Settings())

    await engine.evaluate(event=event, device_created=True)   # alerts
    await engine.evaluate(event=event, device_created=False)  # suppressed

    # Operator flags the device -> cooldown re-arms -> next sighting alerts.
    async with db_session.session_scope() as session:
        await set_status(session, event.mac, DeviceStatus.FLAGGED)
    flagged = await engine.evaluate(event=event, device_created=False)

    assert flagged is not None and flagged.verdict == Verdict.NOTIFY_FLAGGED
    assert [de.notify for de in _drain_bus()] == [True, False, True]
