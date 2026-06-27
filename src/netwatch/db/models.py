"""ORM models.

Schema design intent:

- `devices` is the slowly-changing system-of-record per MAC. Holds policy
  metadata (kind, owner, allowed_ssids), block state, and audit columns.
- `sightings` is an append-only event log — every association/disassoc
  we observe goes here. Used for "first seen", history queries, and
  forensics.
- `policies` stores SSID policy as rows so it can be edited via the UI
  and audited. SSID name is the natural key.
- `actions` is an audit log of every block/unblock/notify we issued.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DeviceKind(StrEnum):
    UNKNOWN = "unknown"
    PERSONAL = "personal"
    IOT = "iot"
    CAMERA = "camera"
    INFRASTRUCTURE = "infrastructure"  # APs, switches


class DeviceStatus(StrEnum):
    UNAPPROVED = "unapproved"  # never seen before -> probably auto-blocked
    KNOWN = "known"            # approved
    FLAGGED = "flagged"        # explicit watchlist
    BLOCKED = "blocked"        # currently blocked at UniFi


class SightingEvent(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ROAMED = "roamed"


class ActionKind(StrEnum):
    BLOCK = "block"
    UNBLOCK = "unblock"
    NOTIFY = "notify"
    POLICY_VIOLATION = "policy_violation"


class ActionResult(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


class Device(Base):
    __tablename__ = "devices"

    mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    oui: Mapped[str] = mapped_column(String(255), default="")
    kind: Mapped[DeviceKind] = mapped_column(
        String(32), default=DeviceKind.UNKNOWN, index=True
    )
    owner: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[DeviceStatus] = mapped_column(
        String(32), default=DeviceStatus.UNAPPROVED, index=True
    )
    # JSON list of SSID strings the device is allowed on.
    allowed_ssids: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")

    # Most-recent sighting denormalized for fast list views.
    last_ssid: Mapped[str] = mapped_column(String(64), default="")
    last_ip: Mapped[str] = mapped_column(String(45), default="")
    last_ap_mac: Mapped[str] = mapped_column(String(17), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    is_online: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    sightings: Mapped[list[Sighting]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Device(mac={self.mac!r}, status={self.status}, name={self.name!r})"


class Sighting(Base):
    __tablename__ = "sightings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str] = mapped_column(
        String(17), ForeignKey("devices.mac", ondelete="CASCADE"), index=True
    )
    event: Mapped[SightingEvent] = mapped_column(String(32), index=True)
    ssid: Mapped[str] = mapped_column(String(64), default="", index=True)
    ip: Mapped[str] = mapped_column(String(45), default="")
    ap_mac: Mapped[str] = mapped_column(String(17), default="")
    rssi: Mapped[int | None] = mapped_column(Integer)
    # Original UniFi event payload, for forensics + future re-processing.
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    device: Mapped[Device] = relationship(back_populates="sightings")


Index("ix_sightings_mac_observed", Sighting.mac, Sighting.observed_at)


class Policy(Base):
    __tablename__ = "policies"

    # SSID is the natural key. We use a surrogate id only because some
    # SSIDs include spaces and we want a stable URL-friendly slug too.
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ssid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    internal_name: Mapped[str] = mapped_column(String(64), default="")
    vlan: Mapped[int | None] = mapped_column(Integer)

    # Policy semantics
    allow_kinds: Mapped[list[str]] = mapped_column(JSON, default=list)
    allow_owners: Mapped[list[str]] = mapped_column(JSON, default=list)
    auto_block_unknown: Mapped[bool] = mapped_column(Boolean, default=True)

    description: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class Action(Base):
    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    ssid: Mapped[str] = mapped_column(String(64), default="")
    kind: Mapped[ActionKind] = mapped_column(String(32), index=True)
    result: Mapped[ActionResult] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    # Free-form context: who triggered (engine vs. user), HA action id, etc.
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


__table_args__ = (
    UniqueConstraint("ssid", name="uq_policies_ssid"),
)
