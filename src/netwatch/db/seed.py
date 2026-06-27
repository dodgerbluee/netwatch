"""One-time seed data run on first startup.

Populates the SSID policy table with the network layout the user provided.
Subsequent startups detect existing rows and skip.
"""

from __future__ import annotations

from netwatch.db.repository import list_policies, upsert_policy
from netwatch.db.session import session_scope
from netwatch.logging import get_logger

log = get_logger(__name__)


# Maps real SSID -> policy. Order matters only for human readability.
DEFAULT_POLICIES: list[dict] = [
    {
        "ssid": "thingernet",
        "internal_name": "IoT",
        "vlan": 50,
        "allow_kinds": ["iot"],
        "allow_owners": [],
        "auto_block_unknown": True,
        "description": "IoT VLAN. Only iot-class devices allowed.",
    },
    {
        "ssid": "lan of the free",
        "internal_name": "Security",
        "vlan": 60,
        "allow_kinds": ["camera"],
        "allow_owners": [],
        "auto_block_unknown": True,
        "description": "Cameras only.",
    },
    {
        "ssid": "blistering supersonic tsunami",
        "internal_name": "Trusted",
        "vlan": 20,
        "allow_kinds": ["personal"],
        "allow_owners": ["greg", "zac"],
        "auto_block_unknown": True,
        "description": "Adults' personal devices.",
    },
    {
        "ssid": "pretty fly for a wifi",
        "internal_name": "Guest",
        "vlan": 80,
        "allow_kinds": [],
        "allow_owners": [],
        "auto_block_unknown": True,
        "description": (
            "Guest WiFi. Treat the same as everything else — nobody pre-approved."
        ),
    },
    {
        "ssid": "kidnapped bandwidth",
        "internal_name": "Kids",
        "vlan": 40,
        "allow_kinds": ["personal"],
        "allow_owners": ["natalie", "gregory", "noah", "hayden"],
        "auto_block_unknown": True,
        "description": "Kids-only personal devices.",
    },
]


async def seed_default_policies_if_empty() -> None:
    async with session_scope() as session:
        existing = await list_policies(session)
        if existing:
            log.info("policies.seed.skip", count=len(existing))
            return
        for p in DEFAULT_POLICIES:
            await upsert_policy(session, **p)
        log.info("policies.seed.inserted", count=len(DEFAULT_POLICIES))
