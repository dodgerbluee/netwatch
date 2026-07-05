"""DB-backed configuration store.

Reads and writes AppConfig rows so the app can be configured entirely
through the web UI instead of env vars.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from netwatch.db.models import AppConfig
from netwatch.db.session import session_scope


async def get_config(key: str) -> dict[str, Any]:
    async with session_scope() as s:
        row = await s.get(AppConfig, key)
        return dict(row.value) if row else {}


async def set_config(key: str, value: dict[str, Any]) -> None:
    async with session_scope() as s:
        row = await s.get(AppConfig, key)
        if row is None:
            row = AppConfig(key=key, value=value)
            s.add(row)
        else:
            row.value = value
            flag_modified(row, "value")


async def get_all_config() -> dict[str, dict[str, Any]]:
    async with session_scope() as s:
        res = await s.execute(select(AppConfig))
        return {row.key: dict(row.value) for row in res.scalars().all()}


async def delete_config(key: str) -> None:
    async with session_scope() as s:
        row = await s.get(AppConfig, key)
        if row is not None:
            await s.delete(row)
