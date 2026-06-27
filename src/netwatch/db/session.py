"""Async session management.

We expose:
- `init_db(settings)`: ensure data dir + run schema migrations.
- `get_engine()`: process-wide AsyncEngine.
- `session_scope()`: context manager that yields an AsyncSession and
  commits on exit (rolls back on exception).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.engine import Engine  # noqa: F401  re-exported for type clarity
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from netwatch.config import Settings
from netwatch.db.models import Base
from netwatch.logging import get_logger

log = get_logger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db(settings: Settings) -> None:
    """Create data directory, open engine, and ensure schema exists.

    Uses metadata.create_all for now; Alembic migrations come once the
    schema starts evolving. The schema is small enough that a clean
    create + idempotent re-run is acceptable for v0.
    """

    global _engine, _session_factory

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    log.info("db.open", path=str(settings.db_path))

    _engine = create_async_engine(
        settings.db_url,
        echo=False,
        # SQLite niceties:
        connect_args={"timeout": 30},
        pool_pre_ping=True,
    )

    # Apply WAL + foreign keys on every new connection.
    @event.listens_for(_engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn: object, _: object) -> None:  # pragma: no cover
        cur = dbapi_conn.cursor()  # type: ignore[attr-defined]
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    # Seed default SSID policies if this is a fresh DB.
    from netwatch.db.seed import seed_default_policies_if_empty

    await seed_default_policies_if_empty()


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("init_db() must be called before get_engine()")
    return _engine


async def dispose_engine() -> None:
    """Close the current engine and reset module-level state.

    Used by `db.backup.restore_snapshot()` when swapping the underlying
    SQLite file out from under us. After calling this, you MUST call
    `init_db()` again before any DB access.
    """

    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("init_db() must be called before get_session_factory()")
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
