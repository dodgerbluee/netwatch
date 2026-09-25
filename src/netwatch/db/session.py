"""Async session management.

We expose:
- `init_db(settings)`: ensure data dir + run schema migrations.
- `get_engine()`: process-wide AsyncEngine.
- `session_scope()`: context manager that yields an AsyncSession and
  commits on exit (rolls back on exception).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
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
    """Create data directory, open engine, and ensure schema exists."""

    global _engine, _session_factory

    data_dir = settings.data_dir
    db_path = settings.db_path
    db_url = settings.db_url
    data_dir.mkdir(parents=True, exist_ok=True)
    log.info("db.open", data_dir=str(data_dir), path=str(db_path), url=db_url)

    _engine = create_async_engine(
        db_url,
        echo=False,
        connect_args={"timeout": 30},
        pool_pre_ping=True,
    )

    @event.listens_for(_engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn: object, _: object) -> None:  # pragma: no cover
        cur = dbapi_conn.cursor()  # type: ignore[attr-defined]
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)

    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    from netwatch.db.seed import seed_default_policies_if_empty

    await seed_default_policies_if_empty()

    from netwatch.auth.bootstrap import ensure_cookie_secret

    ensure_cookie_secret(settings)

    # Load DB-backed config into the settings object.
    await settings.load_from_db()

    from netwatch.auth.oidc import registry as oidc_registry

    await oidc_registry.reload()


def _add_missing_columns(conn: object) -> None:
    """Best-effort schema migration for new columns on existing tables."""
    from sqlalchemy import text

    from netwatch.mac import normalize_mac

    try:
        cols = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(devices)")).fetchall()  # type: ignore[union-attr]
        }
        if "connection_type" not in cols:
            conn.execute(text("ALTER TABLE devices ADD COLUMN connection_type VARCHAR(16) DEFAULT 'unknown'"))  # type: ignore[union-attr]
            log.info("db.migrate.added_column", table="devices", column="connection_type")
        _canonicalize_mac_rows(conn, normalize_mac)

        policy_cols = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(policies)")).fetchall()  # type: ignore[union-attr]
        }
        if "block_wrong_ssid" not in policy_cols:
            conn.execute(text("ALTER TABLE policies ADD COLUMN block_wrong_ssid BOOLEAN DEFAULT 0"))  # type: ignore[union-attr]
            log.info("db.migrate.added_column", table="policies", column="block_wrong_ssid")
    except Exception as exc:  # noqa: BLE001
        log.warning("db.migrate.failed", error=repr(exc))


def _canonicalize_mac_rows(
    conn: object, normalize_mac: Callable[[str], str]
) -> None:
    """Collapse legacy MAC spellings onto lowercase colon-separated keys."""

    from sqlalchemy import text

    device_rows = conn.execute(text("SELECT mac FROM devices")).fetchall()  # type: ignore[union-attr]
    groups: dict[str, list[str]] = {}
    for (mac,) in device_rows:
        canonical = normalize_mac(mac)
        groups.setdefault(canonical, []).append(mac)

    device_cols = [
        row[1]
        for row in conn.execute(text("PRAGMA table_info(devices)")).fetchall()  # type: ignore[union-attr]
    ]
    quoted_cols = ", ".join(f'"{col}"' for col in device_cols)
    select_cols = ", ".join(
        ":canonical" if col == "mac" else f'"{col}"' for col in device_cols
    )

    changed = 0
    for canonical, macs in groups.items():
        if macs == [canonical]:
            continue

        keeper = canonical if canonical in macs else macs[0]
        if canonical not in macs:
            conn.execute(  # type: ignore[union-attr]
                text(
                    f"INSERT INTO devices ({quoted_cols}) "
                    f"SELECT {select_cols} FROM devices WHERE mac = :keeper"
                ),
                {"canonical": canonical, "keeper": keeper},
            )

        for mac in macs:
            if mac == canonical:
                continue
            conn.execute(  # type: ignore[union-attr]
                text("UPDATE sightings SET mac = :canonical WHERE mac = :mac"),
                {"canonical": canonical, "mac": mac},
            )
            conn.execute(  # type: ignore[union-attr]
                text("UPDATE actions SET mac = :canonical WHERE mac = :mac"),
                {"canonical": canonical, "mac": mac},
            )
            conn.execute(  # type: ignore[union-attr]
                text("DELETE FROM devices WHERE mac = :mac"),
                {"mac": mac},
            )
            changed += 1

    if changed:
        log.info("db.migrate.canonicalized_macs", rows=changed)


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("init_db() must be called before get_engine()")
    return _engine


async def dispose_engine() -> None:
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
