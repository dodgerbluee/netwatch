"""Database backup + restore.

Uses SQLite's `VACUUM INTO` to produce a consistent single-file snapshot
even while the service is actively writing — checkpoints the WAL into a
fresh DB file in one atomic operation. Safer than `cp netwatch.db` (which
would skip WAL contents) and faster than stopping the service.

Restore atomically swaps the active DB file and re-opens the engine so
in-flight tasks pick up the new state without a container restart.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

from sqlalchemy import text

from netwatch.config import Settings
from netwatch.logging import get_logger

log = get_logger(__name__)

SQLITE_MAGIC = b"SQLite format 3\x00"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


async def export_snapshot(settings: Settings, dest: Path) -> Path:
    """Write a consistent SQLite snapshot to `dest`.

    Uses `VACUUM INTO` which:
      - Reads all committed + WAL data
      - Writes a single, defragmented .db file at the destination
      - Doesn't touch the live DB
      - Doesn't require WAL checkpoint or quiescing writers
    """

    # Defer import to avoid circular dependency.
    from netwatch.db.session import get_engine

    dest = dest.resolve()
    if dest.exists():
        dest.unlink()
    dest.parent.mkdir(parents=True, exist_ok=True)

    engine = get_engine()
    async with engine.connect() as conn:
        # VACUUM INTO requires a *new* path that doesn't already exist.
        # Use parameterized text via bound string literal (SQLite doesn't
        # allow parameter binding in VACUUM INTO).
        escaped = str(dest).replace("'", "''")
        await conn.execute(text(f"VACUUM INTO '{escaped}'"))
    log.info("db.export.done", dest=str(dest), bytes=dest.stat().st_size)
    return dest


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def validate_sqlite_file(path: Path) -> None:
    """Sanity-check an uploaded file before we trust it.

    Raises ValueError if it's not a SQLite 3 database.
    """

    if not path.exists():
        raise ValueError(f"file not found: {path}")
    if path.stat().st_size < len(SQLITE_MAGIC):
        raise ValueError("file too small to be a SQLite database")
    with path.open("rb") as fh:
        header = fh.read(len(SQLITE_MAGIC))
    if header != SQLITE_MAGIC:
        raise ValueError("not a SQLite 3 database (bad magic header)")


async def restore_snapshot(settings: Settings, source: Path) -> None:
    """Replace the live DB with the contents of `source`.

    Steps:
      1. Validate the source is a real SQLite file.
      2. Quickly verify it has at least our core tables (so we don't
         restore an unrelated DB by mistake).
      3. Dispose the current engine to release file handles + WAL.
      4. Atomic rename source -> live db path; delete stale -wal / -shm.
      5. Re-init the engine, which re-applies pragmas and re-opens.
    """

    from netwatch.db.session import dispose_engine, init_db

    source = source.resolve()
    validate_sqlite_file(source)
    _validate_schema(source)

    live = settings.db_path
    wal = live.with_suffix(live.suffix + "-wal")
    shm = live.with_suffix(live.suffix + "-shm")

    log.info("db.restore.start", source=str(source), live=str(live))

    # 3. Close all SQLAlchemy connections + flush WAL on the live DB.
    await dispose_engine()

    # 4. Atomic swap. shutil.move handles cross-FS gracefully.
    backup = live.with_suffix(live.suffix + ".pre-restore")
    if live.exists():
        live.replace(backup)
    for stale in (wal, shm):
        if stale.exists():
            stale.unlink()
    try:
        shutil.move(str(source), str(live))
    except Exception:
        # Roll back: put the original back.
        if backup.exists():
            backup.replace(live)
        raise
    # Keep `backup` around for one cycle as a safety net; cleaned on next restore.

    # 5. Bring the engine back up.
    await init_db(settings)
    log.info("db.restore.done", live=str(live), backup=str(backup))


def _validate_schema(path: Path) -> None:
    """Open the candidate DB read-only and confirm core tables exist.

    Synchronous sqlite3 stdlib so we don't have to spin up another engine.
    """

    import sqlite3

    required = {"devices", "policies", "sightings", "actions"}
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    tables = {r[0] for r in rows}
    missing = required - tables
    if missing:
        raise ValueError(
            f"uploaded DB is missing required tables: {sorted(missing)}"
        )
