"""Application entrypoint.

Starts:
  - FastAPI HTTP server (web UI + JSON API + healthz)
  - UniFi event listener task (when configured)
  - MQTT publisher / subscriber task (when configured)

Each subsystem runs as a supervised asyncio task. If any of them crash,
the supervisor logs + retries with exponential backoff. The process only
exits on SIGTERM/SIGINT or repeated unrecoverable failures.
"""

from __future__ import annotations

import asyncio
import signal
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI

from netwatch.config import Settings, get_settings
from netwatch.logging import configure_logging, get_logger
from netwatch.web.app import create_app

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    log.info("starting", version=app.version, data_dir=str(settings.data_dir))

    from netwatch.db.session import init_db
    from netwatch.supervisor import Supervisor

    await init_db(settings)
    supervisor = Supervisor(settings)
    await supervisor.start()
    app.state.supervisor = supervisor

    try:
        yield
    finally:
        log.info("shutting down")
        await supervisor.stop()


def create() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = create_app(settings=settings, lifespan=lifespan)
    return app


def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)

    config = uvicorn.Config(
        "netwatch.main:create",
        factory=True,
        host=settings.http_host,
        port=settings.http_port,
        log_level=settings.log_level.lower(),
        access_log=False,
        loop="uvloop" if _has_uvloop() else "auto",
    )
    server = uvicorn.Server(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, server.handle_exit, sig, None)

    try:
        loop.run_until_complete(server.serve())
    finally:
        loop.close()


def _has_uvloop() -> bool:
    try:
        import uvloop  # noqa: F401

        return True
    except ImportError:
        return False


if __name__ == "__main__":
    run()
