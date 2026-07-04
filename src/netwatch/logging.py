"""Structured logging setup.

structlog provides JSON-friendly records and contextual binding ("with this
event's mac/ssid in scope, every nested log automatically includes them").
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


_configured = False


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog + stdlib logging in one place.

    Output is key=value in containers and pretty-printed when stderr is a tty.
    Guarded to run only once even if called multiple times.
    """

    global _configured  # noqa: PLW0603
    if _configured:
        return
    _configured = True

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if sys.stderr.isatty():
        renderer: Any = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logs (uvicorn, sqlalchemy) to stderr with minimal format.
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Quiet down chatty libs.
    for noisy in ("uvicorn.access", "sqlalchemy.engine.Engine", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
