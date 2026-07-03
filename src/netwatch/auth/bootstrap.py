"""First-run cookie secret bootstrap.

Persists a random cookie-signing secret to `<data_dir>/.cookie_secret`
so sessions survive container restarts without requiring an env var.
"""

from __future__ import annotations

import secrets

from netwatch.config import Settings
from netwatch.logging import get_logger

log = get_logger(__name__)


def ensure_cookie_secret(settings: Settings) -> None:
    if settings.auth.cookie_secret:
        return

    secret_path = settings.data_dir / ".cookie_secret"
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    if secret_path.exists():
        value = secret_path.read_text().strip()
    else:
        value = secrets.token_urlsafe(48)
        secret_path.write_text(value)
        secret_path.chmod(0o600)
        log.info("auth.cookie_secret.generated", path=str(secret_path))

    settings.auth.cookie_secret = value
