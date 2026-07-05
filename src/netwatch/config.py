"""Runtime configuration.

Boot-time settings (port, data dir, log level) still load from env vars
because they're needed before the DB is available. Everything else
(UniFi, MQTT, OPNsense, enforcement, auth cookie tuning) lives in the
DB and is configured through the web UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Boot-time settings (env vars only — needed before DB exists)
# ---------------------------------------------------------------------------


class BootSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETWATCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    http_host: str = Field(default="0.0.0.0")  # noqa: S104
    http_port: int = Field(default=8099, ge=1, le=65535)
    data_dir: Annotated[Path, Field(default=Path("/data"))]

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netwatch.db"

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"


# ---------------------------------------------------------------------------
# DB-backed service configuration (plain dataclasses — no env coupling)
# ---------------------------------------------------------------------------


@dataclass
class UniFiConfig:
    host: str = ""
    site: str = "default"
    username: str = ""
    password: str = ""
    verify_tls: bool = False
    bootstrap_grace_seconds: int = 120

    @property
    def configured(self) -> bool:
        return bool(self.host and self.username and self.password)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host.rstrip("/"),
            "site": self.site,
            "username": self.username,
            "password": self.password,
            "verify_tls": self.verify_tls,
            "bootstrap_grace_seconds": self.bootstrap_grace_seconds,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UniFiConfig:
        return cls(
            host=d.get("host", "").rstrip("/"),
            site=d.get("site", "default"),
            username=d.get("username", ""),
            password=d.get("password", ""),
            verify_tls=bool(d.get("verify_tls", False)),
            bootstrap_grace_seconds=int(d.get("bootstrap_grace_seconds", 120)),
        )


@dataclass
class MQTTConfig:
    host: str = ""
    port: int = 1883
    username: str = ""
    password: str = ""
    discovery_prefix: str = "homeassistant"
    base_topic: str = "netwatch"
    client_id: str = "netwatch"

    @property
    def configured(self) -> bool:
        return bool(self.host)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "discovery_prefix": self.discovery_prefix,
            "base_topic": self.base_topic,
            "client_id": self.client_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MQTTConfig:
        return cls(
            host=d.get("host", ""),
            port=int(d.get("port", 1883)),
            username=d.get("username", ""),
            password=d.get("password", ""),
            discovery_prefix=d.get("discovery_prefix", "homeassistant"),
            base_topic=d.get("base_topic", "netwatch"),
            client_id=d.get("client_id", "netwatch"),
        )


@dataclass
class OPNsenseConfig:
    host: str = ""
    api_key: str = ""
    api_secret: str = ""
    verify_tls: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.api_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "api_key": self.api_key,
            "api_secret": self.api_secret,
            "verify_tls": self.verify_tls,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OPNsenseConfig:
        return cls(
            host=d.get("host", ""),
            api_key=d.get("api_key", ""),
            api_secret=d.get("api_secret", ""),
            verify_tls=bool(d.get("verify_tls", False)),
        )


@dataclass
class AuthConfig:
    cookie_name: str = "netwatch_session"
    cookie_secret: str = ""
    session_lifetime_days: int = 30
    cookie_secure: bool = True
    cookie_samesite: str = "lax"
    external_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookie_name": self.cookie_name,
            "session_lifetime_days": self.session_lifetime_days,
            "cookie_secure": self.cookie_secure,
            "cookie_samesite": self.cookie_samesite,
            "external_url": self.external_url,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuthConfig:
        return cls(
            cookie_name=d.get("cookie_name", "netwatch_session"),
            session_lifetime_days=int(d.get("session_lifetime_days", 30)),
            cookie_secure=bool(d.get("cookie_secure", True)),
            cookie_samesite=d.get("cookie_samesite", "lax"),
            external_url=d.get("external_url", ""),
        )


# ---------------------------------------------------------------------------
# Unified Settings object
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    """Unified settings object used throughout the app.

    `boot` comes from env vars. Everything else is populated from the DB
    after init_db() runs, via `load_from_db()`.
    """

    boot: BootSettings = field(default_factory=BootSettings)

    enforcement_enabled: bool = False
    unifi: UniFiConfig = field(default_factory=UniFiConfig)
    mqtt: MQTTConfig = field(default_factory=MQTTConfig)
    opnsense: OPNsenseConfig = field(default_factory=OPNsenseConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)

    # Convenience proxies so callers don't need to say settings.boot.X
    @property
    def log_level(self) -> str:
        return self.boot.log_level

    @property
    def http_host(self) -> str:
        return self.boot.http_host

    @property
    def http_port(self) -> int:
        return self.boot.http_port

    @property
    def data_dir(self) -> Path:
        return self.boot.data_dir

    @property
    def db_path(self) -> Path:
        return self.boot.db_path

    @property
    def db_url(self) -> str:
        return self.boot.db_url

    async def load_from_db(self) -> None:
        from netwatch.db.config_store import get_all_config

        cfg = await get_all_config()
        if "unifi" in cfg:
            self.unifi = UniFiConfig.from_dict(cfg["unifi"])
        if "mqtt" in cfg:
            self.mqtt = MQTTConfig.from_dict(cfg["mqtt"])
        if "opnsense" in cfg:
            self.opnsense = OPNsenseConfig.from_dict(cfg["opnsense"])
        if "general" in cfg:
            raw = cfg["general"].get("enforcement_enabled", False)
            self.enforcement_enabled = bool(raw)
            import structlog
            structlog.get_logger().info(
                "config.load_from_db.general",
                raw_value=raw,
                raw_type=type(raw).__name__,
                final=self.enforcement_enabled,
                sections=list(cfg.keys()),
            )
        if "auth" in cfg:
            secret = self.auth.cookie_secret
            self.auth = AuthConfig.from_dict(cfg["auth"])
            self.auth.cookie_secret = secret

    async def save_section(self, section: str, data: dict[str, Any]) -> None:
        from netwatch.db.config_store import set_config

        await set_config(section, data)
        await self.load_from_db()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
