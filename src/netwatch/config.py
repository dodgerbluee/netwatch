"""Runtime configuration.

All settings load from environment variables prefixed `NETWATCH_`. The HA
add-on wrapper translates its `options.json` into the same env vars, so a
single config surface serves both deployment modes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class UniFiSettings(BaseSettings):
    """UniFi OS controller connection settings."""

    model_config = SettingsConfigDict(env_prefix="NETWATCH_UNIFI_", extra="ignore")

    host: str = Field(
        default="https://192.168.1.1",
        description="Base URL of the UniFi OS controller (UDM/UDR/UCG/CK2+).",
    )
    site: str = Field(default="default", description="UniFi site name.")
    username: str = Field(default="", description="Local UniFi account username.")
    password: SecretStr = Field(default=SecretStr(""), description="Account password.")
    verify_tls: bool = Field(
        default=False,
        description="Verify the UniFi self-signed certificate. Default False for "
        "out-of-the-box compatibility; set True after you install a cert.",
    )

    # Bootstrapping / safety knobs ----------------------------------------
    bootstrap_grace_seconds: int = Field(
        default=120,
        description="Seconds after startup during which existing associations are "
        "ingested without firing 'first seen' alerts. Prevents a notification "
        "storm on first launch.",
    )

    @field_validator("host")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")


class MQTTSettings(BaseSettings):
    """MQTT broker settings — typically the Mosquitto add-on inside HA."""

    model_config = SettingsConfigDict(env_prefix="NETWATCH_MQTT_", extra="ignore")

    host: str = Field(default="homeassistant.local")
    port: int = Field(default=1883, ge=1, le=65535)
    username: str = Field(default="")
    password: SecretStr = Field(default=SecretStr(""))
    discovery_prefix: str = Field(
        default="homeassistant",
        description="HA MQTT discovery prefix. Must match the HA Mosquitto integration.",
    )
    base_topic: str = Field(
        default="netwatch",
        description="Top-level topic netwatch publishes its own state under.",
    )
    client_id: str = Field(default="netwatch")


class OPNsenseSettings(BaseSettings):
    """OPNsense API settings (optional, phase-2 sync)."""

    model_config = SettingsConfigDict(env_prefix="NETWATCH_OPNSENSE_", extra="ignore")

    host: str = Field(default="")
    api_key: SecretStr = Field(default=SecretStr(""))
    api_secret: SecretStr = Field(default=SecretStr(""))
    verify_tls: bool = Field(default=False)

    @property
    def enabled(self) -> bool:
        return bool(self.host) and bool(self.api_key.get_secret_value())


class Settings(BaseSettings):
    """Top-level settings aggregator."""

    model_config = SettingsConfigDict(
        env_prefix="NETWATCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # service ------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    http_host: str = Field(default="0.0.0.0")  # noqa: S104  binding inside a container
    http_port: int = Field(default=8099, ge=1, le=65535)
    data_dir: Annotated[Path, Field(default=Path("/data"))]

    enforcement_enabled: bool = Field(
        default=False,
        description="Master kill-switch for block actions. Leave OFF during initial "
        "bootstrap so you can populate known_devices without blocking anything.",
    )

    # composed ------------------------------------------------------------
    unifi: UniFiSettings = Field(default_factory=UniFiSettings)
    mqtt: MQTTSettings = Field(default_factory=MQTTSettings)
    opnsense: OPNsenseSettings = Field(default_factory=OPNsenseSettings)

    # derived -------------------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "netwatch.db"

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Cached so tests can override by clearing the cache and re-importing.
    """

    return Settings()
