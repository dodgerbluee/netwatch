"""OIDC discovery document fetcher with in-process TTL cache."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from netwatch.logging import get_logger

log = get_logger(__name__)

DISCOVERY_PATH = "/.well-known/openid-configuration"
CACHE_TTL_SECONDS = 3600


@dataclass(slots=True)
class Discovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    end_session_endpoint: str = ""
    raw: dict[str, Any] | None = None

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> Discovery:
        missing = [
            k for k in (
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "jwks_uri",
            )
            if k not in doc
        ]
        if missing:
            raise ValueError(f"discovery doc missing required keys: {missing}")
        return cls(
            issuer=doc["issuer"],
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            userinfo_endpoint=doc["userinfo_endpoint"],
            jwks_uri=doc["jwks_uri"],
            end_session_endpoint=doc.get("end_session_endpoint", ""),
            raw=doc,
        )


_cache: dict[str, tuple[float, Discovery]] = {}


async def fetch_discovery(issuer_url: str) -> Discovery:
    """Return cached Discovery or fetch + cache.

    `issuer_url` is normalized by stripping a trailing slash. If your IdP
    serves discovery at a non-standard path (Authentik does
    `/application/o/<slug>/.well-known/openid-configuration`), just pass
    the issuer URL exactly as it appears in their config.
    """

    key = issuer_url.rstrip("/")
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and (now - cached[0]) < CACHE_TTL_SECONDS:
        return cached[1]

    url = key + DISCOVERY_PATH
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()

    discovery = Discovery.from_doc(doc)
    _cache[key] = (now, discovery)
    log.info("oidc.discovery.cached", issuer=key)
    return discovery


def invalidate_cache(issuer_url: str | None = None) -> None:
    """Drop a single issuer (or everything) from the cache."""

    if issuer_url is None:
        _cache.clear()
        return
    _cache.pop(issuer_url.rstrip("/"), None)
