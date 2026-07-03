"""UniFi OS REST + WebSocket client.

Handles:
  - Session login (UniFi OS unifies the auth across applications: the
    Network application sits behind /proxy/network/).
  - Listing currently associated clients (used for bootstrap + reconcile).
  - Block / unblock client via the stamgr cmd endpoint.
  - WebSocket subscription to live events (/proxy/network/wss/s/<site>/events).

The client tolerates self-signed certs by default and automatically
re-authenticates on 401.
"""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from typing import Any

import httpx
import websockets
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from netwatch.config import UniFiConfig
from netwatch.logging import get_logger

log = get_logger(__name__)


class UnifiAuthError(RuntimeError):
    pass


class UnifiClient:
    """Thin async wrapper around the UniFi OS HTTP + WS APIs."""

    def __init__(self, settings: UniFiConfig) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._csrf: str | None = None

    # ----- lifecycle -----------------------------------------------------

    async def __aenter__(self) -> UnifiClient:
        self._client = httpx.AsyncClient(
            base_url=self._settings.host,
            verify=self._settings.verify_tls,
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
        )
        await self._login()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ----- auth ----------------------------------------------------------

    async def _login(self) -> None:
        assert self._client is not None
        resp = await self._client.post(
            "/api/auth/login",
            json={
                "username": self._settings.username,
                "password": self._settings.password,
                "remember": True,
            },
        )
        if resp.status_code != 200:
            raise UnifiAuthError(
                f"UniFi login failed ({resp.status_code}): {resp.text[:200]}"
            )
        # UDM-Pro requires the CSRF token on subsequent state-changing calls.
        self._csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("x-csrf-token")
        log.info("unifi.login.ok", host=self._settings.host)

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._csrf:
            h["X-CSRF-Token"] = self._csrf
        return h

    # ----- REST: clients -------------------------------------------------

    async def list_active_clients(self) -> list[dict[str, Any]]:
        """Currently associated stations on the configured site."""

        data = await self._get(f"/proxy/network/api/s/{self._settings.site}/stat/sta")
        return list(data.get("data", []))

    async def list_known_clients(self) -> list[dict[str, Any]]:
        """All ever-known clients (UniFi-side identity DB)."""

        data = await self._get(
            f"/proxy/network/api/s/{self._settings.site}/rest/user"
        )
        return list(data.get("data", []))

    # ----- REST: block / unblock ----------------------------------------

    async def block_client(self, mac: str) -> bool:
        return await self._stamgr_cmd("block-sta", mac)

    async def unblock_client(self, mac: str) -> bool:
        return await self._stamgr_cmd("unblock-sta", mac)

    async def _stamgr_cmd(self, cmd: str, mac: str) -> bool:
        ok = await self._post(
            f"/proxy/network/api/s/{self._settings.site}/cmd/stamgr",
            json={"cmd": cmd, "mac": mac.lower()},
        )
        log.info("unifi.stamgr", cmd=cmd, mac=mac, ok=ok)
        return ok

    # ----- WebSocket: events --------------------------------------------

    async def stream_events(self) -> AsyncIterator[dict[str, Any]]:
        """Yield raw events as dicts forever, reconnecting on disconnect."""

        if self._client is None:
            raise RuntimeError("use as async context manager")

        ssl_ctx: ssl.SSLContext | bool
        if self._settings.verify_tls:
            ssl_ctx = ssl.create_default_context()
        else:
            ssl_ctx = ssl._create_unverified_context()  # noqa: S323  self-signed UDM

        # Cookies set by /api/auth/login are stored on the httpx client; we
        # need them for the WS handshake. UniFi sends them as cookies on the
        # same host, so we serialize the jar.
        cookies = "; ".join(
            f"{c.name}={c.value}" for c in self._client.cookies.jar
        )
        ws_url = (
            self._settings.host.replace("https://", "wss://").replace("http://", "ws://")
            + f"/proxy/network/wss/s/{self._settings.site}/events"
        )
        headers = {"Cookie": cookies}
        if self._csrf:
            headers["X-CSRF-Token"] = self._csrf

        async for attempt in AsyncRetrying(
            wait=wait_exponential(multiplier=1, min=2, max=60),
            stop=stop_after_attempt(0),  # forever
            retry=retry_if_exception_type(Exception),
            reraise=True,
        ):
            with attempt:
                log.info("unifi.ws.connecting", url=ws_url)
                async with websockets.connect(
                    ws_url,
                    extra_headers=headers,
                    ssl=ssl_ctx if ws_url.startswith("wss://") else None,
                    ping_interval=25,
                    ping_timeout=20,
                    max_size=2_000_000,
                ) as ws:
                    log.info("unifi.ws.connected")
                    async for raw in ws:
                        try:
                            import json

                            msg: Any = json.loads(raw)
                        except Exception:  # noqa: BLE001
                            continue
                        # UniFi multiplexes various streams; the relevant
                        # ones are wrapped like {"meta": {...}, "data": [...]}.
                        if isinstance(msg, dict) and "data" in msg:
                            for item in msg.get("data") or []:
                                if isinstance(item, dict):
                                    yield item
                        elif isinstance(msg, dict):
                            yield msg

    # ----- internals -----------------------------------------------------

    async def _get(self, path: str) -> dict[str, Any]:
        assert self._client is not None
        resp = await self._client.get(path, headers=self._headers())
        if resp.status_code == 401:
            await self._login()
            resp = await self._client.get(path, headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    async def _post(self, path: str, *, json: dict[str, Any]) -> bool:
        assert self._client is not None
        resp = await self._client.post(path, headers=self._headers(), json=json)
        if resp.status_code == 401:
            await self._login()
            resp = await self._client.post(path, headers=self._headers(), json=json)
        if resp.status_code >= 400:
            log.warning(
                "unifi.post.failed",
                path=path,
                status=resp.status_code,
                body=resp.text[:200],
            )
            return False
        return True
