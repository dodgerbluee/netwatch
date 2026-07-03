"""OIDC provider classes.

Each provider wraps one configured row from `oauth_providers` and knows
how to:
  1. Build the authorize URL (with PKCE + state + nonce)
  2. Exchange the callback `code` for tokens
  3. Validate the ID token signature against the IdP's JWKS
  4. Translate provider-specific claims into a normalized `OIDCIdentity`

`AuthentikProvider` and `GenericOIDCProvider` differ only in claim mapping
(Authentik exposes `groups` and a friendly `name`, while plain OIDC may
not). The base class handles 95% of the work.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import httpx
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError

from netwatch.auth.oidc.discovery import Discovery, fetch_discovery
from netwatch.db.models import OAuthProvider as OAuthProviderRow
from netwatch.db.models import OAuthProviderKind
from netwatch.logging import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class OIDCIdentity:
    """Normalized claims after a successful ID token verification."""

    subject: str
    username: str
    email: str = ""
    display_name: str = ""
    groups: list[str] | None = None
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class AuthorizationStart:
    url: str
    state: str
    code_verifier: str
    nonce: str


class OIDCError(RuntimeError):
    pass


class BaseOIDCProvider:
    """One configured IdP. Instantiated by the registry from a DB row."""

    kind: OAuthProviderKind = OAuthProviderKind.GENERIC_OIDC

    def __init__(self, row: OAuthProviderRow) -> None:
        self.name = row.name
        self.display_name = row.display_name
        self.client_id = row.client_id
        self.client_secret = row.client_secret
        self.issuer_url = row.issuer_url
        self.scopes = [s.strip() for s in (row.scopes or "").split(",") if s.strip()] or [
            "openid", "profile", "email",
        ]
        self.auto_register = row.auto_register
        self.default_admin = row.default_admin

    async def _discovery(self) -> Discovery:
        return await fetch_discovery(self.issuer_url)

    # ----- step 1: kick off the authorize redirect ----------------------

    async def begin_authorization(self, *, redirect_uri: str) -> AuthorizationStart:
        """Compute everything the route needs to redirect the browser.

        The caller persists (state, code_verifier, nonce, redirect_uri) in
        the `oauth_states` table so the callback can validate.
        """

        disc = await self._discovery()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)
        code_verifier = secrets.token_urlsafe(48)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        from urllib.parse import urlencode

        url = f"{disc.authorization_endpoint}?{urlencode(params)}"
        return AuthorizationStart(
            url=url, state=state, code_verifier=code_verifier, nonce=nonce
        )

    # ----- step 2: exchange the code for tokens -------------------------

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        disc = await self._discovery()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                disc.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code_verifier": code_verifier,
                },
                headers={"Accept": "application/json"},
            )
        if resp.status_code != 200:
            log.warning(
                "oidc.token.bad_response",
                provider=self.name,
                status=resp.status_code,
                body=resp.text[:200],
            )
            raise OIDCError(f"token endpoint returned {resp.status_code}")
        return resp.json()

    # ----- step 3: verify ID token + map to identity --------------------

    async def verify_id_token(self, *, id_token: str, nonce: str) -> dict[str, Any]:
        disc = await self._discovery()
        async with httpx.AsyncClient(timeout=10) as client:
            jwks_resp = await client.get(disc.jwks_uri)
            jwks_resp.raise_for_status()
            jwks_doc = jwks_resp.json()

        # authlib lets us pass the raw JWKS doc and resolves the kid.
        jwks = JsonWebKey.import_key_set(jwks_doc)
        # authlib doesn't validate `nonce` for us — we check it manually below.
        claims = JsonWebToken(["RS256", "ES256", "PS256"]).decode(
            id_token,
            key=jwks,
            claims_options={
                "iss": {"essential": True, "value": disc.issuer},
                "aud": {"essential": True, "value": self.client_id},
                "exp": {"essential": True},
            },
        )
        try:
            claims.validate()
        except JoseError as exc:
            raise OIDCError(f"id_token validation failed: {exc}") from exc

        if claims.get("nonce") != nonce:
            raise OIDCError("nonce mismatch on id_token")
        return dict(claims)

    # ----- step 4: claims -> normalized identity ------------------------

    def to_identity(self, claims: dict[str, Any]) -> OIDCIdentity:
        return OIDCIdentity(
            subject=str(claims.get("sub") or ""),
            username=str(
                claims.get("preferred_username")
                or claims.get("email")
                or claims.get("sub")
                or ""
            ).lower(),
            email=str(claims.get("email") or "").lower(),
            display_name=str(claims.get("name") or ""),
            groups=None,
            raw=claims,
        )

    async def fetch_userinfo(self, *, access_token: str) -> dict[str, Any]:
        """Optional: fetch /userinfo for richer claims than id_token offers."""

        disc = await self._discovery()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                disc.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        resp.raise_for_status()
        return resp.json()


class AuthentikProvider(BaseOIDCProvider):
    kind = OAuthProviderKind.AUTHENTIK

    def to_identity(self, claims: dict[str, Any]) -> OIDCIdentity:
        ident = super().to_identity(claims)
        groups = claims.get("groups")
        if isinstance(groups, list):
            ident.groups = [str(g) for g in groups]
        # Authentik usually populates `name` and `preferred_username`.
        # Don't fall back to username — leave display_name empty so we
        # don't overwrite an existing display name with the username.
        return ident


class GenericOIDCProvider(BaseOIDCProvider):
    kind = OAuthProviderKind.GENERIC_OIDC


def build_provider(row: OAuthProviderRow) -> BaseOIDCProvider:
    if row.kind == OAuthProviderKind.AUTHENTIK:
        return AuthentikProvider(row)
    return GenericOIDCProvider(row)
