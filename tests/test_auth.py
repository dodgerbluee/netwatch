"""Auth + OIDC unit tests."""

from __future__ import annotations

import pytest

from netwatch.auth.oidc.discovery import Discovery
from netwatch.auth.passwords import hash_password, needs_rehash, verify_password


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def test_password_hash_round_trip():
    h = hash_password("correcthorsebattery")
    assert h.startswith("$argon2id$")
    assert verify_password("correcthorsebattery", h)
    assert not verify_password("wrong-password", h)


def test_password_min_length():
    with pytest.raises(ValueError):
        hash_password("short")


def test_verify_password_handles_empty_hash():
    assert verify_password("anything", "") is False


def test_needs_rehash_handles_empty():
    assert needs_rehash("") is False


# ---------------------------------------------------------------------------
# OIDC discovery doc parsing
# ---------------------------------------------------------------------------


def test_discovery_from_doc_happy():
    d = Discovery.from_doc({
        "issuer": "https://auth.example.com/application/o/netwatch/",
        "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
        "token_endpoint": "https://auth.example.com/application/o/token/",
        "userinfo_endpoint": "https://auth.example.com/application/o/userinfo/",
        "jwks_uri": "https://auth.example.com/application/o/netwatch/jwks/",
    })
    assert d.issuer == "https://auth.example.com/application/o/netwatch/"
    assert d.authorization_endpoint.endswith("/authorize/")


def test_discovery_from_doc_missing_keys():
    with pytest.raises(ValueError) as ex:
        Discovery.from_doc({"issuer": "x"})
    assert "missing" in str(ex.value)


# ---------------------------------------------------------------------------
# Provider PKCE / state generation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_begin_authorization_produces_required_params(monkeypatch):
    from urllib.parse import parse_qs, urlparse

    from netwatch.auth.oidc.providers import AuthentikProvider

    class _Row:
        name = "test"
        display_name = "Test"
        kind = type("K", (), {"value": "authentik"})()
        client_id = "abc"
        client_secret = "secret"
        issuer_url = "https://auth.example.com/application/o/netwatch/"
        scopes = "openid,profile,email"
        auto_register = True
        default_admin = False

    prov = AuthentikProvider(_Row())

    fake_disc = Discovery.from_doc({
        "issuer": _Row.issuer_url,
        "authorization_endpoint": "https://auth.example.com/o/authorize/",
        "token_endpoint": "https://auth.example.com/o/token/",
        "userinfo_endpoint": "https://auth.example.com/o/userinfo/",
        "jwks_uri": "https://auth.example.com/o/jwks/",
    })

    async def fake_discovery(_: str):
        return fake_disc

    monkeypatch.setattr(
        "netwatch.auth.oidc.providers.fetch_discovery", fake_discovery
    )

    start = await prov.begin_authorization(
        redirect_uri="https://netwatch.example.com/auth/oidc/callback"
    )
    parsed = urlparse(start.url)
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    assert qs["response_type"] == "code"
    assert qs["client_id"] == "abc"
    assert qs["redirect_uri"] == "https://netwatch.example.com/auth/oidc/callback"
    assert qs["state"] == start.state
    assert qs["nonce"] == start.nonce
    assert qs["code_challenge_method"] == "S256"
    assert qs["code_challenge"]  # not empty
    assert "openid" in qs["scope"]


def test_authentik_to_identity_extracts_groups():
    from netwatch.auth.oidc.providers import AuthentikProvider

    class _Row:
        name = "authentik"
        display_name = "Authentik"
        kind = type("K", (), {"value": "authentik"})()
        client_id = "x"
        client_secret = "y"
        issuer_url = "https://auth.example.com/"
        scopes = "openid"
        auto_register = True
        default_admin = False

    prov = AuthentikProvider(_Row())
    ident = prov.to_identity({
        "sub": "abc-123",
        "preferred_username": "Greg",
        "email": "greg@example.com",
        "name": "Greg Foo",
        "groups": ["admin", "users"],
    })
    assert ident.subject == "abc-123"
    assert ident.username == "greg"
    assert ident.email == "greg@example.com"
    assert ident.display_name == "Greg Foo"
    assert ident.groups == ["admin", "users"]


def test_generic_to_identity_no_groups():
    from netwatch.auth.oidc.providers import GenericOIDCProvider

    class _Row:
        name = "g"
        display_name = "G"
        kind = type("K", (), {"value": "generic_oidc"})()
        client_id = "x"
        client_secret = "y"
        issuer_url = "https://idp.example.com/"
        scopes = "openid"
        auto_register = True
        default_admin = False

    prov = GenericOIDCProvider(_Row())
    ident = prov.to_identity({
        "sub": "xyz",
        "email": "a@b.com",
    })
    assert ident.subject == "xyz"
    assert ident.username == "a@b.com"
    assert ident.groups is None
