"""OIDC support (Authentik et al).

Three concerns:
  - `discovery.py` — fetch + cache `/.well-known/openid-configuration` for
    each issuer so we don't hit the IdP on every login.
  - `providers.py` — provider classes that turn discovery + DB row into
    authorize URL + token exchange + ID-token validation.
  - `registry.py` — in-memory `dict[name] -> Provider` populated from DB at
    startup, reloaded after admin CRUD.
"""

from __future__ import annotations
