"""Password hashing (argon2id).

Wraps argon2-cffi so the rest of the code never sees the underlying lib.
Parameters tuned for ~250ms on a small home server CPU; tweak if you run
on a Pi Zero. Argon2id automatically salts and stores all parameters in
the hash string, so future rotations don't break existing logins.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# memory_cost in KiB, time_cost in iterations, parallelism in threads.
# Defaults are RFC 9106 "second recommended option" sized down a touch for
# home hardware.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=64 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plaintext: str) -> str:
    """Return an argon2id hash string ready to store in the DB."""

    if not plaintext or len(plaintext) < 8:
        raise ValueError("password must be at least 8 characters")
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """Constant-time verify. Returns False on mismatch or empty hash."""

    if not stored_hash:
        return False
    try:
        return _hasher.verify(stored_hash, plaintext)
    except VerifyMismatchError:
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash uses weaker params than current defaults.

    Useful when bumping cost parameters — we can transparently re-hash on
    next successful login.
    """

    if not stored_hash:
        return False
    return _hasher.check_needs_rehash(stored_hash)
