"""Password-based key derivation functions (KDFs).

Primary KDF: **Argon2id** (memory-hard, side-channel resistant).
Fallback KDF: **PBKDF2-HMAC-SHA256** (for environments without argon2-cffi).

Both functions return a ``DerivedKey`` named-tuple containing the raw key
bytes and the salt, so callers can store the salt for later re-derivation.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto_toolkit.core.constants import (
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    PBKDF2_HASH,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LEN,
    PBKDF2_SALT_LEN,
)
from crypto_toolkit.core.exceptions import InputValidationError, KeyDerivationError


class DerivedKey(NamedTuple):
    """Container for a derived key and its associated salt."""

    key: bytes
    salt: bytes


def derive_key_argon2(
    password: str | bytes,
    *,
    salt: bytes | None = None,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> DerivedKey:
    """Derive a key from *password* using Argon2id.

    Args:
        password: User password as string or bytes.
        salt: 16+ byte random salt.  Generated securely if ``None``.
        time_cost: Number of Argon2 iterations.
        memory_cost: Memory usage in KiB.
        parallelism: Degree of parallelism.
        hash_len: Output key length in bytes.

    Returns:
        :class:`DerivedKey` with ``.key`` and ``.salt`` attributes.

    Raises:
        KeyDerivationError: If argon2-cffi is unavailable or derivation fails.
        InputValidationError: If parameters are below safe minimums.
    """
    if time_cost < 1:
        raise InputValidationError("Argon2 time_cost must be ≥ 1.")
    if memory_cost < 8192:
        raise InputValidationError("Argon2 memory_cost must be ≥ 8192 KiB (8 MiB).")
    if hash_len < 16:
        raise InputValidationError("Argon2 hash_len must be ≥ 16 bytes.")

    try:
        from argon2.low_level import Type, hash_secret_raw  # type: ignore[import-untyped]
    except ImportError as exc:
        raise KeyDerivationError(
            "argon2-cffi is required for Argon2 derivation.  "
            "Install it with: pip install argon2-cffi"
        ) from exc

    if salt is None:
        salt = secrets.token_bytes(ARGON2_SALT_LEN)

    try:
        password_bytes = password.encode() if isinstance(password, str) else password
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )
        return DerivedKey(key=key, salt=salt)
    except (InputValidationError, KeyDerivationError):
        raise
    except Exception as exc:
        raise KeyDerivationError("Argon2 key derivation failed.") from exc


def derive_key_pbkdf2(
    password: str | bytes,
    *,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
    key_len: int = PBKDF2_KEY_LEN,
) -> DerivedKey:
    """Derive a key from *password* using PBKDF2-HMAC-SHA256.

    Prefer :func:`derive_key_argon2` when available.  This function is
    provided as a standards-compliant fallback.

    Args:
        password: User password.
        salt: Random salt; generated if ``None``.
        iterations: PBKDF2 iteration count (OWASP 2023: ≥ 600 000).
        key_len: Output key length in bytes.

    Returns:
        :class:`DerivedKey`.

    Raises:
        InputValidationError: If iteration count is dangerously low.
        KeyDerivationError: On derivation failure.
    """
    if iterations < 100_000:
        raise InputValidationError(
            "PBKDF2 iterations must be ≥ 100 000.  "
            "OWASP recommends ≥ 600 000 for HMAC-SHA256."
        )

    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_LEN)

    try:
        password_bytes = password.encode() if isinstance(password, str) else password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password_bytes)
        return DerivedKey(key=key, salt=salt)
    except InputValidationError:
        raise
    except Exception as exc:
        raise KeyDerivationError("PBKDF2 key derivation failed.") from exc
