from __future__ import annotations

import secrets
from typing import NamedTuple, Type

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

_PBKDF2_HASH_FACTORIES: dict[str, Type[hashes.HashAlgorithm]] = {
    "sha256":   hashes.SHA256,
    "sha512":   hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_512": hashes.SHA3_512,
}

class DerivedKey(NamedTuple):
    """Container for a derived key and its corresponding salt."""
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
    if time_cost < 1:
        raise InputValidationError("Argon2 time_cost must be >= 1.")
    if memory_cost < 8192:
        raise InputValidationError("Argon2 memory_cost must be >= 8192 KiB (8 MiB).")
    if hash_len < 16:
        raise InputValidationError("Argon2 hash_len must be >= 16 bytes.")

    try:
        from argon2.low_level import Type as Argon2Type, hash_secret_raw  # type: ignore[import-untyped]
    except ImportError as exc:
        raise KeyDerivationError(
            "argon2-cffi is required for Argon2. "
            "Install with: pip install argon2-cffi"
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
            type=Argon2Type.ID,
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
    if iterations < 100_000:
        raise InputValidationError(
            "PBKDF2 iterations must be >= 100,000. "
            "OWASP recommends >= 600,000 for HMAC-SHA256."
        )

    algo_cls = _PBKDF2_HASH_FACTORIES.get(PBKDF2_HASH)
    if algo_cls is None:
        raise KeyDerivationError(
            f"Unsupported PBKDF2 hash algorithm: {PBKDF2_HASH!r}. "
            f"Valid options: {sorted(_PBKDF2_HASH_FACTORIES)}."
        )
    algo = algo_cls()   # new instance per call — thread-safe

    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_LEN)

    try:
        password_bytes = password.encode() if isinstance(password, str) else password
        kdf_obj = PBKDF2HMAC(
            algorithm=algo,
            length=key_len,
            salt=salt,
            iterations=iterations,
        )
        key = kdf_obj.derive(password_bytes)
        return DerivedKey(key=key, salt=salt)
    except InputValidationError:
        raise
    except Exception as exc:
        raise KeyDerivationError("PBKDF2 key derivation failed.") from exc