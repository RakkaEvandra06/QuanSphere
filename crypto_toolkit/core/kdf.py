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

_PBKDF2_MIN_ITERATIONS: dict[str, int] = {
    "sha256":   600_000,
    "sha512":   210_000,
    "sha3_256": 600_000,
    "sha3_512": 210_000,
}

class DerivedKey(NamedTuple):
    key: bytes
    salt: bytes
    pbkdf2_hash: str | None = None
    pbkdf2_iterations: int | None = None

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
        raise InputValidationError(
            f"Argon2 memory_cost must be >= 8192 KiB (8 MiB); "
            f"received {memory_cost} KiB ({memory_cost / 1024:.2f} MiB). "
            f"Note: memory_cost is expressed in KiB, not MiB — "
            f"pass 65536 for 64 MiB (the recommended default)."
        )
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
        # pbkdf2_hash and pbkdf2_iterations remain None — not applicable to Argon2.
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
    hash_algorithm: str = PBKDF2_HASH,
) -> DerivedKey:
    min_iters = _PBKDF2_MIN_ITERATIONS.get(hash_algorithm, 600_000)
    if iterations < min_iters:
        raise InputValidationError(
            f"PBKDF2 iterations must be >= {min_iters:,} for {hash_algorithm!r} "
            f"(OWASP 2023 recommendation). "
            f"Received: {iterations:,}."
        )

    algo_cls = _PBKDF2_HASH_FACTORIES.get(hash_algorithm)
    if algo_cls is None:
        raise KeyDerivationError(
            f"Unsupported PBKDF2 hash algorithm: {hash_algorithm!r}. "
            f"Valid options: {sorted(_PBKDF2_HASH_FACTORIES)}."
        )
    algo = algo_cls()

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
        return DerivedKey(
            key=key,
            salt=salt,
            pbkdf2_hash=hash_algorithm,
            pbkdf2_iterations=iterations,
        )
    except InputValidationError:
        raise
    except Exception as exc:
        raise KeyDerivationError("PBKDF2 key derivation failed.") from exc