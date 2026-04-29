from __future__ import annotations

__all__ = [
    "DerivedKey",
    "derive_key_argon2",
    "derive_key_pbkdf2",
    "PBKDF2_SUPPORTED_HASHES",
    "zero_bytes",
    "ARGON2_MAX_TIME_COST",
    "ARGON2_MAX_MEMORY_COST",
    "ARGON2_MAX_PARALLELISM",
]

import ctypes
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

ARGON2_MAX_TIME_COST:   int = 1_000        # iterations
ARGON2_MAX_MEMORY_COST: int = 2_097_152    # 2 GiB expressed in KiB
ARGON2_MAX_PARALLELISM: int = 64           # lanes / threads
_ARGON2_MAX_HASH_LEN:    int = 128          # output bytes
_PBKDF2_HASH_FACTORIES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256":   hashes.SHA256,
    "sha512":   hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_512": hashes.SHA3_512,
}

PBKDF2_SUPPORTED_HASHES: frozenset[str] = frozenset(_PBKDF2_HASH_FACTORIES)

_PBKDF2_MIN_ITERATIONS: dict[str, int] = {
    "sha256":   600_000,   # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    "sha512":   210_000,   # OWASP 2023 recommendation for PBKDF2-HMAC-SHA512
    "sha3_256": 200_000,   # SHA3-256 is ~3× slower than SHA-256 per iteration
    "sha3_512": 100_000,   # SHA3-512 is ~2× slower than SHA-512 per iteration
}

class DerivedKey(NamedTuple):
    key: bytes
    salt: bytes
    pbkdf2_hash: str | None = None
    pbkdf2_iterations: int | None = None

def zero_bytes(data: bytes) -> None:
    """Best-effort in-place zero of a bytes object (CPython only)."""
    try:
        buf_offset = bytes.__basicsize__ - 1   # 33 on CPython 3.10-3.12 / 64-bit
        ctypes.memset(id(data) + buf_offset, 0, len(data))
        # Verify the wipe in debug builds so any layout change is caught
        # immediately rather than silently allowing key material to persist.
        assert not __debug__ or data == b"\x00" * len(data), (
            "zero_bytes: post-wipe verification failed — "
            "buf_offset calculation may be wrong for this Python build"
        )
    except Exception:
        # Non-CPython runtime or layout mismatch — accept the limitation
        # silently.  The caller still proceeds; this is best-effort only.
        pass

# ── Argon2id key derivation ───────────────────────────────────────────────────

def derive_key_argon2(
    password: str | bytes,
    *,
    salt: bytes | None = None,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> DerivedKey:
    if not password:
        raise InputValidationError("Password must not be empty.")

    if salt is not None and len(salt) < ARGON2_SALT_LEN:
        raise InputValidationError(
            f"Argon2 salt must be at least {ARGON2_SALT_LEN} bytes; "
            f"received {len(salt)} byte(s). "
            "Pass salt=None to have a cryptographically secure random salt "
            "generated automatically."
        )

    if not (1 <= time_cost <= ARGON2_MAX_TIME_COST):
        raise InputValidationError(
            f"Argon2 time_cost must be between 1 and {ARGON2_MAX_TIME_COST}; "
            f"received {time_cost}."
        )
    if not (8192 <= memory_cost <= ARGON2_MAX_MEMORY_COST):
        raise InputValidationError(
            f"Argon2 memory_cost must be between 8192 and {ARGON2_MAX_MEMORY_COST} KiB "
            f"(8 MiB – 2 GiB); received {memory_cost} KiB ({memory_cost / 1024:.2f} MiB). "
            f"Note: memory_cost is expressed in KiB, not MiB — "
            f"pass 65536 for 64 MiB (the recommended default)."
        )
    if not (1 <= parallelism <= ARGON2_MAX_PARALLELISM):
        raise InputValidationError(
            f"Argon2 parallelism must be between 1 and {ARGON2_MAX_PARALLELISM}; "
            f"received {parallelism}."
        )
    if not (16 <= hash_len <= _ARGON2_MAX_HASH_LEN):
        raise InputValidationError(
            f"Argon2 hash_len must be between 16 and {_ARGON2_MAX_HASH_LEN} bytes; "
            f"received {hash_len}."
        )

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

# ── PBKDF2 key derivation ─────────────────────────────────────────────────────

def derive_key_pbkdf2(
    password: str | bytes,
    *,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
    key_len: int = PBKDF2_KEY_LEN,
    hash_algorithm: str = PBKDF2_HASH,
) -> DerivedKey:
    if not password:
        raise InputValidationError("Password must not be empty.")

    algo_cls = _PBKDF2_HASH_FACTORIES.get(hash_algorithm)
    if algo_cls is None:
        raise InputValidationError(
            f"Unsupported PBKDF2 hash algorithm: {hash_algorithm!r}. "
            f"Valid options: {sorted(_PBKDF2_HASH_FACTORIES)}."
        )

    # Now that the hash is confirmed valid, the minimum-iterations lookup is safe
    # (the key is guaranteed to be present) and the error message is accurate.
    min_iters = _PBKDF2_MIN_ITERATIONS[hash_algorithm]
    if iterations < min_iters:
        raise InputValidationError(
            f"PBKDF2 iterations must be >= {min_iters:,} for {hash_algorithm!r} "
            f"(OWASP 2023 recommendation). "
            f"Received: {iterations:,}."
        )

    if salt is not None and len(salt) < PBKDF2_SALT_LEN:
        raise InputValidationError(
            f"PBKDF2 salt must be at least {PBKDF2_SALT_LEN} bytes; "
            f"received {len(salt)} byte(s). "
            "Pass salt=None to have a cryptographically secure random salt "
            "generated automatically."
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