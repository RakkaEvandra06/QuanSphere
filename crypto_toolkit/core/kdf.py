from __future__ import annotations

__all__ = [
    "DerivedKey",
    "derive_key_argon2",
    "derive_key_pbkdf2",
    "PBKDF2_SUPPORTED_HASHES",
    "zero_key",
    "zero_bytes_buffer",
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
    ARGON2_MIN_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    ARGON2_MAX_TIME_COST,
    ARGON2_MAX_MEMORY_COST,
    ARGON2_MAX_PARALLELISM,
    PBKDF2_HASH,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LEN,
    PBKDF2_SALT_LEN,
    PBKDF2_MAX_ITERATIONS as _PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS as _PBKDF2_MIN_ITERATIONS,
)
from crypto_toolkit.core.exceptions import InputValidationError, KeyDerivationError

# Internal cap on output length — not exported because callers use ARGON2_HASH_LEN.
_ARGON2_MAX_HASH_LEN: int = 128          # bytes

# ── PBKDF2 hash algorithm registry ────────────────────────────────────────────

_PBKDF2_HASH_FACTORIES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256":   hashes.SHA256,
    "sha512":   hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_512": hashes.SHA3_512,
}

PBKDF2_SUPPORTED_HASHES: frozenset[str] = frozenset(_PBKDF2_HASH_FACTORIES)

# ── Return type ───────────────────────────────────────────────────────────────

class DerivedKey(NamedTuple):
    """Container for a derived key and the metadata needed to reproduce it."""

    key: bytearray
    salt: bytes
    pbkdf2_hash: str | None = None         # None for Argon2-derived keys
    pbkdf2_iterations: int | None = None   # None for Argon2-derived keys

# ── Secure key erasure ────────────────────────────────────────────────────────

def zero_key(key: bytearray) -> None:
    """Overwrite *key* in place with zero bytes via :func:`ctypes.memset`."""
    if not isinstance(key, bytearray):
        raise TypeError(
            f"zero_key expects a bytearray; got {type(key).__name__!r}. "
            "Use 'del name' to drop bytes references promptly instead."
        )
    if len(key) == 0:
        return
    ctypes.memset((ctypes.c_char * len(key)).from_buffer(key), 0, len(key))

def zero_bytes_buffer(b: bytes) -> None:
    """Best-effort zero of a CPython :class:`bytes` object's internal C buffer."""
    if not isinstance(b, bytes) or len(b) == 0:
        return
    if len(b) == 1:
        return
    try:
        p = ctypes.cast(ctypes.c_char_p(b), ctypes.POINTER(ctypes.c_char))
        ctypes.memset(p, 0, len(b))
    except Exception:  # pragma: no cover  — non-CPython runtime fallback
        pass

# ── Parameter validators ──────────────────────────────────────────────────────

def _validate_argon2_params(
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
    salt: bytes | None,
) -> None:
    """Raise InputValidationError if any Argon2 parameter is out of range."""
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
    if not (ARGON2_MIN_MEMORY_COST <= memory_cost <= ARGON2_MAX_MEMORY_COST):
        raise InputValidationError(
            f"Argon2 memory_cost must be between {ARGON2_MIN_MEMORY_COST} and "
            f"{ARGON2_MAX_MEMORY_COST} KiB "
            f"({ARGON2_MIN_MEMORY_COST // 1024} MiB, "
            f"{ARGON2_MAX_MEMORY_COST // 1024} MiB), "
            f"received {memory_cost} KiB ({memory_cost / 1024:.2f} MiB). "
            "Note: memory_cost is expressed in KiB, not MiB, "
            "pass 65536 for 64 MiB (the recommended default)."
        )
    if not (1 <= parallelism <= ARGON2_MAX_PARALLELISM):
        raise InputValidationError(
            f"Argon2 parallelism must be between 1 and {ARGON2_MAX_PARALLELISM}; "
            f"received {parallelism}."
        )
    if memory_cost < 8 * parallelism:
        raise InputValidationError(
            f"Argon2 memory_cost ({memory_cost} KiB) must be at least "
            f"8 x parallelism ({8 * parallelism} KiB) per the Argon2 "
            f"specification (RFC 9106); received parallelism={parallelism}. "
            "Increase memory_cost or lower parallelism."
        )
    if not (16 <= hash_len <= _ARGON2_MAX_HASH_LEN):
        raise InputValidationError(
            f"Argon2 hash_len must be between 16 and {_ARGON2_MAX_HASH_LEN} bytes; "
            f"received {hash_len}."
        )

def _validate_pbkdf2_params(
    hash_algorithm: str,
    iterations: int,
    salt: bytes | None,
    key_len: int,
) -> None:
    """Raise InputValidationError if any PBKDF2 parameter is invalid."""
    if hash_algorithm not in _PBKDF2_HASH_FACTORIES:
        raise InputValidationError(
            f"Unsupported PBKDF2 hash algorithm: {hash_algorithm!r}. "
            f"Valid options: {sorted(_PBKDF2_HASH_FACTORIES)}."
        )
    if not (16 <= key_len <= _ARGON2_MAX_HASH_LEN):
        raise InputValidationError(
            f"PBKDF2 key_len must be between 16 and {_ARGON2_MAX_HASH_LEN} "
            f"bytes; received {key_len}."
        )
    min_iters = _PBKDF2_MIN_ITERATIONS[hash_algorithm]
    if iterations < min_iters:
        raise InputValidationError(
            f"PBKDF2 iterations must be >= {min_iters:,} for {hash_algorithm!r} "
            f"(OWASP 2023 recommendation). "
            f"Received: {iterations:,}."
        )
    max_iters = _PBKDF2_MAX_ITERATIONS[hash_algorithm]
    if iterations > max_iters:
        raise InputValidationError(
            f"PBKDF2 iterations must be <= {max_iters:,} for {hash_algorithm!r}. "
            f"Received: {iterations:,}. Values above this threshold carry no meaningful "
            "security benefit and risk CPU exhaustion. "
            "Prefer Argon2id (derive_key_argon2) for high work-factor key derivation."
        )
    if salt is not None and len(salt) < PBKDF2_SALT_LEN:
        raise InputValidationError(
            f"PBKDF2 salt must be at least {PBKDF2_SALT_LEN} bytes; "
            f"received {len(salt)} byte(s). "
            "Pass salt=None to have a cryptographically secure random salt "
            "generated automatically."
        )

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
    """Derive a key from *password* using Argon2id."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    _validate_argon2_params(time_cost, memory_cost, parallelism, hash_len, salt)

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
        raw_key: bytes = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Argon2Type.ID,
        )
        key_buf = bytearray(raw_key)
        zero_bytes_buffer(raw_key)
        del raw_key
        return DerivedKey(key=key_buf, salt=salt)
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
    """Derive a key from *password* using PBKDF2-HMAC."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    _validate_pbkdf2_params(hash_algorithm, iterations, salt, key_len)

    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_LEN)

    try:
        password_bytes = password.encode() if isinstance(password, str) else password
        algo_instance = _PBKDF2_HASH_FACTORIES[hash_algorithm]()
        kdf_obj = PBKDF2HMAC(
            algorithm=algo_instance,
            length=key_len,
            salt=salt,
            iterations=iterations,
        )
        raw_key: bytes = kdf_obj.derive(password_bytes)
        key_buf = bytearray(raw_key)
        zero_bytes_buffer(raw_key)
        del raw_key
        return DerivedKey(
            key=key_buf,
            salt=salt,
            pbkdf2_hash=hash_algorithm,
            pbkdf2_iterations=iterations,
        )
    except InputValidationError:
        raise
    except Exception as exc:
        raise KeyDerivationError("PBKDF2 key derivation failed.") from exc