from __future__ import annotations

__all__ = [
    "DerivedKey",
    "derive_key_argon2",
    "derive_key_pbkdf2",
    "PBKDF2_SUPPORTED_HASHES",
    "zero_bytes",
    "zero_key",
    "ARGON2_MAX_TIME_COST",
    "ARGON2_MAX_MEMORY_COST",
    "ARGON2_MAX_PARALLELISM",
]

import ctypes
import platform
import secrets
import warnings
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
    PBKDF2_MIN_ITERATIONS as _PBKDF2_MIN_ITERATIONS,
)
from crypto_toolkit.core.exceptions import InputValidationError, KeyDerivationError

# ── Public limits (exported for use by pbe.py and file_crypto.py) ─────────────

ARGON2_MAX_TIME_COST: int = 1_000        # iterations
ARGON2_MAX_MEMORY_COST: int = 2_097_152  # 2 GiB expressed in KiB
ARGON2_MAX_PARALLELISM: int = 64         # lanes / threads

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
    """Zero a :class:`bytearray` key buffer in-place."""

    if not isinstance(key, bytearray):
        raise TypeError(
            f"zero_key expects a bytearray; got {type(key).__name__!r}. "
            "For bytes objects use zero_bytes (CPython only, best-effort)."
        )
    if len(key) == 0:
        return
    ctypes.memset((ctypes.c_char * len(key)).from_buffer(key), 0, len(key))


def _find_bytes_data_offset() -> int:
    """Probe the CPython bytes object layout to locate the raw character buffer."""
    sentinel = b"\xAA"
    base = id(sentinel)
    for off in range(16, 72):
        try:
            if ctypes.string_at(base + off, 1) == b"\xAA":
                return off
        except Exception:
            continue
    raise RuntimeError(
        "zero_bytes: cannot locate CPython bytes data buffer at any offset 16–71. "
        "The CPython layout may have changed in this build."
    )

# Module-level cache: None = not yet probed, int = confirmed offset.
_BYTES_DATA_OFFSET: int | None = None

def zero_bytes(data: bytes) -> None:
    """Best-effort in-place zeroing of a ``bytes`` object (CPython only)."""
    global _BYTES_DATA_OFFSET

    if platform.python_implementation() != "CPython":
        warnings.warn(
            "zero_bytes: memory wiping is a no-op on non-CPython runtimes "
            f"(detected: {platform.python_implementation()}). "
            "Key material may persist on the heap for the lifetime of the process. "
            "Use a CPython interpreter if in-memory key erasure is a hard requirement.",
            RuntimeWarning,
            stacklevel=2,
        )
        return

    # Probe the buffer offset on first use; cache it for subsequent calls.
    if _BYTES_DATA_OFFSET is None:
        try:
            _BYTES_DATA_OFFSET = _find_bytes_data_offset()
        except RuntimeError as exc:
            warnings.warn(
                f"zero_bytes: {exc}. Key material will not be wiped for this process.",
                RuntimeWarning,
                stacklevel=2,
            )
            return

    try:
        ctypes.memset(id(data) + _BYTES_DATA_OFFSET, 0, len(data))
    except Exception:
        return
    wiped = ctypes.string_at(id(data) + _BYTES_DATA_OFFSET, len(data))
    if any(b != 0 for b in wiped):
        warnings.warn(
            "zero_bytes: post-wipe verification failed; "
            "key material may remain on the heap. "
            "The computed buffer offset may be wrong for this Python build.",
            RuntimeWarning,
            stacklevel=2,
        )

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
    if not (8192 <= memory_cost <= ARGON2_MAX_MEMORY_COST):
        raise InputValidationError(
            f"Argon2 memory_cost must be between 8192 and {ARGON2_MAX_MEMORY_COST} KiB "
            f"(8 MiB – 2 GiB); received {memory_cost} KiB ({memory_cost / 1024:.2f} MiB). "
            "Note: memory_cost is expressed in KiB, not MiB "
            "pass 65536 for 64 MiB (the recommended default)."
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

def _validate_pbkdf2_params(
    hash_algorithm: str,
    iterations: int,
    salt: bytes | None,
) -> None:
    """Raise InputValidationError if any PBKDF2 parameter is invalid."""
    if hash_algorithm not in _PBKDF2_HASH_FACTORIES:
        raise InputValidationError(
            f"Unsupported PBKDF2 hash algorithm: {hash_algorithm!r}. "
            f"Valid options: {sorted(_PBKDF2_HASH_FACTORIES)}."
        )
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
        zero_bytes(raw_key)
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

    _validate_pbkdf2_params(hash_algorithm, iterations, salt)

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
        # F-02: same bytearray wrapping as in derive_key_argon2.
        key_buf = bytearray(raw_key)
        zero_bytes(raw_key)
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