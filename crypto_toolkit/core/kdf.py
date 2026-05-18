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

# OWASP 2023 minimum iteration counts, keyed by hash name.
_PBKDF2_MIN_ITERATIONS: dict[str, int] = {
    "sha256":   600_000,  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    "sha512":   210_000,  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA512
    "sha3_256": 200_000,  # SHA3-256 is ~3× slower than SHA-256 per iteration
    "sha3_512": 100_000,  # SHA3-512 is ~2× slower than SHA-512 per iteration
}

# ── Return type ───────────────────────────────────────────────────────────────

class DerivedKey(NamedTuple):
    """Container for a derived key and the metadata needed to reproduce it."""

    key: bytes
    salt: bytes
    pbkdf2_hash: str | None = None         # None for Argon2-derived keys
    pbkdf2_iterations: int | None = None   # None for Argon2-derived keys

# ── Memory erasure ────────────────────────────────────────────────────────────

def zero_bytes(data: bytes) -> None:
    """Best-effort in-place zeroing of a ``bytes`` object (CPython only)."""
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

    try:
        # CPython lays out bytes objects so that the raw character buffer
        # starts at `id(obj) + bytes.__basicsize__ - 1` on 64-bit builds.
        buf_offset = bytes.__basicsize__ - 1  # 33 on CPython 3.10-3.12 / 64-bit
        ctypes.memset(id(data) + buf_offset, 0, len(data))
        assert data == b"\x00" * len(data), (
            "zero_bytes: post-wipe verification failed "
            "buf_offset calculation may be wrong for this Python build."
        )
    except Exception:
        # Layout mismatch or unexpected CPython internal change — accept the
        # limitation silently. The caller still proceeds; this is best-effort.
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
    # Min-iterations lookup is safe here because hash_algorithm is confirmed valid above.
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
        # Import is deferred so the toolkit degrades gracefully when argon2-cffi
        # is not installed instead of failing at module import time.
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