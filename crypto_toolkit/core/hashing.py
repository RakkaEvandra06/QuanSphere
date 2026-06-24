from __future__ import annotations

__all__ = ["hash_data", "hash_stream", "hash_file", "mac_data", "hmac_data"]

import hashlib
import hmac as _hmac
import warnings
from pathlib import Path
from typing import BinaryIO

from crypto_toolkit.core.constants import DEFAULT_HASH, FILE_CHUNK_SIZE, HASH_ALGORITHMS
from crypto_toolkit.core.exceptions import HashingError, InputValidationError

# Type alias for the hashlib hash object — normalised across Python versions.
try:
    _HashType = hashlib.HASH          # public alias available from Python 3.9+
except AttributeError:                # pragma: no cover
    from typing import Any
    _HashType = Any                   # type: ignore[assignment,misc]

_BLAKE2B_DEFAULT_DIGEST_SIZE: int = 64   # 512-bit — BLAKE2b native maximum.
_BLAKE2S_DEFAULT_DIGEST_SIZE: int = 32   # 256-bit — BLAKE2s native maximum.

_HMAC_SUPPORTED: frozenset[str] = frozenset({
    "sha256", "sha512", "sha3_256", "sha3_512",
})

# BLAKE2 variants are routed to their native keyed mode inside hmac_data.
_BLAKE2_KEYED: frozenset[str] = frozenset({"blake2b", "blake2s"})
_BLAKE2B_MAX_KEY: int = 64   # bytes BLAKE2b native key length maximum
_BLAKE2S_MAX_KEY: int = 32   # bytes BLAKE2s native key length maximum
_HASH_MAX_CHUNK_SIZE: int = 256 * 1024 * 1024   # 256 MiB

# ── Private helpers ───────────────────────────────────────────────────────────

def _get_hash_obj(algorithm: str, digest_size: int | None = None) -> _HashType:
    """Return an initialised hash object for *algorithm*."""
    algo = algorithm.lower()
    if algo not in HASH_ALGORITHMS:
        raise InputValidationError(
            f"Algorithm {algorithm!r} is not supported. "
            f"Choose from: {sorted(HASH_ALGORITHMS)}."
        )
    if algo == "blake2b":
        size = digest_size if digest_size is not None else _BLAKE2B_DEFAULT_DIGEST_SIZE
        if not (1 <= size <= 64):
            raise InputValidationError(
                f"BLAKE2b digest_size must be between 1 and 64 bytes; got {size}."
            )
        return hashlib.blake2b(digest_size=size)
    if algo == "blake2s":
        size = digest_size if digest_size is not None else _BLAKE2S_DEFAULT_DIGEST_SIZE
        if not (1 <= size <= 32):
            raise InputValidationError(
                f"BLAKE2s digest_size must be between 1 and 32 bytes; got {size}."
            )
        return hashlib.blake2s(digest_size=size)
    if digest_size is not None:
        raise InputValidationError(
            f"digest_size is only configurable for 'blake2b'/'blake2s'; "
            f"{algo!r} always produces a fixed-length digest and does not "
            "support truncation. Omit digest_size for this algorithm."
        )
    return hashlib.new(algo)

def _warn_nonzero_stream_position(stream: BinaryIO, *, stacklevel: int) -> None:
    """Emit a UserWarning when *stream* is seekable but not at position 0."""
    if stream.seekable() and stream.tell() != 0:
        warnings.warn(
            f"hash_stream: stream position is {stream.tell()}, not 0. "
            "Only the bytes from the current position onward will be hashed. "
            "Pass seek_to_start=True to hash the full stream from the beginning, "
            "or warn_on_nonzero_pos=False if hashing from a non-zero position "
            "is intentional (e.g. skipping a file header already consumed by "
            "the caller).",
            stacklevel=stacklevel,
        )

def _hash_readable(
    stream: BinaryIO,
    algorithm: str,
    chunk_size: int,
    digest_size: int | None,
) -> str:
    """Read *stream* in chunks and return the hex digest for *algorithm*."""
    h = _get_hash_obj(algorithm, digest_size)
    while chunk := stream.read(chunk_size):
        h.update(chunk)
    return h.hexdigest()

def _hash_stream_impl(
    stream: BinaryIO,
    algorithm: str,
    chunk_size: int,
    digest_size: int | None,
    *,
    seek_to_start: bool,
    warn_on_nonzero_pos: bool,
    _stacklevel: int,
) -> str:
    """Internal implementation shared by hash_stream and hash_file."""
    try:
        if seek_to_start:
            if not stream.seekable():
                raise HashingError(
                    "seek_to_start=True was requested, but the provided stream "
                    "is not seekable (e.g. a pipe, socket, or stdin). "
                    "Either pass a seekable stream or set seek_to_start=False."
                )
            stream.seek(0)
        elif warn_on_nonzero_pos:
            _warn_nonzero_stream_position(stream, stacklevel=_stacklevel)

        return _hash_readable(stream, algorithm, chunk_size, digest_size)
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError("Stream hashing failed.") from exc

# ── Public API ────────────────────────────────────────────────────────────────

def hash_data(
    data: bytes,
    algorithm: str = DEFAULT_HASH,
    *,
    digest_size: int | None = None,
) -> str:
    try:
        h = _get_hash_obj(algorithm, digest_size)
        h.update(data)
        return h.hexdigest()
    except InputValidationError:
        raise
    except Exception as exc:
        raise HashingError("Hashing failed.") from exc

def hash_stream(
    stream: BinaryIO,
    algorithm: str = DEFAULT_HASH,
    chunk_size: int = FILE_CHUNK_SIZE,
    *,
    digest_size: int | None = None,
    seek_to_start: bool = False,
    warn_on_nonzero_pos: bool = True,
) -> str:
    """Hash *stream* in chunks and return the hex digest."""
    if not (1 <= chunk_size <= _HASH_MAX_CHUNK_SIZE):
        raise InputValidationError(
            f"chunk_size must be between 1 and {_HASH_MAX_CHUNK_SIZE:,} bytes "
            f"({_HASH_MAX_CHUNK_SIZE // (1024 * 1024)} MiB); "
            f"received {chunk_size}. "
            "Omit the argument to use the default (65 536 bytes)."
        )
    return _hash_stream_impl(
        stream, algorithm, chunk_size, digest_size,
        seek_to_start=seek_to_start,
        warn_on_nonzero_pos=warn_on_nonzero_pos,
        _stacklevel=4,
    )

def hash_file(
    path: Path,
    algorithm: str = DEFAULT_HASH,
    *,
    digest_size: int | None = None,
) -> str:
    """Hash the entire contents of *path* and return the hex digest."""
    if not path.is_file():
        raise HashingError(f"File not found or not a regular file: {path}")
    try:
        with path.open("rb") as fh:
            return _hash_stream_impl(
                fh, algorithm, FILE_CHUNK_SIZE, digest_size,
                seek_to_start=False,
                warn_on_nonzero_pos=False,
                _stacklevel=4,
            )
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError(f"Failed to hash file {path}: {exc}") from exc

def mac_data(
    key: bytes,
    data: bytes,
    algorithm: str = DEFAULT_HASH,
) -> str:
    """Return a hex-encoded MAC for *data* under *key*."""
    if not key:
        raise InputValidationError(
            "MAC key must not be empty. "
            "Provide a non-empty secret key for authenticated hashing."
        )
    algo = algorithm.lower()

    # ── BLAKE2: native keyed-hash mode ───────────────────────────────────────
    if algo in _BLAKE2_KEYED:
        max_key_len = _BLAKE2B_MAX_KEY if algo == "blake2b" else _BLAKE2S_MAX_KEY
        if len(key) > max_key_len:
            raise InputValidationError(
                f"BLAKE2 keyed-hash key must be at most {max_key_len} bytes "
                f"for {algo!r}; received {len(key)} byte(s). "
                "Shorten the key or switch to a SHA-2/SHA-3 algorithm if a "
                "longer key is required."
            )
        if len(key) < 16:
            import warnings as _w
            _w.warn(
                f"BLAKE2 keyed-hash key is only {len(key)} byte(s); "
                "for full MAC security the key should be at least 16 bytes "
                f"(ideally {max_key_len} bytes for {algo!r}).",
                UserWarning,
                stacklevel=2,
            )
        try:
            # hashlib.blake2b/s(data, key=key) is the canonical keyed MAC for BLAKE2.
            # This is NOT the same as HMAC(BLAKE2) — it uses BLAKE2's built-in keying.
            h = hashlib.new(algo, data, key=key)
            return h.hexdigest()
        except Exception as exc:
            raise HashingError("BLAKE2 keyed-hash computation failed.") from exc

    # ── SHA-2 / SHA-3: standard RFC 2104 HMAC ────────────────────────────────
    if algo not in _HMAC_SUPPORTED:
        raise InputValidationError(
            f"Algorithm {algorithm!r} is not supported. "
            f"Choose from: {sorted(_HMAC_SUPPORTED | _BLAKE2_KEYED)}."
        )
    try:
        mac = _hmac.new(key, data, algo)
        return mac.hexdigest()
    except InputValidationError:
        raise
    except Exception as exc:
        raise HashingError("HMAC computation failed.") from exc

def hmac_data(
    key: bytes,
    data: bytes,
    algorithm: str = DEFAULT_HASH,
) -> str:
    """Deprecated alias for :func:`mac_data`."""
    import warnings as _w
    _w.warn(
        "hmac_data() is deprecated; use mac_data() instead. "
        "The new name clarifies that BLAKE2 algorithms use native keyed-hash "
        "mode (not HMAC-BLAKE2), which is not interoperable with HMAC(BLAKE2) "
        "implementations in other languages.",
        DeprecationWarning,
        stacklevel=2,
    )
    return mac_data(key, data, algorithm)