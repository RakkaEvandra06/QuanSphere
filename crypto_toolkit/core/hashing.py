from __future__ import annotations

__all__ = ["hash_data", "hash_stream", "hash_file"]

import hashlib
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

_BLAKE2B_DEFAULT_DIGEST_SIZE: int = 64   # 512-bit output — native maximum
_BLAKE2S_DEFAULT_DIGEST_SIZE: int = 32   # 256-bit output — native maximum

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
    """Hash *data* and return the hex digest."""
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
    return _hash_stream_impl(
        stream, algorithm, chunk_size, digest_size,
        seek_to_start=seek_to_start,
        warn_on_nonzero_pos=warn_on_nonzero_pos,
        _stacklevel=3,
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
                warn_on_nonzero_pos=True,
                _stacklevel=4,
            )
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError(f"Failed to hash file {path}: {exc}") from exc