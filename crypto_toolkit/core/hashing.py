from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Union

from crypto_toolkit.core.constants import DEFAULT_HASH, FILE_CHUNK_SIZE, HASH_ALGORITHMS
from crypto_toolkit.core.exceptions import HashingError, InputValidationError

try:
    _HashType = hashlib.HASH          # public type alias (Python 3.9+)
except AttributeError:                # pragma: no cover
    from typing import Any
    _HashType = Any                   # type: ignore[assignment,misc]

def _get_hash_obj(algorithm: str) -> _HashType:
    algo = algorithm.lower()
    if algo not in HASH_ALGORITHMS:
        raise InputValidationError(
            f"Algorithm {algorithm!r} is not supported. "
            f"Choose from: {sorted(HASH_ALGORITHMS)}."
        )
    if algo == "blake2b":
        return hashlib.blake2b()
    return hashlib.new(algo)

def hash_data(data: bytes, algorithm: str = DEFAULT_HASH) -> str:
    """Hash bytes and return the hex digest."""
    try:
        h = _get_hash_obj(algorithm)
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
    seek_to_start: bool = False,
) -> str:
    """Hash *stream* and return the hex digest."""
    try:
        if seek_to_start:
            if not stream.seekable():
                raise HashingError(
                    "seek_to_start=True was requested, but the provided stream "
                    "is not seekable (e.g. a pipe, socket, or stdin). "
                    "Either pass a seekable stream or set seek_to_start=False."
                )
            stream.seek(0)
        h = _get_hash_obj(algorithm)
        while chunk := stream.read(chunk_size):
            h.update(chunk)
        return h.hexdigest()
    except InputValidationError:
        raise
    except HashingError:
        raise
    except Exception as exc:
        raise HashingError("Stream hashing failed.") from exc

def hash_file(path: Path, algorithm: str = DEFAULT_HASH) -> str:
    """Hash the entire file content and return the hex digest."""
    if not path.is_file():
        raise HashingError(f"File not found or not a regular file: {path}")
    try:
        with path.open("rb") as fh:
            return hash_stream(fh, algorithm)
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError(f"Failed to hash file {path}: {exc}") from exc