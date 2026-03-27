from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

from crypto_toolkit.core.constants import DEFAULT_HASH, FILE_CHUNK_SIZE, HASH_ALGORITHMS
from crypto_toolkit.core.exceptions import HashingError, InputValidationError


def _get_hash_obj(algorithm: str) -> "hashlib._Hash":
    algo = algorithm.lower()
    if algo not in HASH_ALGORITHMS:
        raise InputValidationError(
            f"Unsupported algorithm {algorithm!r}. Choose from: {sorted(HASH_ALGORITHMS)}."
        )
    if algo == "blake2b":
        return hashlib.blake2b()
    return hashlib.new(algo)


def hash_data(data: bytes, algorithm: str = DEFAULT_HASH) -> str:

    try:
        h = _get_hash_obj(algorithm)
        h.update(data)
        return h.hexdigest()
    except InputValidationError:
        raise
    except Exception as exc:
        raise HashingError("Hashing failed.") from exc


def hash_stream(stream: BinaryIO, algorithm: str = DEFAULT_HASH, chunk_size: int = FILE_CHUNK_SIZE) -> str:

    try:
        h = _get_hash_obj(algorithm)
        while chunk := stream.read(chunk_size):
            h.update(chunk)
        return h.hexdigest()
    except InputValidationError:
        raise
    except Exception as exc:
        raise HashingError("Stream hashing failed.") from exc


def hash_file(path: Path, algorithm: str = DEFAULT_HASH) -> str:

    if not path.is_file():
        raise HashingError(f"File not found or not a regular file: {path}")
    try:
        with path.open("rb") as fh:
            return hash_stream(fh, algorithm)
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError(f"Failed to hash file {path}: {exc}") from exc