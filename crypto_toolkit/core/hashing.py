"""Secure hashing utilities.

Supports SHA-256, SHA-512, SHA3-256, SHA3-512, and BLAKE2b.
MD5 and SHA-1 are intentionally absent.
"""

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
    """Return the hex digest of *data*.

    Args:
        data: Bytes to hash.
        algorithm: One of ``sha256``, ``sha512``, ``sha3_256``, ``sha3_512``, ``blake2b``.

    Returns:
        Lowercase hexadecimal digest string.

    Raises:
        InputValidationError: If the algorithm is not supported.
        HashingError: On unexpected hashing failure.
    """
    try:
        h = _get_hash_obj(algorithm)
        h.update(data)
        return h.hexdigest()
    except InputValidationError:
        raise
    except Exception as exc:
        raise HashingError("Hashing failed.") from exc


def hash_stream(stream: BinaryIO, algorithm: str = DEFAULT_HASH, chunk_size: int = FILE_CHUNK_SIZE) -> str:
    """Hash a readable binary stream in chunks (memory-efficient).

    Args:
        stream: Any file-like object opened in binary mode.
        algorithm: Hash algorithm name.
        chunk_size: Read chunk size in bytes.

    Returns:
        Lowercase hexadecimal digest.

    Raises:
        InputValidationError: Invalid algorithm.
        HashingError: On I/O or hashing failure.
    """
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
    """Hash a file at *path* using chunked reads.

    Args:
        path: Path to an existing file.
        algorithm: Hash algorithm name.

    Returns:
        Lowercase hexadecimal digest.

    Raises:
        InputValidationError: Invalid algorithm.
        HashingError: If the file cannot be read or hashing fails.
    """
    if not path.is_file():
        raise HashingError(f"File not found or not a regular file: {path}")
    try:
        with path.open("rb") as fh:
            return hash_stream(fh, algorithm)
    except (InputValidationError, HashingError):
        raise
    except Exception as exc:
        raise HashingError(f"Failed to hash file {path}: {exc}") from exc
