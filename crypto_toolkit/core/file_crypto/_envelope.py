"""_envelope.py — File-encryption envelope (header) format: key-mode tags,
header builders, the header parser, and per-file raw-key re-keying.

Single responsibility: turning envelope *metadata* (mode tag, salt, KDF
params, chunk count) into header bytes and back. The actual chunked
encrypt/decrypt I/O loop lives in _chunks.py.
"""

from __future__ import annotations

__all__ = [
    "derive_raw_subkey",
    "raw_header",
    "argon2_header",
    "pbkdf2_header",
    "parse_header",
    "KEY_RAW",
    "KEY_ARGON2",
    "KEY_PBKDF2",
    "BLOCK_LEN_FMT",
    "BLOCK_LEN_SIZE",
    "CHUNK_IDX_FMT",
    "CHUNK_COUNT_FMT",
    "MAX_CHUNK_IDX",
    "MIN_BLOCK_SIZE",
    "MAX_BLOCK_SIZE",
]

import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    ARGON2_PARAMS_LEN,
    ARGON2_SALT_LEN,
    FILE_CHUNK_COUNT_SIZE,
    FILE_ENC_MAGIC,
    FILE_ENC_VERSION,
    FILE_MAX_BLOCK_SIZE,
    FILE_RAW_SALT_LEN,
    PBKDF2_SALT_LEN,
)
from crypto_toolkit.core.exceptions import DecryptionError, FileOperationError

# ── Envelope key-mode tags ────────────────────────────────────────────────────

KEY_RAW:    bytes = b"\x00"   # caller-supplied 32-byte AES key, HKDF-rekeyed per file
KEY_ARGON2: bytes = b"\x01"   # Argon2id-derived key (salt + params in header)
KEY_PBKDF2: bytes = b"\x02"   # PBKDF2-derived key (salt + hash_tag + iters in header)

# HKDF domain separator for re-keying the caller-supplied raw key on a
# per-file basis (FIX for Bug #1 — see derive_raw_subkey below).
_RAW_SUBKEY_INFO: bytes = b"crypto-toolkit-file-raw-subkey"

# ── Block framing ─────────────────────────────────────────────────────────────

# 4-byte big-endian uint32 that precedes each nonce+ciphertext block.
BLOCK_LEN_FMT:  str = ">I"
BLOCK_LEN_SIZE: int = 4

# 4-byte big-endian uint32 appended to the header inside per-block AAD.
CHUNK_IDX_FMT: str = ">I"
CHUNK_COUNT_FMT: str = ">I"   # big-endian uint32; FILE_CHUNK_COUNT_SIZE == 4
MAX_CHUNK_IDX: int = 0xFFFF_FFFF

# Minimum valid block: nonce (12 B) + GCM tag (16 B) + 1 plaintext byte = 29 B.
MIN_BLOCK_SIZE: int = AES_NONCE_SIZE + AES_TAG_SIZE + 1
MAX_BLOCK_SIZE: int = FILE_MAX_BLOCK_SIZE

# ── Per-file raw-key re-keying (FIX for Bug #1) ───────────────────────────────

def derive_raw_subkey(key: bytes, file_salt: bytes) -> bytes:
    """Derive a per-file AES-256 subkey from a caller-supplied raw *key*."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=file_salt,
        info=_RAW_SUBKEY_INFO,
    ).derive(key)

# ── Header builders ───────────────────────────────────────────────────────────

def raw_header(file_salt: bytes) -> bytes:
    """Return the header for a raw-key envelope (magic + version + tag + per-file salt)."""
    return FILE_ENC_MAGIC + FILE_ENC_VERSION + KEY_RAW + file_salt

def argon2_header(salt: bytes, params: bytes) -> bytes:
    """Return the header for an Argon2id envelope (magic + version + tag + salt + params)."""
    return FILE_ENC_MAGIC + FILE_ENC_VERSION + KEY_ARGON2 + salt + params

def pbkdf2_header(salt: bytes, hash_tag: bytes, iterations: int) -> bytes:
    """Return the header for a PBKDF2 envelope."""
    return (
        FILE_ENC_MAGIC + FILE_ENC_VERSION + KEY_PBKDF2
        + salt + hash_tag + struct.pack(">I", iterations)
    )

# ── Header parser ─────────────────────────────────────────────────────────────

_MAX_HEADER_PEEK: int = (
    len(FILE_ENC_MAGIC) + 2       # magic (8 B) + version (1 B) + mode_tag (1 B)
    + max(
        FILE_RAW_SALT_LEN,                        # KEY_RAW: per-file salt only
        ARGON2_SALT_LEN + ARGON2_PARAMS_LEN,      # KEY_ARGON2: 16 + 10 = 26 B
        PBKDF2_SALT_LEN + 1 + 4,                  # KEY_PBKDF2: 16 + 1 + 4 = 21 B
    )
    + FILE_CHUNK_COUNT_SIZE                       # chunk-count field (4 B)
)   # = 40 bytes (unchanged numerically: 16 == 16, both equal ARGON2_SALT_LEN's branch)

def parse_header(src: Path) -> tuple[bytes, bytes, bytes | None, int, int]:
    """Parse the file envelope header.

    Returns ``(header, mode_tag, file_salt, block_start, expected_chunks)``.
    *file_salt* is only populated for :data:`KEY_RAW` envelopes; it is
    ``None`` for password-derived modes (their salt lives inside *header*).
    """
    try:
        with src.open("rb") as f:
            peek = f.read(_MAX_HEADER_PEEK)
    except OSError as exc:
        raise FileOperationError(f"Cannot read '{src}': {exc}") from exc

    magic_len = len(FILE_ENC_MAGIC)
    min_prefix = magic_len + 2   # magic + version byte + key-mode tag

    if len(peek) < min_prefix:
        raise DecryptionError("File is too short to be a valid encrypted file.")
    if peek[:magic_len] != FILE_ENC_MAGIC:
        raise DecryptionError(
            "File format not recognised (missing FILE_ENC_MAGIC). "
            "Ensure the file was produced by crypto-toolkit encrypt-file."
        )
    if peek[magic_len : magic_len + 1] != FILE_ENC_VERSION:
        raise DecryptionError(
            f"File encryption version {peek[magic_len:magic_len+1]!r} is not "
            f"supported (expected {FILE_ENC_VERSION!r}). "
            "Files produced under an older version of the toolkit must be "
            "re-encrypted to upgrade to the current format."
        )

    mode_tag = peek[magic_len + 1 : magic_len + 2]
    cursor = magic_len + 2   # byte position after the mode tag
    file_salt: bytes | None = None

    if mode_tag == KEY_RAW:
        needed = cursor + FILE_RAW_SALT_LEN
        if len(peek) < needed:
            raise DecryptionError("Raw-key file header is truncated.")
        file_salt = peek[cursor : needed]
        header = raw_header(file_salt)
    elif mode_tag == KEY_ARGON2:
        needed = cursor + ARGON2_SALT_LEN + ARGON2_PARAMS_LEN
        if len(peek) < needed:
            raise DecryptionError("Argon2 file header is truncated.")
        salt   = peek[cursor : cursor + ARGON2_SALT_LEN]
        params = peek[cursor + ARGON2_SALT_LEN : needed]
        header = argon2_header(salt, params)
    elif mode_tag == KEY_PBKDF2:
        needed = cursor + PBKDF2_SALT_LEN + 1 + 4   # salt + hash_tag + iterations
        if len(peek) < needed:
            raise DecryptionError("PBKDF2 file header is truncated.")
        salt     = peek[cursor : cursor + PBKDF2_SALT_LEN]
        hash_tag = peek[cursor + PBKDF2_SALT_LEN : cursor + PBKDF2_SALT_LEN + 1]
        (iters,) = struct.unpack(">I", peek[cursor + PBKDF2_SALT_LEN + 1 : needed])
        header   = pbkdf2_header(salt, hash_tag, iters)
    else:
        raise DecryptionError(
            f"Unrecognised key-mode tag in file header: {mode_tag!r}. "
            "The file may be corrupt or was produced by a newer version of the toolkit."
        )

    header_end = len(header)
    chunk_count_end = header_end + FILE_CHUNK_COUNT_SIZE
    if len(peek) < chunk_count_end:
        raise DecryptionError(
            "File is truncated: missing chunk-count field after the KDF header."
        )
    (expected_chunks,) = struct.unpack(
        CHUNK_COUNT_FMT, peek[header_end : chunk_count_end]
    )
    if expected_chunks == 0:
        raise DecryptionError(
            "File header declares zero chunks. A legitimate encryption "
            "operation can never produce this (empty source files are "
            "rejected at encrypt time). The file is corrupt or forged."
        )
    block_start = chunk_count_end

    return header, mode_tag, file_salt, block_start, expected_chunks
