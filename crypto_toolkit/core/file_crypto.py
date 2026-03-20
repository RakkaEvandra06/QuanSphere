"""Chunk-based file encryption using AES-256-GCM.

Each chunk is independently authenticated so that truncation or partial
corruption is detected immediately on the affected chunk, rather than only
at the end of a large file.

Encrypted file format
---------------------
Header (fixed):
    FILE_ENC_MAGIC  (8 bytes)
    VERSION         (1 byte)
    SALT            (16 bytes, random, used to derive per-file key via Argon2/PBKDF2)
    CHUNK_SIZE      (4 bytes, big-endian uint32)

Repeated chunk blocks:
    CHUNK_LEN       (4 bytes, big-endian uint32 — length of NONCE+CIPHERTEXT+TAG)
    NONCE           (12 bytes)
    CIPHERTEXT+TAG  (variable)

Terminator:
    CHUNK_LEN = 0   (4-byte zero — signals end of stream)
"""

from __future__ import annotations

import secrets
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    FILE_CHUNK_SIZE,
    FILE_ENC_MAGIC,
    ENVELOPE_VERSION,
)
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, FileOperationError

_HEADER_SALT_LEN = 16
_CHUNK_LEN_FMT = ">I"   # big-endian unsigned 32-bit int


def _write_header(out: BinaryIO, salt: bytes, chunk_size: int) -> None:
    out.write(FILE_ENC_MAGIC)
    out.write(ENVELOPE_VERSION)
    out.write(salt)
    out.write(struct.pack(">I", chunk_size))


def _read_header(src: BinaryIO) -> tuple[bytes, int]:
    """Return ``(salt, chunk_size)`` parsed from the file header."""
    magic = src.read(len(FILE_ENC_MAGIC))
    if magic != FILE_ENC_MAGIC:
        raise DecryptionError("Not a valid encrypted file (bad magic bytes).")
    version = src.read(1)
    if version != ENVELOPE_VERSION:
        raise DecryptionError(f"Unsupported file format version: {version!r}.")
    salt = src.read(_HEADER_SALT_LEN)
    if len(salt) != _HEADER_SALT_LEN:
        raise DecryptionError("Truncated file header (salt).")
    (chunk_size,) = struct.unpack(">I", src.read(4))
    return salt, chunk_size


def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> None:
    """Encrypt *src_path* → *dst_path* using chunked AES-256-GCM.

    Args:
        src_path: Path to plaintext file.
        dst_path: Destination path for the encrypted output.
        key: 32-byte AES key.  Derive from a password with :mod:`crypto_toolkit.core.kdf`.
        chunk_size: Plaintext bytes per chunk (default 64 KiB).

    Raises:
        EncryptionError: On key-length mismatch or cryptographic failure.
        FileOperationError: On I/O failure.
    """
    if len(key) != AES_KEY_SIZE:
        raise EncryptionError(f"Key must be {AES_KEY_SIZE} bytes; got {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    aesgcm = AESGCM(key)
    salt = secrets.token_bytes(_HEADER_SALT_LEN)  # stored for future key-derivation reference

    try:
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            _write_header(dst, salt, chunk_size)
            chunk_index = 0
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    # Write zero-length terminator
                    dst.write(struct.pack(_CHUNK_LEN_FMT, 0))
                    break
                nonce = secrets.token_bytes(AES_NONCE_SIZE)
                # Bind chunk index into AAD to prevent chunk reordering attacks.
                aad = struct.pack(">Q", chunk_index)
                ciphertext = aesgcm.encrypt(nonce, chunk, aad)
                block = nonce + ciphertext
                dst.write(struct.pack(_CHUNK_LEN_FMT, len(block)))
                dst.write(block)
                chunk_index += 1
    except (EncryptionError, FileOperationError):
        raise
    except Exception as exc:
        raise FileOperationError(f"File encryption failed: {exc}") from exc


def decrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
) -> None:
    """Decrypt an encrypted file produced by :func:`encrypt_file`.

    Args:
        src_path: Path to the encrypted file.
        dst_path: Destination path for the decrypted output.
        key: 32-byte AES key (must match the key used during encryption).

    Raises:
        DecryptionError: On authentication failure, bad key, or corrupted data.
        FileOperationError: On I/O failure.
    """
    if len(key) != AES_KEY_SIZE:
        raise DecryptionError(f"Key must be {AES_KEY_SIZE} bytes; got {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    aesgcm = AESGCM(key)

    try:
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            _salt, _chunk_size = _read_header(src)
            chunk_index = 0
            while True:
                len_bytes = src.read(4)
                if len(len_bytes) < 4:
                    raise DecryptionError("Unexpected end of file (missing chunk length).")
                (block_len,) = struct.unpack(_CHUNK_LEN_FMT, len_bytes)
                if block_len == 0:
                    break  # clean EOF
                block = src.read(block_len)
                if len(block) != block_len:
                    raise DecryptionError("Truncated chunk — file may be corrupted.")
                nonce = block[:AES_NONCE_SIZE]
                ciphertext = block[AES_NONCE_SIZE:]
                aad = struct.pack(">Q", chunk_index)
                plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                dst.write(plaintext)
                chunk_index += 1
    except (DecryptionError, FileOperationError):
        raise
    except Exception as exc:
        raise DecryptionError(f"File decryption failed — wrong key or corrupted data: {exc}") from exc
