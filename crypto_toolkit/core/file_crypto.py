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

# KDF tag constants embedded in the file header.
_KDF_TAG_RAW     = b"\x00"  # raw key supplied directly
_KDF_TAG_ARGON2  = b"\x01"  # key derived via Argon2id
_KDF_TAG_PBKDF2  = b"\x02"  # key derived via PBKDF2

def _write_header(
    out: BinaryIO,
    salt: bytes,
    chunk_size: int,
    kdf_tag: bytes = _KDF_TAG_RAW,
) -> None:
    out.write(FILE_ENC_MAGIC)
    out.write(ENVELOPE_VERSION)
    out.write(kdf_tag)
    out.write(salt)
    out.write(struct.pack(">I", chunk_size))

def _read_header(src: BinaryIO) -> tuple[bytes, bytes, int]:
    """Return ``(kdf_tag, salt, chunk_size)`` parsed from the file header."""
    magic = src.read(len(FILE_ENC_MAGIC))
    if magic != FILE_ENC_MAGIC:
        raise DecryptionError("Not a valid encrypted file (bad magic bytes).")
    version = src.read(1)
    if version != ENVELOPE_VERSION:
        raise DecryptionError(f"Unsupported file format version: {version!r}.")
    kdf_tag = src.read(1)
    if kdf_tag not in (_KDF_TAG_RAW, _KDF_TAG_ARGON2, _KDF_TAG_PBKDF2):
        raise DecryptionError(f"Unknown KDF tag in file header: {kdf_tag!r}.")
    salt = src.read(_HEADER_SALT_LEN)
    if len(salt) != _HEADER_SALT_LEN:
        raise DecryptionError("Truncated file header (salt).")
    (chunk_size,) = struct.unpack(">I", src.read(4))
    return kdf_tag, salt, chunk_size

def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> None:
    if len(key) != AES_KEY_SIZE:
        raise EncryptionError(f"Key must be {AES_KEY_SIZE} bytes; got {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    aesgcm = AESGCM(key)
    # Zero-filled salt signals that the caller supplied a raw key.
    salt = b"\x00" * _HEADER_SALT_LEN

    _encrypt_stream(src_path, dst_path, aesgcm, salt, chunk_size, _KDF_TAG_RAW)

def encrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
    use_argon2: bool = True,
) -> None:
    from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2

    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    if use_argon2:
        derived = derive_key_argon2(password)
        kdf_tag = _KDF_TAG_ARGON2
    else:
        derived = derive_key_pbkdf2(password)
        kdf_tag = _KDF_TAG_PBKDF2

    aesgcm = AESGCM(derived.key)
    _encrypt_stream(src_path, dst_path, aesgcm, derived.salt, chunk_size, kdf_tag)

def _encrypt_stream(
    src_path: Path,
    dst_path: Path,
    aesgcm: AESGCM,
    salt: bytes,
    chunk_size: int,
    kdf_tag: bytes,
) -> None:
    """Internal: write encrypted chunks from *src_path* to *dst_path*."""
    try:
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            _write_header(dst, salt, chunk_size, kdf_tag)
            chunk_index = 0
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
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
    if len(key) != AES_KEY_SIZE:
        raise DecryptionError(f"Key must be {AES_KEY_SIZE} bytes; got {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    aesgcm = AESGCM(key)

    try:
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            kdf_tag, _salt, _chunk_size = _read_header(src)
            if kdf_tag != _KDF_TAG_RAW:
                raise DecryptionError(
                    "File was encrypted with a password — use decrypt_file_with_password()."
                )
            _decrypt_stream_with_cipher(src, dst, aesgcm)  # fix: pass aesgcm correctly
    except (DecryptionError, FileOperationError):
        raise
    except Exception as exc:
        raise DecryptionError(f"File decryption failed — wrong key or corrupted data: {exc}") from exc

def decrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
) -> None:
    from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2

    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    try:
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            kdf_tag, salt, _chunk_size = _read_header(src)

            if kdf_tag == _KDF_TAG_RAW:
                raise DecryptionError(
                    "File was encrypted with a raw key — use decrypt_file() instead."
                )
            elif kdf_tag == _KDF_TAG_ARGON2:
                derived = derive_key_argon2(password, salt=salt)
            elif kdf_tag == _KDF_TAG_PBKDF2:
                derived = derive_key_pbkdf2(password, salt=salt)
            else:
                raise DecryptionError(f"Unknown KDF tag: {kdf_tag!r}.")

            # Re-initialise AESGCM with the recovered key, then decrypt chunks.
            aesgcm_local = AESGCM(derived.key)
            _decrypt_stream_with_cipher(src, dst, aesgcm_local)
    except (DecryptionError, FileOperationError):
        raise
    except Exception as exc:
        raise DecryptionError(f"File decryption failed — wrong password or corrupted data: {exc}") from exc

def _decrypt_stream_with_cipher(src: BinaryIO, dst: BinaryIO, aesgcm: AESGCM) -> None:
    """Internal: decrypt chunks using a pre-built *aesgcm* object."""
    _decrypt_chunks(src, dst, aesgcm)

def _decrypt_chunks(src: BinaryIO, dst: BinaryIO, aesgcm: AESGCM | None) -> None:
    """Read and decrypt chunk blocks from *src* (header already consumed)."""
    chunk_index = 0
    while True:
        len_bytes = src.read(4)
        if len(len_bytes) < 4:
            raise DecryptionError("Unexpected end of file (missing chunk length).")
        (block_len,) = struct.unpack(_CHUNK_LEN_FMT, len_bytes)
        if block_len == 0:
            break  # clean EOF terminator
        block = src.read(block_len)
        if len(block) != block_len:
            raise DecryptionError("Truncated chunk — file may be corrupted.")
        nonce = block[:AES_NONCE_SIZE]
        ciphertext = block[AES_NONCE_SIZE:]
        aad = struct.pack(">Q", chunk_index)
        if aesgcm is None:
            raise DecryptionError("Internal error: AESGCM cipher not initialised.")
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        dst.write(plaintext)
        chunk_index += 1