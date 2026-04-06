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
    FILE_MAX_BLOCK_SIZE,
    ENVELOPE_VERSION,
    PBKDF2_HASH_TO_TAG as _PBKDF2_HASH_TO_TAG,
    PBKDF2_TAG_TO_HASH as _PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, FileOperationError

_HEADER_SALT_LEN = 16
_CHUNK_LEN_FMT = ">I"   # big-endian unsigned 32-bit int

# KDF tag embedded in the file header.
_KDF_TAG_RAW    = b"\x00"  # raw key was provided directly
_KDF_TAG_ARGON2 = b"\x01"  # key derived via Argon2id
_KDF_TAG_PBKDF2 = b"\x02"  # key derived via PBKDF2

# ── Header helpers ────────────────────────────────────────────────────────────

def _write_header(
    out: BinaryIO,
    salt: bytes,
    kdf_tag: bytes = _KDF_TAG_RAW,
    *,
    pbkdf2_hash_tag: bytes | None = None,
    pbkdf2_iterations: int | None = None,
) -> None:
    out.write(FILE_ENC_MAGIC)
    out.write(ENVELOPE_VERSION)
    out.write(kdf_tag)
    out.write(salt)
    if kdf_tag == _KDF_TAG_PBKDF2:
        if pbkdf2_hash_tag is None or pbkdf2_iterations is None:
            raise EncryptionError(
                "pbkdf2_hash_tag and pbkdf2_iterations must be provided "
                "when kdf_tag is _KDF_TAG_PBKDF2."
            )
        out.write(pbkdf2_hash_tag)
        out.write(struct.pack(">I", pbkdf2_iterations))

def _read_header(src: BinaryIO) -> tuple[bytes, bytes, str | None, int | None]:
    magic = src.read(len(FILE_ENC_MAGIC))
    if magic != FILE_ENC_MAGIC:
        raise DecryptionError("Invalid encrypted file (incorrect magic bytes).")
    version = src.read(1)
    if version != ENVELOPE_VERSION:
        raise DecryptionError(f"Unsupported file format version: {version!r}.")
    kdf_tag = src.read(1)
    if kdf_tag not in (_KDF_TAG_RAW, _KDF_TAG_ARGON2, _KDF_TAG_PBKDF2):
        raise DecryptionError(f"Unrecognized KDF tag in file header: {kdf_tag!r}.")
    salt = src.read(_HEADER_SALT_LEN)
    if len(salt) != _HEADER_SALT_LEN:
        raise DecryptionError("File header truncated (salt field).")

    pbkdf2_hash: str | None = None
    pbkdf2_iterations: int | None = None

    if kdf_tag == _KDF_TAG_PBKDF2:
        hash_tag_byte = src.read(1)
        pbkdf2_hash   = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
        if pbkdf2_hash is None:
            raise DecryptionError(
                f"Unrecognized PBKDF2 hash tag in file header: {hash_tag_byte!r}."
            )
        (pbkdf2_iterations,) = struct.unpack(">I", src.read(4))

    return kdf_tag, salt, pbkdf2_hash, pbkdf2_iterations

# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> None:
    """Encrypt a file with a raw AES-256 key."""
    if len(key) != AES_KEY_SIZE:
        raise EncryptionError(f"Key must be {AES_KEY_SIZE} bytes; received {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    aesgcm = AESGCM(key)
    salt = b"\x00" * _HEADER_SALT_LEN   # zero salt signals a raw key (no KDF was used)
    _encrypt_stream(
        src_path, dst_path, aesgcm, salt, chunk_size, _KDF_TAG_RAW,
        pbkdf2_hash_tag=None, pbkdf2_iterations=None,
    )

def encrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
    use_argon2: bool = True,
) -> None:
    """Encrypt a file with a password; the key is derived via Argon2id or PBKDF2."""
    from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2

    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    if use_argon2:
        derived  = derive_key_argon2(password)
        kdf_tag  = _KDF_TAG_ARGON2
        pbkdf2_hash_tag   = None
        pbkdf2_iterations = None
    else:
        derived  = derive_key_pbkdf2(password)
        kdf_tag  = _KDF_TAG_PBKDF2
        pbkdf2_hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash or "")
        if pbkdf2_hash_tag is None:
            raise EncryptionError(
                f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into file header."
            )
        pbkdf2_iterations = derived.pbkdf2_iterations

    aesgcm = AESGCM(derived.key)
    _encrypt_stream(
        src_path, dst_path, aesgcm, derived.salt, chunk_size, kdf_tag,
        pbkdf2_hash_tag=pbkdf2_hash_tag,
        pbkdf2_iterations=pbkdf2_iterations,
    )

def decrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
) -> None:
    """Decrypt a file encrypted with a raw AES-256 key."""
    if len(key) != AES_KEY_SIZE:
        raise DecryptionError(f"Key must be {AES_KEY_SIZE} bytes; received {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    aesgcm = AESGCM(key)
    tmp_path = _tmp_path_for(dst_path)
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            kdf_tag, _salt, _pbkdf2_hash, _pbkdf2_iter = _read_header(src)
            if kdf_tag != _KDF_TAG_RAW:
                raise DecryptionError(
                    "This file was encrypted with a password — use decrypt_file_with_password()."
                )
            _decrypt_chunks(src, dst, aesgcm)
        tmp_path.replace(dst_path)
    except (DecryptionError, FileOperationError):
        _cleanup_tmp(tmp_path)
        raise
    except Exception as exc:
        _cleanup_tmp(tmp_path)
        raise DecryptionError(
            f"File decryption failed — incorrect key or corrupted data: {exc}"
        ) from exc

def decrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
) -> None:
    """Decrypt a password-protected encrypted file."""
    from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2

    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    tmp_path = _tmp_path_for(dst_path)
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            kdf_tag, salt, pbkdf2_hash, pbkdf2_iterations = _read_header(src)
            if kdf_tag == _KDF_TAG_RAW:
                raise DecryptionError(
                    "This file was encrypted with a raw key — use decrypt_file()."
                )
            elif kdf_tag == _KDF_TAG_ARGON2:
                derived = derive_key_argon2(password, salt=salt)
            elif kdf_tag == _KDF_TAG_PBKDF2:
                derived = derive_key_pbkdf2(
                    password,
                    salt=salt,
                    iterations=pbkdf2_iterations,   # type: ignore[arg-type]
                    hash_algorithm=pbkdf2_hash,      # type: ignore[arg-type]
                )
            else:
                raise DecryptionError(f"Unrecognized KDF tag: {kdf_tag!r}.")
            aesgcm_local = AESGCM(derived.key)
            _decrypt_chunks(src, dst, aesgcm_local)
        tmp_path.replace(dst_path)
    except (DecryptionError, FileOperationError):
        _cleanup_tmp(tmp_path)
        raise
    except Exception as exc:
        _cleanup_tmp(tmp_path)
        raise DecryptionError(
            f"File decryption failed — incorrect password or corrupted data: {exc}"
        ) from exc

# ── Internal helpers ──────────────────────────────────────────────────────────

def _tmp_path_for(dst_path: Path) -> Path:
    """Return a temporary file path in the same directory as dst_path."""
    return dst_path.with_suffix(dst_path.suffix + ".tmp")

def _cleanup_tmp(tmp_path: Path) -> None:
    """Delete the temporary file if it exists; suppress any OS errors."""
    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass

def _encrypt_stream(
    src_path: Path,
    dst_path: Path,
    aesgcm: AESGCM,
    salt: bytes,
    chunk_size: int,
    kdf_tag: bytes,
    *,
    pbkdf2_hash_tag: bytes | None,
    pbkdf2_iterations: int | None,
) -> None:
    tmp_path = _tmp_path_for(dst_path)
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            _write_header(
                dst, salt, kdf_tag,
                pbkdf2_hash_tag=pbkdf2_hash_tag,
                pbkdf2_iterations=pbkdf2_iterations,
            )
            chunk_index = 0
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    dst.write(struct.pack(_CHUNK_LEN_FMT, 0))
                    break
                nonce = secrets.token_bytes(AES_NONCE_SIZE)
                # Bind the chunk index to the AAD to prevent chunk-reordering attacks.
                aad = struct.pack(">Q", chunk_index)
                ciphertext = aesgcm.encrypt(nonce, chunk, aad)
                block = nonce + ciphertext
                dst.write(struct.pack(_CHUNK_LEN_FMT, len(block)))
                dst.write(block)
                chunk_index += 1
        # Atomic rename — only executed when no exception was raised above.
        tmp_path.replace(dst_path)
    except (EncryptionError, FileOperationError):
        _cleanup_tmp(tmp_path)
        raise
    except Exception as exc:
        _cleanup_tmp(tmp_path)
        raise FileOperationError(f"File encryption failed: {exc}") from exc

def _decrypt_chunks(src: BinaryIO, dst: BinaryIO, aesgcm: AESGCM) -> None:
    """Read and decrypt all chunks from *src* (file header already consumed)."""
    chunk_index = 0
    while True:
        len_bytes = src.read(4)
        if len(len_bytes) < 4:
            raise DecryptionError("Unexpected end of file (chunk length field missing).")
        (block_len,) = struct.unpack(_CHUNK_LEN_FMT, len_bytes)
        if block_len == 0:
            break   # clean EOF sentinel
        if block_len > FILE_MAX_BLOCK_SIZE:
            raise DecryptionError(
                f"Block length {block_len} exceeds the maximum allowed size "
                f"({FILE_MAX_BLOCK_SIZE} bytes) — file may be corrupted or malicious."
            )

        block = src.read(block_len)
        if len(block) != block_len:
            raise DecryptionError("Unexpected end of file (chunk data truncated).")
        nonce = block[:AES_NONCE_SIZE]
        ciphertext = block[AES_NONCE_SIZE:]
        aad = struct.pack(">Q", chunk_index)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        dst.write(plaintext)
        chunk_index += 1