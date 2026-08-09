"""_chunks.py — Path validation, atomic temp-file promotion, and the chunked
AES-256-GCM encrypt/decrypt I/O loops.

Single responsibility: streaming *bytes* through an already-derived key in
64 KiB chunks. Header/envelope construction and parsing lives in
_envelope.py; password/KDF orchestration lives in api.py.
"""

from __future__ import annotations

__all__ = ["validate_paths", "promote_tmp", "encrypt_chunks", "decrypt_chunks"]

import os as _os
import secrets
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import AES_NONCE_SIZE, FILE_CHUNK_SIZE
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    FileOperationError,
    InputValidationError,
)
from crypto_toolkit.core.file_crypto._envelope import (
    BLOCK_LEN_FMT,
    BLOCK_LEN_SIZE,
    CHUNK_COUNT_FMT,
    CHUNK_IDX_FMT,
    MAX_BLOCK_SIZE,
    MAX_CHUNK_IDX,
    MIN_BLOCK_SIZE,
)

# ── Path validation ───────────────────────────────────────────────────────────

def validate_paths(src: Path, dst: Path, *, force: bool = False) -> None:
    """Raise :class:`FileOperationError` or :class:`InputValidationError` for
    obvious path problems."""
    import stat as _stat_mod
    try:
        st = src.stat()
    except FileNotFoundError:
        raise FileOperationError(f"Source file not found: {src}")
    except OSError as exc:
        raise FileOperationError(f"Cannot read source file '{src}': {exc}") from exc

    if not _stat_mod.S_ISREG(st.st_mode):
        raise FileOperationError(f"Source path is not a regular file: {src}")

    if st.st_size == 0:
        raise InputValidationError(
            f"Source file '{src}' is empty. "
            "Encrypting zero bytes produces an output that carries no useful "
            "information; this is likely a mistake."
        )
    try:
        if src.resolve() == dst.resolve():
            raise FileOperationError(
                "Source and destination paths must differ; "
                "in-place encryption/decryption is not supported."
            )
    except OSError:
        # resolve() can fail on Windows for non-existent paths — safe to skip.
        pass

    if dst.exists() and not force:
        raise FileOperationError(
            f"Destination already exists: {dst}. "
            "Pass --force to overwrite it, or choose a different destination."
        )

# ── Core I/O loops ────────────────────────────────────────────────────────────

def promote_tmp(tmp: Path, dst: Path, *, force: bool) -> None:
    """Atomically promote *tmp* to *dst*."""
    if force:
        tmp.replace(dst)
        return
    try:
        _os.link(tmp, dst)
    except FileExistsError:
        raise FileOperationError(
            f"Destination already exists: {dst}. "
            "Pass --force to overwrite it, or choose a different destination."
        )
    finally:
        tmp.unlink(missing_ok=True)

def encrypt_chunks(
    src: Path, dst: Path, key_buf: bytearray, header: bytes, *, force: bool = False
) -> None:
    file_size = src.stat().st_size
    total_chunks = (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

    if total_chunks > MAX_CHUNK_IDX:
        raise EncryptionError(
            f"File is too large to encrypt in a single pass: would require "
            f"{total_chunks:,} chunks but the maximum is {MAX_CHUNK_IDX:,}. "
            "Split the file and encrypt each part separately."
        )

    try:
        cipher = AESGCM(key_buf)
    except Exception as exc:
        raise EncryptionError("Failed to initialise AES-GCM cipher.") from exc

    # Write to a sibling temp file; rename to dst atomically on success so that
    # dst is never left with partial ciphertext if something fails mid-stream.
    tmp = dst.with_suffix(dst.suffix + f".{secrets.token_hex(8)}.tmp")
    fd = -1
    try:
        try:
            fd = _os.open(tmp, _os.O_CREAT | _os.O_WRONLY | _os.O_EXCL, 0o600)
            with _os.fdopen(fd, "wb") as fout:
                fd = -1   # fout now owns the descriptor; reset sentinel
                with src.open("rb") as fin:
                    fout.write(header)
                    fout.write(struct.pack(CHUNK_COUNT_FMT, total_chunks))
                    chunk_idx = 0
                    while True:
                        chunk = fin.read(FILE_CHUNK_SIZE)
                        if not chunk:
                            break
                        nonce = secrets.token_bytes(AES_NONCE_SIZE)
                        aad = (
                            header
                            + struct.pack(CHUNK_COUNT_FMT, total_chunks)
                            + struct.pack(CHUNK_IDX_FMT, chunk_idx)
                        )
                        try:
                            ct = cipher.encrypt(nonce, chunk, aad)
                        except Exception as exc:
                            raise EncryptionError(
                                f"AES-GCM encryption failed at chunk {chunk_idx}."
                            ) from exc
                        block = nonce + ct
                        fout.write(struct.pack(BLOCK_LEN_FMT, len(block)))
                        fout.write(block)
                        chunk_idx += 1

            # Sanity check: if the file grew or shrank during encryption the
            # pre-computed total_chunks will not match the actual chunk_idx.
            if chunk_idx != total_chunks:
                raise EncryptionError(
                    f"File changed during encryption: pre-computed {total_chunks} "
                    f"chunk(s) but produced {chunk_idx}. "
                    "Ensure the source file is not modified during encryption."
                )

            promote_tmp(tmp, dst, force=force)
        except (EncryptionError, FileOperationError):
            raise
        except OSError as exc:
            raise FileOperationError(f"I/O error during encryption: {exc}") from exc
        except Exception as exc:
            raise EncryptionError("File encryption failed.") from exc
    except BaseException:
        # Close the raw fd if _os.fdopen() failed before taking ownership.
        if fd >= 0:
            try:
                _os.close(fd)
            except OSError:
                pass
        # Remove the temp file on any failure including KeyboardInterrupt.
        tmp.unlink(missing_ok=True)
        raise

def decrypt_chunks(
    src: Path,
    dst: Path,
    key_buf: bytearray,
    header: bytes,
    block_start: int,
    expected_chunks: int,
    *,
    force: bool = False,
) -> None:
    try:
        cipher = AESGCM(key_buf)
    except Exception as exc:
        raise DecryptionError("Failed to initialise AES-GCM cipher.") from exc

    tmp = dst.with_suffix(dst.suffix + f".{secrets.token_hex(8)}.tmp")
    fd = -1
    try:
        try:
            # O_EXCL prevents races; 0o600 keeps decrypted data owner-only.
            fd = _os.open(tmp, _os.O_CREAT | _os.O_WRONLY | _os.O_EXCL, 0o600)
            with _os.fdopen(fd, "wb") as fout:
                fd = -1   # fout now owns the descriptor
                with src.open("rb") as fin:
                    fin.seek(block_start)
                    chunk_idx = 0
                    while True:
                        raw_len = fin.read(BLOCK_LEN_SIZE)
                        if not raw_len:
                            break   # EOF — all (remaining) blocks consumed
                        if len(raw_len) < BLOCK_LEN_SIZE:
                            raise DecryptionError(
                                f"File truncated: incomplete block-length field "
                                f"at chunk {chunk_idx}."
                            )
                        (block_len,) = struct.unpack(BLOCK_LEN_FMT, raw_len)
                        if not (MIN_BLOCK_SIZE <= block_len <= MAX_BLOCK_SIZE):
                            raise DecryptionError(
                                f"Block size {block_len} at chunk {chunk_idx} is "
                                f"outside the valid range "
                                f"[{MIN_BLOCK_SIZE}, {MAX_BLOCK_SIZE}]. "
                                "The file is corrupt, truncated, or was produced "
                                "by a different version of the toolkit."
                            )
                        block = fin.read(block_len)
                        if len(block) < block_len:
                            raise DecryptionError(
                                f"File truncated at chunk {chunk_idx}: "
                                f"expected {block_len} B, read {len(block)} B."
                            )
                        nonce, ct = block[:AES_NONCE_SIZE], block[AES_NONCE_SIZE:]
                        aad = (
                            header
                            + struct.pack(CHUNK_COUNT_FMT, expected_chunks)
                            + struct.pack(CHUNK_IDX_FMT, chunk_idx)
                        )
                        try:
                            fout.write(cipher.decrypt(nonce, ct, aad))
                        except InvalidTag:
                            raise DecryptionError(
                                f"Authentication tag invalid at chunk {chunk_idx}. "
                                "Wrong key, corrupted file, or tampered data."
                            )
                        except Exception as exc:
                            raise DecryptionError(
                                f"Decryption failed at chunk {chunk_idx}."
                            ) from exc
                        chunk_idx += 1

            if chunk_idx != expected_chunks:
                raise DecryptionError(
                    f"File is truncated: header claims {expected_chunks} chunk(s) "
                    f"but only {chunk_idx} were present. "
                    "The file may have been tampered with or incompletely transferred."
                )

            # All chunks authenticated and count verified — atomically promote.
            promote_tmp(tmp, dst, force=force)

        except (DecryptionError, FileOperationError):
            raise
        except OSError as exc:
            raise FileOperationError(f"I/O error during decryption: {exc}") from exc
        except Exception as exc:
            raise DecryptionError("File decryption failed.") from exc

    except BaseException:
        # Ensure the temp file is purged on every failure path, including
        # DecryptionError, FileOperationError, KeyboardInterrupt, and SystemExit.
        if fd >= 0:
            try:
                _os.close(fd)
            except OSError:
                pass
        tmp.unlink(missing_ok=True)
        raise
