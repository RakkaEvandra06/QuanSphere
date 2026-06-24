"""file_crypto.py — Chunked AES-256-GCM file encryption for the Crypto Toolkit."""

from __future__ import annotations

__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_with_password",
    "decrypt_file_with_password",
]

import os as _os
import secrets
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    ARGON2_MIN_MEMORY_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_PARAMS_LEN,
    ARGON2_PARAMS_STRUCT,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    DECRYPT_MAX_ARGON2_MEMORY_COST,
    DECRYPT_MAX_ARGON2_PARALLELISM,
    DECRYPT_MAX_ARGON2_TIME_COST,
    FILE_CHUNK_COUNT_SIZE,
    FILE_CHUNK_SIZE,
    FILE_ENC_MAGIC,
    FILE_ENC_VERSION,
    FILE_MAX_BLOCK_SIZE,
    FILE_RAW_SALT_LEN,
    PASSWORD_MIN_LENGTH,
    PBKDF2_HASH_TO_TAG,
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    PBKDF2_SALT_LEN,
    PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    FileOperationError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import (
    derive_key_argon2,
    derive_key_pbkdf2,
    zero_bytes_buffer,
    zero_key,
)

# ── Envelope key-mode tags ────────────────────────────────────────────────────

_KEY_RAW:    bytes = b"\x00"   # caller-supplied 32-byte AES key, HKDF-rekeyed per file
_KEY_ARGON2: bytes = b"\x01"   # Argon2id-derived key (salt + params in header)
_KEY_PBKDF2: bytes = b"\x02"   # PBKDF2-derived key (salt + hash_tag + iters in header)

# HKDF domain separator for re-keying the caller-supplied raw key on a
# per-file basis (FIX for Bug #1 — see _derive_raw_subkey below).
_RAW_SUBKEY_INFO: bytes = b"crypto-toolkit-file-raw-subkey"

# ── Block framing ─────────────────────────────────────────────────────────────

# 4-byte big-endian uint32 that precedes each nonce+ciphertext block.
_BLOCK_LEN_FMT:  str = ">I"
_BLOCK_LEN_SIZE: int = 4

# 4-byte big-endian uint32 appended to the header inside per-block AAD.
_CHUNK_IDX_FMT: str = ">I"
_CHUNK_COUNT_FMT: str = ">I"   # big-endian uint32; FILE_CHUNK_COUNT_SIZE == 4
_MAX_CHUNK_IDX: int = 0xFFFF_FFFF

# Minimum valid block: nonce (12 B) + GCM tag (16 B) + 1 plaintext byte = 29 B.
_MIN_BLOCK_SIZE: int = AES_NONCE_SIZE + AES_TAG_SIZE + 1

_MAX_BLOCK_SIZE: int = FILE_MAX_BLOCK_SIZE
_DECRYPT_MIN_TIME_COST:   int = 1
_DECRYPT_MIN_MEMORY_COST: int = ARGON2_MIN_MEMORY_COST  # 8 MiB in KiB
_DECRYPT_MIN_PARALLELISM: int = 1

_DECRYPT_MAX_TIME_COST:   int = DECRYPT_MAX_ARGON2_TIME_COST
_DECRYPT_MAX_MEMORY_COST: int = DECRYPT_MAX_ARGON2_MEMORY_COST
_DECRYPT_MAX_PARALLELISM: int = DECRYPT_MAX_ARGON2_PARALLELISM

# ── Per-file raw-key re-keying (FIX for Bug #1) ───────────────────────────────

def _derive_raw_subkey(key: bytes, file_salt: bytes) -> bytes:
    """Derive a per-file AES-256 subkey from a caller-supplied raw *key*."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=file_salt,
        info=_RAW_SUBKEY_INFO,
    ).derive(key)

# ── Header builders ───────────────────────────────────────────────────────────

def _raw_header(file_salt: bytes) -> bytes:
    """Return the header for a raw-key envelope (magic + version + tag + per-file salt)."""
    return FILE_ENC_MAGIC + FILE_ENC_VERSION + _KEY_RAW + file_salt

def _argon2_header(salt: bytes, params: bytes) -> bytes:
    """Return the header for an Argon2id envelope (magic + version + tag + salt + params)."""
    return FILE_ENC_MAGIC + FILE_ENC_VERSION + _KEY_ARGON2 + salt + params

def _pbkdf2_header(salt: bytes, hash_tag: bytes, iterations: int) -> bytes:
    """Return the header for a PBKDF2 envelope."""
    return (
        FILE_ENC_MAGIC + FILE_ENC_VERSION + _KEY_PBKDF2
        + salt + hash_tag + struct.pack(">I", iterations)
    )

# ── Path validation ───────────────────────────────────────────────────────────

def _validate_paths(src: Path, dst: Path, *, force: bool = False) -> None:
    """Raise :class:`FileOperationError` or :class:`InputValidationError` for obvious path problems."""
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

def _promote_tmp(tmp: Path, dst: Path, *, force: bool) -> None:
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

def _encrypt_chunks(
    src: Path, dst: Path, key_buf: bytearray, header: bytes, *, force: bool = False
) -> None:
    file_size = src.stat().st_size
    total_chunks = (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

    if total_chunks > _MAX_CHUNK_IDX:
        raise EncryptionError(
            f"File is too large to encrypt in a single pass: would require "
            f"{total_chunks:,} chunks but the maximum is {_MAX_CHUNK_IDX:,}. "
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
                    fout.write(struct.pack(_CHUNK_COUNT_FMT, total_chunks))
                    chunk_idx = 0
                    while True:
                        chunk = fin.read(FILE_CHUNK_SIZE)
                        if not chunk:
                            break
                        nonce = secrets.token_bytes(AES_NONCE_SIZE)
                        aad = (
                            header
                            + struct.pack(_CHUNK_COUNT_FMT, total_chunks)
                            + struct.pack(_CHUNK_IDX_FMT, chunk_idx)
                        )
                        try:
                            ct = cipher.encrypt(nonce, chunk, aad)
                        except Exception as exc:
                            raise EncryptionError(
                                f"AES-GCM encryption failed at chunk {chunk_idx}."
                            ) from exc
                        block = nonce + ct
                        fout.write(struct.pack(_BLOCK_LEN_FMT, len(block)))
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

            _promote_tmp(tmp, dst, force=force)
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

def _decrypt_chunks(
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
                        raw_len = fin.read(_BLOCK_LEN_SIZE)
                        if not raw_len:
                            break   # EOF — all (remaining) blocks consumed
                        if len(raw_len) < _BLOCK_LEN_SIZE:
                            raise DecryptionError(
                                f"File truncated: incomplete block-length field "
                                f"at chunk {chunk_idx}."
                            )
                        (block_len,) = struct.unpack(_BLOCK_LEN_FMT, raw_len)
                        if not (_MIN_BLOCK_SIZE <= block_len <= _MAX_BLOCK_SIZE):
                            raise DecryptionError(
                                f"Block size {block_len} at chunk {chunk_idx} is "
                                f"outside the valid range "
                                f"[{_MIN_BLOCK_SIZE}, {_MAX_BLOCK_SIZE}]. "
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
                            + struct.pack(_CHUNK_COUNT_FMT, expected_chunks)
                            + struct.pack(_CHUNK_IDX_FMT, chunk_idx)
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
            _promote_tmp(tmp, dst, force=force)

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

# ── Header parser ─────────────────────────────────────────────────────────────

_MAX_HEADER_PEEK: int = (
    len(FILE_ENC_MAGIC) + 2       # magic (8 B) + version (1 B) + mode_tag (1 B)
    + max(
        FILE_RAW_SALT_LEN,                        # _KEY_RAW: per-file salt only
        ARGON2_SALT_LEN + ARGON2_PARAMS_LEN,      # _KEY_ARGON2: 16 + 10 = 26 B
        PBKDF2_SALT_LEN + 1 + 4,                  # _KEY_PBKDF2: 16 + 1 + 4 = 21 B
    )
    + FILE_CHUNK_COUNT_SIZE                       # chunk-count field (4 B)
)   # = 40 bytes (unchanged numerically: 16 == 16, both equal ARGON2_SALT_LEN's branch)

def _parse_header(src: Path) -> tuple[bytes, bytes, bytes | None, int, int]:
    """Parse the file envelope header."""
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

    if mode_tag == _KEY_RAW:
        needed = cursor + FILE_RAW_SALT_LEN
        if len(peek) < needed:
            raise DecryptionError("Raw-key file header is truncated.")
        file_salt = peek[cursor : needed]
        header = _raw_header(file_salt)
    elif mode_tag == _KEY_ARGON2:
        needed = cursor + ARGON2_SALT_LEN + ARGON2_PARAMS_LEN
        if len(peek) < needed:
            raise DecryptionError("Argon2 file header is truncated.")
        salt   = peek[cursor : cursor + ARGON2_SALT_LEN]
        params = peek[cursor + ARGON2_SALT_LEN : needed]
        header = _argon2_header(salt, params)
    elif mode_tag == _KEY_PBKDF2:
        needed = cursor + PBKDF2_SALT_LEN + 1 + 4   # salt + hash_tag + iterations
        if len(peek) < needed:
            raise DecryptionError("PBKDF2 file header is truncated.")
        salt     = peek[cursor : cursor + PBKDF2_SALT_LEN]
        hash_tag = peek[cursor + PBKDF2_SALT_LEN : cursor + PBKDF2_SALT_LEN + 1]
        (iters,) = struct.unpack(">I", peek[cursor + PBKDF2_SALT_LEN + 1 : needed])
        header   = _pbkdf2_header(salt, hash_tag, iters)
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
        _CHUNK_COUNT_FMT, peek[header_end : chunk_count_end]
    )
    if expected_chunks == 0:
        raise DecryptionError(
            "File header declares zero chunks. A legitimate encryption "
            "operation can never produce this (empty source files are "
            "rejected at encrypt time). The file is corrupt or forged."
        )
    block_start = chunk_count_end

    return header, mode_tag, file_salt, block_start, expected_chunks

# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_file(src: Path, dst: Path, key: bytes, *, force: bool = False) -> None:
    """Encrypt *src* to *dst* using the provided raw AES-256 *key*."""
    _validate_paths(src, dst, force=force)
    if len(key) != AES_KEY_SIZE:
        raise InputValidationError(
            f"Key must be exactly {AES_KEY_SIZE} bytes received {len(key)}."
        )
    file_salt = secrets.token_bytes(FILE_RAW_SALT_LEN)
    subkey = _derive_raw_subkey(key, file_salt)
    key_buf = bytearray(subkey)
    zero_bytes_buffer(subkey)
    del subkey
    try:
        _encrypt_chunks(src, dst, key_buf, _raw_header(file_salt), force=force)
    finally:
        zero_key(key_buf)

def decrypt_file(src: Path, dst: Path, key: bytes, *, force: bool = False) -> None:
    """Decrypt a file produced by :func:`encrypt_file` to *dst*."""
    _validate_paths(src, dst, force=force)
    if len(key) != AES_KEY_SIZE:
        raise InputValidationError(
            f"Key must be exactly {AES_KEY_SIZE} bytes; received {len(key)}."
        )
    header, mode_tag, file_salt, block_start, expected_chunks = _parse_header(src)
    if mode_tag != _KEY_RAW:
        raise DecryptionError(
            "This file uses a password-derived key. "
            "Use decrypt_file_with_password instead of decrypt_file."
        )
    if file_salt is None:  # pragma: no cover — defensive; _KEY_RAW always sets file_salt
        raise DecryptionError("Raw-key file header is missing its per-file salt.")
    subkey = _derive_raw_subkey(key, file_salt)
    key_buf = bytearray(subkey)
    zero_bytes_buffer(subkey)
    del subkey
    try:
        _decrypt_chunks(src, dst, key_buf, header, block_start, expected_chunks, force=force)
    finally:
        zero_key(key_buf)

def encrypt_file_with_password(
    src: Path,
    dst: Path,
    password: str,
    *,
    use_argon2: bool = True,
    argon2_time_cost: int = ARGON2_TIME_COST,
    argon2_memory_cost: int = ARGON2_MEMORY_COST,
    argon2_parallelism: int = ARGON2_PARALLELISM,
    force: bool = False,
) -> None:
    """Encrypt *src* to *dst* using a password-derived key."""
    _validate_paths(src, dst, force=force)
    if not password:
        raise InputValidationError("Password must not be empty.")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise InputValidationError(
            f"Password is too short ({len(password)} character(s)); "
            f"minimum is {PASSWORD_MIN_LENGTH} characters. "
            "A short password is vulnerable to offline brute-force even with "
            "Argon2id key stretching."
        )

    if use_argon2 and (
        argon2_time_cost > _DECRYPT_MAX_TIME_COST
        or argon2_memory_cost > _DECRYPT_MAX_MEMORY_COST
        or argon2_parallelism > _DECRYPT_MAX_PARALLELISM
    ):
        raise InputValidationError(
            f"Argon2 parameters exceed this toolkit's own decrypt-time "
            f"ceiling (time_cost<={_DECRYPT_MAX_TIME_COST}, "
            f"memory_cost<={_DECRYPT_MAX_MEMORY_COST} KiB, "
            f"parallelism<={_DECRYPT_MAX_PARALLELISM}); received "
            f"time_cost={argon2_time_cost}, memory_cost={argon2_memory_cost}, "
            f"parallelism={argon2_parallelism}. Data encrypted above this "
            "ceiling can never be decrypted by decrypt_file_with_password(), "
            "because decrypt-time bounds are intentionally tighter than "
            "encrypt-time bounds as a DoS guard against untrusted files. "
            "Lower the parameters, or raise DECRYPT_MAX_ARGON2_* in "
            "constants.py if you control both ends and accept the tradeoff."
        )

    if use_argon2:
        derived = derive_key_argon2(
            password,
            time_cost=argon2_time_cost,
            memory_cost=argon2_memory_cost,
            parallelism=argon2_parallelism,
        )
        params = struct.pack(
            ARGON2_PARAMS_STRUCT,
            argon2_time_cost, argon2_memory_cost, argon2_parallelism,
        )
        header = _argon2_header(derived.salt, params)
    else:
        derived = derive_key_pbkdf2(password)
        if derived.pbkdf2_hash is None or derived.pbkdf2_iterations is None:
            raise EncryptionError(
                "derive_key_pbkdf2 returned incomplete metadata "
                "(pbkdf2_hash or pbkdf2_iterations is None)."
            )
        hash_tag = PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash)
        if hash_tag is None:
            raise EncryptionError(
                f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into the file header."
            )
        header = _pbkdf2_header(derived.salt, hash_tag, derived.pbkdf2_iterations)

    try:
        _encrypt_chunks(src, dst, derived.key, header, force=force)
    finally:
        zero_key(derived.key)

def decrypt_file_with_password(src: Path, dst: Path, password: str, *, force: bool = False) -> None:
    """Decrypt a file produced by :func:`encrypt_file_with_password` to *dst*."""
    _validate_paths(src, dst, force=force)
    if not password:
        raise InputValidationError("Password must not be empty.")

    header, mode_tag, _file_salt, block_start, expected_chunks = _parse_header(src)
    # _file_salt is only meaningful for _KEY_RAW envelopes (see decrypt_file);
    # password-derived modes carry their own salt inside `header` instead.

    if mode_tag == _KEY_RAW:
        raise DecryptionError(
            "This file uses a raw AES key, not a password. "
            "Use decrypt_file instead of decrypt_file_with_password."
        )

    # Re-extract KDF parameters from the already-validated header bytes.
    magic_mode_len = len(FILE_ENC_MAGIC) + 2   # past magic + version + tag

    if mode_tag == _KEY_ARGON2:
        salt   = header[magic_mode_len : magic_mode_len + ARGON2_SALT_LEN]
        params = header[magic_mode_len + ARGON2_SALT_LEN :]
        time_cost, memory_cost, parallelism = struct.unpack(ARGON2_PARAMS_STRUCT, params)

        if (time_cost > _DECRYPT_MAX_TIME_COST
                or memory_cost > _DECRYPT_MAX_MEMORY_COST
                or parallelism > _DECRYPT_MAX_PARALLELISM):
            raise DecryptionError(
                "Argon2 parameters stored in the file header exceed the permitted "
                f"decrypt-time maximums (time_cost≤{_DECRYPT_MAX_TIME_COST}, "
                f"memory_cost≤{_DECRYPT_MAX_MEMORY_COST} KiB, "
                f"parallelism≤{_DECRYPT_MAX_PARALLELISM}). "
                "The file may originate from a malicious or untrusted source. "
                "If you legitimately encrypted this file with higher parameters, "
                "raise DECRYPT_MAX_ARGON2_* in constants.py deliberately."
            )

        if (time_cost < _DECRYPT_MIN_TIME_COST
                or memory_cost < _DECRYPT_MIN_MEMORY_COST
                or parallelism < _DECRYPT_MIN_PARALLELISM):
            raise DecryptionError(
                "Argon2 parameters stored in the file header are below the "
                f"minimum allowed (time_cost≥{_DECRYPT_MIN_TIME_COST}, "
                f"memory_cost≥{_DECRYPT_MIN_MEMORY_COST} KiB, "
                f"parallelism≥{_DECRYPT_MIN_PARALLELISM}). "
                "The file may be corrupt or originate from a malicious source."
            )

        derived = derive_key_argon2(
            password, salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )

    else:   # _KEY_PBKDF2
        salt          = header[magic_mode_len : magic_mode_len + PBKDF2_SALT_LEN]
        hash_tag      = header[magic_mode_len + PBKDF2_SALT_LEN : magic_mode_len + PBKDF2_SALT_LEN + 1]
        _iters_start  = magic_mode_len + PBKDF2_SALT_LEN + 1
        (iters,)      = struct.unpack(">I", header[_iters_start : _iters_start + 4])

        pbkdf2_hash = PBKDF2_TAG_TO_HASH.get(hash_tag)
        if pbkdf2_hash is None:
            raise DecryptionError(
                f"Unrecognised PBKDF2 hash tag in file header: {hash_tag!r}."
            )

        max_i = PBKDF2_MAX_ITERATIONS.get(pbkdf2_hash, 10_000_000)
        min_i = PBKDF2_MIN_ITERATIONS.get(pbkdf2_hash, 1)
        if not (min_i <= iters <= max_i):
            raise DecryptionError(
                f"PBKDF2 iteration count {iters:,} in file header is outside the "
                f"permitted range [{min_i:,}, {max_i:,}] for {pbkdf2_hash!r}. "
                "The file may originate from a malicious or untrusted source."
            )

        derived = derive_key_pbkdf2(
            password,
            salt=salt,
            iterations=iters,
            hash_algorithm=pbkdf2_hash,
        )

    try:
        _decrypt_chunks(src, dst, derived.key, header, block_start, expected_chunks, force=force)
    finally:
        zero_key(derived.key)