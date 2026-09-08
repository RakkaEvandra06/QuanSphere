"""api.py — Public chunked-file-encryption API.

Single responsibility: orchestration. Resolves a key (raw or
password-derived via Argon2id/PBKDF2), builds/parses the envelope header
(_envelope.py), and delegates the actual byte-streaming to _chunks.py.
"""

from __future__ import annotations

__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_with_password",
    "decrypt_file_with_password",
]

import secrets
import struct
from pathlib import Path

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_PARAMS_STRUCT,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    DECRYPT_MAX_ARGON2_MEMORY_COST,
    DECRYPT_MAX_ARGON2_PARALLELISM,
    DECRYPT_MAX_ARGON2_TIME_COST,
    FILE_ENC_MAGIC,
    FILE_RAW_SALT_LEN,
    PASSWORD_MIN_LENGTH,
    PBKDF2_HASH_TO_TAG,
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    PBKDF2_HISTORICAL_MIN_ITERATIONS,
    PBKDF2_SALT_LEN,
    PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, InputValidationError
from crypto_toolkit.core.file_crypto._chunks import decrypt_chunks, encrypt_chunks, validate_paths
from crypto_toolkit.core.file_crypto._envelope import (
    KEY_ARGON2,
    KEY_RAW,
    argon2_header,
    derive_raw_subkey,
    parse_header,
    pbkdf2_header,
    raw_header,
)
from crypto_toolkit.core.kdf import (
    derive_key_argon2,
    derive_key_pbkdf2,
    zero_bytes_buffer,
    zero_key,
)

_ARGON2_MIN_MEMORY_COST_KIB = 8_192  # 8 MiB in KiB — Argon2 RFC lower bound
_DECRYPT_MIN_TIME_COST:   int = 1
_DECRYPT_MIN_MEMORY_COST: int = _ARGON2_MIN_MEMORY_COST_KIB
_DECRYPT_MIN_PARALLELISM: int = 1

_DECRYPT_MAX_TIME_COST:   int = DECRYPT_MAX_ARGON2_TIME_COST
_DECRYPT_MAX_MEMORY_COST: int = DECRYPT_MAX_ARGON2_MEMORY_COST
_DECRYPT_MAX_PARALLELISM: int = DECRYPT_MAX_ARGON2_PARALLELISM

# ── Raw-key API ───────────────────────────────────────────────────────────────

def encrypt_file(src: Path, dst: Path, key: bytes, *, force: bool = False) -> None:
    """Encrypt *src* to *dst* using the provided raw AES-256 *key*."""
    validate_paths(src, dst, force=force)
    if len(key) != AES_KEY_SIZE:
        raise InputValidationError(
            f"Key must be exactly {AES_KEY_SIZE} bytes; received {len(key)}."
        )
    file_salt = secrets.token_bytes(FILE_RAW_SALT_LEN)
    subkey = derive_raw_subkey(key, file_salt)
    key_buf = bytearray(subkey)
    zero_bytes_buffer(subkey)
    del subkey
    try:
        encrypt_chunks(src, dst, key_buf, raw_header(file_salt), force=force)
    finally:
        zero_key(key_buf)

def decrypt_file(src: Path, dst: Path, key: bytes, *, force: bool = False) -> None:
    """Decrypt a file produced by :func:`encrypt_file` to *dst*."""
    validate_paths(src, dst, force=force)
    if len(key) != AES_KEY_SIZE:
        raise InputValidationError(
            f"Key must be exactly {AES_KEY_SIZE} bytes; received {len(key)}."
        )
    header, mode_tag, file_salt, block_start, expected_chunks = parse_header(src)
    if mode_tag != KEY_RAW:
        raise DecryptionError(
            "This file uses a password-derived key. "
            "Use decrypt_file_with_password instead of decrypt_file."
        )
    if file_salt is None:  # pragma: no cover — defensive; KEY_RAW always sets file_salt
        raise DecryptionError("Raw-key file header is missing its per-file salt.")
    subkey = derive_raw_subkey(key, file_salt)
    key_buf = bytearray(subkey)
    zero_bytes_buffer(subkey)
    del subkey
    try:
        decrypt_chunks(src, dst, key_buf, header, block_start, expected_chunks, force=force)
    finally:
        zero_key(key_buf)

# ── Password-derived API ──────────────────────────────────────────────────────

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
    validate_paths(src, dst, force=force)
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
        header = argon2_header(derived.salt, params)
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
        header = pbkdf2_header(derived.salt, hash_tag, derived.pbkdf2_iterations)

    try:
        encrypt_chunks(src, dst, derived.key, header, force=force)
    finally:
        zero_key(derived.key)

def decrypt_file_with_password(src: Path, dst: Path, password: str, *, force: bool = False) -> None:
    """Decrypt a file produced by :func:`encrypt_file_with_password` to *dst*."""
    validate_paths(src, dst, force=force)
    if not password:
        raise InputValidationError("Password must not be empty.")

    header, mode_tag, _file_salt, block_start, expected_chunks = parse_header(src)
    # _file_salt is only meaningful for KEY_RAW envelopes (see decrypt_file);
    # password-derived modes carry their own salt inside `header` instead.

    if mode_tag == KEY_RAW:
        raise DecryptionError(
            "This file uses a raw AES key, not a password. "
            "Use decrypt_file instead of decrypt_file_with_password."
        )

    # Re-extract KDF parameters from the already-validated header bytes.
    magic_mode_len = len(FILE_ENC_MAGIC) + 2   # past magic + version + tag

    if mode_tag == KEY_ARGON2:
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

    else:   # KEY_PBKDF2
        salt          = header[magic_mode_len : magic_mode_len + PBKDF2_SALT_LEN]
        hash_tag = header[
            magic_mode_len + PBKDF2_SALT_LEN : magic_mode_len + PBKDF2_SALT_LEN + 1
        ]
        _iters_start  = magic_mode_len + PBKDF2_SALT_LEN + 1
        (iters,)      = struct.unpack(">I", header[_iters_start : _iters_start + 4])

        pbkdf2_hash = PBKDF2_TAG_TO_HASH.get(hash_tag)
        if pbkdf2_hash is None:
            raise DecryptionError(
                f"Unrecognised PBKDF2 hash tag in file header: {hash_tag!r}."
            )

        max_i      = PBKDF2_MAX_ITERATIONS[pbkdf2_hash]
        hist_min_i = PBKDF2_HISTORICAL_MIN_ITERATIONS[pbkdf2_hash]

        if iters > max_i:
            raise DecryptionError(
                f"PBKDF2 iteration count {iters:,} in the file header exceeds "
                f"the maximum ({max_i:,}) for {pbkdf2_hash!r}. "
                "The file may originate from an untrusted or malicious source."
            )
        if iters < hist_min_i:
            raise DecryptionError(
                f"PBKDF2 iteration count {iters:,} in the file header is "
                f"critically low (absolute floor: {hist_min_i:,} for "
                f"{pbkdf2_hash!r}). This file's key-derivation work-factor "
                "is too weak to decrypt safely. The file was likely produced "
                "by a tool configured with dangerously low security parameters."
            )

        derived = derive_key_pbkdf2(
            password,
            salt=salt,
            iterations=iters,
            hash_algorithm=pbkdf2_hash,
        )

    try:
        decrypt_chunks(src, dst, derived.key, header, block_start, expected_chunks, force=force)
    finally:
        zero_key(derived.key)