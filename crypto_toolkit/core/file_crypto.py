from __future__ import annotations

__all__ = [
    "encrypt_file",
    "encrypt_file_with_password",
    "decrypt_file",
    "decrypt_file_with_password",
]

import hashlib
import secrets
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_PARAMS_LEN,
    ARGON2_PARAMS_STRUCT,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    FILE_CHUNK_SIZE,
    FILE_ENC_MAGIC,
    FILE_ENC_VERSION,
    FILE_MAX_BLOCK_SIZE,
    PBKDF2_HASH_TO_TAG as _PBKDF2_HASH_TO_TAG,
    PBKDF2_TAG_TO_HASH as _PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import (
    CryptoToolkitError,
    DecryptionError,
    EncryptionError,
    FileOperationError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import (
    ARGON2_MAX_MEMORY_COST as _ARGON2_MAX_MEMORY_COST,
    ARGON2_MAX_PARALLELISM as _ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST as _ARGON2_MAX_TIME_COST,
    DerivedKey,
    derive_key_argon2,
    derive_key_pbkdf2,
    zero_bytes,
)

_HEADER_SALT_LEN: int = ARGON2_SALT_LEN
_CHUNK_LEN_FMT = ">I"  # big-endian unsigned 32-bit int

# KDF tags embedded in the file header.
_KDF_TAG_RAW: bytes = b"\x00"    # raw key provided directly
_KDF_TAG_ARGON2: bytes = b"\x01" # key derived via Argon2id
_KDF_TAG_PBKDF2: bytes = b"\x02" # key derived via PBKDF2

# EOF sentinel block layout: nonce (12) + 8-byte payload + tag (16) = 36 bytes.
_EOF_BLOCK_LEN: int = AES_NONCE_SIZE + 8 + AES_TAG_SIZE

_MIN_CHUNK_SIZE: int = 4 * 1024       # 4 KiB — avoids degenerate overhead
_MAX_CHUNK_SIZE: int = FILE_CHUNK_SIZE # 64 KiB — matches plaintext read size

# Decryption-side caps prevent DoS from hostile headers.
_DECRYPT_MAX_TIME_COST: int = _ARGON2_MAX_TIME_COST
_DECRYPT_MAX_MEMORY_COST: int = _ARGON2_MAX_MEMORY_COST
_DECRYPT_MAX_PARALLELISM: int = _ARGON2_MAX_PARALLELISM

_PBKDF2_MAX_ITERATIONS: dict[str, int] = {
    "sha256":  10_000_000,
    "sha512":   3_500_000,
    "sha3_256": 3_000_000,
    "sha3_512": 1_500_000,
}
_PBKDF2_MIN_ITERATIONS: dict[str, int] = {
    "sha256":   600_000,
    "sha512":   210_000,
    "sha3_256": 200_000,
    "sha3_512": 100_000,
}

# ── Header helpers ────────────────────────────────────────────────────────────

def _write_header(
    out: BinaryIO,
    salt: bytes,
    kdf_tag: bytes = _KDF_TAG_RAW,
    *,
    pbkdf2_hash_tag: bytes | None = None,
    pbkdf2_iterations: int | None = None,
    argon2_params: bytes | None = None,
) -> None:
    """Write the file header to *out*."""
    out.write(FILE_ENC_MAGIC)
    out.write(FILE_ENC_VERSION)
    out.write(kdf_tag)
    out.write(salt)
    if kdf_tag == _KDF_TAG_ARGON2:
        if argon2_params is None:
            raise EncryptionError(
                "argon2_params must be provided when kdf_tag is _KDF_TAG_ARGON2."
            )
        out.write(argon2_params)
    if kdf_tag == _KDF_TAG_PBKDF2:
        if pbkdf2_hash_tag is None or pbkdf2_iterations is None:
            raise EncryptionError(
                "pbkdf2_hash_tag and pbkdf2_iterations must be provided "
                "when kdf_tag is _KDF_TAG_PBKDF2."
            )
        out.write(pbkdf2_hash_tag)
        out.write(struct.pack(">I", pbkdf2_iterations))

def _read_header(
    src: BinaryIO,
) -> tuple[bytes, bytes, str | None, int | None, bytes | None]:
    """Read and validate the file header from *src*."""
    magic = src.read(len(FILE_ENC_MAGIC))
    if magic != FILE_ENC_MAGIC:
        raise DecryptionError("Invalid encrypted file (incorrect magic bytes).")

    version = src.read(1)
    if version != FILE_ENC_VERSION:
        raise DecryptionError(f"Unsupported file format version: {version!r}.")

    kdf_tag = src.read(1)
    if kdf_tag not in (_KDF_TAG_RAW, _KDF_TAG_ARGON2, _KDF_TAG_PBKDF2):
        raise DecryptionError(f"Unrecognized KDF tag in file header: {kdf_tag!r}.")

    salt = src.read(_HEADER_SALT_LEN)
    if len(salt) != _HEADER_SALT_LEN:
        raise DecryptionError("File header truncated (salt field).")

    argon2_params_raw: bytes | None = None
    pbkdf2_hash: str | None = None
    pbkdf2_iterations: int | None = None

    if kdf_tag == _KDF_TAG_ARGON2:
        argon2_params_raw = src.read(ARGON2_PARAMS_LEN)
        if len(argon2_params_raw) != ARGON2_PARAMS_LEN:
            raise DecryptionError("File header truncated (Argon2 params field).")

    if kdf_tag == _KDF_TAG_PBKDF2:
        hash_tag_byte = src.read(1)
        pbkdf2_hash = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
        if pbkdf2_hash is None:
            raise DecryptionError(
                f"Unrecognized PBKDF2 hash tag in file header: {hash_tag_byte!r}."
            )
        iterations_bytes = src.read(4)
        if len(iterations_bytes) != 4:
            raise DecryptionError("File header truncated (PBKDF2 iterations field).")
        (pbkdf2_iterations,) = struct.unpack(">I", iterations_bytes)

    return kdf_tag, salt, pbkdf2_hash, pbkdf2_iterations, argon2_params_raw

def _build_header_bytes(
    salt: bytes,
    kdf_tag: bytes,
    *,
    pbkdf2_hash_tag: bytes | None,
    pbkdf2_iterations: int | None,
    argon2_params: bytes | None = None,
) -> bytes:
    """Return the exact byte sequence that :func:`_write_header` produces."""
    parts: list[bytes] = [FILE_ENC_MAGIC, FILE_ENC_VERSION, kdf_tag, salt]
    if kdf_tag == _KDF_TAG_ARGON2:
        if argon2_params is None:
            raise EncryptionError(
                "argon2_params is required when kdf_tag is _KDF_TAG_ARGON2 "
                "cannot build a valid header."
            )
        parts.append(argon2_params)
    if kdf_tag == _KDF_TAG_PBKDF2:
        if pbkdf2_hash_tag is None or pbkdf2_iterations is None:
            raise EncryptionError(
                "pbkdf2_hash_tag and pbkdf2_iterations are required when "
                "kdf_tag is _KDF_TAG_PBKDF2 cannot build a valid header."
            )
        parts.append(pbkdf2_hash_tag)
        parts.append(struct.pack(">I", pbkdf2_iterations))
    return b"".join(parts)

def _chunk_aad(chunk_index: int, header_digest: bytes) -> bytes:
    """Return the per-chunk AAD: big-endian chunk index + header SHA-256 digest."""
    return struct.pack(">Q", chunk_index) + header_digest

# ── Validation helpers ────────────────────────────────────────────────────────

def _assert_distinct_paths(src_path: Path, dst_path: Path, operation: str) -> None:
    """Raise FileOperationError when *src_path* and *dst_path* resolve to the same file."""
    if src_path.resolve() == dst_path.resolve():
        raise FileOperationError(
            f"Cannot {operation}: source and destination paths resolve to the "
            f"same file ({src_path.resolve()}). "
            "Provide a different destination path to avoid overwriting the source."
        )

def _validate_chunk_size(chunk_size: int) -> None:
    """Raise EncryptionError if *chunk_size* is outside the accepted range."""
    if not (_MIN_CHUNK_SIZE <= chunk_size <= _MAX_CHUNK_SIZE):
        raise EncryptionError(
            f"chunk_size must be between {_MIN_CHUNK_SIZE} and "
            f"{_MAX_CHUNK_SIZE} bytes; received {chunk_size}. "
            f"Values below {_MIN_CHUNK_SIZE} bytes produce excessive per-chunk overhead; "
            f"values above {_MAX_CHUNK_SIZE} bytes exceed the maximum block size "
            "that the decryption path accepts."
        )

# ── Internal helpers ──────────────────────────────────────────────────────────

def _tmp_path_for(dst_path: Path) -> Path:
    """Return a unique sibling temp path for *dst_path* (8 random hex chars suffix)."""
    random_suffix = secrets.token_hex(4)
    return dst_path.with_suffix(dst_path.suffix + f".{random_suffix}.tmp")

def _cleanup_tmp(tmp_path: Path) -> None:
    """Delete *tmp_path* if it exists; suppress any OS errors."""
    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass

def _derive_key_from_header(
    password: str,
    kdf_tag: bytes,
    salt: bytes,
    pbkdf2_hash: str | None,
    pbkdf2_iterations: int | None,
    argon2_params_raw: bytes | None,
) -> tuple[DerivedKey, bytes | None]:
    """Derive the decryption key and return ``(derived_key, pbkdf2_hash_tag_for_aad)``."""
    pbkdf2_hash_tag_for_aad: bytes | None = None

    if kdf_tag == _KDF_TAG_ARGON2:
        if argon2_params_raw is None:
            raise DecryptionError(
                "File header is corrupt Argon2 params field is missing "
                "despite the Argon2 KDF tag being present."
            )
        time_cost, memory_cost, parallelism = struct.unpack(
            ARGON2_PARAMS_STRUCT, argon2_params_raw
        )

        # Upper-bound DoS cap (pre-existing).
        if (
            time_cost > _DECRYPT_MAX_TIME_COST
            or memory_cost > _DECRYPT_MAX_MEMORY_COST
            or parallelism > _DECRYPT_MAX_PARALLELISM
        ):
            raise DecryptionError(
                f"File header Argon2 parameters exceed the maximum allowed "
                f"(time_cost≤{_DECRYPT_MAX_TIME_COST}, "
                f"memory_cost≤{_DECRYPT_MAX_MEMORY_COST} KiB, "
                f"parallelism≤{_DECRYPT_MAX_PARALLELISM}); "
                f"received time_cost={time_cost}, memory_cost={memory_cost}, "
                f"parallelism={parallelism}. "
                "The file may originate from an untrusted or malicious source."
            )

        if time_cost < 1 or memory_cost < 8192 or parallelism < 1:
            raise DecryptionError(
                f"File header Argon2 parameters are below the minimum allowed "
                f"(time_cost≥1, memory_cost≥8192 KiB, parallelism≥1); "
                f"received time_cost={time_cost}, memory_cost={memory_cost}, "
                f"parallelism={parallelism}. "
                "The file header is corrupt or has been tampered with."
            )

        derived = derive_key_argon2(
            password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )

    elif kdf_tag == _KDF_TAG_PBKDF2:
        if pbkdf2_iterations is None or pbkdf2_hash is None:
            raise DecryptionError(
                "File header is corrupt PBKDF2 iteration count or hash "
                "algorithm field is missing."
            )

        # Upper-bound DoS cap (pre-existing).
        pbkdf2_max = _PBKDF2_MAX_ITERATIONS.get(pbkdf2_hash, 10_000_000)
        if pbkdf2_iterations > pbkdf2_max:
            raise DecryptionError(
                f"File header PBKDF2 iteration count {pbkdf2_iterations:,} "
                f"exceeds the maximum allowed ({pbkdf2_max:,}) for "
                f"{pbkdf2_hash!r}. "
                "The file may originate from an untrusted or malicious source."
            )

        pbkdf2_min = _PBKDF2_MIN_ITERATIONS.get(pbkdf2_hash, 1)
        if pbkdf2_iterations < pbkdf2_min:
            raise DecryptionError(
                f"File header PBKDF2 iteration count {pbkdf2_iterations:,} is below "
                f"the minimum allowed ({pbkdf2_min:,}) for {pbkdf2_hash!r}. "
                "The file header is corrupt or has been tampered with."
            )

        derived = derive_key_pbkdf2(
            password,
            salt=salt,
            iterations=pbkdf2_iterations,
            hash_algorithm=pbkdf2_hash,
        )
        pbkdf2_hash_tag_for_aad = _PBKDF2_HASH_TO_TAG.get(pbkdf2_hash)
        if pbkdf2_hash_tag_for_aad is None:
            raise DecryptionError(
                f"Cannot re-encode PBKDF2 hash {pbkdf2_hash!r} back into a "
                "header tag PBKDF2_HASH_TO_TAG may be out of sync with "
                "PBKDF2_TAG_TO_HASH in constants.py."
            )
    else:
        raise DecryptionError(f"Unrecognized KDF tag: {kdf_tag!r}.")

    return derived, pbkdf2_hash_tag_for_aad

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
    argon2_params: bytes | None,
) -> None:
    """Write an encrypted chunked stream from *src_path* to *dst_path*."""
    assert _MIN_CHUNK_SIZE <= chunk_size <= _MAX_CHUNK_SIZE, (
        f"_encrypt_stream pre-condition violated: chunk_size={chunk_size} is "
        f"outside [{_MIN_CHUNK_SIZE}, {_MAX_CHUNK_SIZE}]. "
        "Callers must call _validate_chunk_size before invoking this function."
    )

    header_bytes = _build_header_bytes(
        salt, kdf_tag,
        pbkdf2_hash_tag=pbkdf2_hash_tag,
        pbkdf2_iterations=pbkdf2_iterations,
        argon2_params=argon2_params,
    )
    header_digest = hashlib.sha256(header_bytes).digest()
    tmp_path = _tmp_path_for(dst_path)

    success = False
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            _write_header(
                dst, salt, kdf_tag,
                pbkdf2_hash_tag=pbkdf2_hash_tag,
                pbkdf2_iterations=pbkdf2_iterations,
                argon2_params=argon2_params,
            )
            chunk_index = 0
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    # Write zero-length sentinel followed by the authenticated EOF block.
                    dst.write(struct.pack(_CHUNK_LEN_FMT, 0))
                    eof_nonce = secrets.token_bytes(AES_NONCE_SIZE)
                    eof_aad = _chunk_aad(chunk_index, header_digest)
                    # Payload = total data-chunk count, authenticated to detect truncation.
                    eof_ct = aesgcm.encrypt(
                        eof_nonce,
                        struct.pack(">Q", chunk_index),
                        eof_aad,
                    )
                    dst.write(eof_nonce + eof_ct)
                    break

                nonce = secrets.token_bytes(AES_NONCE_SIZE)
                aad = _chunk_aad(chunk_index, header_digest)
                ciphertext = aesgcm.encrypt(nonce, chunk, aad)
                block = nonce + ciphertext
                dst.write(struct.pack(_CHUNK_LEN_FMT, len(block)))
                dst.write(block)
                chunk_index += 1

        tmp_path.replace(dst_path)
        success = True
    except (EncryptionError, FileOperationError):
        raise
    except Exception as exc:
        raise FileOperationError(f"File encryption failed: {exc}") from exc
    finally:
        if not success:
            _cleanup_tmp(tmp_path)

def _decrypt_chunks(
    src: BinaryIO,
    dst: BinaryIO,
    aesgcm: AESGCM,
    header_bytes: bytes,
) -> None:
    """Read and decrypt all chunks from *src* (file header already consumed)."""
    header_digest = hashlib.sha256(header_bytes).digest()
    chunk_index = 0

    while True:
        len_bytes = src.read(4)
        if len(len_bytes) < 4:
            raise DecryptionError("Unexpected end of file (chunk length field missing).")

        (block_len,) = struct.unpack(_CHUNK_LEN_FMT, len_bytes)

        if block_len == 0:
            # EOF sentinel — authenticate the block and verify chunk count.
            eof_block = src.read(_EOF_BLOCK_LEN)
            if len(eof_block) != _EOF_BLOCK_LEN:
                raise DecryptionError(
                    f"EOF block is missing or truncated ({len(eof_block)} of "
                    f"{_EOF_BLOCK_LEN} bytes read) "
                    "the file has been truncated or tampered with."
                )
            eof_nonce = eof_block[:AES_NONCE_SIZE]
            eof_ct = eof_block[AES_NONCE_SIZE:]
            eof_aad = _chunk_aad(chunk_index, header_digest)
            try:
                count_bytes = aesgcm.decrypt(eof_nonce, eof_ct, eof_aad)
            except Exception as exc:
                raise DecryptionError(
                    "EOF block authentication failed "
                    "the file is corrupted or has been tampered with."
                ) from exc

            (expected_chunks,) = struct.unpack(">Q", count_bytes)
            if expected_chunks != chunk_index:
                raise DecryptionError(
                    f"File is truncated or tampered with: "
                    f"expected {expected_chunks} chunks, decrypted {chunk_index}."
                )
            break

        if block_len > FILE_MAX_BLOCK_SIZE:
            raise DecryptionError(
                f"Block length {block_len} exceeds the maximum allowed size "
                f"({FILE_MAX_BLOCK_SIZE} bytes) file may be corrupted or malicious."
            )

        block = src.read(block_len)
        if len(block) != block_len:
            raise DecryptionError("Unexpected end of file (chunk data truncated).")

        nonce = block[:AES_NONCE_SIZE]
        ciphertext = block[AES_NONCE_SIZE:]
        aad = _chunk_aad(chunk_index, header_digest)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise DecryptionError(
                f"Authentication failed on chunk {chunk_index} "
                "the file is corrupted or has been tampered with."
            ) from exc

        dst.write(plaintext)
        chunk_index += 1

# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> None:
    """Encrypt *src_path* to *dst_path* using a raw AES-256 key."""
    _assert_distinct_paths(src_path, dst_path, "encrypt file in place")

    if len(key) != AES_KEY_SIZE:
        raise EncryptionError(f"Key must be {AES_KEY_SIZE} bytes; received {len(key)}.")

    _validate_chunk_size(chunk_size)

    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    salt = secrets.token_bytes(_HEADER_SALT_LEN)
    _encrypt_stream(
        src_path, dst_path, AESGCM(key), salt, chunk_size, _KDF_TAG_RAW,
        pbkdf2_hash_tag=None,
        pbkdf2_iterations=None,
        argon2_params=None,
    )

def encrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
    *,
    chunk_size: int = FILE_CHUNK_SIZE,
    use_argon2: bool = True,
    argon2_time_cost: int = ARGON2_TIME_COST,
    argon2_memory_cost: int = ARGON2_MEMORY_COST,
    argon2_parallelism: int = ARGON2_PARALLELISM,
) -> None:
    """Encrypt *src_path* to *dst_path* using a password-derived key."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    _assert_distinct_paths(src_path, dst_path, "encrypt file in place")
    _validate_chunk_size(chunk_size)

    if not src_path.is_file():
        raise FileOperationError(f"Source file not found: {src_path}")

    if use_argon2:
        argon2_params = struct.pack(
            ARGON2_PARAMS_STRUCT,
            argon2_time_cost,
            argon2_memory_cost,
            argon2_parallelism,
        )
        derived = derive_key_argon2(
            password,
            time_cost=argon2_time_cost,
            memory_cost=argon2_memory_cost,
            parallelism=argon2_parallelism,
        )
        kdf_tag = _KDF_TAG_ARGON2
        pbkdf2_hash_tag = None
        pbkdf2_iterations = None
    else:
        derived = derive_key_pbkdf2(password)
        kdf_tag = _KDF_TAG_PBKDF2
        argon2_params = None
        pbkdf2_hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash or "")
        if pbkdf2_hash_tag is None:
            raise EncryptionError(
                f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into file header."
            )
        pbkdf2_iterations = derived.pbkdf2_iterations

    try:
        _encrypt_stream(
            src_path, dst_path, AESGCM(derived.key), derived.salt, chunk_size, kdf_tag,
            pbkdf2_hash_tag=pbkdf2_hash_tag,
            pbkdf2_iterations=pbkdf2_iterations,
            argon2_params=argon2_params,
        )
    finally:
        # Best-effort wipe — runs whether _encrypt_stream succeeds or raises.
        zero_bytes(derived.key)

def decrypt_file(
    src_path: Path,
    dst_path: Path,
    key: bytes,
) -> None:
    """Decrypt *src_path* to *dst_path* using a raw AES-256 key."""
    _assert_distinct_paths(src_path, dst_path, "decrypt file in place")

    if len(key) != AES_KEY_SIZE:
        raise DecryptionError(f"Key must be {AES_KEY_SIZE} bytes; received {len(key)}.")
    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    tmp_path = _tmp_path_for(dst_path)
    success = False
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            kdf_tag, salt, _pbkdf2_hash, _pbkdf2_iterations, _argon2_params = _read_header(src)
            if kdf_tag != _KDF_TAG_RAW:
                raise DecryptionError(
                    "This file was encrypted with a password, use decrypt_file_with_password()."
                )
            header_bytes = _build_header_bytes(
                salt, kdf_tag,
                pbkdf2_hash_tag=None,
                pbkdf2_iterations=None,
                argon2_params=None,
            )
            _decrypt_chunks(src, dst, AESGCM(key), header_bytes)
        tmp_path.replace(dst_path)
        success = True
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            f"File decryption failed, incorrect key or corrupted data: {exc}"
        ) from exc
    finally:
        if not success:
            _cleanup_tmp(tmp_path)

def decrypt_file_with_password(
    src_path: Path,
    dst_path: Path,
    password: str,
) -> None:
    """Decrypt a password-protected file encrypted with :func:`encrypt_file_with_password`."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    _assert_distinct_paths(src_path, dst_path, "decrypt file in place")

    if not src_path.is_file():
        raise FileOperationError(f"Encrypted file not found: {src_path}")

    tmp_path = _tmp_path_for(dst_path)
    derived: DerivedKey | None = None
    success = False
    try:
        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            kdf_tag, salt, pbkdf2_hash, pbkdf2_iterations, argon2_params_raw = _read_header(src)

            if kdf_tag == _KDF_TAG_RAW:
                raise DecryptionError(
                    "This file was encrypted with a raw key, use decrypt_file()."
                )

            derived, pbkdf2_hash_tag_for_aad = _derive_key_from_header(
                password, kdf_tag, salt, pbkdf2_hash, pbkdf2_iterations, argon2_params_raw
            )

            header_bytes = _build_header_bytes(
                salt, kdf_tag,
                pbkdf2_hash_tag=pbkdf2_hash_tag_for_aad,
                pbkdf2_iterations=pbkdf2_iterations,
                argon2_params=argon2_params_raw,
            )
            # AESGCM copies key material internally, so zeroing derived.key in
            # the finally block does not corrupt the cipher object.
            _decrypt_chunks(src, dst, AESGCM(derived.key), header_bytes)

        tmp_path.replace(dst_path)
        success = True
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            f"File decryption failed — incorrect password or corrupted data: {exc}"
        ) from exc
    finally:
        if derived is not None:
            zero_bytes(derived.key)
        if not success:
            _cleanup_tmp(tmp_path)