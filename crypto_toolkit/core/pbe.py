from __future__ import annotations

__all__ = ["password_encrypt", "password_decrypt"]

import base64
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import (
    AEAD_MIN_CIPHERTEXT,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_PARAMS_LEN,
    ARGON2_PARAMS_STRUCT,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    AES_NONCE_SIZE,
    ENVELOPE_VERSION,
    PBE_MAGIC as _PBE_MAGIC,
    PBKDF2_HASH_TO_TAG as _PBKDF2_HASH_TO_TAG,
    PBKDF2_SALT_LEN,
    PBKDF2_TAG_TO_HASH as _PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import (
    CryptoToolkitError,
    DecryptionError,
    EncryptionError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import (
    derive_key_argon2,
    derive_key_pbkdf2,
    zero_bytes,
    ARGON2_MAX_TIME_COST   as _ARGON2_MAX_TIME_COST,
    ARGON2_MAX_MEMORY_COST as _ARGON2_MAX_MEMORY_COST,
    ARGON2_MAX_PARALLELISM as _ARGON2_MAX_PARALLELISM,
)

_KDF_ARGON2 = b"\x01"
_KDF_PBKDF2 = b"\x02"
_DECRYPT_MAX_TIME_COST:   int = _ARGON2_MAX_TIME_COST    # 1 000 iterations
_DECRYPT_MAX_MEMORY_COST: int = _ARGON2_MAX_MEMORY_COST  # 2 GiB in KiB
_DECRYPT_MAX_PARALLELISM: int = _ARGON2_MAX_PARALLELISM  # 64 lanes

_PBKDF2_MAX_ITERATIONS: dict[str, int] = {
    "sha256":   10_000_000,   # 600 k/s × 16× OWASP → ~16 s max
    "sha512":    3_500_000,   # ~210 k/s × 16× OWASP
    "sha3_256":  3_000_000,   # ~200 k/s × 15× OWASP
    "sha3_512":  1_500_000,   # ~100 k/s × 15× OWASP
}

if ARGON2_SALT_LEN != PBKDF2_SALT_LEN:
    raise RuntimeError(
        f"Invariant violated: ARGON2_SALT_LEN ({ARGON2_SALT_LEN}) != "
        f"PBKDF2_SALT_LEN ({PBKDF2_SALT_LEN}). "
        "Both salt lengths must be equal for the single-offset PBE envelope "
        "parser in password_decrypt to work correctly. "
        "Update _build_aad_* and password_decrypt to use per-KDF offsets "
        "if the two constants must differ."
    )
_SALT_LEN: int = ARGON2_SALT_LEN

# ── Minimum envelope length constants ─────────────────────────────────────────

_HEADER_PREFIX_LEN: int = len(_PBE_MAGIC) + 1 + 1   # 9 bytes

# Argon2 envelope layout:
#   magic (7) + version (1) + kdf_tag (1) + salt (16)
#   + argon2_params (10) + nonce (12) + ciphertext (≥17)
_ARGON2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + ARGON2_PARAMS_LEN + AES_NONCE_SIZE
    + AEAD_MIN_CIPHERTEXT
)

# PBKDF2 envelope layout:
#   magic (7) + version (1) + kdf_tag (1) + salt (16) + hash_tag (1)
#   + iterations (4) + nonce (12) + ciphertext (≥17)
_PBKDF2_ITERATIONS_FIELD_LEN = 4
_PBKDF2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + 1 + _PBKDF2_ITERATIONS_FIELD_LEN
    + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)

# ── AAD builders ──────────────────────────────────────────────────────────────

def _build_aad_argon2(salt: bytes, argon2_params: bytes) -> bytes:
    """Return the AAD for an Argon2 envelope (everything before the nonce)."""
    return _PBE_MAGIC + ENVELOPE_VERSION + _KDF_ARGON2 + salt + argon2_params

def _build_aad_pbkdf2(salt: bytes, hash_tag: bytes, iterations: int) -> bytes:
    """Return the AAD for a PBKDF2 envelope (everything before the nonce)."""
    return (
        _PBE_MAGIC
        + ENVELOPE_VERSION
        + _KDF_PBKDF2
        + salt
        + hash_tag
        + struct.pack(">I", iterations)
    )

# ── Public API ────────────────────────────────────────────────────────────────

def password_encrypt(
    plaintext: bytes,
    password: str,
    *,
    use_argon2: bool = True,
    argon2_time_cost:   int = ARGON2_TIME_COST,
    argon2_memory_cost: int = ARGON2_MEMORY_COST,
    argon2_parallelism: int = ARGON2_PARALLELISM,
) -> str:
    """Encrypt bytes with a password using Argon2id or PBKDF2 + AES-256-GCM."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    try:
        nonce = secrets.token_bytes(AES_NONCE_SIZE)

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
            kdf_tag = _KDF_ARGON2
            aad = _build_aad_argon2(derived.salt, argon2_params)
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, aad)

            zero_bytes(derived.key)

            envelope = (
                _PBE_MAGIC
                + ENVELOPE_VERSION
                + kdf_tag
                + derived.salt
                + argon2_params
                + nonce
                + ciphertext
            )

        else:
            derived = derive_key_pbkdf2(password)
            kdf_tag = _KDF_PBKDF2

            if derived.pbkdf2_iterations is None or derived.pbkdf2_hash is None:
                raise EncryptionError(
                    "derive_key_pbkdf2 returned incomplete metadata "
                    "(pbkdf2_iterations or pbkdf2_hash is None) — "
                    "cannot construct a valid PBKDF2 envelope."
                )

            hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash)
            if hash_tag is None:
                raise EncryptionError(
                    f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into envelope."
                )
            iterations_bytes = struct.pack(">I", derived.pbkdf2_iterations)
            aad = _build_aad_pbkdf2(
                derived.salt, hash_tag, derived.pbkdf2_iterations
            )
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, aad)

            zero_bytes(derived.key)

            envelope = (
                _PBE_MAGIC
                + ENVELOPE_VERSION
                + kdf_tag
                + derived.salt
                + hash_tag
                + iterations_bytes
                + nonce
                + ciphertext
            )

        return base64.urlsafe_b64encode(envelope).decode()
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise EncryptionError("Password-based encryption failed.") from exc

def password_decrypt(token: str, password: str) -> bytes:
    """Decrypt a token produced by password_encrypt()."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(_PBE_MAGIC)

        if len(raw) < _HEADER_PREFIX_LEN:
            raise DecryptionError(
                f"Token is too short to be a valid envelope "
                f"({len(raw)} bytes; minimum header prefix is {_HEADER_PREFIX_LEN} bytes). "
                f"The token is likely truncated or corrupted."
            )

        if raw[:magic_len] != _PBE_MAGIC:
            raise DecryptionError("Envelope format not recognized.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("Envelope version not supported.")

        kdf_tag = raw[magic_len + 1 : magic_len + 2]
        # Cursor advances past magic + version byte + kdf_tag byte.
        offset = magic_len + 2

        if kdf_tag not in (_KDF_ARGON2, _KDF_PBKDF2):
            raise DecryptionError("Unrecognized KDF tag inside envelope.")

        min_len = _ARGON2_MIN_ENVELOPE if kdf_tag == _KDF_ARGON2 else _PBKDF2_MIN_ENVELOPE
        kdf_name = "Argon2" if kdf_tag == _KDF_ARGON2 else "PBKDF2"
        if len(raw) < min_len:
            raise DecryptionError(
                f"{kdf_name} envelope is too short ({len(raw)} bytes — "
                f"minimum expected is {min_len}). "
                f"The token is likely truncated or corrupted."
            )

        salt = raw[offset : offset + _SALT_LEN]
        offset += _SALT_LEN

        if kdf_tag == _KDF_ARGON2:
            argon2_params_raw = raw[offset : offset + ARGON2_PARAMS_LEN]
            offset += ARGON2_PARAMS_LEN
            time_cost, memory_cost, parallelism = struct.unpack(
                ARGON2_PARAMS_STRUCT, argon2_params_raw
            )

            if (
                time_cost   > _DECRYPT_MAX_TIME_COST
                or memory_cost  > _DECRYPT_MAX_MEMORY_COST
                or parallelism  > _DECRYPT_MAX_PARALLELISM
            ):
                raise DecryptionError(
                    f"Envelope Argon2 parameters exceed the maximum allowed "
                    f"(time_cost≤{_DECRYPT_MAX_TIME_COST}, "
                    f"memory_cost≤{_DECRYPT_MAX_MEMORY_COST} KiB, "
                    f"parallelism≤{_DECRYPT_MAX_PARALLELISM}); "
                    f"received time_cost={time_cost}, memory_cost={memory_cost}, "
                    f"parallelism={parallelism}. "
                    "The token may originate from an untrusted or malicious source."
                )

            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            offset    += AES_NONCE_SIZE
            ciphertext = raw[offset:]

            derived = derive_key_argon2(
                password,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            aad = _build_aad_argon2(salt, argon2_params_raw)

        else:  # kdf_tag == _KDF_PBKDF2
            hash_tag_byte = raw[offset : offset + 1]
            pbkdf2_hash   = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
            if pbkdf2_hash is None:
                raise DecryptionError(
                    f"Unrecognized PBKDF2 hash tag in envelope: {hash_tag_byte!r}."
                )
            offset += 1  # consume hash_tag byte
            (pbkdf2_iterations,) = struct.unpack(">I", raw[offset : offset + 4])
            offset += 4  # consume 4-byte iterations field

            _pbkdf2_max = _PBKDF2_MAX_ITERATIONS.get(pbkdf2_hash, 10_000_000)
            if pbkdf2_iterations > _pbkdf2_max:
                raise DecryptionError(
                    f"PBKDF2 iteration count {pbkdf2_iterations:,} exceeds the "
                    f"maximum allowed ({_pbkdf2_max:,}) for {pbkdf2_hash!r}. "
                    "The token may originate from an untrusted or malicious source."
                )

            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            offset    += AES_NONCE_SIZE
            ciphertext = raw[offset:]

            derived = derive_key_pbkdf2(
                password,
                salt=salt,
                iterations=pbkdf2_iterations,
                hash_algorithm=pbkdf2_hash,
            )
            aad = _build_aad_pbkdf2(salt, hash_tag_byte, pbkdf2_iterations)

        plaintext = AESGCM(derived.key).decrypt(nonce, ciphertext, aad)

        # key material does not linger in heap memory longer than necessary.
        zero_bytes(derived.key)

        return plaintext
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            "Password-based decryption failed — incorrect password or corrupted data."
        ) from exc