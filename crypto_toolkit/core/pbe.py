from __future__ import annotations

import base64
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import (
    AES_NONCE_SIZE,
    ENVELOPE_VERSION,
    PBKDF2_HASH_TO_TAG as _PBKDF2_HASH_TO_TAG,
    PBKDF2_TAG_TO_HASH as _PBKDF2_TAG_TO_HASH,
)
from crypto_toolkit.core.exceptions import CryptoToolkitError, DecryptionError, EncryptionError
from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2

_PBE_MAGIC = b"CTK-PBE"
_KDF_ARGON2 = b"\x01"
_KDF_PBKDF2 = b"\x02"
_SALT_LEN = 16

# ── Minimum envelope length constants ─────────────────────────────────────────

# Argon2 envelope layout:
#   magic (7) + version (1) + kdf_tag (1) + salt (16) + nonce (12) + ciphertext (≥1)
_ARGON2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + AES_NONCE_SIZE + 1
)

# PBKDF2 envelope layout:
#   magic (7) + version (1) + kdf_tag (1) + salt (16) + hash_tag (1)
#   + iterations (4) + nonce (12) + ciphertext (≥1)
_PBKDF2_ITERATIONS_FIELD_LEN = 4
_PBKDF2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + 1 + _PBKDF2_ITERATIONS_FIELD_LEN
    + AES_NONCE_SIZE + 1
)

def _build_aad_argon2(salt: bytes) -> bytes:
    """Return the AAD for an Argon2 envelope (everything before the nonce)."""
    return _PBE_MAGIC + ENVELOPE_VERSION + _KDF_ARGON2 + salt

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

def password_encrypt(
    plaintext: bytes,
    password: str,
    *,
    use_argon2: bool = True,
) -> str:
    """Encrypt bytes with a password using Argon2id or PBKDF2 + AES-256-GCM."""
    try:
        nonce = secrets.token_bytes(AES_NONCE_SIZE)

        if use_argon2:
            derived = derive_key_argon2(password)
            kdf_tag = _KDF_ARGON2
            aad = _build_aad_argon2(derived.salt)
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, aad)
            envelope = (
                _PBE_MAGIC
                + ENVELOPE_VERSION
                + kdf_tag
                + derived.salt
                + nonce
                + ciphertext
            )
        else:
            derived = derive_key_pbkdf2(password)
            kdf_tag = _KDF_PBKDF2
            hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash or "")
            if hash_tag is None:
                raise EncryptionError(
                    f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into envelope."
                )
            iterations_bytes = struct.pack(">I", derived.pbkdf2_iterations or 0)
            aad = _build_aad_pbkdf2(
                derived.salt, hash_tag, derived.pbkdf2_iterations or 0
            )
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, aad)
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
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(_PBE_MAGIC)

        if raw[:magic_len] != _PBE_MAGIC:
            raise DecryptionError("Envelope format not recognized.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("Envelope version not supported.")

        kdf_tag = raw[magic_len + 1 : magic_len + 2]
        # Cursor advances past magic + version byte + kdf_tag byte.
        offset = magic_len + 2

        if kdf_tag == _KDF_ARGON2:
            if len(raw) < _ARGON2_MIN_ENVELOPE:
                raise DecryptionError(
                    f"Argon2 envelope is too short ({len(raw)} bytes — "
                    f"minimum expected is {_ARGON2_MIN_ENVELOPE}). "
                    f"The token is likely truncated or corrupted."
                )
        elif kdf_tag == _KDF_PBKDF2:
            if len(raw) < _PBKDF2_MIN_ENVELOPE:
                raise DecryptionError(
                    f"PBKDF2 envelope is too short ({len(raw)} bytes — "
                    f"minimum expected is {_PBKDF2_MIN_ENVELOPE}). "
                    f"The token is likely truncated or corrupted."
                )
        else:
            raise DecryptionError("Unrecognized KDF tag inside envelope.")

        salt = raw[offset : offset + _SALT_LEN]
        offset += _SALT_LEN

        if kdf_tag == _KDF_ARGON2:
            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            offset    += AES_NONCE_SIZE
            ciphertext = raw[offset:]
            derived    = derive_key_argon2(password, salt=salt)
            aad = _build_aad_argon2(salt)

        elif kdf_tag == _KDF_PBKDF2:
            hash_tag_byte = raw[offset : offset + 1]
            pbkdf2_hash   = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
            if pbkdf2_hash is None:
                raise DecryptionError(
                    f"Unrecognized PBKDF2 hash tag in envelope: {hash_tag_byte!r}."
                )
            offset += 1  # consume hash_tag byte
            (pbkdf2_iterations,) = struct.unpack(">I", raw[offset : offset + 4])
            offset += 4  # consume 4-byte iterations field

            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            offset    += AES_NONCE_SIZE
            ciphertext = raw[offset:]
            derived    = derive_key_pbkdf2(
                password,
                salt=salt,
                iterations=pbkdf2_iterations,
                hash_algorithm=pbkdf2_hash,
            )
            aad = _build_aad_pbkdf2(salt, hash_tag_byte, pbkdf2_iterations)

        else:
            raise DecryptionError("Unrecognized KDF tag inside envelope.")

        return AESGCM(derived.key).decrypt(nonce, ciphertext, aad)
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            "Password-based decryption failed — incorrect password or corrupted data."
        ) from exc