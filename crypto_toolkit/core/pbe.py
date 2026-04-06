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
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, None)
            # Argon2 envelope — identical to the previous format.
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
            ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, None)

            hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash or "")
            if hash_tag is None:
                raise EncryptionError(
                    f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into envelope."
                )
            iterations_bytes = struct.pack(">I", derived.pbkdf2_iterations or 0)
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

        salt = raw[offset : offset + _SALT_LEN]
        offset += _SALT_LEN

        if kdf_tag == _KDF_ARGON2:
            # Argon2 layout: salt is immediately followed by nonce.
            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            ciphertext = raw[offset + AES_NONCE_SIZE :]
            derived    = derive_key_argon2(password, salt=salt)

        elif kdf_tag == _KDF_PBKDF2:
            hash_tag_byte = raw[offset : offset + 1]
            pbkdf2_hash   = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
            if pbkdf2_hash is None:
                raise DecryptionError(
                    f"Unrecognized PBKDF2 hash tag in envelope: {hash_tag_byte!r}."
                )
            (pbkdf2_iterations,) = struct.unpack(">I", raw[offset + 1 : offset + 5])
            offset += 5  # 1 byte hash_tag + 4 bytes iterations

            nonce      = raw[offset : offset + AES_NONCE_SIZE]
            ciphertext = raw[offset + AES_NONCE_SIZE :]
            derived    = derive_key_pbkdf2(
                password,
                salt=salt,
                iterations=pbkdf2_iterations,
                hash_algorithm=pbkdf2_hash,
            )

        else:
            raise DecryptionError("Unrecognized KDF tag inside envelope.")

        return AESGCM(derived.key).decrypt(nonce, ciphertext, None)
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            "Password-based decryption failed — incorrect password or corrupted data."
        ) from exc