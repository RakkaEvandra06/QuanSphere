"""High-level password-based encryption (PBE) combining KDF + AES-256-GCM.

This module provides the convenient PBE layer used by the CLI's
``encrypt --password`` and ``decrypt --password`` subcommands.

Envelope format (binary, then base64):
    PBE_MAGIC   (7 bytes)
    VERSION     (1 byte)
    KDF_TAG     (1 byte: 0x01 = Argon2, 0x02 = PBKDF2)
    SALT        (16 bytes)
    NONCE       (12 bytes)
    CIPHERTEXT  + GCM-TAG (variable)
"""

from __future__ import annotations

import base64
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_toolkit.core.constants import AES_NONCE_SIZE, ENVELOPE_VERSION
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError
from crypto_toolkit.core.kdf import derive_key_argon2, derive_key_pbkdf2
from crypto_toolkit.core.random_gen import generate_key

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
    """Encrypt *plaintext* with a password-derived key.

    Args:
        plaintext: Data to encrypt.
        password: User-supplied passphrase.
        use_argon2: Use Argon2id (default).  Falls back to PBKDF2 if ``False``.

    Returns:
        URL-safe base64-encoded envelope.

    Raises:
        EncryptionError: On failure.
    """
    try:
        if use_argon2:
            derived = derive_key_argon2(password)
            kdf_tag = _KDF_ARGON2
        else:
            derived = derive_key_pbkdf2(password)
            kdf_tag = _KDF_PBKDF2

        nonce = generate_key(AES_NONCE_SIZE)
        ciphertext = AESGCM(derived.key).encrypt(nonce, plaintext, None)

        envelope = (
            _PBE_MAGIC
            + ENVELOPE_VERSION
            + kdf_tag
            + derived.salt
            + nonce
            + ciphertext
        )
        return base64.urlsafe_b64encode(envelope).decode()
    except Exception as exc:
        raise EncryptionError("Password-based encryption failed.") from exc


def password_decrypt(token: str, password: str) -> bytes:
    """Decrypt an envelope produced by :func:`password_encrypt`.

    Args:
        token: Base64-encoded envelope.
        password: User passphrase.

    Returns:
        Recovered plaintext.

    Raises:
        DecryptionError: On wrong password, corruption, or authentication failure.
    """
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(_PBE_MAGIC)

        if raw[:magic_len] != _PBE_MAGIC:
            raise DecryptionError("Unrecognized envelope format.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("Unsupported envelope version.")

        kdf_tag = raw[magic_len + 1 : magic_len + 2]
        salt = raw[magic_len + 2 : magic_len + 2 + _SALT_LEN]
        rest = raw[magic_len + 2 + _SALT_LEN :]
        nonce, ciphertext = rest[:AES_NONCE_SIZE], rest[AES_NONCE_SIZE:]

        if kdf_tag == _KDF_ARGON2:
            derived = derive_key_argon2(password, salt=salt)
        elif kdf_tag == _KDF_PBKDF2:
            derived = derive_key_pbkdf2(password, salt=salt)
        else:
            raise DecryptionError("Unknown KDF tag in envelope.")

        return AESGCM(derived.key).decrypt(nonce, ciphertext, None)
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError("Password-based decryption failed — wrong password or corrupted data.") from exc
