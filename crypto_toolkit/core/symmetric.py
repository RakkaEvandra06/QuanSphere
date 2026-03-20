"""Symmetric encryption using AES-256-GCM and ChaCha20-Poly1305.

Both algorithms provide *authenticated* encryption, meaning the ciphertext
integrity is verified on decryption.  Tampering or corruption raises
``DecryptionError`` rather than producing garbage plaintext.

Envelope format (base64-decoded):
    MAGIC (7 bytes) | VERSION (1) | NONCE (12 or 16) | CIPHERTEXT+TAG
"""

import base64
import secrets
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    CHACHA_KEY_SIZE,
    CHACHA_NONCE_SIZE,
    ENVELOPE_VERSION,
    SYMMETRIC_MAGIC,
)
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, InputValidationError

Algorithm = Literal["aes-gcm", "chacha20"]


def _validate_key(key: bytes, expected_size: int) -> None:
    if len(key) != expected_size:
        raise InputValidationError(
            f"Key must be exactly {expected_size} bytes; got {len(key)}."
        )


def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    algorithm: Algorithm = "aes-gcm",
    associated_data: bytes | None = None,
) -> str:
    """Encrypt *plaintext* with *key* and return a base64-encoded envelope.

    Args:
        plaintext: Raw bytes to encrypt.
        key: 32-byte symmetric key.
        algorithm: ``"aes-gcm"`` (default) or ``"chacha20"``.
        associated_data: Optional authenticated-but-not-encrypted context.

    Returns:
        URL-safe base64 string containing the full envelope.

    Raises:
        InputValidationError: If the key length is wrong.
        EncryptionError: If the underlying primitive fails.
    """
    try:
        if algorithm == "aes-gcm":
            _validate_key(key, AES_KEY_SIZE)
            nonce = secrets.token_bytes(AES_NONCE_SIZE)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        elif algorithm == "chacha20":
            _validate_key(key, CHACHA_KEY_SIZE)
            nonce = secrets.token_bytes(CHACHA_NONCE_SIZE)
            ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data)
        else:
            raise InputValidationError(f"Unknown algorithm: {algorithm!r}")

        algo_tag = b"\x01" if algorithm == "aes-gcm" else b"\x02"
        envelope = SYMMETRIC_MAGIC + ENVELOPE_VERSION + algo_tag + nonce + ciphertext
        return base64.urlsafe_b64encode(envelope).decode()
    except InputValidationError:
        raise
    except Exception as exc:
        raise EncryptionError("Encryption failed.") from exc


def decrypt(
    token: str,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt a base64 envelope produced by :func:`encrypt`.

    Args:
        token: Base64-encoded envelope string.
        key: 32-byte symmetric key.
        associated_data: Must match the value used during encryption, if any.

    Returns:
        Recovered plaintext bytes.

    Raises:
        DecryptionError: On authentication failure, bad key, or malformed data.
    """
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(SYMMETRIC_MAGIC)

        if raw[:magic_len] != SYMMETRIC_MAGIC:
            raise DecryptionError("Unrecognized envelope format.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("Unsupported envelope version.")

        algo_tag = raw[magic_len + 1 : magic_len + 2]
        payload = raw[magic_len + 2 :]

        if algo_tag == b"\x01":
            _validate_key(key, AES_KEY_SIZE)
            nonce, ciphertext = payload[:AES_NONCE_SIZE], payload[AES_NONCE_SIZE:]
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        elif algo_tag == b"\x02":
            _validate_key(key, CHACHA_KEY_SIZE)
            nonce, ciphertext = payload[:CHACHA_NONCE_SIZE], payload[CHACHA_NONCE_SIZE:]
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
        else:
            raise DecryptionError("Unknown algorithm tag in envelope.")
    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError("Decryption failed — wrong key or corrupted data.") from exc
