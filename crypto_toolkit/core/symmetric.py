from __future__ import annotations

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
            f"Key must be exactly {expected_size} bytes; received {len(key)}."
        )

def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    algorithm: Algorithm = "aes-gcm",
    associated_data: bytes | None = None,
) -> str:
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
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(SYMMETRIC_MAGIC)
        if raw[:magic_len] != SYMMETRIC_MAGIC:
            raise DecryptionError("The envelope format is not recognized.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("The envelope version is not supported.")
        algo_tag = raw[magic_len + 1 : magic_len + 2]
        payload = raw[magic_len + 2 :]
        if algo_tag == b"\x01":
            _validate_key(key, AES_KEY_SIZE)
            nonce, ciphertext = payload[:AES_NONCE_SIZE], payload[AES_NONCE_SIZE:]
            return _aead_decrypt(AESGCM(key), nonce, ciphertext, associated_data)
        elif algo_tag == b"\x02":
            _validate_key(key, CHACHA_KEY_SIZE)
            nonce, ciphertext = payload[:CHACHA_NONCE_SIZE], payload[CHACHA_NONCE_SIZE:]
            return _aead_decrypt(ChaCha20Poly1305(key), nonce, ciphertext, associated_data)
        else:
            raise DecryptionError("An unknown algorithm tag is found inside the envelope.")
    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError("Decryption failed.") from exc

def _aead_decrypt(
    cipher: AESGCM | ChaCha20Poly1305,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None,
) -> bytes:
    try:
        return cipher.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        if associated_data is None:
            hint = (
                " If the token was encrypted with associated_data, "
                "ensure the same parameter is provided during decryption."
            )
        else:
            hint = (
                " Ensure the associated_data provided is identical to the one used during encryption."
            )
        raise DecryptionError(
            f"Decryption failed — incorrect key, corrupted data, or mismatched associated_data.{hint}"
        ) from exc