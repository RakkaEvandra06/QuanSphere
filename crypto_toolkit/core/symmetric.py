from __future__ import annotations

import base64
import secrets
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    CHACHA_KEY_SIZE,
    CHACHA_NONCE_SIZE,
    ENVELOPE_VERSION,
    SYMMETRIC_MAGIC,
)
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, InputValidationError

Algorithm = Literal["aes-gcm", "chacha20"]

_AES_MIN_PAYLOAD   = AES_NONCE_SIZE + AES_TAG_SIZE + 1   # 29 bytes
_CHACHA_MIN_PAYLOAD = CHACHA_NONCE_SIZE + 16 + 1         # 29 bytes (Poly1305 tag = 16)

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
            if len(payload) < _AES_MIN_PAYLOAD:
                raise DecryptionError(
                    f"Token payload is too short for AES-GCM "
                    f"({len(payload)} bytes; minimum is {_AES_MIN_PAYLOAD}). "
                    f"The token is likely truncated or corrupted."
                )
            nonce, ciphertext = payload[:AES_NONCE_SIZE], payload[AES_NONCE_SIZE:]
            return _aead_decrypt(AESGCM(key), nonce, ciphertext, associated_data)

        elif algo_tag == b"\x02":
            _validate_key(key, CHACHA_KEY_SIZE)
            if len(payload) < _CHACHA_MIN_PAYLOAD:
                raise DecryptionError(
                    f"Token payload is too short for ChaCha20-Poly1305 "
                    f"({len(payload)} bytes; minimum is {_CHACHA_MIN_PAYLOAD}). "
                    f"The token is likely truncated or corrupted."
                )
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
        raise DecryptionError(
            "Decryption failed — incorrect key, corrupted data, or mismatched "
            "associated_data (ensure the same value used during encryption is "
            "supplied here, including None if none was used)."
        ) from exc