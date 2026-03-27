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

    try:
        if algorithm == "aes-gcm":
            _validate_key(key, AES_KEY_SIZE)
            nonce = secrets.token_bytes(AES_NONCE_SIZE)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        elif algorithm == "chacha20":
            _validate_key(key, CHACHA_KEY_SIZE)
            # CHACHA_NONCE_SIZE is 12 bytes (RFC 8439 standard).
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
            # CHACHA_NONCE_SIZE is 12 bytes (RFC 8439 standard).
            nonce, ciphertext = payload[:CHACHA_NONCE_SIZE], payload[CHACHA_NONCE_SIZE:]
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
        else:
            raise DecryptionError("Unknown algorithm tag in envelope.")
    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError("Decryption failed — wrong key or corrupted data.") from exc