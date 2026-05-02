from __future__ import annotations

"""symmetric.py — AES-256-GCM and ChaCha20-Poly1305 authenticated encryption."""

__all__ = ["Algorithm", "encrypt", "decrypt"]

import base64
import secrets
import warnings
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

# Minimum payload on the decryption path: nonce + tag + 1 plaintext byte.
_AES_MIN_PAYLOAD: int = AES_NONCE_SIZE + AES_TAG_SIZE + 1          # 29 bytes
_CHACHA_MIN_PAYLOAD: int = CHACHA_NONCE_SIZE + 16 + 1              # 29 bytes (Poly1305 tag = 16)

# One-byte algorithm tags embedded in the envelope.
_AES_TAG: bytes = b"\x01"
_CHACHA_TAG: bytes = b"\x02"

# Map algorithm name → (tag, key_size, nonce_size, min_payload).
_ALGO_META: dict[str, tuple[bytes, int, int, int]] = {
    "aes-gcm":  (_AES_TAG,    AES_KEY_SIZE,   AES_NONCE_SIZE,   _AES_MIN_PAYLOAD),
    "chacha20": (_CHACHA_TAG, CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE, _CHACHA_MIN_PAYLOAD),
}

# ── Private helpers ───────────────────────────────────────────────────────────

def _validate_key(key: bytes, expected_size: int) -> None:
    """Raise InputValidationError if *key* is not exactly *expected_size* bytes."""
    if len(key) != expected_size:
        raise InputValidationError(
            f"Key must be exactly {expected_size} bytes; received {len(key)}."
        )

def _build_aad(header: bytes, associated_data: bytes | None) -> bytes:
    """Construct the internal AAD from the envelope header and caller-supplied data."""
    if associated_data is not None and len(associated_data) == 0:
        warnings.warn(
            "associated_data=b'' is equivalent to None (no AAD is applied). "
            "Pass None explicitly to suppress this warning, or supply a "
            "non-empty binding context (e.g. b'user:alice').",
            UserWarning,
            stacklevel=3,
        )
        associated_data = None

    return header if associated_data is None else header + associated_data

def _make_cipher(algo_tag: bytes, key: bytes) -> AESGCM | ChaCha20Poly1305:
    """Instantiate the AEAD cipher for the given *algo_tag* and *key*."""
    if algo_tag == _AES_TAG:
        return AESGCM(key)
    return ChaCha20Poly1305(key)

def _aead_decrypt(
    cipher: AESGCM | ChaCha20Poly1305,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None,
) -> bytes:
    """Wrap AEAD decryption with a uniform DecryptionError on failure."""
    try:
        return cipher.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        raise DecryptionError(
            "Decryption failed incorrect key, corrupted data, or mismatched "
            "associated_data (ensure the same value used during encryption is "
            "supplied here, including None if none was used)."
        ) from exc

# ── Public API ────────────────────────────────────────────────────────────────

def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    algorithm: Algorithm = "aes-gcm",
    associated_data: bytes | None = None,
) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 token."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "Encrypting zero bytes produces a ciphertext that contains only the "
            "authentication tag and carries no useful information."
        )

    algo_meta = _ALGO_META.get(algorithm)
    if algo_meta is None:
        raise InputValidationError(f"Unknown algorithm: {algorithm!r}")

    algo_tag, key_size, nonce_size, _ = algo_meta

    try:
        _validate_key(key, key_size)
        nonce = secrets.token_bytes(nonce_size)

        header = SYMMETRIC_MAGIC + ENVELOPE_VERSION + algo_tag
        aad_internal = _build_aad(header, associated_data)

        ciphertext = _make_cipher(algo_tag, key).encrypt(nonce, plaintext, aad_internal)
        envelope = header + nonce + ciphertext
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
    """Decrypt a token produced by :func:`encrypt`."""
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        magic_len = len(SYMMETRIC_MAGIC)

        if raw[:magic_len] != SYMMETRIC_MAGIC:
            raise DecryptionError("The envelope format is not recognized.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("The envelope version is not supported.")

        algo_tag = raw[magic_len + 1 : magic_len + 2]
        # header = magic + version byte + algo_tag byte
        header = raw[: magic_len + 2]
        payload = raw[magic_len + 2 :]
        aad_internal = _build_aad(header, associated_data)

        if algo_tag == _AES_TAG:
            _validate_key(key, AES_KEY_SIZE)
            if len(payload) < _AES_MIN_PAYLOAD:
                raise DecryptionError(
                    f"Token payload is too short for AES-GCM "
                    f"({len(payload)} bytes; minimum is {_AES_MIN_PAYLOAD}). "
                    "The token is likely truncated or corrupted."
                )
            nonce, ciphertext = payload[:AES_NONCE_SIZE], payload[AES_NONCE_SIZE:]

        elif algo_tag == _CHACHA_TAG:
            _validate_key(key, CHACHA_KEY_SIZE)
            if len(payload) < _CHACHA_MIN_PAYLOAD:
                raise DecryptionError(
                    f"Token payload is too short for ChaCha20-Poly1305 "
                    f"({len(payload)} bytes; minimum is {_CHACHA_MIN_PAYLOAD}). "
                    "The token is likely truncated or corrupted."
                )
            nonce, ciphertext = payload[:CHACHA_NONCE_SIZE], payload[CHACHA_NONCE_SIZE:]

        else:
            raise DecryptionError("An unknown algorithm tag is found inside the envelope.")

        return _aead_decrypt(_make_cipher(algo_tag, key), nonce, ciphertext, aad_internal)

    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError("Decryption failed.") from exc