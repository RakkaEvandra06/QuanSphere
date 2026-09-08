"""x25519_hybrid.py — X25519 hybrid encryption: ephemeral Diffie-Hellman +
HKDF-SHA-256 + AES-256-GCM.

Single responsibility: the X25519 hybrid envelope only. RSA-OAEP lives in
rsa_ops.py; the ECC (P-256) hybrid scheme lives in ecc_hybrid.py.
"""

from __future__ import annotations

__all__ = ["x25519_hybrid_encrypt", "x25519_hybrid_decrypt"]

import hmac
import secrets
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from crypto_toolkit.core._aead_utils import aesgcm_context
from crypto_toolkit.core.asymmetric._shared import (
    _ASYM_HEADER_LEN,
    _ASYM_X25519_HEADER,
    _HYBRID_MAX_PLAINTEXT,
    _X25519_HKDF_INFO,
    _X25519_MIN_ENVELOPE,
    _X25519_PUB_LEN,
    _X25519_ZERO_SECRET,
    _hkdf_derive,
)
from crypto_toolkit.core.constants import (
    AES_NONCE_SIZE,
    ASYM_MAGIC,
    ASYM_X25519_TAG,
    ENVELOPE_VERSION,
)
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import zero_bytes_buffer, zero_key


def x25519_hybrid_encrypt(
    plaintext: bytes,
    recipient_pub: x25519.X25519PublicKey,
) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral X25519 + AES-GCM."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "Encrypting zero bytes produces a ciphertext containing only the "
            "authentication tag and carries no useful information."
        )
    if len(plaintext) > _HYBRID_MAX_PLAINTEXT:
        raise InputValidationError(
            f"Plaintext ({len(plaintext):,} bytes) exceeds the "
            f"{_HYBRID_MAX_PLAINTEXT // (1024 * 1024)} MiB limit for in-memory "
            "hybrid encryption. Use file_crypto.encrypt_file_with_password for "
            "large payloads, it streams data in 64 KiB chunks."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()

        # cast(bytes, …) narrows the type for Pyright.  See ecc_hybrid.py
        # for a full explanation of why this is needed when the cryptography
        # package is absent from the Pyright analysis environment.
        shared_secret_bytes = cast(bytes, ephemeral_priv.exchange(recipient_pub))
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _X25519_ZERO_SECRET):
            raise EncryptionError(
                "X25519 key exchange produced a zero shared secret "
                "the recipient public key is a low-order point and must be "
                "rejected. Verify that the recipient's public key is valid."
            )

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        recipient_pub_raw = recipient_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        _aad = _ASYM_X25519_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, _aad)

        return _ASYM_X25519_HEADER + ephemeral_pub_bytes + nonce + ciphertext

    except (EncryptionError, InputValidationError):
        raise
    except Exception as exc:
        raise EncryptionError("X25519 hybrid encryption failed.") from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)

def x25519_hybrid_decrypt(
    envelope: bytes,
    private_key: x25519.X25519PrivateKey,
) -> bytes:
    """Decrypt an envelope produced by :func:`x25519_hybrid_encrypt`."""
    if len(envelope) < _X25519_MIN_ENVELOPE:
        raise DecryptionError(
            f"X25519 envelope is too short ({len(envelope)} bytes); "
            f"minimum expected is {_X25519_MIN_ENVELOPE} bytes."
        )

    magic_len = len(ASYM_MAGIC)
    if envelope[:magic_len] != ASYM_MAGIC:
        raise DecryptionError("Envelope format not recognised (missing ASYM_MAGIC).")
    if envelope[magic_len : magic_len + 1] != ENVELOPE_VERSION:
        raise DecryptionError("Envelope version not supported.")
    if envelope[magic_len + 1 : magic_len + 2] != ASYM_X25519_TAG:
        raise DecryptionError(
            "Envelope algorithm tag mismatch: expected X25519 (0x02). "
            "Ensure you are using x25519_hybrid_decrypt for X25519-encrypted data, "
            "not ecc_hybrid_decrypt."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        offset = _ASYM_HEADER_LEN
        ephemeral_pub_bytes = envelope[offset : offset + _X25519_PUB_LEN]
        nonce_start = offset + _X25519_PUB_LEN
        nonce = envelope[nonce_start : nonce_start + AES_NONCE_SIZE]
        ciphertext = envelope[nonce_start + AES_NONCE_SIZE :]

        ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

        # Same cast for the decrypt path — see comment in x25519_hybrid_encrypt.
        shared_secret_bytes = cast(bytes, private_key.exchange(ephemeral_pub))
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _X25519_ZERO_SECRET):
            raise DecryptionError(
                "X25519 key exchange produced a zero shared secret "
                "the ephemeral public key is a low-order point and the "
                "envelope must be rejected."
            )

        recipient_pub_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        _aad = _ASYM_X25519_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            return cipher.decrypt(nonce, ciphertext, _aad)

    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(
            "X25519 hybrid decryption failed, wrong key or corrupted data."
        ) from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)