"""rsa_ops.py — Direct RSA-OAEP / SHA-256 encryption and decryption.

Single responsibility: RSA-OAEP only. For payloads larger than a single RSA
block, see ecc_hybrid.py / x25519_hybrid.py instead.
"""

from __future__ import annotations

__all__ = ["rsa_encrypt", "rsa_decrypt"]

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.core.asymmetric._shared import _SHA256_DIGEST_SIZE, _make_oaep_padding
from crypto_toolkit.core.constants import RSA_MIN_KEY_SIZE
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, InputValidationError


def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt *plaintext* with *public_key* using RSA-OAEP / SHA-256."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "RSA-OAEP cannot encrypt zero bytes."
        )
    if public_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA public key is {public_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    max_plaintext = (public_key.key_size // 8) - 2 * _SHA256_DIGEST_SIZE - 2
    if len(plaintext) > max_plaintext:
        raise InputValidationError(
            f"Plaintext ({len(plaintext)} bytes) exceeds the RSA-OAEP maximum "
            f"({max_plaintext} bytes) for a {public_key.key_size}-bit key. "
            "Use ecc_hybrid_encrypt or x25519_hybrid_encrypt for large payloads."
        )
    try:
        return public_key.encrypt(plaintext, _make_oaep_padding())
    except Exception as exc:
        raise EncryptionError("RSA-OAEP encryption failed.") from exc

def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt *ciphertext* with *private_key* using RSA-OAEP / SHA-256."""
    if private_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA private key is {private_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    expected_len: int = (private_key.key_size + 7) // 8
    if len(ciphertext) != expected_len:
        raise DecryptionError(
            f"RSA ciphertext must be exactly {expected_len} bytes for a "
            f"{private_key.key_size}-bit key; received {len(ciphertext)} bytes. "
            "Ensure you are decrypting a raw RSA-OAEP ciphertext, not a "
            "base64-encoded or hex-encoded value."
        )
    try:
        return private_key.decrypt(ciphertext, _make_oaep_padding())
    except Exception as exc:
        raise DecryptionError(
            "RSA-OAEP decryption failed, wrong key or corrupted ciphertext."
        ) from exc
