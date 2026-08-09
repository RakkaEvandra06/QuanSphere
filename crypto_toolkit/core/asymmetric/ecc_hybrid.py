"""ecc_hybrid.py — ECC (SECP256R1) hybrid encryption: ephemeral ECDH +
HKDF-SHA-256 + AES-256-GCM.

Single responsibility: the ECC hybrid envelope only. RSA-OAEP lives in
rsa_ops.py; the X25519 hybrid scheme lives in x25519_hybrid.py.
"""

from __future__ import annotations

__all__ = ["ecc_hybrid_encrypt", "ecc_hybrid_decrypt"]

import hmac
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from crypto_toolkit.core._aead_utils import aesgcm_context
from crypto_toolkit.core.asymmetric._shared import (
    _ASYM_ECC_HEADER,
    _ASYM_HEADER_LEN,
    _ECC_HKDF_INFO,
    _ECC_MIN_ENVELOPE,
    _ECC_UNCOMPRESSED_PUB_LEN,
    _ECC_ZERO_SECRET,
    _HYBRID_MAX_PLAINTEXT,
    _UNCOMPRESSED_POINT_PREFIX,
    _assert_secp256r1,
    _hkdf_derive,
)
from crypto_toolkit.core.constants import (
    AES_NONCE_SIZE,
    ASYM_ECC_TAG,
    ASYM_MAGIC,
    ENVELOPE_VERSION,
)
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import zero_bytes_buffer, zero_key


def ecc_hybrid_encrypt(plaintext: bytes, recipient_pub: EllipticCurvePublicKey) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral ECDH + AES-GCM."""
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
    _assert_secp256r1(recipient_pub, "hybrid encryption")

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret_bytes = ephemeral_priv.exchange(ECDH(), recipient_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _ECC_ZERO_SECRET):
            raise EncryptionError(
                "ECDH key exchange produced a zero shared secret, "
                "the recipient public key may be degenerate. "
                "Verify that the key is a valid SECP256R1 point."
            )

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        recipient_pub_bytes = recipient_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        _aad = _ASYM_ECC_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, _aad)

        return _ASYM_ECC_HEADER + ephemeral_pub_bytes + nonce + ciphertext

    except (EncryptionError, InputValidationError):
        raise
    except Exception as exc:
        raise EncryptionError("ECC hybrid encryption failed.") from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)   # reliable ctypes.memset wipe of bytearray
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)

def ecc_hybrid_decrypt(envelope: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Decrypt an envelope produced by :func:`ecc_hybrid_encrypt`."""
    _assert_secp256r1(private_key, "hybrid decryption")

    if len(envelope) < _ECC_MIN_ENVELOPE:
        raise DecryptionError(
            f"ECC envelope is too short ({len(envelope)} bytes); "
            f"minimum expected is {_ECC_MIN_ENVELOPE} bytes."
        )

    magic_len = len(ASYM_MAGIC)
    if envelope[:magic_len] != ASYM_MAGIC:
        raise DecryptionError("Envelope format not recognised (missing ASYM_MAGIC).")
    if envelope[magic_len : magic_len + 1] != ENVELOPE_VERSION:
        raise DecryptionError("Envelope version not supported.")
    if envelope[magic_len + 1 : magic_len + 2] != ASYM_ECC_TAG:
        raise DecryptionError(
            "Envelope algorithm tag mismatch: expected ECC (0x01). "
            "Ensure you are using ecc_hybrid_decrypt for ECC-encrypted data, "
            "not x25519_hybrid_decrypt."
        )

    offset = _ASYM_HEADER_LEN
    ephemeral_pub_bytes = envelope[offset : offset + _ECC_UNCOMPRESSED_PUB_LEN]
    if ephemeral_pub_bytes[0] != _UNCOMPRESSED_POINT_PREFIX:
        raise DecryptionError(
            f"ECC envelope contains an invalid ephemeral public key "
            f"expected uncompressed point marker 0x04, "
            f"got 0x{ephemeral_pub_bytes[0]:02x}. "
            "The envelope may be corrupt or use an unsupported point encoding."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        nonce_start = offset + _ECC_UNCOMPRESSED_PUB_LEN
        nonce = envelope[nonce_start : nonce_start + AES_NONCE_SIZE]
        ciphertext = envelope[nonce_start + AES_NONCE_SIZE :]

        ephemeral_pub = EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_bytes
        )

        shared_secret_bytes = private_key.exchange(ECDH(), ephemeral_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _ECC_ZERO_SECRET):
            raise DecryptionError(
                "ECDH key exchange produced a zero shared secret, "
                "the ephemeral public key in the envelope is degenerate. "
                "The envelope must be rejected."
            )

        recipient_pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        _aad = _ASYM_ECC_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            return cipher.decrypt(nonce, ciphertext, _aad)

    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(
            "ECC hybrid decryption failed, wrong key or corrupted data."
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
