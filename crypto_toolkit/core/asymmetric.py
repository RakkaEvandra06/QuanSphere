"""Asymmetric encryption and key-pair management.

Supported schemes
-----------------
* **RSA-4096** with OAEP + SHA-256 padding for encryption/decryption.
* **ECC (P-256)** with ECDH + HKDF for hybrid encryption and Ed25519 for
  digital signatures.

Key serialisation uses PEM with optional password protection (AES-256-CBC
via the standard ``cryptography`` serialisation layer).
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDH,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core.constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    RSA_KEY_SIZE,
    RSA_PUBLIC_EXPONENT,
)
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    InputValidationError,
    KeyGenerationError,
)


# ── RSA Key management ────────────────────────────────────────────────────────


def generate_rsa_keypair(
    key_size: int = RSA_KEY_SIZE,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key-pair.

    Args:
        key_size: RSA modulus bit-length (minimum 2048; default 4096).

    Returns:
        ``(private_key, public_key)`` tuple.

    Raises:
        KeyGenerationError: If *key_size* is below the safe minimum.
    """
    if key_size < 2048:
        raise KeyGenerationError("RSA key size must be at least 2048 bits.")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=key_size,
        )
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("RSA key generation failed.") from exc


def generate_ecc_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a P-256 ECDH key-pair for hybrid encryption.

    Returns:
        ``(private_key, public_key)`` tuple.

    Raises:
        KeyGenerationError: On unexpected failure.
    """
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("ECC key generation failed.") from exc


# ── Serialisation helpers ─────────────────────────────────────────────────────


def private_key_to_pem(key: RSAPrivateKey | EllipticCurvePrivateKey, password: bytes | None = None) -> bytes:
    """Serialise a private key to PEM.

    Args:
        key: An RSA or ECC private key object.
        password: Optional passphrase for PKCS8 encryption.

    Returns:
        PEM-encoded private key bytes.
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(key: RSAPublicKey | EllipticCurvePublicKey) -> bytes:
    """Serialise a public key to PEM (SubjectPublicKeyInfo format)."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: bytes | None = None) -> RSAPrivateKey | EllipticCurvePrivateKey:
    """Load an RSA or ECC private key from PEM bytes."""
    try:
        return serialization.load_pem_private_key(pem, password=password)  # type: ignore[return-value]
    except Exception as exc:
        raise InputValidationError("Failed to load private key — wrong password or corrupt PEM.") from exc


def load_public_key(pem: bytes) -> RSAPublicKey | EllipticCurvePublicKey:
    """Load an RSA or ECC public key from PEM bytes."""
    try:
        return serialization.load_pem_public_key(pem)  # type: ignore[return-value]
    except Exception as exc:
        raise InputValidationError("Failed to load public key — corrupt PEM.") from exc


# ── RSA Encryption / Decryption ───────────────────────────────────────────────


def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt *plaintext* with RSA-OAEP (SHA-256).

    RSA encryption is suitable only for small payloads (≤ key_size/8 − 66 bytes
    for OAEP-SHA256).  For larger data use hybrid encryption via :func:`ecc_hybrid_encrypt`.

    Args:
        plaintext: Data to encrypt (small payloads only).
        public_key: Recipient's RSA public key.

    Returns:
        Ciphertext bytes (length equals the RSA modulus size).

    Raises:
        EncryptionError: If the payload is too large or encryption fails.
    """
    try:
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise EncryptionError(f"RSA encryption failed — payload may be too large: {exc}") from exc
    except Exception as exc:
        raise EncryptionError("RSA encryption failed.") from exc


def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt RSA-OAEP ciphertext.

    Args:
        ciphertext: Encrypted bytes from :func:`rsa_encrypt`.
        private_key: Corresponding RSA private key.

    Returns:
        Recovered plaintext.

    Raises:
        DecryptionError: On invalid padding, wrong key, or corrupted data.
    """
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise DecryptionError("RSA decryption failed — wrong key or corrupted data.") from exc


# ── ECC Hybrid Encryption ─────────────────────────────────────────────────────
# ECDH → shared secret → HKDF → AES-256-GCM key → encrypt payload.
# Envelope: ephemeral_pub (65 bytes uncompressed) | nonce (12) | ciphertext+tag


def ecc_hybrid_encrypt(plaintext: bytes, recipient_pub: EllipticCurvePublicKey) -> bytes:
    """Hybrid-encrypt *plaintext* for *recipient_pub* using ECDH + AES-256-GCM.

    An ephemeral P-256 key-pair is generated per encryption to ensure
    forward secrecy.

    Args:
        plaintext: Arbitrary-length data to encrypt.
        recipient_pub: Recipient's ECC public key.

    Returns:
        Raw ciphertext envelope bytes.

    Raises:
        EncryptionError: On any cryptographic failure.
    """
    try:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret = ephemeral_priv.exchange(ECDH(), recipient_pub)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=b"crypto-toolkit-ecc-hybrid-v1",
        ).derive(shared_secret)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return ephemeral_pub_bytes + nonce + ciphertext
    except Exception as exc:
        raise EncryptionError("ECC hybrid encryption failed.") from exc


def ecc_hybrid_decrypt(envelope: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Decrypt an envelope produced by :func:`ecc_hybrid_encrypt`.

    Args:
        envelope: Raw envelope bytes.
        private_key: Recipient's ECC private key.

    Returns:
        Recovered plaintext.

    Raises:
        DecryptionError: On authentication failure, wrong key, or corrupt data.
    """
    try:
        # Uncompressed P-256 point is always 65 bytes.
        pub_len = 65
        ephemeral_pub_bytes = envelope[:pub_len]
        nonce = envelope[pub_len : pub_len + AES_NONCE_SIZE]
        ciphertext = envelope[pub_len + AES_NONCE_SIZE :]

        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_bytes
        )
        shared_secret = private_key.exchange(ECDH(), ephemeral_pub)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=b"crypto-toolkit-ecc-hybrid-v1",
        ).derive(shared_secret)

        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise DecryptionError("ECC hybrid decryption failed — wrong key or corrupted data.") from exc
