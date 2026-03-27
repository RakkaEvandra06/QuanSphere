from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
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

    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("ECC key generation failed.") from exc


def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:

    try:
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("X25519 key generation failed.") from exc

# ── Serialisation helpers ─────────────────────────────────────────────────────

def private_key_to_pem(
    key: RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey,
    password: bytes | None = None,
) -> bytes:

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

def public_key_to_pem(
    key: RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey,
) -> bytes:
    """Serialise a public key to PEM (SubjectPublicKeyInfo format)."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_private_key(
    pem: bytes,
    password: bytes | None = None,
) -> RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey:
    """Load an RSA, ECC, or X25519 private key from PEM bytes."""
    try:
        return serialization.load_pem_private_key(pem, password=password)  # type: ignore[return-value]
    except Exception as exc:
        raise InputValidationError("Failed to load private key — wrong password or corrupt PEM.") from exc


def load_public_key(
    pem: bytes,
) -> RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey:
    """Load an RSA, ECC, or X25519 public key from PEM bytes."""
    try:
        return serialization.load_pem_public_key(pem)  # type: ignore[return-value]
    except Exception as exc:
        raise InputValidationError("Failed to load public key — corrupt PEM.") from exc

# ── RSA Encryption / Decryption ───────────────────────────────────────────────

def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:

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

def ecc_hybrid_encrypt(plaintext: bytes, recipient_pub: EllipticCurvePublicKey) -> bytes:

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

    try:
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

# ── X25519 Hybrid Encryption ──────────────────────────────────────────────────

def x25519_hybrid_encrypt(plaintext: bytes, recipient_pub: x25519.X25519PublicKey) -> bytes:

    try:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret = ephemeral_priv.exchange(recipient_pub)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=b"crypto-toolkit-x25519-hybrid-v1",
        ).derive(shared_secret)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        # Raw X25519 public key is always 32 bytes.
        return ephemeral_pub_bytes + nonce + ciphertext
    except Exception as exc:
        raise EncryptionError("X25519 hybrid encryption failed.") from exc


def x25519_hybrid_decrypt(envelope: bytes, private_key: x25519.X25519PrivateKey) -> bytes:

    try:
        pub_len = 32  # Raw X25519 public key is always 32 bytes
        ephemeral_pub_bytes = envelope[:pub_len]
        nonce = envelope[pub_len : pub_len + AES_NONCE_SIZE]
        ciphertext = envelope[pub_len + AES_NONCE_SIZE :]

        ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = private_key.exchange(ephemeral_pub)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=b"crypto-toolkit-x25519-hybrid-v1",
        ).derive(shared_secret)

        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise DecryptionError("X25519 hybrid decryption failed — wrong key or corrupted data.") from exc