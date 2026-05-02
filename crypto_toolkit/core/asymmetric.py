from __future__ import annotations

__all__ = [
    # Key generation
    "generate_rsa_keypair",
    "generate_ecc_keypair",
    "generate_x25519_keypair",
    # Serialisation
    "private_key_to_pem",
    "public_key_to_pem",
    "load_private_key",
    "load_public_key",
    # RSA encryption
    "rsa_encrypt",
    "rsa_decrypt",
    # ECC hybrid encryption
    "ecc_hybrid_encrypt",
    "ecc_hybrid_decrypt",
    # X25519 hybrid encryption
    "x25519_hybrid_encrypt",
    "x25519_hybrid_decrypt",
]

import hmac
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core.constants import (
    AEAD_MIN_CIPHERTEXT,
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
from crypto_toolkit.core.kdf import zero_bytes

# Expected first byte for an uncompressed SEC1 elliptic-curve point (X9.62 §4.3.6).
_UNCOMPRESSED_POINT_PREFIX = 0x04
# P-256 uncompressed point: 1-byte 0x04 prefix + 32-byte X + 32-byte Y = 65 bytes.
_ECC_UNCOMPRESSED_PUB_LEN: int = 65
# X25519 raw public key is always 32 bytes (RFC 7748 §6.1).
_X25519_PUB_LEN: int = 32

# Minimum envelope byte lengths.
_ECC_MIN_ENVELOPE: int = _ECC_UNCOMPRESSED_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
_X25519_MIN_ENVELOPE: int = _X25519_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT

# HKDF domain separators keep ECC and X25519 key streams cryptographically independent.
_ECC_HKDF_INFO: bytes = b"crypto-toolkit-ecc-hybrid"
_X25519_HKDF_INFO: bytes = b"crypto-toolkit-x25519-hybrid"

# A low-order X25519 point produces an all-zero shared secret — reject it.
_X25519_ZERO_SECRET: bytes = b"\x00" * 32

# Supported key types accepted by the load_* helpers.
_SUPPORTED_PRIVATE_KEY_TYPES: tuple[type, ...] = (
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
)
_SUPPORTED_PUBLIC_KEY_TYPES: tuple[type, ...] = (
    RSAPublicKey,
    EllipticCurvePublicKey,
    x25519.X25519PublicKey,
)

_VALID_RSA_KEY_SIZES: frozenset[int] = frozenset({2048, 3072, 4096})
_MIN_RSA_KEY_SIZE: int = 2048

# ── Private helpers ───────────────────────────────────────────────────────────

def _make_oaep_padding() -> padding.OAEP:
    """Return a pre-configured OAEP padding instance (SHA-256, MGF1-SHA-256)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

def _hkdf_derive(shared_secret: bytes, *, salt: bytes, info: bytes) -> bytes:
    """Derive an AES-256 key from *shared_secret* using HKDF-SHA-256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(shared_secret)

def _assert_secp256r1(
    key: EllipticCurvePublicKey | EllipticCurvePrivateKey,
    operation: str,
) -> None:
    """Raise InputValidationError if *key* does not use SECP256R1."""
    if not isinstance(key.curve, ec.SECP256R1):
        raise InputValidationError(
            f"ECC {operation} requires a SECP256R1 key; "
            f"received {type(key.curve).__name__}."
        )

# ── Key generation ────────────────────────────────────────────────────────────

def generate_rsa_keypair(
    key_size: int = RSA_KEY_SIZE,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair of *key_size* bits (2048, 3072, or 4096)."""
    if key_size not in _VALID_RSA_KEY_SIZES:
        raise KeyGenerationError(
            f"RSA key size must be one of {sorted(_VALID_RSA_KEY_SIZES)} bits; "
            f"received {key_size}. "
            "Non-standard sizes are not supported, they produce keys that most "
            "PKI infrastructure will reject."
        )
    try:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=key_size,
        )
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("RSA key generation failed.") from exc

def generate_ecc_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECC key pair on the SECP256R1 (P-256) curve."""
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("ECC key generation failed.") from exc

def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate an X25519 key pair."""
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
    """Serialise *key* to PKCS8 PEM, optionally encrypted with *password*."""
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
    """Serialise *key* to SubjectPublicKeyInfo PEM."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_private_key(
    pem: bytes,
    password: bytes | None = None,
) -> RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey:
    """Load an RSA, ECC (SECP256R1), or X25519 private key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except Exception as exc:
        raise InputValidationError(
            "Failed to load private key, wrong password or corrupt PEM."
        ) from exc

    if not isinstance(key, _SUPPORTED_PRIVATE_KEY_TYPES):
        raise InputValidationError(
            f"PEM contains an unsupported private key type: {type(key).__name__}. "
            "Expected one of: RSA, ECC (SECP256R1), or X25519."
        )

    if isinstance(key, RSAPrivateKey) and key.key_size < _MIN_RSA_KEY_SIZE:
        raise InputValidationError(
            f"Loaded RSA private key is only {key.key_size} bits; "
            f"a minimum of {_MIN_RSA_KEY_SIZE} bits is required by this toolkit. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )

    if isinstance(key, EllipticCurvePrivateKey) and not isinstance(key.curve, ec.SECP256R1):
        raise InputValidationError(
            f"Loaded ECC private key uses curve {type(key.curve).__name__!r}; "
            "only SECP256R1 (P-256) is supported by this toolkit."
        )

    return key  # type: ignore[return-value]

def load_public_key(
    pem: bytes,
) -> RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey:
    """Load an RSA, ECC (SECP256R1), or X25519 public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        raise InputValidationError(
            "Failed to load public key, corrupt PEM."
        ) from exc

    if not isinstance(key, _SUPPORTED_PUBLIC_KEY_TYPES):
        raise InputValidationError(
            f"PEM contains an unsupported public key type: {type(key).__name__}. "
            "Expected one of: RSA, ECC (SECP256R1), or X25519."
        )

    if isinstance(key, RSAPublicKey) and key.key_size < _MIN_RSA_KEY_SIZE:
        raise InputValidationError(
            f"Loaded RSA public key is only {key.key_size} bits; "
            f"a minimum of {_MIN_RSA_KEY_SIZE} bits is required by this toolkit. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )

    if isinstance(key, EllipticCurvePublicKey) and not isinstance(key.curve, ec.SECP256R1):
        raise InputValidationError(
            f"Loaded ECC public key uses curve {type(key.curve).__name__!r}; "
            "only SECP256R1 (P-256) is supported by this toolkit."
        )

    return key  # type: ignore[return-value]

# ── RSA encryption / decryption ───────────────────────────────────────────────

def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt *plaintext* with *public_key* using RSA-OAEP / SHA-256."""
    try:
        return public_key.encrypt(plaintext, _make_oaep_padding())
    except ValueError as exc:
        raise EncryptionError(
            f"RSA encryption failed, payload may be too large: {exc}"
        ) from exc
    except Exception as exc:
        raise EncryptionError("RSA encryption failed.") from exc

def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt *ciphertext* with *private_key* using RSA-OAEP / SHA-256."""
    expected_len: int = (private_key.key_size + 7) // 8
    if len(ciphertext) != expected_len:
        raise DecryptionError(
            f"RSA ciphertext must be exactly {expected_len} bytes for a "
            f"{private_key.key_size}-bit key; received {len(ciphertext)} bytes. "
            "The ciphertext may be truncated, corrupted, or intended for a "
            "different key."
        )
    try:
        return private_key.decrypt(ciphertext, _make_oaep_padding())
    except Exception as exc:
        raise DecryptionError(
            "RSA decryption failed, wrong key or corrupted data."
        ) from exc

# ── ECC hybrid encryption ─────────────────────────────────────────────────────

def ecc_hybrid_encrypt(plaintext: bytes, recipient_pub: EllipticCurvePublicKey) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral ECDH + AES-GCM."""
    _assert_secp256r1(recipient_pub, "hybrid encryption")

    shared_secret: bytes | None = None
    aes_key: bytes | None = None
    try:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret = ephemeral_priv.exchange(ECDH(), recipient_pub)

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        recipient_pub_bytes = recipient_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

        aes_key = _hkdf_derive(
            shared_secret,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, ephemeral_pub_bytes)

        return ephemeral_pub_bytes + nonce + ciphertext
    except InputValidationError:
        raise
    except Exception as exc:
        raise EncryptionError("ECC hybrid encryption failed.") from exc
    finally:
        if shared_secret is not None:
            zero_bytes(shared_secret)
        if aes_key is not None:
            zero_bytes(aes_key)

def ecc_hybrid_decrypt(envelope: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Decrypt an envelope produced by :func:`ecc_hybrid_encrypt`."""
    _assert_secp256r1(private_key, "hybrid decryption")

    if len(envelope) < _ECC_MIN_ENVELOPE:
        raise DecryptionError(
            f"ECC envelope is too short ({len(envelope)} bytes); "
            f"minimum expected is {_ECC_MIN_ENVELOPE} bytes."
        )

    ephemeral_pub_bytes = envelope[:_ECC_UNCOMPRESSED_PUB_LEN]
    if ephemeral_pub_bytes[0] != _UNCOMPRESSED_POINT_PREFIX:
        raise DecryptionError(
            f"ECC envelope contains an invalid ephemeral public key "
            f"expected uncompressed point marker 0x04, "
            f"got 0x{ephemeral_pub_bytes[0]:02x}. "
            "The envelope may be corrupt or use an unsupported point encoding."
        )

    shared_secret: bytes | None = None
    aes_key: bytes | None = None
    try:
        nonce = envelope[_ECC_UNCOMPRESSED_PUB_LEN : _ECC_UNCOMPRESSED_PUB_LEN + AES_NONCE_SIZE]
        ciphertext = envelope[_ECC_UNCOMPRESSED_PUB_LEN + AES_NONCE_SIZE :]

        ephemeral_pub = EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_bytes
        )
        shared_secret = private_key.exchange(ECDH(), ephemeral_pub)

        recipient_pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        aes_key = _hkdf_derive(
            shared_secret,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )

        # AAD must match what ecc_hybrid_encrypt used — ephemeral_pub_bytes.
        return AESGCM(aes_key).decrypt(nonce, ciphertext, ephemeral_pub_bytes)
    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(
            "ECC hybrid decryption failed, wrong key or corrupted data."
        ) from exc
    finally:
        if shared_secret is not None:
            zero_bytes(shared_secret)
        if aes_key is not None:
            zero_bytes(aes_key)

# ── X25519 hybrid encryption ──────────────────────────────────────────────────

def x25519_hybrid_encrypt(
    plaintext: bytes,
    recipient_pub: x25519.X25519PublicKey,
) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral X25519 + AES-GCM."""
    shared_secret: bytes | None = None
    aes_key: bytes | None = None
    try:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret = ephemeral_priv.exchange(recipient_pub)

        if hmac.compare_digest(shared_secret, _X25519_ZERO_SECRET):
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

        aes_key = _hkdf_derive(
            shared_secret,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        # Bind the ciphertext to this envelope by passing the ephemeral public
        # key as AEAD AAD, mirroring the ECC hybrid pattern.
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, ephemeral_pub_bytes)

        return ephemeral_pub_bytes + nonce + ciphertext
    except (EncryptionError, InputValidationError):
        raise
    except Exception as exc:
        raise EncryptionError("X25519 hybrid encryption failed.") from exc
    finally:
        if shared_secret is not None:
            zero_bytes(shared_secret)
        if aes_key is not None:
            zero_bytes(aes_key)

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

    shared_secret: bytes | None = None
    aes_key: bytes | None = None
    try:
        ephemeral_pub_bytes = envelope[:_X25519_PUB_LEN]
        nonce = envelope[_X25519_PUB_LEN : _X25519_PUB_LEN + AES_NONCE_SIZE]
        ciphertext = envelope[_X25519_PUB_LEN + AES_NONCE_SIZE :]

        ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = private_key.exchange(ephemeral_pub)

        if hmac.compare_digest(shared_secret, _X25519_ZERO_SECRET):
            raise DecryptionError(
                "X25519 key exchange produced a zero shared secret "
                "the ephemeral public key is a low-order point and the "
                "envelope must be rejected."
            )

        recipient_pub_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        aes_key = _hkdf_derive(
            shared_secret,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )

        # AAD must match what x25519_hybrid_encrypt used — ephemeral_pub_bytes.
        return AESGCM(aes_key).decrypt(nonce, ciphertext, ephemeral_pub_bytes)
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError(
            "X25519 hybrid decryption failed, wrong key or corrupted data."
        ) from exc
    finally:
        if shared_secret is not None:
            zero_bytes(shared_secret)
        if aes_key is not None:
            zero_bytes(aes_key)