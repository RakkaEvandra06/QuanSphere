from __future__ import annotations

__all__ = [
    # Ed25519
    "generate_ed25519_keypair",
    "sign_ed25519",
    "verify_ed25519",
    "verify_ed25519_or_raise",
    "ed25519_private_key_to_pem",
    "ed25519_public_key_to_pem",
    "load_ed25519_private_key",
    "load_ed25519_public_key",
    # RSA-PSS
    "sign_rsa_pss",
    "verify_rsa_pss",
    "verify_rsa_pss_or_raise",
]

import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.core.constants import RSA_MIN_KEY_SIZE
from crypto_toolkit.core.exceptions import InputValidationError, KeyGenerationError, SignatureError

_RSA_LEGACY_THRESHOLD: int = 2048

# ── Private helpers ───────────────────────────────────────────────────────────

def _pss_padding() -> padding.PSS:
    """Return a pre-configured RSA-PSS padding instance (MGF1-SHA-256, MAX salt)."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )

# ── Ed25519 key generation ────────────────────────────────────────────────────

def generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair."""
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("Ed25519 key generation failed.") from exc

# ── Ed25519 sign / verify ─────────────────────────────────────────────────────

def sign_ed25519(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign *data* with *private_key* and return the 64-byte Ed25519 signature."""
    try:
        return private_key.sign(data)
    except Exception as exc:
        raise SignatureError("Ed25519 signing failed.") from exc

def verify_ed25519(
    data: bytes,
    signature: bytes,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError) as exc:
        raise SignatureError(
            "Ed25519 verification received malformed input, "
            "the signature bytes or key may be corrupt."
        ) from exc
    except Exception as exc:
        raise SignatureError(
            "Ed25519 verification encountered an unexpected error."
        ) from exc

def verify_ed25519_or_raise(
    data: bytes,
    signature: bytes,
    public_key: ed25519.Ed25519PublicKey,
) -> None:
    if not verify_ed25519(data, signature, public_key):
        raise SignatureError(
            "Ed25519 signature verification failed: the signature is not valid "
            "for the given data and public key."
        )

# ── Ed25519 serialisation ─────────────────────────────────────────────────────

def ed25519_private_key_to_pem(
    key: ed25519.Ed25519PrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialise *key* to PKCS8 PEM, optionally encrypted with *password*."""
    if password is not None and len(password) == 0:
        raise InputValidationError(
            "PEM encryption password must not be empty (received b''). "
            "Pass a non-empty bytes secret to encrypt the PEM, or pass "
            "password=None to produce an unencrypted PEM."
        )

    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

def ed25519_public_key_to_pem(key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialise *key* to SubjectPublicKeyInfo PEM."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_ed25519_private_key(
    pem: bytes,
    password: bytes | None = None,
) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise InputValidationError("PEM does not contain an Ed25519 private key.")
        return key
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load Ed25519 private key, wrong password or corrupt PEM."
        ) from exc

def load_ed25519_public_key(pem: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise InputValidationError("PEM does not contain an Ed25519 public key.")
        return key
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load Ed25519 public key, corrupt PEM."
        ) from exc

# ── RSA-PSS sign / verify ─────────────────────────────────────────────────────

def sign_rsa_pss(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign *data* with *private_key* using RSA-PSS / SHA-256."""
    if private_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA signing key is {private_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    if private_key.key_size <= _RSA_LEGACY_THRESHOLD:
        warnings.warn(
            f"RSA signing key is {private_key.key_size} bits. "
            "NIST SP 800-131A Rev. 2 recommends ≥3072 bits for keys expected "
            "to remain secure beyond 2030. Consider re-generating with a "
            "3072- or 4096-bit key.",
            UserWarning,
            stacklevel=2,
        )
    try:
        return private_key.sign(data, _pss_padding(), hashes.SHA256())
    except Exception as exc:
        raise SignatureError("RSA-PSS signing failed.") from exc

def verify_rsa_pss(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    if public_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA verification key is {public_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    if public_key.key_size <= _RSA_LEGACY_THRESHOLD:
        warnings.warn(
            f"RSA verification key is {public_key.key_size} bits. "
            "NIST SP 800-131A Rev. 2 recommends ≥3072 bits for keys expected "
            "to remain secure beyond 2030. Consider re-generating with a "
            "3072- or 4096-bit key.",
            UserWarning,
            stacklevel=2,
        )
    try:
        public_key.verify(signature, data, _pss_padding(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError) as exc:
        raise SignatureError(
            "RSA-PSS verification received malformed input, "
            "the signature bytes or key may be corrupt."
        ) from exc
    except Exception as exc:
        raise SignatureError(
            "RSA-PSS verification encountered an unexpected error."
        ) from exc

def verify_rsa_pss_or_raise(
    data: bytes,
    signature: bytes,
    public_key: RSAPublicKey,
) -> None:
    if not verify_rsa_pss(data, signature, public_key):
        raise SignatureError(
            "RSA-PSS signature verification failed: the signature is not valid "
            "for the given data and public key."
        )