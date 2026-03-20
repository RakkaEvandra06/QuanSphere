"""Digital signature operations.

Supported schemes
-----------------
* **Ed25519** — fast, modern, constant-time EdDSA (recommended for new systems).
* **RSA-PSS** with SHA-256 — for interoperability with RSA infrastructure.

Signatures are returned as raw bytes.  The caller is responsible for encoding
(e.g. base64) before storage or transmission.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.core.exceptions import KeyGenerationError, SignatureError


# ── Ed25519 ───────────────────────────────────────────────────────────────────


def generate_ed25519_keypair() -> (
    tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]
):
    """Generate an Ed25519 signing key-pair.

    Returns:
        ``(private_key, public_key)`` tuple.

    Raises:
        KeyGenerationError: On unexpected failure.
    """
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("Ed25519 key generation failed.") from exc


def sign_ed25519(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign *data* with an Ed25519 private key.

    Args:
        data: Arbitrary data to sign.
        private_key: Ed25519 signing key.

    Returns:
        64-byte raw signature.

    Raises:
        SignatureError: On signing failure.
    """
    try:
        return private_key.sign(data)
    except Exception as exc:
        raise SignatureError("Ed25519 signing failed.") from exc


def verify_ed25519(
    data: bytes,
    signature: bytes,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify an Ed25519 *signature* over *data*.

    Args:
        data: Original data that was signed.
        signature: 64-byte signature from :func:`sign_ed25519`.
        public_key: Corresponding Ed25519 public key.

    Returns:
        ``True`` if the signature is valid; ``False`` otherwise.
    """
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        raise SignatureError("Ed25519 verification encountered an unexpected error.") from exc


# ── Ed25519 key serialisation ─────────────────────────────────────────────────


def ed25519_private_key_to_pem(
    key: ed25519.Ed25519PrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialise an Ed25519 private key to PEM (PKCS8)."""
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


def ed25519_public_key_to_pem(key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialise an Ed25519 public key to PEM (SubjectPublicKeyInfo)."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_ed25519_private_key(
    pem: bytes,
    password: bytes | None = None,
) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes."""
    from crypto_toolkit.core.exceptions import InputValidationError

    try:
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise InputValidationError("PEM does not contain an Ed25519 private key.")
        return key
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load Ed25519 private key — wrong password or corrupt PEM."
        ) from exc


def load_ed25519_public_key(pem: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes."""
    from crypto_toolkit.core.exceptions import InputValidationError

    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise InputValidationError("PEM does not contain an Ed25519 public key.")
        return key
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError("Failed to load Ed25519 public key — corrupt PEM.") from exc


# ── RSA-PSS signatures ────────────────────────────────────────────────────────


def sign_rsa_pss(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign *data* with RSA-PSS (SHA-256).

    Args:
        data: Data to sign.
        private_key: RSA private key (≥ 2048 bits).

    Returns:
        Raw signature bytes.

    Raises:
        SignatureError: On failure.
    """
    try:
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise SignatureError("RSA-PSS signing failed.") from exc


def verify_rsa_pss(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Verify an RSA-PSS *signature* over *data*.

    Args:
        data: Original signed data.
        signature: Signature bytes from :func:`sign_rsa_pss`.
        public_key: RSA public key.

    Returns:
        ``True`` if valid; ``False`` on invalid signature.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        raise SignatureError("RSA-PSS verification encountered an unexpected error.") from exc
