"""keys.py — RSA / ECC / X25519 key generation, PEM serialisation, and PEM
loading.

Single responsibility: turning key *material* into objects and back into
bytes. No encryption/decryption logic lives here — see rsa_ops.py,
ecc_hybrid.py, and x25519_hybrid.py for that.
"""

from __future__ import annotations

__all__ = [
    "generate_rsa_keypair",
    "generate_ecc_keypair",
    "generate_x25519_keypair",
    "private_key_to_pem",
    "public_key_to_pem",
    "load_private_key",
    "load_public_key",
]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.core.asymmetric._shared import (
    _SUPPORTED_PRIVATE_KEY_TYPES,
    _SUPPORTED_PUBLIC_KEY_TYPES,
    _VALID_RSA_KEY_SIZES,
)
from crypto_toolkit.core.constants import RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT
from crypto_toolkit.core.exceptions import InputValidationError, KeyGenerationError

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

# ── Serialisation ─────────────────────────────────────────────────────────────

def private_key_to_pem(
    key: RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey,
    password: bytes | None = None,
    *,
    argon2_protect: bool = False,
) -> bytes:
    """Serialise *key* to PKCS8 PEM, optionally protected with *password*."""
    if password is not None and len(password) == 0:
        raise InputValidationError(
            "PEM encryption password must not be empty (received b''). "
            "Pass a non-empty bytes secret to encrypt the PEM, or pass "
            "password=None to produce an unencrypted PEM."
        )

    if password is not None and argon2_protect:
        # Lazy import: avoids a circular dependency at module-load time.
        # Dependency chain: pbe → kdf → constants.  keys.py → asymmetric._shared,
        # constants.  No cycle when the import occurs inside the function body.
        from crypto_toolkit.core.pbe import password_encrypt  # noqa: PLC0415

        try:
            password_str = password.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputValidationError(
                "argon2_protect=True requires a UTF-8-compatible password. "
                "The provided password bytes cannot be decoded as UTF-8. "
                "Pass argon2_protect=False to use the standard PKCS#8 "
                "BestAvailableEncryption scheme, which accepts arbitrary "
                "byte passwords."
            ) from exc

        # Serialise to unencrypted PKCS8 so the PBE envelope provides all
        # key protection.  The raw PEM is discarded immediately after wrapping.
        raw_pem: bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            token: str = password_encrypt(raw_pem, password_str)
        finally:
            # best-effort: raw_pem is an immutable bytes object so ctypes
            # zeroing is attempted but not guaranteed — see zero_bytes_buffer.
            from crypto_toolkit.core.kdf import zero_bytes_buffer  # noqa: PLC0415
            zero_bytes_buffer(raw_pem)

        # Return as ASCII bytes; load_private_key detects the non-PEM prefix.
        return token.encode("ascii")

    # ── Legacy / backward-compatible path: library-default PKCS#8 encryption ─
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
    """Load a private key from PEM bytes or an Argon2-protected envelope."""
    pem_stripped = pem.strip()

    if not pem_stripped.startswith(b"-----"):
        # The data does not begin with the standard PEM marker.  Assume it is
        # an Argon2id+AES-GCM envelope produced by private_key_to_pem with
        # argon2_protect=True.  Reject DER-encoded inputs with a clear message.
        if password is None:
            raise InputValidationError(
                "The supplied data does not begin with '-----BEGIN' and appears "
                "to be an Argon2-protected private key produced by "
                "private_key_to_pem(..., argon2_protect=True). "
                "Provide the same password used during serialisation. "
                "If the key is DER-encoded, convert it to PEM format before "
                "passing it to this function."
            )

        from crypto_toolkit.core.pbe import password_decrypt  # noqa: PLC0415

        try:
            password_str = password.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputValidationError(
                "Failed to decode the password as UTF-8. Argon2-protected "
                "private keys require a UTF-8-compatible password."
            ) from exc

        try:
            envelope_str = pem_stripped.decode("ascii")
        except UnicodeDecodeError as exc:
            raise InputValidationError(
                "Failed to decode the key data as ASCII. The data may be "
                "corrupt or is not a valid Argon2-wrapped PEM key."
            ) from exc

        try:
            decrypted_pem: bytes = password_decrypt(envelope_str, password_str)
        except Exception as exc:
            raise InputValidationError(
                "Failed to decrypt the Argon2-protected private key. "
                "The password may be incorrect or the envelope may be corrupt."
            ) from exc

        # The unwrapped inner PEM is unencrypted PKCS8 — do not forward the
        # password to load_pem_private_key.
        pem = decrypted_pem
        password = None

    # ── Standard PEM loading ──────────────────────────────────────────────────
    try:
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, _SUPPORTED_PRIVATE_KEY_TYPES):
            raise InputValidationError(
                f"Unsupported private key type: {type(key).__name__}. "
                f"Supported types: RSA, ECC (P-256), X25519."
            )
        return key  # type: ignore[return-value]
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load private key, wrong password or corrupt PEM."
        ) from exc

def load_public_key(
    pem: bytes,
) -> RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey:
    """Load a public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, _SUPPORTED_PUBLIC_KEY_TYPES):
            raise InputValidationError(
                f"Unsupported public key type: {type(key).__name__}. "
                f"Supported types: RSA, ECC (P-256), X25519."
            )
        return key  # type: ignore[return-value]
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load public key, corrupt PEM."
        ) from exc