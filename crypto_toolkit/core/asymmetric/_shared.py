"""_shared.py — Internal constants and helpers shared across the asymmetric
sub-package (keys.py, rsa_ops.py, ecc_hybrid.py, x25519_hybrid.py).

Nothing in this module is part of the public API; it exists purely so the
five sibling modules don't each redefine the same envelope-layout constants
and small crypto helpers (single source of truth, DRY).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, x25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core.constants import (
    AEAD_MIN_CIPHERTEXT,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    ASYM_ECC_TAG,
    ASYM_MAGIC,
    ASYM_X25519_TAG,
    ENVELOPE_VERSION,
)
from crypto_toolkit.core.exceptions import InputValidationError

# Expected first byte for an uncompressed SEC1 elliptic-curve point (X9.62 §4.3.6).
_UNCOMPRESSED_POINT_PREFIX = 0x04
# P-256 uncompressed point: 1-byte 0x04 prefix + 32-byte X + 32-byte Y = 65 bytes.
_ECC_UNCOMPRESSED_PUB_LEN: int = 65
# X25519 raw public key is always 32 bytes (RFC 7748 §6.1).
_X25519_PUB_LEN: int = 32

# Header layout: ASYM_MAGIC (8 B) + ENVELOPE_VERSION (1 B) + algo_tag (1 B) = 10 bytes.
# Having a fixed-length constant avoids recomputing len() at every call site.
_ASYM_ECC_HEADER: bytes = ASYM_MAGIC + ENVELOPE_VERSION + ASYM_ECC_TAG
_ASYM_X25519_HEADER: bytes = ASYM_MAGIC + ENVELOPE_VERSION + ASYM_X25519_TAG

if len(_ASYM_ECC_HEADER) != len(_ASYM_X25519_HEADER):
    raise RuntimeError(
        f"Invariant violated: ECC header length ({len(_ASYM_ECC_HEADER)}) != "
        f"X25519 header length ({len(_ASYM_X25519_HEADER)}). "
        "Both envelope types must share the same fixed header size for "
        "_ASYM_HEADER_LEN to be valid. Update the constant or use per-scheme "
        "offsets if the tag widths must differ."
    )

_ASYM_HEADER_LEN: int = len(_ASYM_ECC_HEADER)  # 10 — asserted equal for both schemes

# Minimum envelope byte lengths.
_ECC_MIN_ENVELOPE: int = (
    _ASYM_HEADER_LEN + _ECC_UNCOMPRESSED_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)
_X25519_MIN_ENVELOPE: int = (
    _ASYM_HEADER_LEN + _X25519_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)

# HKDF domain separators keep ECC and X25519 key streams cryptographically independent.
_ECC_HKDF_INFO: bytes = b"crypto-toolkit-ecc-hybrid"
_X25519_HKDF_INFO: bytes = b"crypto-toolkit-x25519-hybrid"

# A low-order X25519 point produces an all-zero shared secret — reject it.
_X25519_ZERO_SECRET: bytes = b"\x00" * 32
_ECC_ZERO_SECRET: bytes = b"\x00" * 32

# Supported key types accepted by the load_* helpers (keys.py).
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
_SHA256_DIGEST_SIZE: int = 32
_HYBRID_MAX_PLAINTEXT: int = 64 * 1024 * 1024   # 64 MiB

# ── Shared small helpers ──────────────────────────────────────────────────────

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

__all__ = [
    "_UNCOMPRESSED_POINT_PREFIX",
    "_ECC_UNCOMPRESSED_PUB_LEN",
    "_X25519_PUB_LEN",
    "_ASYM_ECC_HEADER",
    "_ASYM_X25519_HEADER",
    "_ASYM_HEADER_LEN",
    "_ECC_MIN_ENVELOPE",
    "_X25519_MIN_ENVELOPE",
    "_ECC_HKDF_INFO",
    "_X25519_HKDF_INFO",
    "_X25519_ZERO_SECRET",
    "_ECC_ZERO_SECRET",
    "_SUPPORTED_PRIVATE_KEY_TYPES",
    "_SUPPORTED_PUBLIC_KEY_TYPES",
    "_VALID_RSA_KEY_SIZES",
    "_SHA256_DIGEST_SIZE",
    "_HYBRID_MAX_PLAINTEXT",
    "_make_oaep_padding",
    "_hkdf_derive",
    "_assert_secp256r1",
]
