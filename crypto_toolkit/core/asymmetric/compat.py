"""compat.py — Migration utilities for upgrading deprecated envelope formats."""

from __future__ import annotations

__all__ = [
    "migrate_ecc_v1_to_v2",
    "migrate_x25519_v1_to_v2",
]

import warnings

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from crypto_toolkit.core.asymmetric.ecc_hybrid import ecc_hybrid_decrypt, ecc_hybrid_encrypt
from crypto_toolkit.core.asymmetric.x25519_hybrid import (
    x25519_hybrid_decrypt,
    x25519_hybrid_encrypt,
)
from crypto_toolkit.core.constants import ASYM_MAGIC, ENVELOPE_VERSION

def _is_v1_envelope(envelope: bytes) -> bool:
    """Return ``True`` if *envelope* carries a V1 version byte."""
    magic_len = len(ASYM_MAGIC)
    if len(envelope) <= magic_len:
        return False
    return envelope[magic_len : magic_len + 1] == ENVELOPE_VERSION

def migrate_ecc_v1_to_v2(
    envelope: bytes,
    private_key: EllipticCurvePrivateKey,
    public_key: EllipticCurvePublicKey,
) -> bytes:
    """Decrypt a V1 ECC hybrid envelope and re-encrypt it as V2."""

    if not _is_v1_envelope(envelope):
        raise ValueError(
            "migrate_ecc_v1_to_v2: the supplied envelope is not a V1 envelope "
            f"(version byte is not {ENVELOPE_VERSION!r}). "
            "No migration is necessary.  If you intended to re-encrypt an "
            "existing V2 envelope, use ecc_hybrid_decrypt followed by "
            "ecc_hybrid_encrypt directly."
        )

    # Suppress the DeprecationWarning emitted during V1 decryption.
    # The caller knows this is a V1 envelope — that is why they are
    # invoking the migration utility.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        plaintext = ecc_hybrid_decrypt(envelope, private_key)

    return ecc_hybrid_encrypt(plaintext, public_key)

def migrate_x25519_v1_to_v2(
    envelope: bytes,
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
) -> bytes:
    """Decrypt a V1 X25519 hybrid envelope and re-encrypt it as V2."""
    if not _is_v1_envelope(envelope):
        raise ValueError(
            "migrate_x25519_v1_to_v2: the supplied envelope is not a V1 envelope "
            f"(version byte is not {ENVELOPE_VERSION!r}). "
            "No migration is necessary.  If you intended to re-encrypt an "
            "existing V2 envelope, use x25519_hybrid_decrypt followed by "
            "x25519_hybrid_encrypt directly."
        )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        plaintext = x25519_hybrid_decrypt(envelope, private_key)

    return x25519_hybrid_encrypt(plaintext, public_key)