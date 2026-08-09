"""crypto_toolkit.core.asymmetric — RSA-4096, ECC P-256, and X25519 key
generation, RSA-OAEP encryption, and ECC/X25519 hybrid encryption.

This is a *package* instead of a single module purely to keep each file
under ~600 lines for easier indexing/editing by AI coding agents and humans
alike (see /REFACTORING.md at the repo root for the full rationale). The
public API below is byte-for-byte identical to the pre-refactor single-file
`asymmetric.py` — every name that used to be importable from
`crypto_toolkit.core.asymmetric` still is, from the same dotted path.

    from crypto_toolkit.core import asymmetric
    asymmetric.generate_rsa_keypair()       # -> keys.py
    asymmetric.rsa_encrypt(...)             # -> rsa_ops.py
    asymmetric.ecc_hybrid_encrypt(...)      # -> ecc_hybrid.py
    asymmetric.x25519_hybrid_decrypt(...)   # -> x25519_hybrid.py

Module map (each file's single responsibility):
    _shared.py        shared envelope constants + small crypto helpers
    keys.py            keygen, PEM serialisation, PEM loading
    rsa_ops.py          direct RSA-OAEP encrypt/decrypt
    ecc_hybrid.py        ECC (P-256) ephemeral-ECDH hybrid envelope
    x25519_hybrid.py     X25519 ephemeral-DH hybrid envelope
"""

from __future__ import annotations

from crypto_toolkit.core.asymmetric.ecc_hybrid import ecc_hybrid_decrypt, ecc_hybrid_encrypt
from crypto_toolkit.core.asymmetric.keys import (
    generate_ecc_keypair,
    generate_rsa_keypair,
    generate_x25519_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
)
from crypto_toolkit.core.asymmetric.rsa_ops import rsa_decrypt, rsa_encrypt
from crypto_toolkit.core.asymmetric.x25519_hybrid import (
    x25519_hybrid_decrypt,
    x25519_hybrid_encrypt,
)

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
