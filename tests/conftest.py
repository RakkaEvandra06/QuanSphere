"""Shared pytest fixtures and configuration."""

import pytest

from crypto_toolkit.core.constants import AES_KEY_SIZE
from crypto_toolkit.core.random_gen import generate_key


@pytest.fixture(scope="session")
def aes_key_32() -> bytes:
    """A session-scoped 32-byte AES key for read-only tests."""
    return generate_key(AES_KEY_SIZE)


@pytest.fixture(scope="session")
def ed25519_keypair():
    """Session-scoped Ed25519 keypair for read-only tests."""
    from crypto_toolkit.core.signatures import generate_ed25519_keypair
    return generate_ed25519_keypair()


@pytest.fixture(scope="session")
def rsa_keypair_2048():
    """Session-scoped RSA-2048 keypair (faster than 4096 for tests)."""
    from crypto_toolkit.core.asymmetric import generate_rsa_keypair
    return generate_rsa_keypair(key_size=2048)


@pytest.fixture(scope="session")
def ecc_keypair():
    """Session-scoped ECC keypair."""
    from crypto_toolkit.core.asymmetric import generate_ecc_keypair
    return generate_ecc_keypair()
