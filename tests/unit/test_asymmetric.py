"""Unit tests for asymmetric encryption and key management."""

import pytest

from crypto_toolkit.core import asymmetric
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, KeyGenerationError


class TestRsaKeypair:
    def test_generates_correctly(self) -> None:
        priv, pub = asymmetric.generate_rsa_keypair(key_size=2048)
        assert priv is not None
        assert pub is not None

    def test_key_size_too_small_raises(self) -> None:
        with pytest.raises(KeyGenerationError):
            asymmetric.generate_rsa_keypair(key_size=1024)

    def test_pem_roundtrip_no_password(self) -> None:
        priv, pub = asymmetric.generate_rsa_keypair(key_size=2048)
        priv_pem = asymmetric.private_key_to_pem(priv)
        pub_pem = asymmetric.public_key_to_pem(pub)
        assert b"BEGIN PRIVATE KEY" in priv_pem
        assert b"BEGIN PUBLIC KEY" in pub_pem

        loaded_priv = asymmetric.load_private_key(priv_pem)
        loaded_pub = asymmetric.load_public_key(pub_pem)
        assert loaded_priv is not None
        assert loaded_pub is not None

    def test_pem_roundtrip_with_password(self) -> None:
        priv, _ = asymmetric.generate_rsa_keypair(key_size=2048)
        pem = asymmetric.private_key_to_pem(priv, password=b"s3cret")
        loaded = asymmetric.load_private_key(pem, password=b"s3cret")
        assert loaded is not None

    def test_wrong_password_raises(self) -> None:
        from crypto_toolkit.core.exceptions import InputValidationError

        priv, _ = asymmetric.generate_rsa_keypair(key_size=2048)
        pem = asymmetric.private_key_to_pem(priv, password=b"correct")
        with pytest.raises(InputValidationError):
            asymmetric.load_private_key(pem, password=b"wrong")


class TestRsaEncryptDecrypt:
    @pytest.fixture()
    def keypair(self):
        return asymmetric.generate_rsa_keypair(key_size=2048)

    def test_roundtrip(self, keypair) -> None:
        priv, pub = keypair
        ct = asymmetric.rsa_encrypt(b"hello RSA", pub)
        assert asymmetric.rsa_decrypt(ct, priv) == b"hello RSA"

    def test_oversized_payload_raises(self, keypair) -> None:
        _, pub = keypair
        with pytest.raises(EncryptionError):
            asymmetric.rsa_encrypt(b"X" * 1000, pub)

    def test_wrong_key_raises(self, keypair) -> None:
        priv, pub = keypair
        priv2, _ = asymmetric.generate_rsa_keypair(key_size=2048)
        ct = asymmetric.rsa_encrypt(b"data", pub)
        with pytest.raises(DecryptionError):
            asymmetric.rsa_decrypt(ct, priv2)


class TestEccHybrid:
    @pytest.fixture()
    def keypair(self):
        return asymmetric.generate_ecc_keypair()

    def test_roundtrip_small(self, keypair) -> None:
        priv, pub = keypair
        plaintext = b"ECC hybrid encrypt test"
        envelope = asymmetric.ecc_hybrid_encrypt(plaintext, pub)
        assert asymmetric.ecc_hybrid_decrypt(envelope, priv) == plaintext

    def test_roundtrip_large(self, keypair) -> None:
        priv, pub = keypair
        plaintext = b"Z" * (100 * 1024)  # 100 KiB
        envelope = asymmetric.ecc_hybrid_encrypt(plaintext, pub)
        assert asymmetric.ecc_hybrid_decrypt(envelope, priv) == plaintext

    def test_wrong_private_key_raises(self, keypair) -> None:
        _, pub = keypair
        priv2, _ = asymmetric.generate_ecc_keypair()
        envelope = asymmetric.ecc_hybrid_encrypt(b"secret", pub)
        with pytest.raises(DecryptionError):
            asymmetric.ecc_hybrid_decrypt(envelope, priv2)

    def test_tampered_envelope_raises(self, keypair) -> None:
        priv, pub = keypair
        envelope = bytearray(asymmetric.ecc_hybrid_encrypt(b"data", pub))
        envelope[-1] ^= 0xFF
        with pytest.raises(DecryptionError):
            asymmetric.ecc_hybrid_decrypt(bytes(envelope), priv)

    def test_ephemeral_key_differs_per_call(self, keypair) -> None:
        _, pub = keypair
        e1 = asymmetric.ecc_hybrid_encrypt(b"same", pub)
        e2 = asymmetric.ecc_hybrid_encrypt(b"same", pub)
        assert e1 != e2  # ephemeral key is random
