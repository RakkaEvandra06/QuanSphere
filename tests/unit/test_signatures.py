"""Unit tests for digital signature operations."""

import pytest

from crypto_toolkit.core import signatures
from crypto_toolkit.core.exceptions import InputValidationError, KeyGenerationError


class TestEd25519:
    @pytest.fixture()
    def keypair(self):
        return signatures.generate_ed25519_keypair()

    def test_sign_and_verify(self, keypair) -> None:
        priv, pub = keypair
        data = b"message to sign"
        sig = signatures.sign_ed25519(data, priv)
        assert signatures.verify_ed25519(data, sig, pub) is True

    def test_invalid_signature_returns_false(self, keypair) -> None:
        priv, pub = keypair
        data = b"original"
        sig = signatures.sign_ed25519(data, priv)
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert signatures.verify_ed25519(data, bytes(bad_sig), pub) is False

    def test_modified_data_fails_verification(self, keypair) -> None:
        priv, pub = keypair
        sig = signatures.sign_ed25519(b"original", priv)
        assert signatures.verify_ed25519(b"tampered", sig, pub) is False

    def test_wrong_public_key_returns_false(self, keypair) -> None:
        priv, _ = keypair
        _, pub2 = signatures.generate_ed25519_keypair()
        sig = signatures.sign_ed25519(b"data", priv)
        assert signatures.verify_ed25519(b"data", sig, pub2) is False

    def test_signature_is_64_bytes(self, keypair) -> None:
        priv, _ = keypair
        sig = signatures.sign_ed25519(b"test", priv)
        assert len(sig) == 64

    def test_deterministic_for_ed25519(self, keypair) -> None:
        # Ed25519 is deterministic — same key + data → same signature.
        priv, _ = keypair
        data = b"deterministic"
        assert signatures.sign_ed25519(data, priv) == signatures.sign_ed25519(data, priv)

    def test_pem_roundtrip_no_password(self, keypair) -> None:
        priv, pub = keypair
        priv_pem = signatures.ed25519_private_key_to_pem(priv)
        pub_pem = signatures.ed25519_public_key_to_pem(pub)

        loaded_priv = signatures.load_ed25519_private_key(priv_pem)
        loaded_pub = signatures.load_ed25519_public_key(pub_pem)

        data = b"pem roundtrip"
        sig = signatures.sign_ed25519(data, loaded_priv)
        assert signatures.verify_ed25519(data, sig, loaded_pub)

    def test_pem_roundtrip_with_password(self, keypair) -> None:
        priv, _ = keypair
        pem = signatures.ed25519_private_key_to_pem(priv, password=b"passphrase")
        loaded = signatures.load_ed25519_private_key(pem, password=b"passphrase")
        assert loaded is not None

    def test_wrong_password_raises(self, keypair) -> None:
        priv, _ = keypair
        pem = signatures.ed25519_private_key_to_pem(priv, password=b"correct")
        with pytest.raises(InputValidationError):
            signatures.load_ed25519_private_key(pem, password=b"wrong")

    def test_wrong_pem_type_raises(self) -> None:
        from crypto_toolkit.core import asymmetric

        priv_rsa, _ = asymmetric.generate_rsa_keypair(key_size=2048)
        rsa_pem = asymmetric.private_key_to_pem(priv_rsa)
        with pytest.raises(InputValidationError):
            signatures.load_ed25519_private_key(rsa_pem)


class TestRsaPss:
    @pytest.fixture()
    def keypair(self):
        from crypto_toolkit.core import asymmetric
        return asymmetric.generate_rsa_keypair(key_size=2048)

    def test_sign_and_verify(self, keypair) -> None:
        priv, pub = keypair
        data = b"rsa-pss message"
        sig = signatures.sign_rsa_pss(data, priv)
        assert signatures.verify_rsa_pss(data, sig, pub) is True

    def test_tampered_signature_returns_false(self, keypair) -> None:
        priv, pub = keypair
        sig = signatures.sign_rsa_pss(b"data", priv)
        bad = bytearray(sig)
        bad[-1] ^= 0xFF
        assert signatures.verify_rsa_pss(b"data", bytes(bad), pub) is False

    def test_tampered_data_fails(self, keypair) -> None:
        priv, pub = keypair
        sig = signatures.sign_rsa_pss(b"original", priv)
        assert signatures.verify_rsa_pss(b"modified", sig, pub) is False
