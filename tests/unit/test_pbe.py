"""Unit tests for password-based encryption."""

import pytest

from crypto_toolkit.core import pbe
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError


class TestPasswordEncryptDecrypt:
    def test_roundtrip_argon2(self) -> None:
        ct = pbe.password_encrypt(b"secret data", "strongpassword")
        assert pbe.password_decrypt(ct, "strongpassword") == b"secret data"

    def test_roundtrip_pbkdf2(self) -> None:
        ct = pbe.password_encrypt(b"pbkdf2 data", "mypassword", use_argon2=False)
        assert pbe.password_decrypt(ct, "mypassword") == b"pbkdf2 data"

    def test_wrong_password_raises(self) -> None:
        ct = pbe.password_encrypt(b"data", "correct")
        with pytest.raises(DecryptionError):
            pbe.password_decrypt(ct, "wrong")

    def test_different_ciphertexts_per_call(self) -> None:
        # Salt is random per call → ciphertexts differ.
        ct1 = pbe.password_encrypt(b"same", "pw")
        ct2 = pbe.password_encrypt(b"same", "pw")
        assert ct1 != ct2

    def test_empty_plaintext(self) -> None:
        ct = pbe.password_encrypt(b"", "password")
        assert pbe.password_decrypt(ct, "password") == b""

    def test_large_data(self) -> None:
        data = b"Z" * (100 * 1024)
        ct = pbe.password_encrypt(data, "bigpassword")
        assert pbe.password_decrypt(ct, "bigpassword") == data

    def test_malformed_token_raises(self) -> None:
        with pytest.raises(DecryptionError):
            pbe.password_decrypt("notavalidtoken", "pw")

    def test_corrupted_token_raises(self) -> None:
        import base64

        ct = pbe.password_encrypt(b"data", "pw")
        raw = bytearray(base64.urlsafe_b64decode(ct.encode()))
        raw[-1] ^= 0xFF
        bad = base64.urlsafe_b64encode(bytes(raw)).decode()
        with pytest.raises(DecryptionError):
            pbe.password_decrypt(bad, "pw")
