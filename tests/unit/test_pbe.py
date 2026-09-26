"""Unit tests for password-based encryption."""

import pytest
from crypto_toolkit.core import pbe
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError

_PW:        str = "StrongP4ssword!"     # 15 chars — general purpose
_PW_PBKDF2: str = "mypassword_long!"    # 16 chars — PBKDF2 round-trip test
_PW_ENC:    str = "correct_p4ssword!"   # 17 chars — encryption half of wrong-pw test
_PW_DEC:    str = "wrong_p4ssword!!"    # 16 chars — decryption half (wrong password)
_PW_SAME:   str = "pw_long_password!"   # 16 chars — ciphertext diversity test
_PW_BIG:    str = "bigpassword_long!"   # 17 chars — large-data test
_PW_CORRUPT: str = "pw_corrupt_test!!"  # 17 chars — corrupted-token test

class TestPasswordEncryptDecrypt:
    def test_roundtrip_argon2(self) -> None:
        ct = pbe.password_encrypt(b"secret data", _PW)
        assert pbe.password_decrypt(ct, _PW) == b"secret data"

    def test_roundtrip_pbkdf2(self) -> None:
        ct = pbe.password_encrypt(b"pbkdf2 data", _PW_PBKDF2, use_argon2=False)
        assert pbe.password_decrypt(ct, _PW_PBKDF2) == b"pbkdf2 data"

    def test_wrong_password_raises(self) -> None:
        ct = pbe.password_encrypt(b"data", _PW_ENC)
        with pytest.raises(DecryptionError):
            pbe.password_decrypt(ct, _PW_DEC)

    def test_different_ciphertexts_per_call(self) -> None:
        # Salt is random per call → ciphertexts differ.
        ct1 = pbe.password_encrypt(b"same", _PW_SAME)
        ct2 = pbe.password_encrypt(b"same", _PW_SAME)
        assert ct1 != ct2

    def test_empty_plaintext(self) -> None:
        # password_encrypt rejects empty plaintext (pre-existing behaviour).
        with pytest.raises(Exception):
            pbe.password_encrypt(b"", _PW)

    def test_large_data(self) -> None:
        data = b"Z" * (100 * 1024)
        ct = pbe.password_encrypt(data, _PW_BIG)
        assert pbe.password_decrypt(ct, _PW_BIG) == data

    def test_malformed_token_raises(self) -> None:
        # Decrypt path bypasses PASSWORD_MIN_LENGTH; a non-empty password is enough.
        with pytest.raises(DecryptionError):
            pbe.password_decrypt("notavalidtoken", "pw")

    def test_corrupted_token_raises(self) -> None:
        import base64

        ct = pbe.password_encrypt(b"data", _PW_CORRUPT)
        raw = bytearray(base64.urlsafe_b64decode(ct.encode()))
        raw[-1] ^= 0xFF
        bad = base64.urlsafe_b64encode(bytes(raw)).decode()
        with pytest.raises(DecryptionError):
            pbe.password_decrypt(bad, _PW_CORRUPT)

    def test_short_password_encrypt_raises(self) -> None:
        with pytest.raises(Exception, match="too short|minimum"):
            pbe.password_encrypt(b"data", "short")