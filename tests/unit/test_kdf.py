"""Unit tests for key derivation functions."""

import pytest

from crypto_toolkit.core import kdf
from crypto_toolkit.core.exceptions import InputValidationError, KeyDerivationError


class TestArgon2:
    def test_derives_key(self) -> None:
        result = kdf.derive_key_argon2("password123")
        assert len(result.key) == 32
        assert len(result.salt) == 16

    def test_same_password_same_salt_deterministic(self) -> None:
        r1 = kdf.derive_key_argon2("password", salt=b"\x00" * 16)
        r2 = kdf.derive_key_argon2("password", salt=b"\x00" * 16)
        assert r1.key == r2.key

    def test_different_salts_different_keys(self) -> None:
        r1 = kdf.derive_key_argon2("password", salt=b"\x00" * 16)
        r2 = kdf.derive_key_argon2("password", salt=b"\x01" * 16)
        assert r1.key != r2.key

    def test_different_passwords_different_keys(self) -> None:
        r1 = kdf.derive_key_argon2("password1")
        r2 = kdf.derive_key_argon2("password2")
        assert r1.key != r2.key

    def test_salt_generated_randomly(self) -> None:
        r1 = kdf.derive_key_argon2("password")
        r2 = kdf.derive_key_argon2("password")
        assert r1.salt != r2.salt  # statistically certain

    def test_low_time_cost_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2("pw", time_cost=0)

    def test_low_memory_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2("pw", memory_cost=1024)

    def test_short_hash_len_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2("pw", hash_len=8)

    def test_bytes_password(self) -> None:
        r = kdf.derive_key_argon2(b"bytes_password")
        assert len(r.key) == 32


class TestPbkdf2:
    def test_derives_key(self) -> None:
        result = kdf.derive_key_pbkdf2("password123")
        assert len(result.key) == 32
        assert len(result.salt) == 16

    def test_deterministic_with_fixed_salt(self) -> None:
        salt = b"\xAB" * 16
        r1 = kdf.derive_key_pbkdf2("pw", salt=salt)
        r2 = kdf.derive_key_pbkdf2("pw", salt=salt)
        assert r1.key == r2.key

    def test_different_passwords_differ(self) -> None:
        r1 = kdf.derive_key_pbkdf2("pw1")
        r2 = kdf.derive_key_pbkdf2("pw2")
        assert r1.key != r2.key

    def test_low_iterations_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_pbkdf2("pw", iterations=1000)

    def test_bytes_password(self) -> None:
        r = kdf.derive_key_pbkdf2(b"bytes_pw")
        assert len(r.key) == 32
