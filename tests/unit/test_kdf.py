"""Unit tests for key derivation functions."""

import pytest
from crypto_toolkit.core import kdf
from crypto_toolkit.core.exceptions import InputValidationError, KeyDerivationError

_PW: str        = "StrongP4ssword!"      # 15 chars — used where any valid password works
_PW_A: str      = "StrongP4ssword_A"     # 16 chars — used for "password A" comparisons
_PW_B: str      = "StrongP4ssword_B"     # 16 chars — used for "password B" comparisons
_PW_BYTES: bytes = b"bytes_password_ok"  # 18 bytes — bytes-input variant

class TestArgon2:
    def test_derives_key(self) -> None:
        result = kdf.derive_key_argon2(_PW)
        assert len(result.key) == 32
        assert len(result.salt) == 16

    def test_same_password_same_salt_deterministic(self) -> None:
        r1 = kdf.derive_key_argon2(_PW, salt=b"\x00" * 16)
        r2 = kdf.derive_key_argon2(_PW, salt=b"\x00" * 16)
        assert r1.key == r2.key

    def test_different_salts_different_keys(self) -> None:
        r1 = kdf.derive_key_argon2(_PW, salt=b"\x00" * 16)
        r2 = kdf.derive_key_argon2(_PW, salt=b"\x01" * 16)
        assert r1.key != r2.key

    def test_different_passwords_different_keys(self) -> None:
        r1 = kdf.derive_key_argon2(_PW_A)
        r2 = kdf.derive_key_argon2(_PW_B)
        assert r1.key != r2.key

    def test_salt_generated_randomly(self) -> None:
        r1 = kdf.derive_key_argon2(_PW)
        r2 = kdf.derive_key_argon2(_PW)
        assert r1.salt != r2.salt  # statistically certain

    def test_short_password_raises(self) -> None:
        with pytest.raises(InputValidationError, match="too short"):
            kdf.derive_key_argon2("short")

    def test_min_password_len_bypass_allows_short_secret(self) -> None:
        """High-entropy programmatic secrets may bypass the length policy."""
        import secrets
        short_secret = secrets.token_bytes(8)   # 8 bytes < 12 but high entropy
        result = kdf.derive_key_argon2(short_secret, min_password_len=0)
        assert len(result.key) == 32

    def test_low_time_cost_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2(_PW, time_cost=0)

    def test_low_memory_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2(_PW, memory_cost=1024)

    def test_short_hash_len_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_argon2(_PW, hash_len=8)

    def test_bytes_password(self) -> None:
        r = kdf.derive_key_argon2(_PW_BYTES)
        assert len(r.key) == 32

class TestPbkdf2:
    def test_derives_key(self) -> None:
        result = kdf.derive_key_pbkdf2(_PW)
        assert len(result.key) == 32
        assert len(result.salt) == 16

    def test_deterministic_with_fixed_salt(self) -> None:
        salt = b"\xAB" * 16
        r1 = kdf.derive_key_pbkdf2(_PW, salt=salt)
        r2 = kdf.derive_key_pbkdf2(_PW, salt=salt)
        assert r1.key == r2.key

    def test_different_passwords_differ(self) -> None:
        r1 = kdf.derive_key_pbkdf2(_PW_A)
        r2 = kdf.derive_key_pbkdf2(_PW_B)
        assert r1.key != r2.key

    def test_short_password_raises(self) -> None:
        with pytest.raises(InputValidationError, match="too short"):
            kdf.derive_key_pbkdf2("short")

    def test_min_password_len_bypass_allows_short_secret(self) -> None:
        """High-entropy programmatic secrets may bypass the length policy."""
        import secrets
        short_secret = secrets.token_bytes(8)
        result = kdf.derive_key_pbkdf2(short_secret, min_password_len=0)
        assert len(result.key) == 32

    def test_low_iterations_raises(self) -> None:
        with pytest.raises(InputValidationError):
            kdf.derive_key_pbkdf2(_PW, iterations=1000)

    def test_bytes_password(self) -> None:
        r = kdf.derive_key_pbkdf2(_PW_BYTES)
        assert len(r.key) == 32