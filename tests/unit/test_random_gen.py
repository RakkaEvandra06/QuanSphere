"""Unit tests for secure random generation utilities."""

import re

import pytest

from crypto_toolkit.core import random_gen
from crypto_toolkit.core.exceptions import InputValidationError


class TestGenerateKey:
    def test_default_size(self) -> None:
        key = random_gen.generate_key()
        assert len(key) == 32

    def test_custom_size(self) -> None:
        key = random_gen.generate_key(16)
        assert len(key) == 16

    def test_returns_bytes(self) -> None:
        assert isinstance(random_gen.generate_key(), bytes)

    def test_zero_size_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_key(0)

    def test_negative_size_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_key(-1)

    def test_keys_are_unique(self) -> None:
        keys = {random_gen.generate_key() for _ in range(100)}
        assert len(keys) == 100  # no collisions expected


class TestGenerateToken:
    def test_returns_string(self) -> None:
        assert isinstance(random_gen.generate_token(), str)

    def test_url_safe_characters(self) -> None:
        token = random_gen.generate_token()
        assert re.match(r"^[A-Za-z0-9_-]+$", token)

    def test_tokens_are_unique(self) -> None:
        tokens = {random_gen.generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_zero_bytes_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_token(0)


class TestGenerateHex:
    def test_correct_length(self) -> None:
        hex_str = random_gen.generate_hex(16)
        assert len(hex_str) == 32

    def test_is_hex(self) -> None:
        hex_str = random_gen.generate_hex()
        int(hex_str, 16)  # raises ValueError if not valid hex

    def test_zero_bytes_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_hex(0)


class TestGeneratePassword:
    def test_default_length(self) -> None:
        pwd = random_gen.generate_password()
        assert len(pwd) == 20

    def test_custom_length(self) -> None:
        pwd = random_gen.generate_password(length=30)
        assert len(pwd) == 30

    def test_too_short_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_password(length=8)

    def test_contains_digit_by_default(self) -> None:
        pwd = random_gen.generate_password(length=50)
        assert any(c.isdigit() for c in pwd)

    def test_contains_uppercase_by_default(self) -> None:
        pwd = random_gen.generate_password(length=50)
        assert any(c.isupper() for c in pwd)

    def test_no_symbols_when_disabled(self) -> None:
        symbols = set("!@#$%^&*()-_=+")
        for _ in range(20):
            pwd = random_gen.generate_password(use_symbols=False)
            assert not any(c in symbols for c in pwd)

    def test_passwords_are_unique(self) -> None:
        pwds = {random_gen.generate_password() for _ in range(50)}
        assert len(pwds) == 50


class TestGenerateBytesB64:
    def test_returns_string(self) -> None:
        assert isinstance(random_gen.generate_bytes_b64(), str)

    def test_valid_base64(self) -> None:
        import base64
        result = random_gen.generate_bytes_b64(32)
        decoded = base64.b64decode(result.encode())
        assert len(decoded) == 32

    def test_zero_bytes_raises(self) -> None:
        with pytest.raises(InputValidationError):
            random_gen.generate_bytes_b64(0)
