"""Unit tests for symmetric encryption (AES-256-GCM and ChaCha20-Poly1305)."""

import pytest

from crypto_toolkit.core import symmetric
from crypto_toolkit.core.constants import AES_KEY_SIZE, CHACHA_KEY_SIZE
from crypto_toolkit.core.exceptions import DecryptionError, EncryptionError, InputValidationError
from crypto_toolkit.core.random_gen import generate_key


class TestAesGcm:
    def test_encrypt_decrypt_roundtrip(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        plaintext = b"hello, authenticated world"
        token = symmetric.encrypt(plaintext, key, algorithm="aes-gcm")
        assert symmetric.decrypt(token, key) == plaintext

    def test_different_nonces_each_call(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        t1 = symmetric.encrypt(b"same", key)
        t2 = symmetric.encrypt(b"same", key)
        assert t1 != t2  # nonce is random → ciphertext differs

    def test_wrong_key_raises_decryption_error(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        token = symmetric.encrypt(b"secret", key)
        wrong_key = generate_key(AES_KEY_SIZE)
        with pytest.raises(DecryptionError):
            symmetric.decrypt(token, wrong_key)

    def test_tampered_ciphertext_raises_decryption_error(self) -> None:
        import base64

        key = generate_key(AES_KEY_SIZE)
        token = symmetric.encrypt(b"intact", key)
        raw = bytearray(base64.urlsafe_b64decode(token.encode()))
        raw[-1] ^= 0xFF  # flip last byte
        bad_token = base64.urlsafe_b64encode(bytes(raw)).decode()
        with pytest.raises(DecryptionError):
            symmetric.decrypt(bad_token, key)

    def test_associated_data_mismatch_raises(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        token = symmetric.encrypt(b"data", key, associated_data=b"context-A")
        with pytest.raises(DecryptionError):
            symmetric.decrypt(token, key, associated_data=b"context-B")

    def test_associated_data_roundtrip(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        token = symmetric.encrypt(b"data", key, associated_data=b"ctx")
        assert symmetric.decrypt(token, key, associated_data=b"ctx") == b"data"

    def test_short_key_raises_input_validation_error(self) -> None:
        with pytest.raises(InputValidationError):
            symmetric.encrypt(b"x", b"tooshort")

    def test_empty_plaintext(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        token = symmetric.encrypt(b"", key)
        assert symmetric.decrypt(token, key) == b""

    def test_large_plaintext(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        data = b"A" * (1024 * 1024)  # 1 MiB
        token = symmetric.encrypt(data, key)
        assert symmetric.decrypt(token, key) == data


class TestChaCha20:
    def test_roundtrip(self) -> None:
        key = generate_key(CHACHA_KEY_SIZE)
        plaintext = b"chacha20 poly1305 test"
        token = symmetric.encrypt(plaintext, key, algorithm="chacha20")
        assert symmetric.decrypt(token, key) == plaintext

    def test_wrong_key_raises(self) -> None:
        key = generate_key(CHACHA_KEY_SIZE)
        token = symmetric.encrypt(b"secret", key, algorithm="chacha20")
        with pytest.raises(DecryptionError):
            symmetric.decrypt(token, generate_key(CHACHA_KEY_SIZE))

    def test_invalid_algorithm_raises(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        with pytest.raises(InputValidationError):
            symmetric.encrypt(b"x", key, algorithm="ecb")  # type: ignore[arg-type]

    def test_malformed_token_raises(self) -> None:
        key = generate_key(AES_KEY_SIZE)
        with pytest.raises(DecryptionError):
            symmetric.decrypt("notvalidbase64!!!!", key)
