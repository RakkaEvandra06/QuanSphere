"""Unit tests for chunked file encryption/decryption."""

from pathlib import Path
import pytest
from crypto_toolkit.core import file_crypto
from crypto_toolkit.core.constants import AES_KEY_SIZE
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    FileOperationError,
    InputValidationError,
)
from crypto_toolkit.core.random_gen import generate_key

@pytest.fixture()
def aes_key() -> bytes:
    return generate_key(AES_KEY_SIZE)

@pytest.fixture()
def tmp_files(tmp_path: Path):
    src = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    dec = tmp_path / "plain.dec"
    return src, enc, dec

class TestFileEncryption:
    def test_roundtrip_small_file(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        data = b"small file contents"
        src.write_bytes(data)
        file_crypto.encrypt_file(src, enc, aes_key)
        file_crypto.decrypt_file(enc, dec, aes_key)
        assert dec.read_bytes() == data

    def test_roundtrip_exact_chunk_boundary(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        data = b"X" * (64 * 1024)  # exactly one chunk
        src.write_bytes(data)
        file_crypto.encrypt_file(src, enc, aes_key)
        file_crypto.decrypt_file(enc, dec, aes_key)
        assert dec.read_bytes() == data

    def test_roundtrip_multi_chunk(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        data = b"M" * (200 * 1024)  # ~3 chunks
        src.write_bytes(data)
        file_crypto.encrypt_file(src, enc, aes_key)
        file_crypto.decrypt_file(enc, dec, aes_key)
        assert dec.read_bytes() == data

    def test_roundtrip_empty_file(self, aes_key, tmp_files) -> None:
        # Empty source files are intentionally rejected with InputValidationError
        # (encrypting zero bytes produces a ciphertext with no payload, which
        # is almost certainly a caller mistake).
        src, enc, _ = tmp_files
        src.write_bytes(b"")
        with pytest.raises(InputValidationError):
            file_crypto.encrypt_file(src, enc, aes_key)

    def test_encrypted_differs_from_plaintext(self, aes_key, tmp_files) -> None:
        src, enc, _ = tmp_files
        data = b"readable text"
        src.write_bytes(data)
        file_crypto.encrypt_file(src, enc, aes_key)
        assert enc.read_bytes() != data

    def test_wrong_key_raises_decryption_error(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        src.write_bytes(b"top secret")
        file_crypto.encrypt_file(src, enc, aes_key)
        wrong_key = generate_key(AES_KEY_SIZE)
        with pytest.raises(DecryptionError):
            file_crypto.decrypt_file(enc, dec, wrong_key)

    def test_short_key_raises_input_validation_error_on_encrypt(self, tmp_files) -> None:
        # encrypt_file validates the key length before touching the filesystem;
        # the raised exception is InputValidationError, not EncryptionError,
        # because no encryption attempt is made with a malformed key.
        src, enc, _ = tmp_files
        src.write_bytes(b"data")
        with pytest.raises(InputValidationError):
            file_crypto.encrypt_file(src, enc, b"shortkey")

    def test_short_key_raises_input_validation_error_on_decrypt(self, aes_key, tmp_files) -> None:
        # Same reasoning as above: key-length validation fires before decryption.
        src, enc, dec = tmp_files
        src.write_bytes(b"data")
        file_crypto.encrypt_file(src, enc, aes_key)
        with pytest.raises(InputValidationError):
            file_crypto.decrypt_file(enc, dec, b"shortkey")

    def test_missing_source_file_raises(self, aes_key, tmp_files) -> None:
        _, enc, _ = tmp_files
        with pytest.raises(FileOperationError):
            file_crypto.encrypt_file(Path("/nonexistent/file.bin"), enc, aes_key)

    def test_corrupt_magic_raises_decryption_error(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        src.write_bytes(b"content")
        file_crypto.encrypt_file(src, enc, aes_key)
        raw = bytearray(enc.read_bytes())
        raw[0] ^= 0xFF
        enc.write_bytes(bytes(raw))
        with pytest.raises(DecryptionError):
            file_crypto.decrypt_file(enc, dec, aes_key)

    def test_tampered_chunk_raises_decryption_error(self, aes_key, tmp_files) -> None:
        src, enc, dec = tmp_files
        src.write_bytes(b"A" * 1024)
        file_crypto.encrypt_file(src, enc, aes_key)
        raw = bytearray(enc.read_bytes())
        raw[-10] ^= 0xAA
        enc.write_bytes(bytes(raw))
        with pytest.raises(DecryptionError):
            file_crypto.decrypt_file(enc, dec, aes_key)

    def test_default_chunk_size_roundtrip(self, aes_key, tmp_files) -> None:
        # encrypt_file uses a fixed 64 KiB chunk size (FILE_CHUNK_SIZE constant);
        # there is no caller-facing chunk_size parameter.  This test verifies
        # that data spanning multiple chunks decrypts correctly with the default.
        src, enc, dec = tmp_files
        data = b"chunky" * 1000
        src.write_bytes(data)
        file_crypto.encrypt_file(src, enc, aes_key)
        file_crypto.decrypt_file(enc, dec, aes_key)
        assert dec.read_bytes() == data