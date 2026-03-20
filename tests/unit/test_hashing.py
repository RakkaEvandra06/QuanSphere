"""Unit tests for the hashing module."""

import io
from pathlib import Path

import pytest

from crypto_toolkit.core import hashing
from crypto_toolkit.core.exceptions import HashingError, InputValidationError


class TestHashData:
    def test_sha256_known_vector(self) -> None:
        digest = hashing.hash_data(b"", "sha256")
        assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha512(self) -> None:
        digest = hashing.hash_data(b"abc", "sha512")
        assert len(digest) == 128

    def test_sha3_256(self) -> None:
        digest = hashing.hash_data(b"test", "sha3_256")
        assert len(digest) == 64

    def test_sha3_512(self) -> None:
        digest = hashing.hash_data(b"test", "sha3_512")
        assert len(digest) == 128

    def test_blake2b(self) -> None:
        digest = hashing.hash_data(b"data", "blake2b")
        assert len(digest) == 128  # BLAKE2b default = 64 bytes → 128 hex chars

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(InputValidationError):
            hashing.hash_data(b"x", "md5")

    def test_sha1_blocked(self) -> None:
        with pytest.raises(InputValidationError):
            hashing.hash_data(b"x", "sha1")

    def test_deterministic(self) -> None:
        d1 = hashing.hash_data(b"hello", "sha256")
        d2 = hashing.hash_data(b"hello", "sha256")
        assert d1 == d2

    def test_avalanche_effect(self) -> None:
        d1 = hashing.hash_data(b"hello", "sha256")
        d2 = hashing.hash_data(b"hellp", "sha256")
        assert d1 != d2


class TestHashStream:
    def test_stream_matches_data_hash(self) -> None:
        data = b"streaming test data " * 500
        stream = io.BytesIO(data)
        digest_stream = hashing.hash_stream(stream, "sha256")
        digest_data = hashing.hash_data(data, "sha256")
        assert digest_stream == digest_data

    def test_empty_stream(self) -> None:
        stream = io.BytesIO(b"")
        digest = hashing.hash_stream(stream, "sha256")
        assert digest == hashing.hash_data(b"", "sha256")


class TestHashFile:
    def test_hashes_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"file content here")
        digest = hashing.hash_file(f, "sha256")
        expected = hashing.hash_data(b"file content here", "sha256")
        assert digest == expected

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(HashingError):
            hashing.hash_file(tmp_path / "nonexistent.bin")

    def test_large_file_chunked(self, tmp_path: Path) -> None:
        f = tmp_path / "large.bin"
        data = b"B" * (512 * 1024)  # 512 KiB
        f.write_bytes(data)
        digest = hashing.hash_file(f)
        assert digest == hashing.hash_data(data)
