"""crypto_toolkit.core.file_crypto — Chunked AES-256-GCM file encryption.

This is a *package* instead of a single module purely to keep each file
under ~600 lines for easier indexing/editing by AI coding agents and humans
alike (see /REFACTORING.md at the repo root). The public API is
byte-for-byte identical to the pre-refactor single-file `file_crypto.py`:

    from crypto_toolkit.core import file_crypto
    file_crypto.encrypt_file(...)
    file_crypto.decrypt_file(...)
    file_crypto.encrypt_file_with_password(...)
    file_crypto.decrypt_file_with_password(...)

Module map (each file's single responsibility):
    _envelope.py   header/tag format: builders + parser
    _chunks.py      path validation + the chunked AES-GCM I/O loop
    api.py           public orchestration functions (this is what callers use)
"""

from __future__ import annotations

from crypto_toolkit.core.file_crypto.api import (
    decrypt_file,
    decrypt_file_with_password,
    encrypt_file,
    encrypt_file_with_password,
)

__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_with_password",
    "decrypt_file_with_password",
]
