"""_aead_utils.py — Shared AEAD cipher utilities for the Crypto Toolkit."""

from __future__ import annotations

__all__ = ["aesgcm_context"]

from collections.abc import Generator
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

@contextmanager
def aesgcm_context(key: bytearray) -> Generator[AESGCM, None, None]:
    """Scoped :class:`AESGCM` cipher constructed from a *key* bytearray."""
    cipher = AESGCM(key)
    try:
        yield cipher
    finally:
        del cipher