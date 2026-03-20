"""Domain-level exceptions for the crypto toolkit.

All exceptions are safe to surface to the CLI layer — they never
embed raw key material, plaintext, or stack traces with sensitive data.
"""


class CryptoToolkitError(Exception):
    """Base exception for all toolkit errors."""


class EncryptionError(CryptoToolkitError):
    """Raised when an encryption operation fails."""


class DecryptionError(CryptoToolkitError):
    """Raised when decryption fails (bad key, corrupted data, authentication failure)."""


class KeyGenerationError(CryptoToolkitError):
    """Raised when key generation fails."""


class SignatureError(CryptoToolkitError):
    """Raised when signing or verification fails."""


class HashingError(CryptoToolkitError):
    """Raised when a hashing operation fails."""


class KeyDerivationError(CryptoToolkitError):
    """Raised when key derivation fails."""


class InputValidationError(CryptoToolkitError):
    """Raised when input parameters fail validation."""


class FileOperationError(CryptoToolkitError):
    """Raised when a file read/write/encrypt/decrypt operation fails."""
