"""exceptions.py — Exception hierarchy for the Crypto Toolkit."""

__all__ = [
    "CryptoToolkitError",
    "EncryptionError",
    "DecryptionError",
    "KeyGenerationError",
    "SignatureError",
    "HashingError",
    "KeyDerivationError",
    "InputValidationError",
    "FileOperationError",
]

class CryptoToolkitError(Exception):
    """Base class for all Crypto Toolkit errors."""

class EncryptionError(CryptoToolkitError):
    """Raised when an encryption operation fails."""

class DecryptionError(CryptoToolkitError):
    """Raised when a decryption or authentication operation fails."""

class KeyGenerationError(CryptoToolkitError):
    """Raised when key generation fails (RSA, ECC, X25519, Ed25519)."""

class SignatureError(CryptoToolkitError):
    """Raised when signing or signature verification fails."""

class HashingError(CryptoToolkitError):
    """Raised when a hashing operation fails."""

class KeyDerivationError(CryptoToolkitError):
    """Raised when Argon2 or PBKDF2 key derivation fails."""

class InputValidationError(CryptoToolkitError):
    """Raised when caller-supplied arguments fail validation before any crypto operation."""

class FileOperationError(CryptoToolkitError):
    """Raised when a file I/O operation fails (read, write, or path resolution)."""