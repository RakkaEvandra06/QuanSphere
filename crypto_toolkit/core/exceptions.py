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
    pass

class EncryptionError(CryptoToolkitError):
    pass

class DecryptionError(CryptoToolkitError):
    pass

class KeyGenerationError(CryptoToolkitError):
    pass

class SignatureError(CryptoToolkitError):
    pass

class HashingError(CryptoToolkitError):
    pass

class KeyDerivationError(CryptoToolkitError):
    pass

class InputValidationError(CryptoToolkitError):
    pass

class FileOperationError(CryptoToolkitError):
    pass