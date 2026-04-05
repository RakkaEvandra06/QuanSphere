from __future__ import annotations

import base64
import secrets
import string

from crypto_toolkit.core.constants import AES_KEY_SIZE
from crypto_toolkit.core.exceptions import InputValidationError

def generate_key(size: int = AES_KEY_SIZE) -> bytes:

    if size <= 0:
        raise InputValidationError("Key size must be a positive integer.")
    return secrets.token_bytes(size)

def generate_token(nbytes: int = 32) -> str:
    if nbytes <= 0:
        raise InputValidationError("Token byte count must be positive.")
    return secrets.token_urlsafe(nbytes)

def generate_hex(nbytes: int = 32) -> str:
    if nbytes <= 0:
        raise InputValidationError("Byte count must be positive.")
    return secrets.token_hex(nbytes)

def generate_password(
    length: int = 20,
    *,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < 12:
        raise InputValidationError("Password length must be at least 12 for security.")

    alphabet = string.ascii_lowercase
    if use_uppercase:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"

    # Guarantee at least one character from each selected category.
    required: list[str] = [secrets.choice(string.ascii_lowercase)]
    if use_uppercase:
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        required.append(secrets.choice(string.digits))
    if use_symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+"))

    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    combined = required + remaining

    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    return "".join(combined)

def generate_bytes_b64(nbytes: int = 32) -> str:
    if nbytes <= 0:
        raise InputValidationError("Byte count must be positive.")
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()