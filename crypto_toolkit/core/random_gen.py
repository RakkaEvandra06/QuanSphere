"""Secure random data generation backed by OS entropy.

All functions use Python's ``secrets`` module (or ``os.urandom`` directly),
which is backed by the platform's CSPRNG (e.g. ``/dev/urandom``, ``CryptGenRandom``).

``random`` and ``numpy.random`` are **never** used here.
"""

from __future__ import annotations

import base64
import secrets
import string

from crypto_toolkit.core.constants import AES_KEY_SIZE
from crypto_toolkit.core.exceptions import InputValidationError


def generate_key(size: int = AES_KEY_SIZE) -> bytes:
    """Generate *size* cryptographically random bytes suitable for use as a symmetric key.

    Args:
        size: Key size in bytes.  Must be 16, 24, or 32 for AES compatibility.

    Returns:
        Random byte string.

    Raises:
        InputValidationError: If *size* is not a positive integer.
    """
    if size <= 0:
        raise InputValidationError("Key size must be a positive integer.")
    return secrets.token_bytes(size)


def generate_token(nbytes: int = 32) -> str:
    """Generate a URL-safe base64-encoded random token.

    Suitable for use as API keys, session tokens, or CSRF tokens.

    Args:
        nbytes: Entropy bytes (the token string will be longer due to base64).

    Returns:
        URL-safe base64 string without padding.
    """
    if nbytes <= 0:
        raise InputValidationError("Token byte count must be positive.")
    return secrets.token_urlsafe(nbytes)


def generate_hex(nbytes: int = 32) -> str:
    """Generate a lowercase hex string from *nbytes* of random data.

    Args:
        nbytes: Number of random bytes.

    Returns:
        Hexadecimal string of length ``2 * nbytes``.
    """
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
    """Generate a cryptographically secure random password.

    Args:
        length: Desired password length (minimum 12).
        use_uppercase: Include uppercase letters.
        use_digits: Include digits.
        use_symbols: Include ``!@#$%^&*`` symbols.

    Returns:
        Random password string.

    Raises:
        InputValidationError: If *length* is below 12.
    """
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
    # Shuffle with secrets to avoid predictable positions.
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)


def generate_bytes_b64(nbytes: int = 32) -> str:
    """Return *nbytes* of random data as a base64-encoded string (standard encoding).

    Args:
        nbytes: Number of random bytes.

    Returns:
        Base64 string (with ``=`` padding).
    """
    if nbytes <= 0:
        raise InputValidationError("Byte count must be positive.")
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()
