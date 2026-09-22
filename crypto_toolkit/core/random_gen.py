from __future__ import annotations

__all__ = [
    "generate_key",
    "generate_token",
    "generate_hex",
    "generate_password",
    "generate_bytes_b64",
]

import base64
import math
import secrets
import string

from crypto_toolkit.core.constants import AES_KEY_SIZE
from crypto_toolkit.core.exceptions import InputValidationError

# ── Constants ─────────────────────────────────────────────────────────────────

_MIN_PASSWORD_ENTROPY_BITS: int = 72
_SYMBOL_CHARS: str = "!@#$%^&*()-_=+"
_MAX_RANDOM_BYTES: int = 64 * 1024 * 1024  # 64 MiB

# ── Private helpers ───────────────────────────────────────────────────────────

def _build_alphabet(
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> str:
    """Return the full character pool for password generation."""
    parts = [string.ascii_lowercase]
    if use_uppercase:
        parts.append(string.ascii_uppercase)
    if use_digits:
        parts.append(string.digits)
    if use_symbols:
        parts.append(_SYMBOL_CHARS)
    return "".join(parts)

def _required_chars(
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> list[str]:
    """Return one guaranteed character per active category."""
    required = [secrets.choice(string.ascii_lowercase)]
    if use_uppercase:
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        required.append(secrets.choice(string.digits))
    if use_symbols:
        required.append(secrets.choice(_SYMBOL_CHARS))
    return required

def _compute_entropy(
    length: int,
    alphabet: str,
    required: list[str],
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> float:
    """Return the approximate Shannon entropy (bits) for a password of *length*."""
    category_sizes: list[int] = [len(string.ascii_lowercase)]
    if use_uppercase:
        category_sizes.append(len(string.ascii_uppercase))
    if use_digits:
        category_sizes.append(len(string.digits))
    if use_symbols:
        category_sizes.append(len(_SYMBOL_CHARS))

    free_positions = length - len(required)
    return (
        free_positions * math.log2(len(alphabet))
        + sum(math.log2(s) for s in category_sizes)
    )

def _shuffle_inplace(chars: list[str]) -> None:
    """Fisher-Yates shuffle using :func:`secrets.randbelow` for cryptographic fairness."""
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

_HARD_MIN_LENGTH: int = 12

def _minimum_viable_length(
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> int:
    """Return the shortest length guaranteed to pass the entropy gate for these settings."""
    alphabet = _build_alphabet(use_uppercase, use_digits, use_symbols)
    # One required character per enabled category (same count as _required_chars()).
    req_count = 1 + int(use_uppercase) + int(use_digits) + int(use_symbols)
    dummy_required = ["x"] * req_count  # values irrelevant; only len() matters
    for length in range(req_count, 200):
        if (
            _compute_entropy(
                length, alphabet, dummy_required,
                use_uppercase, use_digits, use_symbols,
            )
            >= _MIN_PASSWORD_ENTROPY_BITS
        ):
            return length
    return 200  # unreachable in practice with any real alphabet

# ── Public API ────────────────────────────────────────────────────────────────

def generate_key(size: int = AES_KEY_SIZE) -> bytes:
    """Return *size* cryptographically secure random bytes."""
    if size <= 0:
        raise InputValidationError("Key size must be a positive integer.")
    if size > _MAX_RANDOM_BYTES:
        raise InputValidationError(
            f"Key size must be at most {_MAX_RANDOM_BYTES:,} bytes "
            f"({_MAX_RANDOM_BYTES // (1024 * 1024)} MiB); received {size:,}. "
            "No legitimate cryptographic key requires this much random material."
        )
    return secrets.token_bytes(size)

def generate_token(nbytes: int = 32) -> str:
    """Return a URL-safe base64 token backed by *nbytes* random bytes."""
    if nbytes <= 0:
        raise InputValidationError("Token byte count must be positive.")
    if nbytes > _MAX_RANDOM_BYTES:
        raise InputValidationError(
            f"Token byte count must be at most {_MAX_RANDOM_BYTES:,} bytes "
            f"({_MAX_RANDOM_BYTES // (1024 * 1024)} MiB); received {nbytes:,}."
        )
    return secrets.token_urlsafe(nbytes)

def generate_hex(nbytes: int = 32) -> str:
    """Return a hex string backed by *nbytes* random bytes."""
    if nbytes <= 0:
        raise InputValidationError("Byte count must be positive.")
    if nbytes > _MAX_RANDOM_BYTES:
        raise InputValidationError(
            f"Byte count must be at most {_MAX_RANDOM_BYTES:,} bytes "
            f"({_MAX_RANDOM_BYTES // (1024 * 1024)} MiB); received {nbytes:,}."
        )
    return secrets.token_hex(nbytes)

def generate_password(
    length: int = 20,
    *,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password."""
    min_viable = max(_HARD_MIN_LENGTH, _minimum_viable_length(use_uppercase, use_digits, use_symbols))
    if length < min_viable:
        raise InputValidationError(
            f"Password length {length} is too short for the selected character "
            f"classes to reach {_MIN_PASSWORD_ENTROPY_BITS} bits of entropy "
            f"(minimum required: {min_viable} characters). "
            "Increase --size or enable additional character classes "
            "(--uppercase, --digits, --symbols)."
        )

    alphabet = _build_alphabet(use_uppercase, use_digits, use_symbols)
    required = _required_chars(use_uppercase, use_digits, use_symbols)

    entropy = _compute_entropy(length, alphabet, required, use_uppercase, use_digits, use_symbols)
    if entropy < _MIN_PASSWORD_ENTROPY_BITS:  # pragma: no cover
        raise InputValidationError(
            f"Internal error: the entropy gate fired after the length pre-check "
            f"({entropy:.1f} bits < {_MIN_PASSWORD_ENTROPY_BITS} required). "
            "Please report this as a bug (length={length}, uppercase={use_uppercase}, "
            "digits={use_digits}, symbols={use_symbols})."
        )

    free_chars = [secrets.choice(alphabet) for _ in range(length - len(required))]
    combined = required + free_chars
    _shuffle_inplace(combined)
    return "".join(combined)

def generate_bytes_b64(nbytes: int = 32) -> str:
    """Return a standard base64 string backed by *nbytes* random bytes."""
    if nbytes <= 0:
        raise InputValidationError("Byte count must be positive.")
    if nbytes > _MAX_RANDOM_BYTES:
        raise InputValidationError(
            f"Byte count must be at most {_MAX_RANDOM_BYTES:,} bytes "
            f"({_MAX_RANDOM_BYTES // (1024 * 1024)} MiB); received {nbytes:,}."
        )
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()