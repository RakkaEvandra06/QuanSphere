"""_shared.py — Cross-command Typer state: the error-handling decorator, the
shared Rich console, and small constants used by more than one command
module.

Every module under cli/commands/ imports from here instead of from
cli/main.py, which avoids a circular import (main.py is the *assembler*
that imports the command modules, not the other way around).
"""

from __future__ import annotations

__all__ = [
    "console",
    "_handle_error",
    "_handle_errors",
    "_MIN_PASSWORD_LENGTH",
    "_DEFAULT_PASSWORD_LENGTH",
    "_DEFAULT_KEY_SIZE",
    "_ASYMMETRIC_TYPES",
    "_MAX_INLINE_BYTES",
    "_MAX_KEY_FILE_BYTES",
]

import functools
from typing import Callable, TypeVar

import typer
from rich.console import Console

from crypto_toolkit.cli import output
from crypto_toolkit.core.constants import PASSWORD_MIN_LENGTH
from crypto_toolkit.core.exceptions import CryptoToolkitError

console = Console()

_F = TypeVar("_F", bound=Callable[..., object])

# Minimum password character length — single source of truth lives in constants.py.
_MIN_PASSWORD_LENGTH: int = PASSWORD_MIN_LENGTH

_DEFAULT_PASSWORD_LENGTH: int = 20
_DEFAULT_KEY_SIZE: int = 32  # symmetric / token default (AES-256 = 32 bytes)

# Key types that produce a private+public pair written into a directory.
_ASYMMETRIC_TYPES = frozenset({"rsa", "ecc", "x25519", "ed25519"})

_MAX_INLINE_BYTES: int = 64 * 1024 * 1024  # 64 MiB
_MAX_KEY_FILE_BYTES: int = 1 * 1024 * 1024  # 1 MiB

def _handle_error(exc: Exception) -> None:
    """Translate a toolkit exception into a user-friendly CLI message, then exit."""
    if isinstance(exc, CryptoToolkitError):
        output.error(str(exc))
    else:
        output.error(
            f"Unexpected internal error ({type(exc).__name__}). "
            "This may indicate a bug, please report it."
        )
    raise typer.Exit(code=1)

def _handle_errors(fn: _F) -> _F:
    """Decorator: catch all exceptions from a CLI command and route to _handle_error."""
    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> object:
        try:
            return fn(*args, **kwargs)
        except typer.Exit:
            raise  # explicit typer.Exit(1) calls inside commands propagate unchanged
        except Exception as exc:
            _handle_error(exc)
            return None  # unreachable; satisfies the type checker
    return wrapper  # type: ignore[return-value]
