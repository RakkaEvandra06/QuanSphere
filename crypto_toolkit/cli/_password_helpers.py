"""_password_helpers.py — Password and key-password prompting/resolution,
plus the shared asymmetric-keypair writer used by the generate-key command.

Single responsibility: turning CLI password flags (--password,
--prompt-password, --key-password, --prompt-key-password) into resolved
secrets, with consistent shell-history warnings. Generic file/stdin I/O
lives in _io_helpers.py.
"""

from __future__ import annotations

__all__ = [
    "_warn_cli_password",
    "_resolve_password",
    "_resolve_key_password",
    "_write_asymmetric_keypair",
]

from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _write_file
from crypto_toolkit.cli._shared import _MIN_PASSWORD_LENGTH


def _warn_cli_password() -> None:
    """Emit the standard warning when a password is passed as a CLI argument."""
    output.warn(
        "Password provided as a CLI argument, it may appear in shell "
        "history and the process list. Use "
        "[bold]--prompt-password[/bold] for sensitive passwords."
    )

def _resolve_password(
    password: Optional[str],
    prompt_password: bool,
    *,
    confirm: bool = False,
    enforce_min_length: bool = True,
) -> str:
    """Return the effective password, prompting interactively when requested."""
    if prompt_password:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=confirm)
    elif password:
        _warn_cli_password()

    if not password:
        output.error("Password must not be empty.")
        raise typer.Exit(1)

    if enforce_min_length and len(password) < _MIN_PASSWORD_LENGTH:
        output.error(
            f"Password is too short ({len(password)} character(s)); "
            f"minimum is {_MIN_PASSWORD_LENGTH} characters. "
            "Run [bold]crypto-toolkit generate-key --type password[/bold] to "
            "generate a strong password."
        )
        raise typer.Exit(1)

    return password

def _resolve_key_password(
    key_password: Optional[str],
    prompt_key_password: bool,
    *,
    confirm: bool = False,
) -> Optional[bytes]:
    """Return the PEM encryption password as bytes, or None if not set."""
    if prompt_key_password:
        pwd = typer.prompt(
            "Key password (press Enter for none)",
            hide_input=True,
            confirmation_prompt=confirm,
        )
        if pwd:
            return pwd.encode()
        # User pressed Enter without typing — explicitly treat as no password.
        output.info(
            "No key password entered, PEM will be loaded or saved as unencrypted."
        )
        return None
    if key_password:
        output.warn(
            "Key password provided as a CLI argument, it may appear in shell "
            "history and the process list. "
            "Use [bold]--prompt-key-password[/bold] to avoid this."
        )
        return key_password.encode()
    return None

def _write_asymmetric_keypair(
    priv_pem: bytes,
    pub_pem: bytes,
    key_name: str,
    output_dir: Optional[Path],
    label: str,
    *,
    force: bool = False,
) -> None:
    """Write or display an asymmetric key pair."""
    if output_dir:
        _write_file(output_dir / f"{key_name}_private.pem", priv_pem, mode=0o600, force=force)
        _write_file(output_dir / f"{key_name}_public.pem", pub_pem, force=force)
        output.success(f"{label} key pair written to {output_dir}/")
    else:
        output.result(f"{label} Private Key", priv_pem.decode())
        output.result(f"{label} Public Key", pub_pem.decode())
