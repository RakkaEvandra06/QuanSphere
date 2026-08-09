"""file_cmd.py — `crypto-toolkit encrypt-file` / `crypto-toolkit decrypt-file`."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _parse_hex
from crypto_toolkit.cli._password_helpers import _resolve_password
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import file_crypto


def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def encrypt_file(
        src: Path = typer.Argument(..., help="Source plaintext file."),
        dst: Path = typer.Argument(..., help="Encrypted destination file."),
        key_hex: Optional[str] = typer.Option(
            None, "--key", "-k", help="32-byte AES-256 key (hex)."
        ),
        password: Optional[str] = typer.Option(
            None, "--password", "-p", help="Derive key from password (embedded in output).",
            hide_input=True,
        ),
        prompt_password: bool = typer.Option(
            False, "--prompt-password", help="Interactively prompt for a password."
        ),
        use_pbkdf2: bool = typer.Option(False, "--pbkdf2", help="Use PBKDF2 instead of Argon2id."),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the destination file if it already exists."
        ),
    ) -> None:
        """Encrypt a file with AES-256-GCM using a raw key or password (Argon2id/PBKDF2)."""
        if (prompt_password or password) and key_hex:
            output.warn(
                "Both --password/--prompt-password and --key were provided; "
                "--password takes priority and --key will be ignored."
            )
        if prompt_password or password:
            resolved = _resolve_password(password, prompt_password, confirm=True)
            file_crypto.encrypt_file_with_password(
                src, dst, resolved, use_argon2=not use_pbkdf2, force=force
            )
            algo = "PBKDF2" if use_pbkdf2 else "Argon2id"
            output.success(f"Encrypted ({algo}): {src} -> {dst}")
            output.info(
                "The KDF salt is embedded in the output file, no need to save it separately."
            )
        elif key_hex:
            key = _parse_hex(key_hex, "--key", sensitive=True)
            file_crypto.encrypt_file(src, dst, key, force=force)
            output.success(f"Encrypted: {src} -> {dst}")
        else:
            output.error("Provide --key (hex) or --password.")
            raise typer.Exit(1)

    @app.command()
    @_handle_errors
    def decrypt_file(
        src: Path = typer.Argument(..., help="Encrypted source file."),
        dst: Path = typer.Argument(..., help="Decrypted destination file."),
        key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte AES key (hex)."),
        password: Optional[str] = typer.Option(
            None, "--password", "-p", help="Password used during encryption.", hide_input=True
        ),
        prompt_password: bool = typer.Option(
            False, "--prompt-password", help="Interactively prompt for a password."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the destination file if it already exists."
        ),
    ) -> None:
        """Decrypt a file encrypted with [bold]encrypt-file[/bold]."""
        if (prompt_password or password) and key_hex:
            output.warn(
                "Both --password/--prompt-password and --key were provided; "
                "--password takes priority and --key will be ignored."
            )
        if prompt_password or password:
            # enforce_min_length=False: same rationale as the symmetric decrypt
            # command — decryption must never be blocked by a write-time policy.
            resolved = _resolve_password(
                password, prompt_password, confirm=False, enforce_min_length=False
            )
            file_crypto.decrypt_file_with_password(src, dst, resolved, force=force)
            output.success(f"Decrypted: {src} -> {dst}")
        elif key_hex:
            key = _parse_hex(key_hex, "--key", sensitive=True)
            file_crypto.decrypt_file(src, dst, key, force=force)
            output.success(f"Decrypted: {src} -> {dst}")
        else:
            output.error("Provide --key (hex) or --password.")
            raise typer.Exit(1)
