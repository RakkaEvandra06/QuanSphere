"""symmetric_cmd.py — `crypto-toolkit encrypt` / `crypto-toolkit decrypt`.

Covers raw-key AES-256-GCM / ChaCha20-Poly1305 encryption and the
password-based (Argon2id-via-pbe) path. File encryption lives in
file_cmd.py; RSA-OAEP lives in rsa_cmd.py.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import (
    _parse_hex,
    _read_ascii_stdin,
    _read_plaintext,
    _write_output,
)
from crypto_toolkit.cli._password_helpers import _resolve_password
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import pbe, symmetric


class SymAlgo(str, Enum):
    aes_gcm = "aes-gcm"
    chacha20 = "chacha20"

def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def encrypt(
        plaintext: Optional[str] = typer.Argument(
            None,
            help="Text to encrypt. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
        ),
        key_hex: Optional[str] = typer.Option(
            None, "--key", "-k", help="32-byte symmetric key as a hex string (AES-256 or ChaCha20)."
        ),
        password: Optional[str] = typer.Option(
            None, "--password", "-p", help="Derive key from password (Argon2id).", hide_input=True,
        ),
        algorithm: SymAlgo = typer.Option(
            SymAlgo.aes_gcm, "--algo", "-a", help="Cipher algorithm."
        ),
        prompt_password: bool = typer.Option(
            False, "--prompt-password", help="Interactively prompt for a password."
        ),
        stdin: bool = typer.Option(False, "--stdin", help="Read plaintext from stdin."),
        input_file: Optional[Path] = typer.Option(
            None, "--input-file", "-i", help="Read plaintext from a file."
        ),
        output_file: Optional[Path] = typer.Option(
            None, "--output", "-o", help="Write ciphertext to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the output file if it already exists."
        ),
    ) -> None:
        """Encrypt data using AES-256-GCM or ChaCha20-Poly1305."""
        data = _read_plaintext(plaintext, stdin, input_file)

        if (prompt_password or password) and key_hex:
            output.warn(
                "Both --password/--prompt-password and --key were provided; "
                "--password takes priority and --key will be ignored."
            )

        if prompt_password or password:
            resolved = _resolve_password(password, prompt_password, confirm=True)
            if algorithm != SymAlgo.aes_gcm:
                output.error(
                    f"[bold]--algo {algorithm.value!r}[/bold] cannot be combined with "
                    "[bold]--password[/bold]. "
                    "Password-based encryption always uses AES-256-GCM via the PBE path. "
                    "To use ChaCha20-Poly1305, omit [bold]--password[/bold] and supply "
                    "a raw 32-byte key with [bold]--key[/bold] instead."
                )
                raise typer.Exit(1)

            token = pbe.password_encrypt(data, resolved)
            _write_output(token, output_file, "Encrypted (PBE)", force=force)
            return

        if not key_hex:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        key = _parse_hex(key_hex, "--key", sensitive=True)
        token = symmetric.encrypt(data, key, algorithm=algorithm.value)
        _write_output(token, output_file, "Encrypted", force=force)

    @app.command()
    @_handle_errors
    def decrypt(
        token: Optional[str] = typer.Argument(
            None, help="Encrypted token (base64). Leave empty to use --stdin."
        ),
        key_hex: Optional[str] = typer.Option(
            None, "--key", "-k", help="32-byte key as a hex string."
        ),
        password: Optional[str] = typer.Option(
            None, "--password", "-p", help="Password used during encryption.", hide_input=True
        ),
        prompt_password: bool = typer.Option(
            False, "--prompt-password", help="Interactively prompt for a password."
        ),
        stdin: bool = typer.Option(False, "--stdin", help="Read token from stdin."),
        output_file: Optional[Path] = typer.Option(
            None, "--output", "-o", help="Write decrypted plaintext to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the output file if it already exists."
        ),
    ) -> None:
        """Decrypt an encrypted token produced by the [bold]encrypt[/bold] command."""
        if stdin:
            raw_token = _read_ascii_stdin("Encrypted tokens")
        elif token:
            raw_token = token
        else:
            output.error("Provide a token argument or use --stdin.")
            raise typer.Exit(1)

        if (prompt_password or password) and key_hex:
            output.warn(
                "Both --password/--prompt-password and --key were provided; "
                "--password takes priority and --key will be ignored."
            )

        if prompt_password or password:
            resolved = _resolve_password(
                password, prompt_password, confirm=False, enforce_min_length=False
            )
            plaintext = pbe.password_decrypt(raw_token, resolved)
        elif key_hex:
            key = _parse_hex(key_hex, "--key", sensitive=True)
            plaintext = symmetric.decrypt(raw_token, key)
        else:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        _write_output(plaintext, output_file, "Decrypted", force=force)
