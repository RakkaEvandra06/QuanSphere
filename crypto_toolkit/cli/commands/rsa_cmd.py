"""rsa_cmd.py — `crypto-toolkit rsa-encrypt` / `crypto-toolkit rsa-decrypt`."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

import typer
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import (
    _read_ascii_stdin,
    _read_key_file,
    _read_plaintext,
    _write_output,
)
from crypto_toolkit.cli._password_helpers import _resolve_key_password
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import asymmetric
from crypto_toolkit.core.exceptions import InputValidationError


def register(app: typer.Typer) -> None:
    @app.command(name="rsa-encrypt")
    @_handle_errors
    def rsa_encrypt_cmd(
        plaintext: Optional[str] = typer.Argument(
            None,
            help="Text to encrypt. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
        ),
        public_key_file: Path = typer.Option(
            ..., "--key", "-k", help="Path to the RSA PEM public key."
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
        """Encrypt data with an RSA-4096 public key (OAEP / SHA-256)."""
        data = _read_plaintext(plaintext, stdin, input_file)
        pem = _read_key_file(public_key_file, "Public key file")
        pub = asymmetric.load_public_key(pem)

        if not isinstance(pub, RSAPublicKey):
            raise InputValidationError(
                "rsa-encrypt requires an RSA public key; "
                f"received {type(pub).__name__}. "
                "Ensure you are passing an RSA PEM file."
            )

        raw_ct = asymmetric.rsa_encrypt(data, pub)
        _write_output(
            base64.b64encode(raw_ct).decode(), output_file, "RSA Ciphertext (base64)", force=force
        )

    @app.command(name="rsa-decrypt")
    @_handle_errors
    def rsa_decrypt_cmd(
        ciphertext_b64: Optional[str] = typer.Argument(
            None, help="Base64-encoded RSA ciphertext. Leave empty to use --stdin."
        ),
        private_key_file: Path = typer.Option(
            ..., "--key", "-k", help="Path to the RSA PEM private key."
        ),
        key_password: Optional[str] = typer.Option(
            None,
            "--key-password",
            help=(
                "Password protecting the private key. "
                "Warning: visible in process list and shell history. "
                "Prefer [bold]--prompt-key-password[/bold] for sensitive keys."
            ),
            hide_input=True,
        ),
        prompt_key_password: bool = typer.Option(
            False,
            "--prompt-key-password",
            help=(
                "Interactively prompt for the private key password "
                "(never exposed in shell history)."
            ),
        ),
        stdin: bool = typer.Option(False, "--stdin", help="Read ciphertext from stdin."),
        output_file: Optional[Path] = typer.Option(
            None, "--output", "-o", help="Write plaintext to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the output file if it already exists."
        ),
    ) -> None:
        """Decrypt RSA-OAEP ciphertext with a private key."""
        if stdin:
            raw_b64 = _read_ascii_stdin("RSA ciphertext")
        elif ciphertext_b64:
            raw_b64 = ciphertext_b64
        else:
            output.error("Provide a ciphertext argument or use --stdin.")
            raise typer.Exit(1)

        pem = _read_key_file(private_key_file, "Private key file")
        pwd_bytes = _resolve_key_password(key_password, prompt_key_password)
        priv = asymmetric.load_private_key(pem, pwd_bytes)

        if not isinstance(priv, RSAPrivateKey):
            raise InputValidationError(
                "rsa-decrypt requires an RSA private key; "
                f"received {type(priv).__name__}. "
                "Ensure you are passing the correct PEM key file."
            )

        try:
            ct_bytes = base64.b64decode(raw_b64)
        except Exception:
            output.error(
                "Ciphertext is not valid base64. Ensure the value was copied "
                "completely and was not modified in transit."
            )
            raise typer.Exit(1)

        plaintext = asymmetric.rsa_decrypt(ct_bytes, priv)
        _write_output(plaintext, output_file, "RSA Decrypted", force=force)
