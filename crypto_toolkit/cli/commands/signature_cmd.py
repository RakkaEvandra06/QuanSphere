"""signature_cmd.py — `crypto-toolkit sign` / `crypto-toolkit verify`."""

from __future__ import annotations

import base64
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _read_key_file, _read_plaintext, _write_output
from crypto_toolkit.cli._password_helpers import _resolve_key_password
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import asymmetric, signatures
from crypto_toolkit.core.exceptions import InputValidationError


class SignAlgo(str, Enum):
    ed25519 = "ed25519"
    rsa_pss = "rsa-pss"

def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def sign(
        data: Optional[str] = typer.Argument(
            None,
            help="Data to sign. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
        ),
        private_key_file: Path = typer.Option(
            ..., "--key", "-k", help="Path to the PEM private key."
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
            help="Interactively prompt for the private key password "
                 "(never exposed in shell history).",
        ),
        algorithm: SignAlgo = typer.Option(
            SignAlgo.ed25519, "--algo", "-a",
            help="Signature algorithm: ed25519 (default) or rsa-pss.",
        ),
        stdin: bool = typer.Option(False, "--stdin", help="Read data from stdin."),
        input_file: Optional[Path] = typer.Option(
            None, "--input-file", "-i", help="Read data from a file."
        ),
        output_file: Optional[Path] = typer.Option(
            None, "--output", "-o", help="Write signature to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the output file if it already exists."
        ),
    ) -> None:
        """Sign data with an Ed25519 or RSA-PSS private key."""
        raw_data = _read_plaintext(data, stdin, input_file, warn_on_cli_arg=False)
        pem = _read_key_file(private_key_file, "Private key file")
        pwd_bytes = _resolve_key_password(key_password, prompt_key_password)

        if algorithm == SignAlgo.ed25519:
            priv = signatures.load_ed25519_private_key(pem, pwd_bytes)
            sig = signatures.sign_ed25519(raw_data, priv)
        else:  # rsa-pss
            priv = asymmetric.load_private_key(pem, pwd_bytes)
            if not isinstance(priv, RSAPrivateKey):
                raise InputValidationError(
                    "RSA-PSS signing requires an RSA private key; "
                    f"received {type(priv).__name__}. "
                    "Ensure you are passing the correct key file."
                )
            sig = signatures.sign_rsa_pss(raw_data, priv)

        _write_output(
            base64.b64encode(sig).decode(), output_file,
            f"Signature ({algorithm.value}, base64)", force=force,
        )

    @app.command()
    @_handle_errors
    def verify(
        data: Optional[str] = typer.Argument(
            None,
            help="Original data to verify. "
                 "[dim]Use --stdin or --input-file for sensitive data.[/dim]",
        ),
        signature_b64: str = typer.Option(..., "--sig", "-s", help="Base64-encoded signature."),
        public_key_file: Path = typer.Option(
            ..., "--key", "-k", help="Path to the PEM public key."
        ),
        algorithm: SignAlgo = typer.Option(
            SignAlgo.ed25519, "--algo", "-a",
            help="Signature algorithm: ed25519 (default) or rsa-pss.",
        ),
        stdin: bool = typer.Option(False, "--stdin", help="Read original data from stdin."),
        input_file: Optional[Path] = typer.Option(
            None, "--input-file", "-i", help="Read original data from a file."
        ),
    ) -> None:
        """Verify an Ed25519 or RSA-PSS signature."""
        raw_data = _read_plaintext(data, stdin, input_file, warn_on_cli_arg=False)
        pem = _read_key_file(public_key_file, "Public key file")

        try:
            sig = base64.b64decode(signature_b64.encode())
        except Exception:
            output.error(
                "--sig value is not valid base64. "
                "Ensure the signature was not truncated or modified."
            )
            raise typer.Exit(1)
        if algorithm == SignAlgo.ed25519:
            pub = signatures.load_ed25519_public_key(pem)
            signatures.verify_ed25519_or_raise(raw_data, sig, pub)
        else:  # rsa-pss
            pub = asymmetric.load_public_key(pem)
            if not isinstance(pub, RSAPublicKey):
                raise InputValidationError(
                    "RSA-PSS verification requires an RSA public key; "
                    f"received {type(pub).__name__}. "
                    "Ensure you are passing the correct key file."
                )
            signatures.verify_rsa_pss_or_raise(raw_data, sig, pub)

        output.success(f"Signature ({algorithm.value}) VALID.")
