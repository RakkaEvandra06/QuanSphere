"""keygen_cmd.py — `crypto-toolkit generate-key`."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _write_file
from crypto_toolkit.cli._password_helpers import _resolve_key_password, _write_asymmetric_keypair
from crypto_toolkit.cli._shared import (
    _ASYMMETRIC_TYPES,
    _DEFAULT_KEY_SIZE,
    _DEFAULT_PASSWORD_LENGTH,
    _MIN_PASSWORD_LENGTH,
    _handle_errors,
)
from crypto_toolkit.core import asymmetric, random_gen, signatures
from crypto_toolkit.core.constants import RSA_KEY_SIZE


class KeyType(str, Enum):
    symmetric = "symmetric"
    rsa = "rsa"
    ecc = "ecc"
    x25519 = "x25519"
    ed25519 = "ed25519"
    token = "token"
    password = "password"

def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def generate_key(
        key_type: KeyType = typer.Option(
            KeyType.symmetric, "--type", "-t", help="Type of key to generate."
        ),
        output_dir: Optional[Path] = typer.Option(
            None, "--out", "-o", help="Write key to this directory."
        ),
        key_password: Optional[str] = typer.Option(
            None,
            "--key-password",
            help=(
                "Encrypt the private key with this password (asymmetric types only). "
                "Warning: visible in process list and shell history. "
                "Prefer [bold]--prompt-key-password[/bold] for sensitive keys."
            ),
            hide_input=True,
        ),
        prompt_key_password: bool = typer.Option(
            False,
            "--prompt-key-password",
            help=(
                "Interactively prompt for the private key encryption password "
                "(asymmetric types only)."
            ),
        ),
        size: Optional[int] = typer.Option(
            None,
            "--size", "-s",
            help=(
                f"Byte count for symmetric-key/token types (default {_DEFAULT_KEY_SIZE}). "
                f"Character length when --type is 'password' "
                f"(minimum {_MIN_PASSWORD_LENGTH}, default {_DEFAULT_PASSWORD_LENGTH})."
            ),
        ),
        output_file: Optional[Path] = typer.Option(
            None, "--output-file", help="Write token/password/symmetric key to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite output file(s) if they already exist."
        ),
    ) -> None:
        """Generate cryptographic keys (symmetric, RSA-4096, ECC P-256, X25519,
        Ed25519, token, password)."""
        is_asymmetric = key_type.value in _ASYMMETRIC_TYPES

        size_was_explicit = size is not None
        if key_type == KeyType.password:
            effective_size = size if size_was_explicit else _DEFAULT_PASSWORD_LENGTH
        else:
            effective_size = size if size_was_explicit else _DEFAULT_KEY_SIZE
        size = effective_size

        if is_asymmetric:
            if output_file:
                output.warn(
                    f"--output-file is ignored for --type {key_type.value}. "
                    "Asymmetric key pairs (private + public) are written as two "
                    "separate files. Use [bold]--out <directory>[/bold] instead."
                )
            if size_was_explicit:
                output.warn(
                    f"--size {size} is ignored for --type {key_type.value}. "
                    "Asymmetric key sizes are fixed by their algorithm "
                    "(RSA-4096, ECC P-256, X25519 32-byte, Ed25519 32-byte)."
                )

        if not is_asymmetric and (key_password or prompt_key_password):
            output.warn(
                f"--key-password / --prompt-key-password is only applicable to "
                f"asymmetric key types ({', '.join(sorted(_ASYMMETRIC_TYPES))}). "
                f"It is ignored for --type {key_type.value}. "
                "The generated key will be stored as plaintext."
            )

        pwd_bytes = (
            _resolve_key_password(key_password, prompt_key_password, confirm=True)
            if is_asymmetric
            else None
        )

        if key_type == KeyType.symmetric:
            key = random_gen.generate_key(size)
            if output_file:
                _write_file(output_file, key.hex().encode(), mode=0o600, force=force)
            elif output_dir:
                _write_file(
                    output_dir / "symmetric.key", key.hex().encode(), mode=0o600, force=force
                )
            else:
                output.result("Symmetric Key (hex)", key.hex())

        elif key_type == KeyType.token:
            tok = random_gen.generate_token(size)
            if output_file:
                _write_file(output_file, tok.encode(), mode=0o600, force=force)
            else:
                output.result("Secure Token", tok)

        elif key_type == KeyType.password:
            if size < _MIN_PASSWORD_LENGTH:
                output.error(
                    f"Password length (--size) must be at least {_MIN_PASSWORD_LENGTH} "
                    f"characters for acceptable security. Got: {size}."
                )
                raise typer.Exit(1)
            pwd = random_gen.generate_password(size)
            if output_file:
                _write_file(output_file, pwd.encode(), mode=0o600, force=force)
            else:
                output.result("Generated Password", pwd)

        elif key_type == KeyType.rsa:
            priv, pub = asymmetric.generate_rsa_keypair()
            _write_asymmetric_keypair(
                asymmetric.private_key_to_pem(priv, pwd_bytes),
                asymmetric.public_key_to_pem(pub),
                "rsa", output_dir, f"RSA-{RSA_KEY_SIZE}", force=force,
            )

        elif key_type == KeyType.ecc:
            priv, pub = asymmetric.generate_ecc_keypair()
            _write_asymmetric_keypair(
                asymmetric.private_key_to_pem(priv, pwd_bytes),
                asymmetric.public_key_to_pem(pub),
                "ecc", output_dir, "ECC P-256", force=force,
            )

        elif key_type == KeyType.x25519:
            priv, pub = asymmetric.generate_x25519_keypair()
            _write_asymmetric_keypair(
                asymmetric.private_key_to_pem(priv, pwd_bytes),
                asymmetric.public_key_to_pem(pub),
                "x25519", output_dir, "X25519", force=force,
            )

        elif key_type == KeyType.ed25519:
            priv, pub = signatures.generate_ed25519_keypair()
            _write_asymmetric_keypair(
                signatures.ed25519_private_key_to_pem(priv, pwd_bytes),
                signatures.ed25519_public_key_to_pem(pub),
                "ed25519", output_dir, "Ed25519", force=force,
            )
