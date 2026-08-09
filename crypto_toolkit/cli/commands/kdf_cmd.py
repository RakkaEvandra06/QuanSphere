"""kdf_cmd.py — `crypto-toolkit derive-key`."""

from __future__ import annotations

from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _parse_hex
from crypto_toolkit.cli._password_helpers import _resolve_password
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import kdf
from crypto_toolkit.core.kdf import PBKDF2_SUPPORTED_HASHES, zero_key

# Valid PBKDF2 hash choices — derived from kdf.PBKDF2_SUPPORTED_HASHES (single source of truth).
# Adding a hash to kdf._PBKDF2_HASH_FACTORIES automatically exposes it here.
_PBKDF2_HASH_CHOICES = tuple(sorted(PBKDF2_SUPPORTED_HASHES))

def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def derive_key(
        password: Optional[str] = typer.Option(
            None, "--password", "-p",
            help="Password to derive a key from.",
            hide_input=True,
        ),
        prompt_password: bool = typer.Option(
            False, "--prompt-password", help="Interactively prompt for a password."
        ),
        use_pbkdf2: bool = typer.Option(False, "--pbkdf2", help="Use PBKDF2 instead of Argon2id."),
        salt_hex: Optional[str] = typer.Option(
            None, "--salt", help="Existing salt (hex) for re-derivation."
        ),
        hash_algo: str = typer.Option(
            "sha256",
            "--hash-algo",
            help=(
                f"PBKDF2 hash algorithm (ignored for Argon2id). "
                f"Choices: {_PBKDF2_HASH_CHOICES}."
            ),
        ),
    ) -> None:
        """Derive an AES-256 key from a password using Argon2id or PBKDF2."""
        if prompt_password or password:
            resolved = _resolve_password(password, prompt_password, confirm=not salt_hex)
        else:
            output.error("Provide --password or --prompt-password.")
            raise typer.Exit(1)

        salt = _parse_hex(salt_hex, "--salt") if salt_hex else None

        if use_pbkdf2:
            if hash_algo not in _PBKDF2_HASH_CHOICES:
                output.error(
                    f"Invalid --hash-algo {hash_algo!r}. "
                    f"Choose from: {_PBKDF2_HASH_CHOICES}."
                )
                raise typer.Exit(1)
            derived = kdf.derive_key_pbkdf2(resolved, salt=salt, hash_algorithm=hash_algo)
            algo_label = f"PBKDF2-HMAC-{hash_algo.upper()}"
        else:
            if hash_algo != "sha256":
                output.warn(
                    f"--hash-algo {hash_algo!r} is only meaningful with --pbkdf2. "
                    "Argon2id does not use a separate hash-algorithm parameter; "
                    "the flag will be ignored."
                )
            derived = kdf.derive_key_argon2(resolved, salt=salt)
            algo_label = "Argon2id"
        try:
            output.result(f"Derived Key ({algo_label})", derived.key.hex())
            output.result("Salt (save this for re-derivation)", derived.salt.hex())
        finally:
            zero_key(derived.key)
