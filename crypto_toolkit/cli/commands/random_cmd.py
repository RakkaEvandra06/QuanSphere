"""random_cmd.py — `crypto-toolkit random`."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _write_output
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import random_gen


class RandomKind(str, Enum):
    bytes_hex = "hex"
    bytes_b64 = "base64"
    token = "token"
    password = "password"

def register(app: typer.Typer) -> None:
    @app.command(name="random")
    @_handle_errors
    def random_cmd(
        kind: RandomKind = typer.Option(RandomKind.token, "--kind", "-k", help="Output type."),
        nbytes: int = typer.Option(32, "--bytes", "-n", help="Number of random bytes."),
        length: int = typer.Option(
            20, "--length", "-l", help="Password length (for --kind password)."
        ),
        output_file: Optional[Path] = typer.Option(
            None, "--output", "-o", help="Write output to a file."
        ),
        force: bool = typer.Option(
            False, "--force", help="Overwrite the output file if it already exists."
        ),
    ) -> None:
        """Generate cryptographically secure random data."""
        if kind == RandomKind.bytes_hex:
            _write_output(random_gen.generate_hex(nbytes), output_file, "Random Hex", force=force)
        elif kind == RandomKind.bytes_b64:
            _write_output(
                random_gen.generate_bytes_b64(nbytes), output_file, "Random Base64", force=force
            )
        elif kind == RandomKind.token:
            _write_output(
                random_gen.generate_token(nbytes), output_file, "Secure Token", force=force
            )
        elif kind == RandomKind.password:
            _write_output(
                random_gen.generate_password(length), output_file, "Generated Password", force=force
            )
        else:
            # Defensive: unreachable as long as RandomKind is kept in sync.
            output.error(f"Unknown random kind: {kind!r}")
            raise typer.Exit(1)
