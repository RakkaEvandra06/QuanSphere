"""hash_cmd.py — `crypto-toolkit hash`."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._io_helpers import _read_stdin_bounded
from crypto_toolkit.cli._shared import _handle_errors
from crypto_toolkit.core import hashing
from crypto_toolkit.core.constants import HASH_ALGORITHMS


def register(app: typer.Typer) -> None:
    @app.command(name="hash")
    @_handle_errors
    def hash_cmd(
        data: Optional[str] = typer.Argument(
            None, help="Text to hash (leave blank to use --stdin or --file)."
        ),
        algorithm: str = typer.Option(
            "sha256", "--algo", "-a", help=f"Hash algorithm: {sorted(HASH_ALGORITHMS)}"
        ),
        file: Optional[Path] = typer.Option(None, "--file", "-f", help="Hash a file."),
        stdin: bool = typer.Option(False, "--stdin", help="Read data from stdin."),
    ) -> None:
        """Compute a cryptographic hash (SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b)."""
        if algorithm.lower() not in HASH_ALGORITHMS:
            output.error(
                f"Unknown hash algorithm {algorithm!r}. "
                f"Valid choices: {sorted(HASH_ALGORITHMS)}."
            )
            raise typer.Exit(1)
        if file:
            digest = hashing.hash_file(file, algorithm)
            output.result(f"{algorithm.upper()} ({file.name})", digest)
        elif stdin:
            raw = _read_stdin_bounded("hashing")
            digest = hashing.hash_data(raw, algorithm)
            output.result(f"{algorithm.upper()} (stdin)", digest)
        elif data:
            digest = hashing.hash_data(data.encode(), algorithm)
            output.result(f"{algorithm.upper()}", digest)
        else:
            if sys.stdin.isatty():
                output.info(
                    "No input source specified, reading from stdin. "
                    "Type your data and press Ctrl-D (Unix) or Ctrl-Z+Enter (Windows) "
                    "when finished, or use [bold]--file[/bold] / [bold]--stdin[/bold] "
                    "explicitly."
                )
            raw = _read_stdin_bounded("hashing")
            digest = hashing.hash_data(raw, algorithm)
            output.result(f"{algorithm.upper()} (stdin)", digest)
