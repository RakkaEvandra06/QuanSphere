"""version_cmd.py — `crypto-toolkit version`."""

from __future__ import annotations

import typer

from crypto_toolkit.cli import __version__, output
from crypto_toolkit.cli._shared import _handle_errors


def register(app: typer.Typer) -> None:
    @app.command()
    @_handle_errors
    def version() -> None:
        """Display the toolkit version."""
        output.info(f"Hardened Crypto Toolkit v{__version__}")
