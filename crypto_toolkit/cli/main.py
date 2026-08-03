"""main.py — CLI entry point.

This file is intentionally thin. It is the console-script target declared
in pyproject.toml (`crypto-toolkit = "crypto_toolkit.cli.main:app"`), so the
import path and the `app` object name must keep working unchanged — but all
the actual command logic now lives under cli/commands/, one module per
command group, and shared plumbing lives in cli/_shared.py,
cli/_io_helpers.py, and cli/_password_helpers.py.

See /REFACTORING.md at the repository root for the full line-count
rationale behind this split.
"""

from __future__ import annotations

import typer

from crypto_toolkit.cli.commands import (
    file_cmd,
    hash_cmd,
    kdf_cmd,
    keygen_cmd,
    random_cmd,
    rsa_cmd,
    signature_cmd,
    symmetric_cmd,
    version_cmd,
)

app = typer.Typer(
    name="crypto-toolkit",
    help="Hardened Crypto Toolkit — cryptographic CLI.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Order matches the original main.py's command order so `--help` output is
# unchanged: version, encrypt/decrypt, hash, generate-key, sign/verify,
# rsa-encrypt/rsa-decrypt, encrypt-file/decrypt-file, derive-key, random.
for _module in (
    version_cmd,
    symmetric_cmd,
    hash_cmd,
    keygen_cmd,
    signature_cmd,
    rsa_cmd,
    file_cmd,
    kdf_cmd,
    random_cmd,
):
    _module.register(app)

if __name__ == "__main__":
    app()
