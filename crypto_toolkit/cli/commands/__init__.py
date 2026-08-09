"""crypto_toolkit.cli.commands — one module per CLI command group.

Every module exposes a single `register(app: typer.Typer) -> None` function
that attaches its command(s) to the shared Typer app. cli/main.py imports
each module and calls `register()` — this keeps command modules decoupled
from each other and avoids any circular import with main.py.
"""
