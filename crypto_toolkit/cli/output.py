"""output.py — Styled terminal output helpers for the Crypto Toolkit CLI."""

from __future__ import annotations

__all__ = ["success", "info", "warn", "error", "result", "result_bytes"]

from rich.console import Console
from rich.panel import Panel

# stdout console — used for normal output.
console = Console()
# stderr console — used for warnings and errors so they don't pollute piped output.
error_console = Console(stderr=True)

def success(message: str) -> None:
    """Print a green success indicator followed by *message*."""
    console.print(f"[bold green]✓[/bold green] {message}")

def info(message: str) -> None:
    """Print a blue informational indicator followed by *message*."""
    console.print(f"[bold blue]ℹ[/bold blue] {message}")

def warn(message: str) -> None:
    """Print a yellow warning to stderr."""
    error_console.print(f"[bold yellow]⚠[/bold yellow] {message}")

def error(message: str) -> None:
    """Print a red error message to stderr."""
    error_console.print(f"[bold red]✗[/bold red] {message}")

def result(label: str, value: str) -> None:
    """Display *value* inside a labelled panel on stdout."""
    console.print(Panel(value, title=f"[bold cyan]{label}[/bold cyan]", expand=False))

def result_bytes(label: str, data: bytes) -> None:
    """Display raw *data* as a hex-encoded panel on stdout."""
    result(f"{label} (hex)", data.hex())