from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()
error_console = Console(stderr=True)


def success(message: str) -> None:
    """Print a green success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def info(message: str) -> None:
    """Print a blue informational message."""
    console.print(f"[bold blue]ℹ[/bold blue] {message}")


def warn(message: str) -> None:
    """Print a yellow warning."""
    error_console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def error(message: str) -> None:
    """Print a red error message to stderr."""
    error_console.print(f"[bold red]✗[/bold red] {message}")


def result(label: str, value: str) -> None:
    """Display a labelled result value in a panel."""
    console.print(Panel(value, title=f"[bold cyan]{label}[/bold cyan]", expand=False))


def result_bytes(label: str, data: bytes) -> None:
    """Display raw bytes as a hex dump panel."""
    hex_str = data.hex()
    result(label, hex_str)