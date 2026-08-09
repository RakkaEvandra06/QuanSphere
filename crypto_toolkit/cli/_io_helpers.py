"""_io_helpers.py — Reading plaintext/tokens/keys from stdin, files, or CLI
arguments, and writing results back out (atomically, to a file or to the
terminal).

Single responsibility: I/O plumbing only. Password prompting and
asymmetric-keypair-specific writing live in _password_helpers.py.
"""

from __future__ import annotations

__all__ = [
    "_parse_hex",
    "_read_stdin_bounded",
    "_read_ascii_stdin",
    "_read_plaintext",
    "_read_key_file",
    "_atomic_write",
    "_write_file",
    "_write_output",
]

import os as _os
import secrets
import sys
import warnings as _warnings
from pathlib import Path
from typing import Optional

import typer

from crypto_toolkit.cli import output
from crypto_toolkit.cli._shared import _MAX_INLINE_BYTES, _MAX_KEY_FILE_BYTES
from crypto_toolkit.core.exceptions import FileOperationError

# ── Hex / stdin parsing ───────────────────────────────────────────────────────

def _parse_hex(value: str, label: str = "hex value", *, sensitive: bool = False) -> bytes:
    """Parse *value* as a hexadecimal string; exit with an error on failure."""
    try:
        return bytes.fromhex(value)
    except ValueError:
        if sensitive:
            detail = f"received {len(value)} character(s); value withheld (sensitive)."
        else:
            preview = (value[:8] + "...") if len(value) > 8 else value
            detail = f"received {len(value)} character(s) starting with {preview!r}."
        output.error(
            f"{label} is not a valid hexadecimal string "
            f"(expected characters 0-9 and a-f; {detail}) "
            "Ensure you are passing a hex-encoded key, not a raw password or base64 value."
        )
        raise typer.Exit(1)

def _read_stdin_bounded(context_label: str) -> bytes:
    """Read at most *_MAX_INLINE_BYTES* from stdin; exit with an error if the
    stream is larger."""
    data = sys.stdin.buffer.read(_MAX_INLINE_BYTES + 1)
    if len(data) > _MAX_INLINE_BYTES:
        output.error(
            f"stdin data exceeds the {_MAX_INLINE_BYTES // (1024 * 1024)} MiB "
            f"limit for in-memory {context_label}. "
            "Use [bold]encrypt-file[/bold] / [bold]hash --file[/bold] for large "
            "inputs, they process data in 64 KiB chunks without loading the "
            "entire file into memory."
        )
        raise typer.Exit(1)
    return data

def _read_ascii_stdin(context_label: str) -> str:
    """Read at most *_MAX_INLINE_BYTES* from stdin and decode as ASCII."""
    raw_bytes = sys.stdin.buffer.read(_MAX_INLINE_BYTES + 1)
    if len(raw_bytes) > _MAX_INLINE_BYTES:
        output.error(
            f"stdin data exceeds the {_MAX_INLINE_BYTES // (1024 * 1024)} MiB "
            f"limit for in-memory {context_label}. "
            "Pipe a shorter token or write it to a file and use "
            "[bold]--input-file[/bold] instead."
        )
        raise typer.Exit(1)
    try:
        return raw_bytes.decode("ascii").strip()
    except UnicodeDecodeError:
        output.error(
            f"stdin data is not valid ASCII. {context_label} are URL-safe "
            "base64 strings. Ensure you are piping a text token, not raw binary data."
        )
        raise typer.Exit(1)

def _read_plaintext(
    plaintext_arg: Optional[str],
    stdin_flag: bool,
    input_file: Optional[Path],
    *,
    warn_on_cli_arg: bool = True,
) -> bytes:
    """Resolve plaintext from one of three sources: stdin, file, or CLI argument."""
    if stdin_flag and input_file:
        output.warn(
            "--stdin and --input-file were both provided; --stdin takes priority "
            "and the file will be ignored."
        )
    if stdin_flag:
        return _read_stdin_bounded("encryption")
    if input_file:
        if not input_file.is_file():
            output.error(f"Input file not found: {input_file}")
            raise typer.Exit(1)
        try:
            try:
                if input_file.stat().st_size > _MAX_INLINE_BYTES:
                    output.error(
                        f"Input file exceeds the "
                        f"{_MAX_INLINE_BYTES // (1024 * 1024)} MiB limit for "
                        "in-memory encryption. "
                        "Use [bold]encrypt-file[/bold] for large files, it "
                        "processes data in 64 KiB chunks without loading the "
                        "entire file into memory."
                    )
                    raise typer.Exit(1)
            except typer.Exit:
                raise
            except OSError:
                # stat() may fail on exotic filesystems or under race conditions;
                # fall through to read_bytes() which will surface any real I/O error.
                pass

            data = input_file.read_bytes()

            # Authoritative post-read size check — closes the TOCTOU window.
            if len(data) > _MAX_INLINE_BYTES:
                output.error(
                    f"Input file is {len(data) // (1024 * 1024)} MiB, which exceeds "
                    f"the {_MAX_INLINE_BYTES // (1024 * 1024)} MiB limit for "
                    "in-memory encryption. "
                    "Use [bold]encrypt-file[/bold] for large files — it "
                    "processes data in 64 KiB chunks without loading the "
                    "entire file into memory."
                )
                raise typer.Exit(1)

            return data

        except typer.Exit:
            raise
        except OSError as exc:
            output.error(f"Cannot read input file '{input_file}': {exc}")
            raise typer.Exit(1)
    if plaintext_arg is not None:
        if warn_on_cli_arg:
            output.warn(
                "Plaintext provided as a CLI argument, it may appear in the shell history "
                "and the process list. Use [bold]--stdin[/bold] or "
                "[bold]--input-file[/bold] for sensitive data."
            )
        return plaintext_arg.encode()
    output.error(
        "Provide plaintext via argument, [bold]--stdin[/bold], or [bold]--input-file[/bold]."
    )
    raise typer.Exit(1)

# ── Key-file reading ──────────────────────────────────────────────────────────

def _read_key_file(path: Path, label: str = "Key file") -> bytes:
    """Read a PEM key file; raise FileOperationError with a clear message on failure."""
    if not path.is_file():
        raise FileOperationError(f"{label} not found: {path}")
    try:
        size = path.stat().st_size
        if size > _MAX_KEY_FILE_BYTES:
            raise FileOperationError(
                f"{label} '{path}' is {size:,} bytes, which exceeds the "
                f"{_MAX_KEY_FILE_BYTES // 1024} KiB sanity limit for a PEM key file. "
                "This is almost certainly the wrong file."
            )
        return path.read_bytes()
    except FileOperationError:
        raise
    except OSError as exc:
        raise FileOperationError(
            f"Cannot read {label.lower()} '{path}': {exc}"
        ) from exc

# ── Atomic writes ──────────────────────────────────────────────────────────────

def _atomic_write(path: Path, data: bytes, *, mode: int = 0o644, force: bool = False) -> None:
    """Write *data* to *path* atomically via a sibling temp file."""
    if path.exists() and not force:
        raise FileOperationError(
            f"Destination already exists: {path}. "
            "Pass --force to overwrite it, or choose a different destination."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{secrets.token_hex(8)}.tmp")

    fd: int = -1
    fh = None
    try:
        # O_EXCL ensures no other process can race to create the same temp path.
        fd = _os.open(tmp, _os.O_CREAT | _os.O_WRONLY | _os.O_EXCL, mode)

        # Transfer ownership of fd to the file object.  After this line we must
        # never call _os.close(fd) — only fh.close() is valid.
        fh = _os.fdopen(fd, "wb")
        fd = -1  # sentinel: fd now owned by fh; do NOT close it via _os.close

        fh.write(data)

        fh.flush()
        _os.fsync(fh.fileno())

        fh.close()   # explicit close before rename so errors surface here
        fh = None    # mark as already closed

        if force:
            tmp.replace(path)  # atomic on POSIX; best-effort on Windows
        else:
            try:
                _os.link(tmp, path)
            except FileExistsError:
                raise FileOperationError(
                    f"Destination already exists: {path}. "
                    "Pass --force to overwrite it, or choose a different destination."
                )
            finally:
                tmp.unlink(missing_ok=True)

        try:
            dir_fd = _os.open(str(path.parent), _os.O_RDONLY)
            try:
                _os.fsync(dir_fd)
            finally:
                _os.close(dir_fd)
        except OSError as _fsync_exc:
            _warnings.warn(
                f"Could not fsync parent directory of '{path}' after atomic rename "
                f"({_fsync_exc}). "
                "The file is written but may not survive a system crash on some "
                "filesystems. This is expected on Windows, tmpfs, and network shares.",
                RuntimeWarning,
                stacklevel=4,
            )

    except Exception as exc:
        # Close whichever resource still holds the descriptor.
        if fh is not None:
            # fdopen succeeded but write, flush, fsync, or close raised — fh owns fd.
            try:
                fh.close()
            except OSError:
                pass
        elif fd >= 0:
            # fdopen itself failed — fd was never wrapped; close the raw descriptor.
            try:
                _os.close(fd)
            except OSError:
                pass

        tmp.unlink(missing_ok=True)

        if isinstance(exc, OSError):
            raise FileOperationError(f"Failed to write file '{path}': {exc}") from exc
        raise

def _write_file(path: Path, data: bytes, *, mode: int = 0o644, force: bool = False) -> None:
    """Write *data* to *path* atomically, then log the destination path."""
    _atomic_write(path, data, mode=mode, force=force)
    output.info(f"Written: {path}")

def _write_output(
    data: str | bytes, output_file: Optional[Path], label: str, *, force: bool = False
) -> None:
    """Display *data* on the terminal or write it to *output_file*."""
    raw: bytes = data.encode() if isinstance(data, str) else data

    if output_file:
        _atomic_write(output_file, raw, mode=0o600, force=force)
        output.success(f"Output written to: {output_file}")
        return

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        output.warn(
            "Decrypted output contains non-UTF-8 binary data; displaying as hex. "
            "Use [bold]--output <file>[/bold] to write the raw bytes to disk."
        )
        output.result(label + " (hex)", raw.hex())
        return

    output.result(label, text)
