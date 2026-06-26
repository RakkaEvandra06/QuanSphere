from __future__ import annotations

import base64
import functools
import os as _os
import secrets
import sys
import warnings as _warnings
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, TypeVar

import typer
from rich.console import Console

from crypto_toolkit.cli import __version__
from crypto_toolkit.cli import output
from crypto_toolkit.core import (
    asymmetric,
    file_crypto,
    hashing,
    kdf,
    pbe,
    random_gen,
    signatures,
    symmetric,
)
from crypto_toolkit.core.constants import HASH_ALGORITHMS, PASSWORD_MIN_LENGTH
from crypto_toolkit.core.exceptions import (
    CryptoToolkitError,
    FileOperationError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import PBKDF2_SUPPORTED_HASHES, zero_key

app = typer.Typer(
    name="crypto-toolkit",
    help="Hardened Crypto Toolkit — cryptographic CLI.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

# ── Shared helpers ────────────────────────────────────────────────────────────

_F = TypeVar("_F", bound=Callable[..., object])

# Minimum password character length — single source of truth lives in constants.py.
_MIN_PASSWORD_LENGTH: int = PASSWORD_MIN_LENGTH

_DEFAULT_PASSWORD_LENGTH: int = 20
_DEFAULT_KEY_SIZE: int = 32  # symmetric / token default (AES-256 = 32 bytes)

# Key types that produce a private+public pair written into a directory.
_ASYMMETRIC_TYPES = frozenset({"rsa", "ecc", "x25519", "ed25519"})

_MAX_INLINE_BYTES: int = 64 * 1024 * 1024  # 64 MiB

def _handle_error(exc: Exception) -> None:
    """Translate a toolkit exception into a user-friendly CLI message, then exit."""
    if isinstance(exc, CryptoToolkitError):
        output.error(str(exc))
    else:
        output.error(
            f"Unexpected internal error ({type(exc).__name__}). "
            "This may indicate a bug, please report it."
        )
    raise typer.Exit(code=1)

def _handle_errors(fn: _F) -> _F:
    """Decorator: catch all exceptions from a CLI command and route to _handle_error."""
    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> object:
        try:
            return fn(*args, **kwargs)
        except typer.Exit:
            raise  # explicit typer.Exit(1) calls inside commands propagate unchanged
        except Exception as exc:
            _handle_error(exc)
            return None  # unreachable; satisfies the type checker
    return wrapper  # type: ignore[return-value]

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

_MAX_KEY_FILE_BYTES: int = 1 * 1024 * 1024  # 1 MiB

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

def _warn_cli_password() -> None:
    """Emit the standard warning when a password is passed as a CLI argument."""
    output.warn(
        "Password provided as a CLI argument, it may appear in shell "
        "history and the process list. Use "
        "[bold]--prompt-password[/bold] for sensitive passwords."
    )

def _resolve_password(
    password: Optional[str],
    prompt_password: bool,
    *,
    confirm: bool = False,
    enforce_min_length: bool = True,
) -> str:
    """Return the effective password, prompting interactively when requested."""
    if prompt_password:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=confirm)
    elif password:
        _warn_cli_password()

    if not password:
        output.error("Password must not be empty.")
        raise typer.Exit(1)

    if enforce_min_length and len(password) < _MIN_PASSWORD_LENGTH:
        output.error(
            f"Password is too short ({len(password)} character(s)); "
            f"minimum is {_MIN_PASSWORD_LENGTH} characters. "
            "Run [bold]crypto-toolkit generate-key --type password[/bold] to "
            "generate a strong password."
        )
        raise typer.Exit(1)

    return password

def _resolve_key_password(
    key_password: Optional[str],
    prompt_key_password: bool,
    *,
    confirm: bool = False,
) -> Optional[bytes]:
    """Return the PEM encryption password as bytes, or None if not set."""
    if prompt_key_password:
        pwd = typer.prompt(
            "Key password (press Enter for none)",
            hide_input=True,
            confirmation_prompt=confirm,
        )
        if pwd:
            return pwd.encode()
        # User pressed Enter without typing — explicitly treat as no password.
        output.info(
            "No key password entered, PEM will be loaded or saved as unencrypted."
        )
        return None
    if key_password:
        output.warn(
            "Key password provided as a CLI argument, it may appear in shell "
            "history and the process list. "
            "Use [bold]--prompt-key-password[/bold] to avoid this."
        )
        return key_password.encode()
    return None

def _write_asymmetric_keypair(
    priv_pem: bytes,
    pub_pem: bytes,
    key_name: str,
    output_dir: Optional[Path],
    label: str,
    *,
    force: bool = False,
) -> None:
    """Write or display an asymmetric key pair."""
    if output_dir:
        _write_file(output_dir / f"{key_name}_private.pem", priv_pem, mode=0o600, force=force)
        _write_file(output_dir / f"{key_name}_public.pem", pub_pem, force=force)
        output.success(f"{label} key pair written to {output_dir}/")
    else:
        output.result(f"{label} Private Key", priv_pem.decode())
        output.result(f"{label} Public Key", pub_pem.decode())

# ── Version ───────────────────────────────────────────────────────────────────

@app.command()
@_handle_errors
def version() -> None:
    """Display the toolkit version."""
    output.info(f"Hardened Crypto Toolkit v{__version__}")

# ── encrypt ───────────────────────────────────────────────────────────────────

class SymAlgo(str, Enum):
    aes_gcm = "aes-gcm"
    chacha20 = "chacha20"

@app.command()
@_handle_errors
def encrypt(
    plaintext: Optional[str] = typer.Argument(
        None,
        help="Text to encrypt. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
    ),
    key_hex: Optional[str] = typer.Option(
        None, "--key", "-k", help="32-byte symmetric key as a hex string (AES-256 or ChaCha20)."
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Derive key from password (Argon2id).", hide_input=True,
    ),
    algorithm: SymAlgo = typer.Option(SymAlgo.aes_gcm, "--algo", "-a", help="Cipher algorithm."),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for a password."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read plaintext from stdin."),
    input_file: Optional[Path] = typer.Option(
        None, "--input-file", "-i", help="Read plaintext from a file."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write ciphertext to a file."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the output file if it already exists."
    ),
) -> None:
    """Encrypt data using AES-256-GCM or ChaCha20-Poly1305."""
    data = _read_plaintext(plaintext, stdin, input_file)

    if (prompt_password or password) and key_hex:
        output.warn(
            "Both --password/--prompt-password and --key were provided; "
            "--password takes priority and --key will be ignored."
        )

    if prompt_password or password:
        resolved = _resolve_password(password, prompt_password, confirm=True)
        if algorithm != SymAlgo.aes_gcm:
            output.error(
                f"[bold]--algo {algorithm.value!r}[/bold] cannot be combined with "
                "[bold]--password[/bold]. "
                "Password-based encryption always uses AES-256-GCM via the PBE path. "
                "To use ChaCha20-Poly1305, omit [bold]--password[/bold] and supply "
                "a raw 32-byte key with [bold]--key[/bold] instead."
            )
            raise typer.Exit(1)

        token = pbe.password_encrypt(data, resolved)
        _write_output(token, output_file, "Encrypted (PBE)", force=force)
        return

    if not key_hex:
        output.error("Provide --key or --password.")
        raise typer.Exit(1)

    key = _parse_hex(key_hex, "--key", sensitive=True)
    token = symmetric.encrypt(data, key, algorithm=algorithm.value)
    _write_output(token, output_file, "Encrypted", force=force)

# ── decrypt ───────────────────────────────────────────────────────────────────

@app.command()
@_handle_errors
def decrypt(
    token: Optional[str] = typer.Argument(
        None, help="Encrypted token (base64). Leave empty to use --stdin."
    ),
    key_hex: Optional[str] = typer.Option(
        None, "--key", "-k", help="32-byte key as a hex string."
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password used during encryption.", hide_input=True
    ),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for a password."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read token from stdin."),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write decrypted plaintext to a file."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the output file if it already exists."
    ),
) -> None:
    """Decrypt an encrypted token produced by the [bold]encrypt[/bold] command."""
    if stdin:
        raw_token = _read_ascii_stdin("Encrypted tokens")
    elif token:
        raw_token = token
    else:
        output.error("Provide a token argument or use --stdin.")
        raise typer.Exit(1)

    if (prompt_password or password) and key_hex:
        output.warn(
            "Both --password/--prompt-password and --key were provided; "
            "--password takes priority and --key will be ignored."
        )

    if prompt_password or password:
        resolved = _resolve_password(
            password, prompt_password, confirm=False, enforce_min_length=False
        )
        plaintext = pbe.password_decrypt(raw_token, resolved)
    elif key_hex:
        key = _parse_hex(key_hex, "--key", sensitive=True)
        plaintext = symmetric.decrypt(raw_token, key)
    else:
        output.error("Provide --key or --password.")
        raise typer.Exit(1)

    _write_output(plaintext, output_file, "Decrypted", force=force)

# ── hash ──────────────────────────────────────────────────────────────────────

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

# ── generate-key ──────────────────────────────────────────────────────────────

class KeyType(str, Enum):
    symmetric = "symmetric"
    rsa = "rsa"
    ecc = "ecc"
    x25519 = "x25519"
    ed25519 = "ed25519"
    token = "token"
    password = "password"

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
    """Generate cryptographic keys (symmetric, RSA-4096, ECC P-256, X25519, Ed25519, token, password)."""
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
            _write_file(output_dir / "symmetric.key", key.hex().encode(), mode=0o600, force=force)
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
        from crypto_toolkit.core.constants import RSA_KEY_SIZE as _RSA_KEY_SIZE
        priv, pub = asymmetric.generate_rsa_keypair()
        _write_asymmetric_keypair(
            asymmetric.private_key_to_pem(priv, pwd_bytes),
            asymmetric.public_key_to_pem(pub),
            "rsa", output_dir, f"RSA-{_RSA_KEY_SIZE}", force=force,
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

# ── sign ──────────────────────────────────────────────────────────────────────

class SignAlgo(str, Enum):
    ed25519 = "ed25519"
    rsa_pss = "rsa-pss"

@app.command()
@_handle_errors
def sign(
    data: Optional[str] = typer.Argument(
        None,
        help="Data to sign. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
    ),
    private_key_file: Path = typer.Option(..., "--key", "-k", help="Path to the PEM private key."),
    key_password: Optional[str] = typer.Option(
        None,
        "--key-password",
        help=(
            "Password protecting the private key. "
            "Warning: visible in process list and shell history. "
            "Prefer [bold]--prompt-key-password[/bold] for sensitive keys."
        ),
        hide_input=True,
    ),
    prompt_key_password: bool = typer.Option(
        False,
        "--prompt-key-password",
        help="Interactively prompt for the private key password (never exposed in shell history).",
    ),
    algorithm: SignAlgo = typer.Option(
        SignAlgo.ed25519, "--algo", "-a",
        help="Signature algorithm: ed25519 (default) or rsa-pss.",
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read data from stdin."),
    input_file: Optional[Path] = typer.Option(
        None, "--input-file", "-i", help="Read data from a file."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write signature to a file."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the output file if it already exists."
    ),
) -> None:
    """Sign data with an Ed25519 or RSA-PSS private key."""
    raw_data = _read_plaintext(data, stdin, input_file, warn_on_cli_arg=False)
    pem = _read_key_file(private_key_file, "Private key file")
    pwd_bytes = _resolve_key_password(key_password, prompt_key_password)

    if algorithm == SignAlgo.ed25519:
        priv = signatures.load_ed25519_private_key(pem, pwd_bytes)
        sig = signatures.sign_ed25519(raw_data, priv)
    else:  # rsa-pss
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        priv = asymmetric.load_private_key(pem, pwd_bytes)
        if not isinstance(priv, RSAPrivateKey):
            raise InputValidationError(
                "RSA-PSS signing requires an RSA private key; "
                f"received {type(priv).__name__}. "
                "Ensure you are passing the correct key file."
            )
        sig = signatures.sign_rsa_pss(raw_data, priv)

    _write_output(
        base64.b64encode(sig).decode(), output_file,
        f"Signature ({algorithm.value}, base64)", force=force,
    )

# ── verify ────────────────────────────────────────────────────────────────────

@app.command()
@_handle_errors
def verify(
    data: Optional[str] = typer.Argument(
        None,
        help="Original data to verify. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
    ),
    signature_b64: str = typer.Option(..., "--sig", "-s", help="Base64-encoded signature."),
    public_key_file: Path = typer.Option(..., "--key", "-k", help="Path to the PEM public key."),
    algorithm: SignAlgo = typer.Option(
        SignAlgo.ed25519, "--algo", "-a",
        help="Signature algorithm: ed25519 (default) or rsa-pss.",
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read original data from stdin."),
    input_file: Optional[Path] = typer.Option(
        None, "--input-file", "-i", help="Read original data from a file."
    ),
) -> None:
    """Verify an Ed25519 or RSA-PSS signature."""
    raw_data = _read_plaintext(data, stdin, input_file, warn_on_cli_arg=False)
    pem = _read_key_file(public_key_file, "Public key file")

    try:
        sig = base64.b64decode(signature_b64.encode())
    except Exception:
        output.error(
            "--sig value is not valid base64. "
            "Ensure the signature was not truncated or modified."
        )
        raise typer.Exit(1)
    if algorithm == SignAlgo.ed25519:
        pub = signatures.load_ed25519_public_key(pem)
        signatures.verify_ed25519_or_raise(raw_data, sig, pub)
    else:  # rsa-pss
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        pub = asymmetric.load_public_key(pem)
        if not isinstance(pub, RSAPublicKey):
            raise InputValidationError(
                "RSA-PSS verification requires an RSA public key; "
                f"received {type(pub).__name__}. "
                "Ensure you are passing the correct key file."
            )
        signatures.verify_rsa_pss_or_raise(raw_data, sig, pub)

    output.success(f"Signature ({algorithm.value}) VALID.")

# ── rsa-encrypt ───────────────────────────────────────────────────────────────

@app.command(name="rsa-encrypt")
@_handle_errors
def rsa_encrypt_cmd(
    plaintext: Optional[str] = typer.Argument(
        None,
        help="Text to encrypt. [dim]Use --stdin or --input-file for sensitive data.[/dim]",
    ),
    public_key_file: Path = typer.Option(..., "--key", "-k", help="Path to the RSA PEM public key."),
    stdin: bool = typer.Option(False, "--stdin", help="Read plaintext from stdin."),
    input_file: Optional[Path] = typer.Option(
        None, "--input-file", "-i", help="Read plaintext from a file."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write ciphertext to a file."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the output file if it already exists."
    ),
) -> None:
    """Encrypt data with an RSA-4096 public key (OAEP / SHA-256)."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    data = _read_plaintext(plaintext, stdin, input_file)
    pem = _read_key_file(public_key_file, "Public key file")
    pub = asymmetric.load_public_key(pem)

    if not isinstance(pub, RSAPublicKey):
        raise InputValidationError(
            "rsa-encrypt requires an RSA public key; "
            f"received {type(pub).__name__}. "
            "Ensure you are passing an RSA PEM file."
        )

    raw_ct = asymmetric.rsa_encrypt(data, pub)
    _write_output(
        base64.b64encode(raw_ct).decode(), output_file, "RSA Ciphertext (base64)", force=force
    )

# ── rsa-decrypt ───────────────────────────────────────────────────────────────

@app.command(name="rsa-decrypt")
@_handle_errors
def rsa_decrypt_cmd(
    ciphertext_b64: Optional[str] = typer.Argument(
        None, help="Base64-encoded RSA ciphertext. Leave empty to use --stdin."
    ),
    private_key_file: Path = typer.Option(..., "--key", "-k", help="Path to the RSA PEM private key."),
    key_password: Optional[str] = typer.Option(
        None,
        "--key-password",
        help=(
            "Password protecting the private key. "
            "Warning: visible in process list and shell history. "
            "Prefer [bold]--prompt-key-password[/bold] for sensitive keys."
        ),
        hide_input=True,
    ),
    prompt_key_password: bool = typer.Option(
        False,
        "--prompt-key-password",
        help="Interactively prompt for the private key password (never exposed in shell history).",
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read ciphertext from stdin."),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write plaintext to a file."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the output file if it already exists."
    ),
) -> None:
    """Decrypt RSA-OAEP ciphertext with a private key."""
    if stdin:
        raw_b64 = _read_ascii_stdin("RSA ciphertext")
    elif ciphertext_b64:
        raw_b64 = ciphertext_b64
    else:
        output.error("Provide a ciphertext argument or use --stdin.")
        raise typer.Exit(1)

    pem = _read_key_file(private_key_file, "Private key file")
    pwd_bytes = _resolve_key_password(key_password, prompt_key_password)
    priv = asymmetric.load_private_key(pem, pwd_bytes)

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    if not isinstance(priv, RSAPrivateKey):
        raise InputValidationError(
            "rsa-decrypt requires an RSA private key; "
            f"received {type(priv).__name__}. "
            "Ensure you are passing the correct PEM key file."
        )

    try:
        ct_bytes = base64.b64decode(raw_b64)
    except Exception:
        output.error(
            "Ciphertext is not valid base64. Ensure the value was copied "
            "completely and was not modified in transit."
        )
        raise typer.Exit(1)

    plaintext = asymmetric.rsa_decrypt(ct_bytes, priv)
    _write_output(plaintext, output_file, "RSA Decrypted", force=force)

# ── encrypt-file ──────────────────────────────────────────────────────────────

@app.command()
@_handle_errors
def encrypt_file(
    src: Path = typer.Argument(..., help="Source plaintext file."),
    dst: Path = typer.Argument(..., help="Encrypted destination file."),
    key_hex: Optional[str] = typer.Option(
        None, "--key", "-k", help="32-byte AES-256 key (hex)."
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Derive key from password (embedded in output).",
        hide_input=True,
    ),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for a password."
    ),
    use_pbkdf2: bool = typer.Option(False, "--pbkdf2", help="Use PBKDF2 instead of Argon2id."),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the destination file if it already exists."
    ),
) -> None:
    """Encrypt a file with AES-256-GCM using a raw key or password (Argon2id/PBKDF2)."""
    if (prompt_password or password) and key_hex:
        output.warn(
            "Both --password/--prompt-password and --key were provided; "
            "--password takes priority and --key will be ignored."
        )
    if prompt_password or password:
        resolved = _resolve_password(password, prompt_password, confirm=True)
        file_crypto.encrypt_file_with_password(
            src, dst, resolved, use_argon2=not use_pbkdf2, force=force
        )
        algo = "PBKDF2" if use_pbkdf2 else "Argon2id"
        output.success(f"Encrypted ({algo}): {src} -> {dst}")
        output.info("The KDF salt is embedded in the output file, no need to save it separately.")
    elif key_hex:
        key = _parse_hex(key_hex, "--key", sensitive=True)
        file_crypto.encrypt_file(src, dst, key, force=force)
        output.success(f"Encrypted: {src} -> {dst}")
    else:
        output.error("Provide --key (hex) or --password.")
        raise typer.Exit(1)

# ── decrypt-file ──────────────────────────────────────────────────────────────

@app.command()
@_handle_errors
def decrypt_file(
    src: Path = typer.Argument(..., help="Encrypted source file."),
    dst: Path = typer.Argument(..., help="Decrypted destination file."),
    key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte AES key (hex)."),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password used during encryption.", hide_input=True
    ),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for a password."
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite the destination file if it already exists."
    ),
) -> None:
    """Decrypt a file encrypted with [bold]encrypt-file[/bold]."""
    if (prompt_password or password) and key_hex:
        output.warn(
            "Both --password/--prompt-password and --key were provided; "
            "--password takes priority and --key will be ignored."
        )
    if prompt_password or password:
        # enforce_min_length=False: same rationale as the symmetric decrypt
        # command — decryption must never be blocked by a write-time policy.
        resolved = _resolve_password(
            password, prompt_password, confirm=False, enforce_min_length=False
        )
        file_crypto.decrypt_file_with_password(src, dst, resolved, force=force)
        output.success(f"Decrypted: {src} -> {dst}")
    elif key_hex:
        key = _parse_hex(key_hex, "--key", sensitive=True)
        file_crypto.decrypt_file(src, dst, key, force=force)
        output.success(f"Decrypted: {src} -> {dst}")
    else:
        output.error("Provide --key (hex) or --password.")
        raise typer.Exit(1)

# ── derive-key ────────────────────────────────────────────────────────────────

# Valid PBKDF2 hash choices — derived from kdf.PBKDF2_SUPPORTED_HASHES (single source of truth).
# Adding a hash to kdf._PBKDF2_HASH_FACTORIES automatically exposes it here.
_PBKDF2_HASH_CHOICES = tuple(sorted(PBKDF2_SUPPORTED_HASHES))

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

# ── random ────────────────────────────────────────────────────────────────────

class RandomKind(str, Enum):
    bytes_hex = "hex"
    bytes_b64 = "base64"
    token = "token"
    password = "password"

@app.command(name="random")
@_handle_errors
def random_cmd(
    kind: RandomKind = typer.Option(RandomKind.token, "--kind", "-k", help="Output type."),
    nbytes: int = typer.Option(32, "--bytes", "-n", help="Number of random bytes."),
    length: int = typer.Option(20, "--length", "-l", help="Password length (for --kind password)."),
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
        _write_output(random_gen.generate_bytes_b64(nbytes), output_file, "Random Base64", force=force)
    elif kind == RandomKind.token:
        _write_output(random_gen.generate_token(nbytes), output_file, "Secure Token", force=force)
    elif kind == RandomKind.password:
        _write_output(random_gen.generate_password(length), output_file, "Generated Password", force=force)
    else:
        # Defensive: unreachable as long as RandomKind is kept in sync.
        output.error(f"Unknown random kind: {kind!r}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()