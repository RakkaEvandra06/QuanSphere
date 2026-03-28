from __future__ import annotations

import base64
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

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
from crypto_toolkit.core.constants import HASH_ALGORITHMS
from crypto_toolkit.core.exceptions import CryptoToolkitError

app = typer.Typer(
    name="crypto-toolkit",
    help="Hardened Crypto Toolkit — production-grade cryptographic CLI.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _handle_error(exc: Exception) -> None:
    """Translate toolkit errors into CLI-friendly messages and exit."""
    if isinstance(exc, CryptoToolkitError):
        output.error(str(exc))
    else:
        output.error(f"Unexpected error: {type(exc).__name__}")
    raise typer.Exit(code=1)


def _read_plaintext(
    plaintext_arg: Optional[str],
    stdin_flag: bool,
    input_file: Optional[Path],
) -> bytes:

    if stdin_flag:
        return sys.stdin.buffer.read()
    if input_file:
        if not input_file.is_file():
            output.error(f"Input file not found: {input_file}")
            raise typer.Exit(1)
        return input_file.read_bytes()
    if plaintext_arg is not None:
        output.warn(
            "Plaintext supplied as a CLI argument — it may be visible in shell "
            "history and process listings.  Use [bold]--stdin[/bold] or "
            "[bold]--input-file[/bold] for sensitive data."
        )
        return plaintext_arg.encode()
    output.error("Provide plaintext via argument, [bold]--stdin[/bold], or [bold]--input-file[/bold].")
    raise typer.Exit(1)


def _write_output(data: str | bytes, output_file: Optional[Path], label: str) -> None:

    if output_file:
        raw = data.encode() if isinstance(data, str) else data
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(raw)
        output.success(f"Output written to: {output_file}")
    else:
        output.result(label, data if isinstance(data, str) else data.decode(errors="replace"))


# ── Version ───────────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show the toolkit version."""
    output.info(f"Hardened Crypto Toolkit v{__version__}")

# ── encrypt ───────────────────────────────────────────────────────────────────

class SymAlgo(str, Enum):
    aes_gcm = "aes-gcm"
    chacha20 = "chacha20"


@app.command()
def encrypt(
    plaintext: Optional[str] = typer.Argument(
        None,
        help="Text to encrypt. [dim]Prefer --stdin or --input-file to avoid shell history exposure.[/dim]",
    ),
    key_hex: Optional[str] = typer.Option(
        None, "--key", "-k", help="32-byte AES key as hex string."
    ),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        "-p",
        help="Derive key from password (Argon2id).",
        hide_input=True,
    ),
    algorithm: SymAlgo = typer.Option(SymAlgo.aes_gcm, "--algo", "-a", help="Cipher algorithm."),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for password."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read plaintext from stdin (avoids shell history)."),
    input_file: Optional[Path] = typer.Option(None, "--input-file", "-i", help="Read plaintext from file."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write ciphertext to file."),
) -> None:

    try:
        data = _read_plaintext(plaintext, stdin, input_file)

        if prompt_password:
            password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

        if password:
            token = pbe.password_encrypt(data, password)
            _write_output(token, output_file, "Encrypted (PBE)")
            return

        if key_hex:
            key = bytes.fromhex(key_hex)
        else:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        token = symmetric.encrypt(data, key, algorithm=algorithm.value)
        _write_output(token, output_file, "Encrypted")
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── decrypt ───────────────────────────────────────────────────────────────────

@app.command()
def decrypt(
    token: Optional[str] = typer.Argument(None, help="Encrypted token (base64). Omit to use --stdin."),
    key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte key as hex."),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password used during encryption.", hide_input=True
    ),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for password."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read token from stdin."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write plaintext to file."),
) -> None:
    """Decrypt a token produced by the [bold]encrypt[/bold] command."""
    try:
        if stdin:
            raw_token = sys.stdin.read().strip()
        elif token:
            raw_token = token
        else:
            output.error("Provide a token argument or use --stdin.")
            raise typer.Exit(1)

        if prompt_password:
            password = typer.prompt("Password", hide_input=True)

        if password:
            plaintext = pbe.password_decrypt(raw_token, password)
        elif key_hex:
            key = bytes.fromhex(key_hex)
            plaintext = symmetric.decrypt(raw_token, key)
        else:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        _write_output(plaintext, output_file, "Decrypted")
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── hash ──────────────────────────────────────────────────────────────────────

@app.command(name="hash")
def hash_cmd(
    data: Optional[str] = typer.Argument(None, help="Text to hash (omit to hash stdin or --file)."),
    algorithm: str = typer.Option("sha256", "--algo", "-a", help=f"Algorithm: {sorted(HASH_ALGORITHMS)}"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Hash a file instead."),
    stdin: bool = typer.Option(False, "--stdin", help="Read data from stdin."),
) -> None:
    """Compute a cryptographic hash (SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b)."""
    try:
        if file:
            digest = hashing.hash_file(file, algorithm)
            output.result(f"{algorithm.upper()} ({file.name})", digest)
        elif stdin:
            raw = sys.stdin.buffer.read()
            digest = hashing.hash_data(raw, algorithm)
            output.result(f"{algorithm.upper()} (stdin)", digest)
        elif data:
            digest = hashing.hash_data(data.encode(), algorithm)
            output.result(f"{algorithm.upper()}", digest)
        else:
            # Fall back to stdin if no source given (pipe-friendly).
            raw = sys.stdin.buffer.read()
            digest = hashing.hash_data(raw, algorithm)
            output.result(f"{algorithm.upper()} (stdin)", digest)
    except CryptoToolkitError as exc:
        _handle_error(exc)

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
def generate_key(
    key_type: KeyType = typer.Option(KeyType.symmetric, "--type", "-t", help="Key type to generate."),
    output_dir: Optional[Path] = typer.Option(None, "--out", "-o", help="Write keys to directory."),
    key_password: Optional[str] = typer.Option(
        None, "--key-password", help="Encrypt private key with this password.", hide_input=True
    ),
    size: int = typer.Option(32, "--size", "-s", help="Byte size for symmetric key or token."),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", help="Write token/password to file (for token/password types)."
    ),
) -> None:
    """Generate cryptographic keys (symmetric, RSA-4096, ECC P-256, X25519, Ed25519, tokens)."""
    try:
        if key_type == KeyType.symmetric:
            key = random_gen.generate_key(size)
            if output_dir:
                _write_file(output_dir / "symmetric.key", key.hex().encode())
            else:
                output.result("Symmetric Key (hex)", key.hex())

        elif key_type == KeyType.token:
            token = random_gen.generate_token(size)
            if output_file:
                _write_file(output_file, token.encode())
            else:
                output.result("Secure Token", token)

        elif key_type == KeyType.password:
            pwd = random_gen.generate_password()
            if output_file:
                _write_file(output_file, pwd.encode())
            else:
                output.result("Generated Password", pwd)

        elif key_type == KeyType.rsa:
            priv, pub = asymmetric.generate_rsa_keypair()
            pwd_bytes = key_password.encode() if key_password else None
            priv_pem = asymmetric.private_key_to_pem(priv, pwd_bytes)
            pub_pem = asymmetric.public_key_to_pem(pub)
            if output_dir:
                _write_file(output_dir / "rsa_private.pem", priv_pem)
                _write_file(output_dir / "rsa_public.pem", pub_pem)
                output.success(f"RSA-4096 key pair written to {output_dir}/")
            else:
                output.result("RSA Private Key", priv_pem.decode())
                output.result("RSA Public Key", pub_pem.decode())

        elif key_type == KeyType.ecc:
            priv, pub = asymmetric.generate_ecc_keypair()
            pwd_bytes = key_password.encode() if key_password else None
            priv_pem = asymmetric.private_key_to_pem(priv, pwd_bytes)
            pub_pem = asymmetric.public_key_to_pem(pub)
            if output_dir:
                _write_file(output_dir / "ecc_private.pem", priv_pem)
                _write_file(output_dir / "ecc_public.pem", pub_pem)
                output.success(f"ECC P-256 key pair written to {output_dir}/")
            else:
                output.result("ECC Private Key", priv_pem.decode())
                output.result("ECC Public Key", pub_pem.decode())

        elif key_type == KeyType.x25519:
            priv, pub = asymmetric.generate_x25519_keypair()
            pwd_bytes = key_password.encode() if key_password else None
            priv_pem = asymmetric.private_key_to_pem(priv, pwd_bytes)
            pub_pem = asymmetric.public_key_to_pem(pub)
            if output_dir:
                _write_file(output_dir / "x25519_private.pem", priv_pem)
                _write_file(output_dir / "x25519_public.pem", pub_pem)
                output.success(f"X25519 key pair written to {output_dir}/")
            else:
                output.result("X25519 Private Key", priv_pem.decode())
                output.result("X25519 Public Key", pub_pem.decode())

        elif key_type == KeyType.ed25519:
            priv, pub = signatures.generate_ed25519_keypair()
            pwd_bytes = key_password.encode() if key_password else None
            priv_pem = signatures.ed25519_private_key_to_pem(priv, pwd_bytes)
            pub_pem = signatures.ed25519_public_key_to_pem(pub)
            if output_dir:
                _write_file(output_dir / "ed25519_private.pem", priv_pem)
                _write_file(output_dir / "ed25519_public.pem", pub_pem)
                output.success(f"Ed25519 key pair written to {output_dir}/")
            else:
                output.result("Ed25519 Private Key", priv_pem.decode())
                output.result("Ed25519 Public Key", pub_pem.decode())

    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── sign ──────────────────────────────────────────────────────────────────────

@app.command()
def sign(
    data: Optional[str] = typer.Argument(
        None,
        help="Text data to sign. [dim]Prefer --stdin or --input-file.[/dim]",
    ),
    private_key_file: Path = typer.Option(..., "--key", "-k", help="Path to Ed25519 private key PEM."),
    key_password: Optional[str] = typer.Option(
        None, "--key-password", help="Private key password.", hide_input=True
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read data to sign from stdin."),
    input_file: Optional[Path] = typer.Option(None, "--input-file", "-i", help="Read data from file."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write signature to file."),
) -> None:
    """Sign data with an Ed25519 private key."""
    try:
        raw_data = _read_plaintext(data, stdin, input_file)
        pem = private_key_file.read_bytes()
        pwd_bytes = key_password.encode() if key_password else None
        priv = signatures.load_ed25519_private_key(pem, pwd_bytes)
        sig = signatures.sign_ed25519(raw_data, priv)
        sig_b64 = base64.b64encode(sig).decode()
        _write_output(sig_b64, output_file, "Signature (base64)")
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── verify ────────────────────────────────────────────────────────────────────

@app.command()
def verify(
    data: Optional[str] = typer.Argument(
        None,
        help="Original text that was signed. [dim]Prefer --stdin or --input-file.[/dim]",
    ),
    signature_b64: str = typer.Option(..., "--sig", "-s", help="Base64-encoded signature."),
    public_key_file: Path = typer.Option(..., "--key", "-k", help="Path to Ed25519 public key PEM."),
    stdin: bool = typer.Option(False, "--stdin", help="Read original data from stdin."),
    input_file: Optional[Path] = typer.Option(None, "--input-file", "-i", help="Read original data from file."),
) -> None:
    """Verify an Ed25519 signature."""
    try:
        raw_data = _read_plaintext(data, stdin, input_file)
        pem = public_key_file.read_bytes()
        pub = signatures.load_ed25519_public_key(pem)
        sig = base64.b64decode(signature_b64.encode())
        valid = signatures.verify_ed25519(raw_data, sig, pub)
        if valid:
            output.success("Signature is [bold green]VALID[/bold green].")
        else:
            output.error("Signature is INVALID.")
            raise typer.Exit(1)
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── encrypt-file ──────────────────────────────────────────────────────────────

@app.command()
def encrypt_file(
    src: Path = typer.Argument(..., help="Source plaintext file."),
    dst: Path = typer.Argument(..., help="Destination encrypted file."),
    key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte AES key (hex)."),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Derive key from password (embedded in output).", hide_input=True
    ),
    prompt_password: bool = typer.Option(False, "--prompt-password", help="Prompt for password."),
    use_pbkdf2: bool = typer.Option(False, "--pbkdf2", help="Use PBKDF2 instead of Argon2id."),
) -> None:

    try:
        if prompt_password:
            password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

        if password:
            file_crypto.encrypt_file_with_password(
                src, dst, password, use_argon2=not use_pbkdf2
            )
            algo = "PBKDF2" if use_pbkdf2 else "Argon2id"
            output.success(f"Encrypted ({algo}): {src} → {dst}")
            output.info("KDF salt is embedded in the output file — no need to save it separately.")
        elif key_hex:
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                from crypto_toolkit.core.exceptions import InputValidationError
                raise InputValidationError("Key must be exactly 32 bytes (64 hex chars).")
            file_crypto.encrypt_file(src, dst, key)
            output.success(f"Encrypted: {src} → {dst}")
        else:
            output.error("Provide --key (hex) or --password.")
            raise typer.Exit(1)
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── decrypt-file ──────────────────────────────────────────────────────────────

@app.command()
def decrypt_file(
    src: Path = typer.Argument(..., help="Encrypted source file."),
    dst: Path = typer.Argument(..., help="Destination decrypted file."),
    key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte AES key (hex)."),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password used during encryption.", hide_input=True
    ),
    prompt_password: bool = typer.Option(False, "--prompt-password", help="Prompt for password."),
) -> None:

    try:
        if prompt_password:
            password = typer.prompt("Password", hide_input=True)

        if password:
            file_crypto.decrypt_file_with_password(src, dst, password)
            output.success(f"Decrypted: {src} → {dst}")
        elif key_hex:
            key = bytes.fromhex(key_hex)
            file_crypto.decrypt_file(src, dst, key)
            output.success(f"Decrypted: {src} → {dst}")
        else:
            output.error("Provide --key (hex) or --password.")
            raise typer.Exit(1)
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── derive-key ────────────────────────────────────────────────────────────────

@app.command()
def derive_key(
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password to derive key from.", hide_input=True
    ),
    prompt_password: bool = typer.Option(False, "--prompt-password", help="Prompt for password."),
    use_pbkdf2: bool = typer.Option(False, "--pbkdf2", help="Use PBKDF2 instead of Argon2id."),
    salt_hex: Optional[str] = typer.Option(None, "--salt", help="Existing salt (hex) for re-derivation."),
) -> None:
    """Derive an AES-256 key from a password using Argon2id or PBKDF2."""
    try:
        if prompt_password:
            password = typer.prompt("Password", hide_input=True, confirmation_prompt=not salt_hex)
        if not password:
            output.error("Provide --password or --prompt-password.")
            raise typer.Exit(1)

        salt = bytes.fromhex(salt_hex) if salt_hex else None

        if use_pbkdf2:
            derived = kdf.derive_key_pbkdf2(password, salt=salt)
            algo = "PBKDF2-HMAC-SHA256"
        else:
            derived = kdf.derive_key_argon2(password, salt=salt)
            algo = "Argon2id"

        output.result(f"Derived Key ({algo})", derived.key.hex())
        output.result("Salt (save for re-derivation)", derived.salt.hex())
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── random ────────────────────────────────────────────────────────────────────

class RandomKind(str, Enum):
    bytes_hex = "hex"
    bytes_b64 = "base64"
    token = "token"
    password = "password"


@app.command(name="random")
def random_cmd(
    kind: RandomKind = typer.Option(RandomKind.token, "--kind", "-k", help="Output type."),
    nbytes: int = typer.Option(32, "--bytes", "-n", help="Number of random bytes."),
    length: int = typer.Option(20, "--length", "-l", help="Password length (for --kind password)."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to file."),
) -> None:
    """Generate cryptographically secure random data."""
    try:
        if kind == RandomKind.bytes_hex:
            value = random_gen.generate_hex(nbytes)
            _write_output(value, output_file, "Random Hex")
        elif kind == RandomKind.bytes_b64:
            value = random_gen.generate_bytes_b64(nbytes)
            _write_output(value, output_file, "Random Base64")
        elif kind == RandomKind.token:
            value = random_gen.generate_token(nbytes)
            _write_output(value, output_file, "Secure Token")
        elif kind == RandomKind.password:
            value = random_gen.generate_password(length)
            _write_output(value, output_file, "Generated Password")
    except CryptoToolkitError as exc:
        _handle_error(exc)

# ── Private helpers ───────────────────────────────────────────────────────────

def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    output.info(f"Written: {path}")


if __name__ == "__main__":
    app()