"""Main CLI application for the Hardened Crypto Toolkit.

Entry point: ``crypto-toolkit`` (defined in pyproject.toml ``[project.scripts]``).

All sensitive inputs (passwords, keys) are read via ``typer.Option(prompt=True,
hide_input=True)`` to avoid shell-history exposure.
"""

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
    plaintext: str = typer.Argument(..., help="Text to encrypt."),
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
) -> None:
    """Encrypt text using AES-256-GCM or ChaCha20-Poly1305.

    Supply either [bold]--key[/bold] (hex) or [bold]--password[/bold].
    """
    try:
        data = plaintext.encode()

        if prompt_password:
            password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

        if password:
            token = pbe.password_encrypt(data, password)
            output.result("Encrypted (PBE)", token)
            return

        if key_hex:
            key = bytes.fromhex(key_hex)
        else:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        token = symmetric.encrypt(data, key, algorithm=algorithm.value)
        output.result("Encrypted", token)
    except CryptoToolkitError as exc:
        _handle_error(exc)


# ── decrypt ───────────────────────────────────────────────────────────────────


@app.command()
def decrypt(
    token: str = typer.Argument(..., help="Encrypted token (base64)."),
    key_hex: Optional[str] = typer.Option(None, "--key", "-k", help="32-byte key as hex."),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="Password used during encryption.", hide_input=True
    ),
    prompt_password: bool = typer.Option(
        False, "--prompt-password", help="Interactively prompt for password."
    ),
) -> None:
    """Decrypt a token produced by the [bold]encrypt[/bold] command."""
    try:
        if prompt_password:
            password = typer.prompt("Password", hide_input=True)

        if password:
            plaintext = pbe.password_decrypt(token, password)
        elif key_hex:
            key = bytes.fromhex(key_hex)
            plaintext = symmetric.decrypt(token, key)
        else:
            output.error("Provide --key or --password.")
            raise typer.Exit(1)

        output.result("Decrypted", plaintext.decode(errors="replace"))
    except CryptoToolkitError as exc:
        _handle_error(exc)


# ── hash ──────────────────────────────────────────────────────────────────────


@app.command(name="hash")
def hash_cmd(
    data: Optional[str] = typer.Argument(None, help="Text to hash (omit to hash stdin)."),
    algorithm: str = typer.Option("sha256", "--algo", "-a", help=f"Algorithm: {sorted(HASH_ALGORITHMS)}"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Hash a file instead."),
) -> None:
    """Compute a cryptographic hash (SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b)."""
    try:
        if file:
            digest = hashing.hash_file(file, algorithm)
            output.result(f"{algorithm.upper()} ({file.name})", digest)
        elif data:
            digest = hashing.hash_data(data.encode(), algorithm)
            output.result(f"{algorithm.upper()}", digest)
        else:
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
    size: int = typer.Option(32, "--size", "-s", help="Byte size for symmetric key."),
) -> None:
    """Generate cryptographic keys (symmetric, RSA-4096, ECC P-256, Ed25519, tokens)."""
    try:
        if key_type == KeyType.symmetric:
            key = random_gen.generate_key(size)
            output.result("Symmetric Key (hex)", key.hex())
            if output_dir:
                _write_file(output_dir / "symmetric.key", key.hex().encode())

        elif key_type == KeyType.token:
            token = random_gen.generate_token()
            output.result("Secure Token", token)

        elif key_type == KeyType.password:
            pwd = random_gen.generate_password()
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
    data: str = typer.Argument(..., help="Text data to sign."),
    private_key_file: Path = typer.Option(..., "--key", "-k", help="Path to Ed25519 private key PEM."),
    key_password: Optional[str] = typer.Option(
        None, "--key-password", help="Private key password.", hide_input=True
    ),
) -> None:
    """Sign data with an Ed25519 private key."""
    try:
        pem = private_key_file.read_bytes()
        pwd_bytes = key_password.encode() if key_password else None
        priv = signatures.load_ed25519_private_key(pem, pwd_bytes)
        sig = signatures.sign_ed25519(data.encode(), priv)
        output.result("Signature (base64)", base64.b64encode(sig).decode())
    except CryptoToolkitError as exc:
        _handle_error(exc)


# ── verify ────────────────────────────────────────────────────────────────────


@app.command()
def verify(
    data: str = typer.Argument(..., help="Original text that was signed."),
    signature_b64: str = typer.Option(..., "--sig", "-s", help="Base64-encoded signature."),
    public_key_file: Path = typer.Option(..., "--key", "-k", help="Path to Ed25519 public key PEM."),
) -> None:
    """Verify an Ed25519 signature."""
    try:
        pem = public_key_file.read_bytes()
        pub = signatures.load_ed25519_public_key(pem)
        sig = base64.b64decode(signature_b64.encode())
        valid = signatures.verify_ed25519(data.encode(), sig, pub)
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
        None, "--password", "-p", help="Derive key from password.", hide_input=True
    ),
    prompt_password: bool = typer.Option(False, "--prompt-password", help="Prompt for password."),
) -> None:
    """Encrypt a file using chunked AES-256-GCM (handles large files)."""
    try:
        key = _resolve_file_key(key_hex, password, prompt_password, confirm=True)
        file_crypto.encrypt_file(src, dst, key)
        output.success(f"Encrypted: {src} → {dst}")
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
    """Decrypt a file encrypted by the [bold]encrypt-file[/bold] command."""
    try:
        key = _resolve_file_key(key_hex, password, prompt_password, confirm=False)
        file_crypto.decrypt_file(src, dst, key)
        output.success(f"Decrypted: {src} → {dst}")
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
        output.result("Salt (save this!)", derived.salt.hex())
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
) -> None:
    """Generate cryptographically secure random data."""
    try:
        if kind == RandomKind.bytes_hex:
            output.result("Random Hex", random_gen.generate_hex(nbytes))
        elif kind == RandomKind.bytes_b64:
            output.result("Random Base64", random_gen.generate_bytes_b64(nbytes))
        elif kind == RandomKind.token:
            output.result("Secure Token", random_gen.generate_token(nbytes))
        elif kind == RandomKind.password:
            output.result("Generated Password", random_gen.generate_password(length))
    except CryptoToolkitError as exc:
        _handle_error(exc)


# ── Private helpers ───────────────────────────────────────────────────────────


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    output.info(f"Written: {path}")


def _resolve_file_key(
    key_hex: Optional[str],
    password: Optional[str],
    prompt_password: bool,
    *,
    confirm: bool,
) -> bytes:
    """Return a 32-byte AES key from hex or a password-derived one."""
    from crypto_toolkit.core.exceptions import InputValidationError

    if prompt_password:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=confirm)

    if password:
        derived = kdf.derive_key_argon2(password)
        output.info(f"KDF salt (save for decryption): {derived.salt.hex()}")
        return derived.key

    if key_hex:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise InputValidationError("Key must be exactly 32 bytes (64 hex chars).")
        return key

    raise InputValidationError("Provide --key (hex) or --password.")


if __name__ == "__main__":
    app()
