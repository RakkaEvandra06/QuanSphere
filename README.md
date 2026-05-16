<p align="center">
  <img src="assets/animated-zerotracer-v4.svg" width="100%" alt="ZeroTracer Banner"/>
</p>

<div align="center">

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-4.0.0-informational)](https://github.com/RakkaEvandra06/QuanSphere/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Security](https://img.shields.io/badge/Security%20Rating-A%2B-brightgreen?logo=shield)](https://github.com/RakkaEvandra06/QuanSphere)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM%20%7C%20ChaCha20-blue)](https://github.com/RakkaEvandra06/QuanSphere)
[![KDF](https://img.shields.io/badge/KDF-Argon2id%20%7C%20PBKDF2-orange)](https://github.com/RakkaEvandra06/QuanSphere)
[![Status](https://img.shields.io/badge/status-stable-brightgreen)](https://github.com/RakkaEvandra06/QuanSphere)
[![Coverage](https://img.shields.io/badge/coverage-80%25%2B-success)](https://github.com/RakkaEvandra06/QuanSphere)

</div>

---

# QuanSphere — Hardened Crypto Toolkit

**ZeroTrace** is a production-grade, hardened cryptography toolkit and CLI engineered for secure data operations in Python. It covers the full spectrum of everyday cryptographic needs: symmetric and asymmetric encryption, hybrid key-exchange, digital signatures, multi-algorithm hashing, password-based encryption, chunked file encryption, and cryptographically secure random generation all from a single unified `crypto-toolkit` command.

---

## Table of Contents

- [About the Project](#about-the-project)
- [Architecture](#architecture)
- [Installation](#installation)
- [Verify Installation](#verify-installation)
- [Usage](#usage)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## 💡 About the Project

QuanSphere was designed around the principle that **correct cryptography should be the path of least resistance**. Every decision in the toolkit reflects this:

- **Defense-in-depth envelope format** every ciphertext token carries a versioned magic header, algorithm tag, nonce, and GCM authentication tag. Tampering is detected before any plaintext byte is released.
- **Hybrid encryption** ECC (SECP256R1 / ECDH) and X25519 hybrid paths combine ephemeral Diffie-Hellman with AES-256-GCM and HKDF-SHA-256, so a recipient's long-term private key is never used to directly encrypt data.
- **Argon2id by default** password-based encryption and file encryption derive keys with Argon2id (time cost 3, memory 64 MiB, parallelism 4) out of the box. PBKDF2-HMAC is available as a fallback with OWASP 2023-compliant iteration counts.
- **DoS guards on decryption** all PBE and file-encryption paths cap the KDF parameters read from an untrusted envelope, preventing an adversary from triggering excessive CPU or memory usage.
- **Key material zeroing** shared secrets and derived keys are overwritten with `ctypes.memset` (CPython) immediately after use.
- **No plaintext leakage** raw passwords and sensitive arguments are never logged, printed, or stored. CLI flags emit a visible warning when a password appears in shell history and always prefer `--prompt-password`.
- **Chunked file streaming** files of arbitrary size are encrypted in 64 KiB chunks with per-chunk AAD binding each block to its position and the file header, detecting both bit-flip attacks and truncation.

---

## 🏗️ Architecture

```
QuanSphere/
├── assets/                            # Banner images and static assets
├── crypto_toolkit/
│   ├── cli/
│   │   ├── __init__.py                # CLI package version
│   │   ├── main.py                    # Typer app all CLI commands
│   │   └── output.py                  # Rich-powered terminal output helpers
│   └── core/
│       ├── asymmetric.py              # RSA-4096, ECC P-256, X25519 keygen, OAEP, hybrid ECDH
│       ├── constants.py               # Shared algorithm parameters and envelope magic bytes
│       ├── exceptions.py              # Typed exception hierarchy (8 exception classes)
│       ├── file_crypto.py             # Chunked AES-256-GCM file encryption/decryption
│       ├── hashing.py                 # SHA-256/512, SHA3-256/512, BLAKE2b/s data, stream, file
│       ├── kdf.py                     # Argon2id and PBKDF2-HMAC key derivation
│       ├── pbe.py                     # Password-based encryption (Argon2id or PBKDF2 + AES-GCM)
│       ├── random_gen.py              # Cryptographically secure key, token, and password generation
│       ├── signatures.py              # Ed25519 and RSA-PSS sign/verify + PEM serialisation
│       └── symmetric.py               # AES-256-GCM and ChaCha20-Poly1305 authenticated encryption
├── tests/
│   ├── integration/
│   │   ├── __init__.py
│   │   └── test_cli.py                # End-to-end CLI integration tests
│   └── unit/
│       ├── __init__.py
│       ├── conftest.py                # Shared fixtures
│       ├── test_asymmetric.py
│       ├── test_file_crypto.py
│       ├── test_hashing.py
│       ├── test_kdf.py
│       ├── test_pbe.py
│       ├── test_random_gen.py
│       ├── test_signatures.py
│       └── test_symmetric.py
├── LICENSE.txt
├── pyproject.toml
└── README.md
```

---

## ⚙️ Installation

**Requirements:** Python ≥ 3.10

```bash
# 1. Clone the repository
git clone https://github.com/RakkaEvandra06/QuanSphere.git
cd QuanSphere

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install with all development dependencies
pip install -e ".[dev]"
```

**Install runtime only (no dev tools):**

```bash
pip install -e .
```

### Verify Installation

```bash
crypto-toolkit --help
```

---

## 🚀 Usage

### Symmetric Encryption

```bash
# Generate a 256-bit AES key
crypto-toolkit generate-key --type symmetric
# → Symmetric Key (hex): a1b2c3...

# Encrypt with key (AES-256-GCM)
crypto-toolkit encrypt "my secret message" --key <hex-key>

# Decrypt
crypto-toolkit decrypt <token> --key <hex-key>

# Use ChaCha20-Poly1305 instead of AES-GCM
crypto-toolkit encrypt "data" --key <hex-key> --algo chacha20

# Encrypt with password (Argon2id KDF — no key management needed)
crypto-toolkit encrypt "my secret" --password "strongpassword"
crypto-toolkit decrypt <token> --password "strongpassword"

# Interactive password prompt — never stored in shell history
crypto-toolkit encrypt "data" --prompt-password

# Read plaintext from stdin or a file
echo "secret" | crypto-toolkit encrypt --stdin --key <hex-key>
crypto-toolkit encrypt --input-file document.txt --key <hex-key> --output document.enc
```

### Hashing

```bash
# SHA-256 (default)
crypto-toolkit hash "hello world"

# Other algorithms
crypto-toolkit hash "hello world" --algo sha512
crypto-toolkit hash "hello world" --algo sha3_256
crypto-toolkit hash "hello world" --algo blake2b

# Hash a file
crypto-toolkit hash --file /path/to/document.pdf

# Hash from stdin
echo -n "pipe this" | crypto-toolkit hash --stdin

# Supported: sha256, sha512, sha3_256, sha3_512, blake2b, blake2s
```

### Key Generation

```bash
# Symmetric AES-256 key (hex)
crypto-toolkit generate-key --type symmetric

# Ed25519 signing keypair → ed25519_private.pem + ed25519_public.pem
crypto-toolkit generate-key --type ed25519 --out ./keys/

# ECC P-256 keypair (for hybrid encryption)
crypto-toolkit generate-key --type ecc --out ./keys/

# X25519 keypair (for Diffie-Hellman hybrid encryption)
crypto-toolkit generate-key --type x25519 --out ./keys/

# RSA-4096 keypair
crypto-toolkit generate-key --type rsa --out ./keys/

# Encrypt the private key with a passphrase
crypto-toolkit generate-key --type rsa --out ./keys/ --key-password "keypass"

# URL-safe secure random token (32 bytes entropy)
crypto-toolkit generate-key --type token

# Secure random password (default 20 chars, uppercase + digits + symbols)
crypto-toolkit generate-key --type password
crypto-toolkit generate-key --type password --size 32
```

### Digital Signatures

```bash
# Generate an Ed25519 keypair
crypto-toolkit generate-key --type ed25519 --out ./keys/

# Sign data
crypto-toolkit sign "important document" --key ./keys/ed25519_private.pem
# → Signature (ed25519, base64): <base64-sig>

# Sign a file
crypto-toolkit sign --input-file contract.pdf --key ./keys/ed25519_private.pem

# Verify signature
crypto-toolkit verify "important document" \
  --sig <base64-signature> \
  --key ./keys/ed25519_public.pem
# → ✓ Signature (ed25519) VALID.   (exit 0)
# → ✗ Signature (ed25519) INVALID. (exit 1)

# RSA-PSS (SHA-256) alternative
crypto-toolkit sign "data" --key ./keys/rsa_private.pem --algo rsa-pss
crypto-toolkit verify "data" --sig <sig> --key ./keys/rsa_public.pem --algo rsa-pss

# Passphrase-protected private key
crypto-toolkit sign "data" --key ./keys/rsa_private.pem --key-password "keypass"
```

### RSA Encryption

```bash
# Generate RSA-4096 keypair
crypto-toolkit generate-key --type rsa --out ./keys/

# Encrypt with RSA-OAEP / SHA-256 (suitable for small payloads, e.g. session keys)
crypto-toolkit rsa-encrypt "secret session key" --key ./keys/rsa_public.pem

# Decrypt
crypto-toolkit rsa-decrypt <base64-ciphertext> --key ./keys/rsa_private.pem

# Passphrase-protected private key
crypto-toolkit rsa-decrypt <base64-ciphertext> \
  --key ./keys/rsa_private.pem \
  --key-password "keypass"
```

### File Encryption

```bash
# Generate a key
crypto-toolkit generate-key --type symmetric
# → a1b2c3...

# Encrypt a file (raw key)
crypto-toolkit encrypt-file secret.pdf secret.pdf.enc --key <hex-key>

# Decrypt
crypto-toolkit decrypt-file secret.pdf.enc recovered.pdf --key <hex-key>

# Encrypt with Argon2id-derived key (KDF salt embedded in output file)
crypto-toolkit encrypt-file data.zip data.zip.enc --password "vaultpassword"
crypto-toolkit decrypt-file data.zip.enc data.zip --password "vaultpassword"

# Use PBKDF2 instead of Argon2id
crypto-toolkit encrypt-file data.zip data.zip.enc --pbkdf2 --password "vaultpassword"

# Interactive prompt (recommended for sensitive files)
crypto-toolkit encrypt-file sensitive.db sensitive.db.enc --prompt-password
crypto-toolkit decrypt-file sensitive.db.enc sensitive.db --prompt-password
```

### Key Derivation

```bash
# Derive a key with Argon2id (default)
crypto-toolkit derive-key --password "mypassword"
# → Derived Key (Argon2id): <hex-key>
# → Salt (save this for re-derivation): <hex-salt>

# Re-derive using a stored salt (produces the same key)
crypto-toolkit derive-key --password "mypassword" --salt <hex-salt>

# PBKDF2-HMAC-SHA256 (OWASP 2023: 600,000 iterations)
crypto-toolkit derive-key --password "mypassword" --pbkdf2

# PBKDF2-HMAC-SHA512 (OWASP 2023: 210,000 iterations)
crypto-toolkit derive-key --password "mypassword" --pbkdf2 --hash-algo sha512

# Interactive prompt (recommended)
crypto-toolkit derive-key --prompt-password
```

### Secure Random Generation

```bash
# URL-safe random token (default, 32 bytes entropy)
crypto-toolkit random

# Hex-encoded random bytes
crypto-toolkit random --kind hex --bytes 64

# Base64-encoded random bytes
crypto-toolkit random --kind base64 --bytes 32

# Secure random password (20 chars, uppercase + digits + symbols guaranteed)
crypto-toolkit random --kind password --length 24

# Write output to a file
crypto-toolkit random --kind token --output ./secrets/token.txt
```

---

## 🛠️ Development

### Running tests

```bash
# Run all tests with coverage (recommended)
pytest

# Verbose output
pytest -v

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Generate HTML coverage report
pytest --cov=crypto_toolkit --cov-report=html
# → open htmlcov/index.html in your browser
```

### Linting and type checking

```bash
# Install lint extras
pip install -e ".[lint]"

# Lint and auto-fix with ruff
ruff check .
ruff check . --fix

# Static type checking with mypy
mypy crypto_toolkit/
```

### Build and publish

```bash
# Install build tools
pip install build twine

# Build source distribution and wheel
python -m build

# Validate the distribution package
twine check dist/*

# Upload to PyPI
twine upload dist/*
```

---

## 🤝 Contributing

Contributions are welcome. Here's how to get started:

1. **Fork** the repository and create a branch from `main`.
2. **Install** all dev dependencies: `pip install -e ".[dev]"`.
3. **Write code** — keep changes focused on a single concern.
4. **Add or update tests** to cover new or changed behaviour.
5. **Run the full suite** and confirm coverage stays at ≥ 80 %: `pytest`.
6. **Lint** your code: `ruff check . && mypy crypto_toolkit/`.
7. **Open a Pull Request** with a clear title and description.

For larger changes or new cryptographic primitives, please open an issue first to discuss the design. Security-sensitive changes should include a rationale for why the chosen primitive and parameters are appropriate.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE.txt`](LICENSE.txt) for the full text.

---

## ⚠️ Disclaimer

QuanSphere is developed for **educational and research purposes**. While it applies well-established cryptographic primitives and follows current best-practice parameter recommendations, no toolkit can substitute for a formal security audit before deployment in production or safety-critical environments. Always review cryptographic choices with a qualified professional for your specific threat model.

<p align="center">
  <img src="assets/quansphere-ascii-art-text.png" width="100%" />
</p>