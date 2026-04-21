<p align="center">
  <img src="assets/animated-zerotracer-v4.svg" width="100%" alt="ZeroTracer Banner"/>
</p>

<div align="center">

![Security Rating](https://img.shields.io/badge/Security%20Rating-A%2B-brightgreen)
![Encryption](https://img.shields.io/badge/Encryption-AES--256%20%7C%20RSA--4096-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

---

# CryptoToolkit — Hardened Crypto Toolkit

ZeroTrace v4 is a hardened cryptography toolkit engineered for secure data encryption built in Python. It supports AES-GCM, KDF (Argon2id, PBKDF2-HMAC), RSA-OAEP, Hybrid Encryption, Digital Signature (RSA-PSS, Ed25519), and SHA hashing with enhanced security validation.

---

## 🏗️ Architecture

```bash
QuanSphere/
├── assets/
├── crypto_toolkit/
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py              
│   │   └── output.py     
│   └── core/                    
│      ├── asymmetric.py         
│      ├── constants.py        
│      ├── exception.py         
│      ├── file_crypto.py        
│      ├── hashing.py           
│      ├── kdf.py               
│      ├── pbe.py        
│      ├── random_gen.py       
│      ├── signatures.py               
│      └── symmetric.py               
├── tests/
│   ├── integration/           
│   │   ├── __init__.py
│   │   └── test_cli.py
│   └── unit/                    
│       ├── test_asymmetric.py
│       ├── test_file_crypto.py
│       ├── test_hashing.py
│       ├── test_kdf.py
│       ├── test_pbe.py
│       ├── test_random_gen.py
│       ├── test_signatures.py
│       ├── test_symmetric.py
│       ├── __init__.py
│       └── conftest.py
├── LICENSE.txt
├── pyproject.toml
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/RakkaEvandra06/QuanSphere.git
cd QuanSphere

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with all dependencies
pip install -e ".[dev]"
```

### ✅ Verify installation

```bash
crypto-toolkit version
```

---

## 🚀 Usage

### Symmetric Encryption

```bash
# Generate a 256-bit key
crypto-toolkit generate-key --type symmetric
# → outputs hex key

# Encrypt with key
crypto-toolkit encrypt "my secret message" --key <hex-key>

# Decrypt
crypto-toolkit decrypt <token> --key <hex-key>

# Encrypt with password (Argon2id key derivation)
crypto-toolkit encrypt "my secret" --password "strongpassword"

# Decrypt with password
crypto-toolkit decrypt <token> --password "strongpassword"

# Use ChaCha20-Poly1305 instead of AES-GCM
crypto-toolkit encrypt "data" --key <hex-key> --algo chacha20

# Interactive password prompt (avoids shell history)
crypto-toolkit encrypt "data" --prompt-password
```

### Hashing

```bash
# Hash a string (SHA-256 by default)
crypto-toolkit hash "hello world"

# Hash with SHA-512
crypto-toolkit hash "hello world" --algo sha512

# Hash a file
crypto-toolkit hash --file /path/to/file.pdf

# Supported algorithms: sha256, sha512, sha3_256, sha3_512, blake2b
crypto-toolkit hash "data" --algo blake2b

# Hash stdin
echo -n "pipe this" | crypto-toolkit hash
```

### Key Generation

```bash
# Symmetric AES-256 key (hex)
crypto-toolkit generate-key --type symmetric

# Ed25519 signing keypair
crypto-toolkit generate-key --type ed25519

# ECC P-256 keypair (for hybrid encryption)
crypto-toolkit generate-key --type ecc

# RSA-4096 keypair
crypto-toolkit generate-key --type rsa

# Save keypair to directory
crypto-toolkit generate-key --type ed25519 --out ./keys/

# Encrypt private key with passphrase
crypto-toolkit generate-key --type rsa --out ./keys/ --key-password "keypass"

# Secure URL-safe token
crypto-toolkit generate-key --type token

# Secure password
crypto-toolkit generate-key --type password
```

### Digital Signatures

```bash
# Generate Ed25519 keypair
crypto-toolkit generate-key --type ed25519 --out ./keys/

# Sign data
crypto-toolkit sign "important document content" --key ./keys/ed25519_private.pem
# → outputs base64 signature

# Verify signature
crypto-toolkit verify "important document content" \
  --sig <base64-signature> \
  --key ./keys/ed25519_public.pem
# → ✓ Signature is VALID  (exit 0)
# → ✗ Signature is INVALID (exit 1)
```

### File Encryption

```bash
# Generate a key
crypto-toolkit generate-key --type symmetric
# → e.g. a1b2c3...

# Encrypt a file (any size — uses 64 KiB chunks)
crypto-toolkit encrypt-file secret.pdf secret.pdf.enc --key <hex-key>

# Decrypt
crypto-toolkit decrypt-file secret.pdf.enc recovered.pdf --key <hex-key>

# Use password-derived key
crypto-toolkit encrypt-file data.zip data.zip.enc --password "vaultpassword"
# NOTE: save the displayed KDF salt for decryption!

crypto-toolkit decrypt-file data.zip.enc data.zip --password "vaultpassword"

# Interactive prompt (recommended)
crypto-toolkit encrypt-file sensitive.db sensitive.db.enc --prompt-password
```

### Key Derivation

```bash
# Derive a key with Argon2id (default)
crypto-toolkit derive-key --password "mypassword"
# → Derived Key (hex) + Salt (hex, save this!)

# Re-derive the same key using stored salt
crypto-toolkit derive-key --password "mypassword" --salt <hex-salt>

# Use PBKDF2-HMAC-SHA256 instead
crypto-toolkit derive-key --password "mypassword" --pbkdf2

# Interactive prompt
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

# Random password (20 chars, includes symbols/digits/uppercase)
crypto-toolkit random --kind password --length 24
```

---

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=crypto_toolkit

# Lint
ruff check .

# Format
black .

# Type check
mypy crypto_toolkit/
```

---

## ⚠️ Disclaimer

This toolkit is developed for educational and research purposes.

<p align="center">
  <img src="assets/quansphere-ascii-art-text.png" width="100%" />
</p>