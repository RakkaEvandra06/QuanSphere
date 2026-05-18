"""constants.py — Shared constants for the Crypto Toolkit."""

__all__ = [
    # Symmetric
    "AES_KEY_SIZE",
    "AES_NONCE_SIZE",
    "AES_TAG_SIZE",
    "CHACHA_KEY_SIZE",
    "CHACHA_NONCE_SIZE",
    "AEAD_MIN_CIPHERTEXT",
    # Asymmetric / RSA
    "RSA_KEY_SIZE",
    "RSA_PUBLIC_EXPONENT",
    # ECC
    "ECC_CURVE",
    # Hashing
    "HASH_ALGORITHMS",
    "DEFAULT_HASH",
    # Argon2id
    "ARGON2_TIME_COST",
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_HASH_LEN",
    "ARGON2_SALT_LEN",
    "ARGON2_PARAMS_STRUCT",
    "ARGON2_PARAMS_LEN",
    # PBKDF2
    "PBKDF2_ITERATIONS",
    "PBKDF2_HASH",
    "PBKDF2_KEY_LEN",
    "PBKDF2_SALT_LEN",
    "PBKDF2_HASH_TO_TAG",
    "PBKDF2_TAG_TO_HASH",
    # File encryption
    "FILE_CHUNK_SIZE",
    "FILE_MAX_BLOCK_SIZE",
    # Envelope markers
    "ENVELOPE_VERSION",
    "SYMMETRIC_MAGIC",
    "FILE_ENC_MAGIC",
    "FILE_ENC_VERSION",
    "ASYM_MAGIC",
    "PBE_MAGIC",
]

# ── Symmetric encryption ──────────────────────────────────────────────────────

AES_KEY_SIZE: int = 32          # AES-256 key length (bytes)
AES_NONCE_SIZE: int = 12        # GCM recommended nonce length (bytes)
AES_TAG_SIZE: int = 16          # GCM authentication tag length (bytes)

CHACHA_KEY_SIZE: int = 32       # ChaCha20-Poly1305 key (bytes)
CHACHA_NONCE_SIZE: int = 12     # RFC 8439 standard nonce length (bytes)

# Minimum valid ciphertext: 16-byte GCM tag + at least 1 byte of plaintext.
AEAD_MIN_CIPHERTEXT: int = AES_TAG_SIZE + 1   # 17 bytes

# ── Asymmetric / RSA ──────────────────────────────────────────────────────────

RSA_KEY_SIZE: int = 4096        # bits — 2048 is the absolute minimum; we default to 4096
RSA_PUBLIC_EXPONENT: int = 65537

# ── ECC ───────────────────────────────────────────────────────────────────────

ECC_CURVE: str = "secp256r1"    # NIST P-256 — widely supported and audited

# ── Hashing ───────────────────────────────────────────────────────────────────

HASH_ALGORITHMS: frozenset[str] = frozenset({
    "sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s",
})
DEFAULT_HASH: str = "sha256"

# ── Key derivation (Argon2id) ─────────────────────────────────────────────────

ARGON2_TIME_COST: int = 3       # iteration count
ARGON2_MEMORY_COST: int = 65536 # 64 MiB expressed in KiB
ARGON2_PARALLELISM: int = 4     # lanes / threads
ARGON2_HASH_LEN: int = 32       # key output length (bytes)
ARGON2_SALT_LEN: int = 16       # random salt length (bytes)

# struct.pack format for the three Argon2 tuning parameters stored in envelopes:
#   >  — big-endian
#   I  — time_cost   (unsigned 32-bit)
#   I  — memory_cost (unsigned 32-bit)
#   H  — parallelism (unsigned 16-bit)
ARGON2_PARAMS_STRUCT: str = ">IIH"
ARGON2_PARAMS_LEN: int = 10    # total packed length in bytes (4 + 4 + 2)

# ── PBKDF2 (fallback KDF) ────────────────────────────────────────────────────

PBKDF2_ITERATIONS: int = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
PBKDF2_HASH: str = "sha256"
PBKDF2_KEY_LEN: int = 32
PBKDF2_SALT_LEN: int = 16

# One-byte tags used to encode the PBKDF2 hash algorithm inside envelopes.
# PBKDF2_TAG_TO_HASH is derived automatically so the two dicts stay in sync.
PBKDF2_HASH_TO_TAG: dict[str, bytes] = {
    "sha256":   b"\x01",
    "sha512":   b"\x02",
    "sha3_256": b"\x03",
    "sha3_512": b"\x04",
}
PBKDF2_TAG_TO_HASH: dict[bytes, str] = {v: k for k, v in PBKDF2_HASH_TO_TAG.items()}

# ── File encryption ───────────────────────────────────────────────────────────

# Maximum plaintext bytes read per encryption pass (write side).
FILE_CHUNK_SIZE: int = 64 * 1024  # 64 KiB

# Maximum encoded block size on the decryption side:
#   plaintext chunk (64 KiB) + nonce (12 B) + GCM tag (16 B) = 65 564 bytes.
FILE_MAX_BLOCK_SIZE: int = FILE_CHUNK_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE

# ── Envelope format markers ───────────────────────────────────────────────────

ENVELOPE_VERSION: bytes = b"\x01"    # single-byte version tag present in all envelopes
SYMMETRIC_MAGIC: bytes = b"CTK-SYM"
FILE_ENC_MAGIC: bytes = b"CTK-FILE"
FILE_ENC_VERSION: bytes = b"\x02"    # file-encryption envelope version (separate from ENVELOPE_VERSION)
ASYM_MAGIC: bytes = b"CTK-ASYM"
PBE_MAGIC: bytes = b"CTK-PBE"