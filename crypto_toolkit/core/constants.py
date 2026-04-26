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

AES_KEY_SIZE = 32          # AES-256 (bytes)
AES_NONCE_SIZE = 12        # GCM recommended nonce length (bytes)
AES_TAG_SIZE = 16          # GCM authentication tag (bytes)

CHACHA_KEY_SIZE = 32       # ChaCha20-Poly1305 key (bytes)
CHACHA_NONCE_SIZE = 12     # RFC 8439 standard nonce length (bytes)
AEAD_MIN_CIPHERTEXT = AES_TAG_SIZE + 1   # 17 bytes (16-byte tag + 1-byte plaintext)

# ── Asymmetric / RSA ──────────────────────────────────────────────────────────

RSA_KEY_SIZE = 4096        # bits — 2048 is the absolute minimum; defaults to 4096
RSA_PUBLIC_EXPONENT = 65537

# ── ECC ───────────────────────────────────────────────────────────────────────

ECC_CURVE = "secp256r1"    # NIST P-256, widely supported and audited

# ── Hashing ───────────────────────────────────────────────────────────────────

HASH_ALGORITHMS = frozenset({"sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"})
DEFAULT_HASH = "sha256"

# ── Key derivation (Argon2id) ─────────────────────────────────────────────────

ARGON2_TIME_COST = 3       # iterations
ARGON2_MEMORY_COST = 65536 # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32       # key output length (bytes)
ARGON2_SALT_LEN = 16       # random salt (bytes)
ARGON2_PARAMS_STRUCT = ">IIH"   # struct.pack format string
ARGON2_PARAMS_LEN = 10          # total packed length in bytes

# ── PBKDF2 (fallback) ────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
PBKDF2_HASH = "sha256"
PBKDF2_KEY_LEN = 32
PBKDF2_SALT_LEN = 16

# ── PBKDF2 hash tag encoding ──────────────────────────────────────────────────

PBKDF2_HASH_TO_TAG: dict[str, bytes] = {
    "sha256":   b"\x01",
    "sha512":   b"\x02",
    "sha3_256": b"\x03",
    "sha3_512": b"\x04",
}
PBKDF2_TAG_TO_HASH: dict[bytes, str] = {v: k for k, v in PBKDF2_HASH_TO_TAG.items()}

# ── File encryption ───────────────────────────────────────────────────────────

# FILE_CHUNK_SIZE is the maximum *plaintext* bytes read per encryption pass (write side).
FILE_CHUNK_SIZE = 64 * 1024  # 64 KiB per chunk

FILE_MAX_BLOCK_SIZE = FILE_CHUNK_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE  # 65564 bytes

# ── Encoded format markers ────────────────────────────────────────────────────

ENVELOPE_VERSION = b"\x01"       # one-byte tag added to all envelopes
SYMMETRIC_MAGIC = b"CTK-SYM"
FILE_ENC_MAGIC = b"CTK-FILE"

FILE_ENC_VERSION = b"\x02"
ASYM_MAGIC = b"CTK-ASYM"
PBE_MAGIC = b"CTK-PBE"