# ── Symmetric encryption ──────────────────────────────────────────────────────

AES_KEY_SIZE = 32          # AES-256 (bytes)
AES_NONCE_SIZE = 12        # GCM recommended nonce length (bytes)
AES_TAG_SIZE = 16          # GCM authentication tag (bytes)

CHACHA_KEY_SIZE = 32       # ChaCha20-Poly1305 key (bytes)
CHACHA_NONCE_SIZE = 12     # RFC 8439 standard nonce length (bytes) — was incorrectly 16

# ── Asymmetric / RSA ─────────────────────────────────────────────────────────

RSA_KEY_SIZE = 4096        # bits — 2048 is the absolute minimum; we default to 4096
RSA_PUBLIC_EXPONENT = 65537

# ── ECC ──────────────────────────────────────────────────────────────────────

ECC_CURVE = "secp256r1"    # NIST P-256, widely supported and reviewed

# ── Hashing ───────────────────────────────────────────────────────────────────

HASH_ALGORITHMS = frozenset({"sha256", "sha512", "sha3_256", "sha3_512", "blake2b"})
DEFAULT_HASH = "sha256"

# ── Key derivation (Argon2id) ─────────────────────────────────────────────────

ARGON2_TIME_COST = 3       # iterations
ARGON2_MEMORY_COST = 65536 # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32       # output key length (bytes)
ARGON2_SALT_LEN = 16       # random salt (bytes)

# ── PBKDF2 (fallback) ────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
PBKDF2_HASH = "sha256"
PBKDF2_KEY_LEN = 32
PBKDF2_SALT_LEN = 16

# ── File encryption ───────────────────────────────────────────────────────────

FILE_CHUNK_SIZE = 64 * 1024  # 64 KiB per chunk

# ── Encoded format markers ────────────────────────────────────────────────────

ENVELOPE_VERSION = b"\x01"       # single byte version tag prepended to all envelopes
SYMMETRIC_MAGIC = b"CTK-SYM"
FILE_ENC_MAGIC = b"CTK-FILE"
ASYM_MAGIC = b"CTK-ASYM"