from __future__ import annotations

__all__ = [
    # Key generation
    "generate_rsa_keypair",
    "generate_ecc_keypair",
    "generate_x25519_keypair",
    # Serialisation
    "private_key_to_pem",
    "public_key_to_pem",
    "load_private_key",
    "load_public_key",
    # RSA encryption
    "rsa_encrypt",
    "rsa_decrypt",
    # ECC hybrid encryption
    "ecc_hybrid_encrypt",
    "ecc_hybrid_decrypt",
    # X25519 hybrid encryption
    "x25519_hybrid_encrypt",
    "x25519_hybrid_decrypt",
]

import hmac
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_toolkit.core._aead_utils import aesgcm_context
from crypto_toolkit.core.constants import (
    AEAD_MIN_CIPHERTEXT,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    ASYM_MAGIC,
    ASYM_ECC_TAG,
    ASYM_X25519_TAG,
    ENVELOPE_VERSION,
    RSA_KEY_SIZE,
    RSA_MIN_KEY_SIZE,
    RSA_PUBLIC_EXPONENT,
)
from crypto_toolkit.core.exceptions import (
    DecryptionError,
    EncryptionError,
    InputValidationError,
    KeyGenerationError,
)
from crypto_toolkit.core.kdf import (
    zero_key,
    zero_bytes_buffer,
)

# Expected first byte for an uncompressed SEC1 elliptic-curve point (X9.62 §4.3.6).
_UNCOMPRESSED_POINT_PREFIX = 0x04
# P-256 uncompressed point: 1-byte 0x04 prefix + 32-byte X + 32-byte Y = 65 bytes.
_ECC_UNCOMPRESSED_PUB_LEN: int = 65
# X25519 raw public key is always 32 bytes (RFC 7748 §6.1).
_X25519_PUB_LEN: int = 32

# Header layout: ASYM_MAGIC (8 B) + ENVELOPE_VERSION (1 B) + algo_tag (1 B) = 10 bytes.
# Having a fixed-length constant avoids recomputing len() at every call site.
_ASYM_ECC_HEADER: bytes = ASYM_MAGIC + ENVELOPE_VERSION + ASYM_ECC_TAG
_ASYM_X25519_HEADER: bytes = ASYM_MAGIC + ENVELOPE_VERSION + ASYM_X25519_TAG

if len(_ASYM_ECC_HEADER) != len(_ASYM_X25519_HEADER):
    raise RuntimeError(
        f"Invariant violated: ECC header length ({len(_ASYM_ECC_HEADER)}) != "
        f"X25519 header length ({len(_ASYM_X25519_HEADER)}). "
        "Both envelope types must share the same fixed header size for "
        "_ASYM_HEADER_LEN to be valid. Update the constant or use per-scheme "
        "offsets if the tag widths must differ."
    )

_ASYM_HEADER_LEN: int = len(_ASYM_ECC_HEADER)  # 10 — asserted equal for both schemes

# Minimum envelope byte lengths.
_ECC_MIN_ENVELOPE: int = (
    _ASYM_HEADER_LEN + _ECC_UNCOMPRESSED_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)
_X25519_MIN_ENVELOPE: int = (
    _ASYM_HEADER_LEN + _X25519_PUB_LEN + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)

# HKDF domain separators keep ECC and X25519 key streams cryptographically independent.
_ECC_HKDF_INFO: bytes = b"crypto-toolkit-ecc-hybrid"
_X25519_HKDF_INFO: bytes = b"crypto-toolkit-x25519-hybrid"

# A low-order X25519 point produces an all-zero shared secret — reject it.
_X25519_ZERO_SECRET: bytes = b"\x00" * 32
_ECC_ZERO_SECRET: bytes = b"\x00" * 32

# Supported key types accepted by the load_* helpers.
_SUPPORTED_PRIVATE_KEY_TYPES: tuple[type, ...] = (
    RSAPrivateKey,
    EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
)
_SUPPORTED_PUBLIC_KEY_TYPES: tuple[type, ...] = (
    RSAPublicKey,
    EllipticCurvePublicKey,
    x25519.X25519PublicKey,
)

_VALID_RSA_KEY_SIZES: frozenset[int] = frozenset({2048, 3072, 4096})
# RSA_MIN_KEY_SIZE is imported from constants — no local alias needed.
_SHA256_DIGEST_SIZE: int = 32
_HYBRID_MAX_PLAINTEXT: int = 64 * 1024 * 1024   # 64 MiB

# ── Private helpers ───────────────────────────────────────────────────────────

def _make_oaep_padding() -> padding.OAEP:
    """Return a pre-configured OAEP padding instance (SHA-256, MGF1-SHA-256)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

def _hkdf_derive(shared_secret: bytes, *, salt: bytes, info: bytes) -> bytes:
    """Derive an AES-256 key from *shared_secret* using HKDF-SHA-256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(shared_secret)

def _assert_secp256r1(
    key: EllipticCurvePublicKey | EllipticCurvePrivateKey,
    operation: str,
) -> None:
    """Raise InputValidationError if *key* does not use SECP256R1."""
    if not isinstance(key.curve, ec.SECP256R1):
        raise InputValidationError(
            f"ECC {operation} requires a SECP256R1 key; "
            f"received {type(key.curve).__name__}."
        )

# ── Key generation ────────────────────────────────────────────────────────────

def generate_rsa_keypair(
    key_size: int = RSA_KEY_SIZE,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair of *key_size* bits (2048, 3072, or 4096)."""
    if key_size not in _VALID_RSA_KEY_SIZES:
        raise KeyGenerationError(
            f"RSA key size must be one of {sorted(_VALID_RSA_KEY_SIZES)} bits; "
            f"received {key_size}. "
            "Non-standard sizes are not supported, they produce keys that most "
            "PKI infrastructure will reject."
        )
    try:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=key_size,
        )
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("RSA key generation failed.") from exc

def generate_ecc_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECC key pair on the SECP256R1 (P-256) curve."""
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("ECC key generation failed.") from exc

def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate an X25519 key pair."""
    try:
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()
    except Exception as exc:
        raise KeyGenerationError("X25519 key generation failed.") from exc

# ── Serialisation ─────────────────────────────────────────────────────────────

def private_key_to_pem(
    key: RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialise *key* to PKCS8 PEM, optionally encrypted with *password*."""
    if password is not None and len(password) == 0:
        raise InputValidationError(
            "PEM encryption password must not be empty (received b''). "
            "Pass a non-empty bytes secret to encrypt the PEM, or pass "
            "password=None to produce an unencrypted PEM."
        )
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

def public_key_to_pem(
    key: RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey,
) -> bytes:
    """Serialise *key* to SubjectPublicKeyInfo PEM."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_private_key(
    pem: bytes,
    password: bytes | None = None,
) -> RSAPrivateKey | EllipticCurvePrivateKey | x25519.X25519PrivateKey:
    """Load a private key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, _SUPPORTED_PRIVATE_KEY_TYPES):
            raise InputValidationError(
                f"Unsupported private key type: {type(key).__name__}. "
                f"Supported types: RSA, ECC (P-256), X25519."
            )
        return key  # type: ignore[return-value]
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load private key, wrong password or corrupt PEM."
        ) from exc

def load_public_key(
    pem: bytes,
) -> RSAPublicKey | EllipticCurvePublicKey | x25519.X25519PublicKey:
    """Load a public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, _SUPPORTED_PUBLIC_KEY_TYPES):
            raise InputValidationError(
                f"Unsupported public key type: {type(key).__name__}. "
                f"Supported types: RSA, ECC (P-256), X25519."
            )
        return key  # type: ignore[return-value]
    except InputValidationError:
        raise
    except Exception as exc:
        raise InputValidationError(
            "Failed to load public key, corrupt PEM."
        ) from exc

# ── RSA encryption ────────────────────────────────────────────────────────────

def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt *plaintext* with *public_key* using RSA-OAEP / SHA-256."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "RSA-OAEP cannot encrypt zero bytes."
        )
    if public_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA public key is {public_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    max_plaintext = (public_key.key_size // 8) - 2 * _SHA256_DIGEST_SIZE - 2
    if len(plaintext) > max_plaintext:
        raise InputValidationError(
            f"Plaintext ({len(plaintext)} bytes) exceeds the RSA-OAEP maximum "
            f"({max_plaintext} bytes) for a {public_key.key_size}-bit key. "
            "Use ecc_hybrid_encrypt or x25519_hybrid_encrypt for large payloads."
        )
    try:
        return public_key.encrypt(plaintext, _make_oaep_padding())
    except Exception as exc:
        raise EncryptionError("RSA-OAEP encryption failed.") from exc

def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt *ciphertext* with *private_key* using RSA-OAEP / SHA-256."""
    if private_key.key_size < RSA_MIN_KEY_SIZE:
        raise InputValidationError(
            f"RSA private key is {private_key.key_size} bits; "
            f"a minimum of {RSA_MIN_KEY_SIZE} bits is required. "
            "Keys smaller than 2048 bits are considered cryptographically broken."
        )
    expected_len: int = (private_key.key_size + 7) // 8
    if len(ciphertext) != expected_len:
        raise DecryptionError(
            f"RSA ciphertext must be exactly {expected_len} bytes for a "
            f"{private_key.key_size}-bit key; received {len(ciphertext)} bytes. "
            "Ensure you are decrypting a raw RSA-OAEP ciphertext, not a "
            "base64-encoded or hex-encoded value."
        )
    try:
        return private_key.decrypt(ciphertext, _make_oaep_padding())
    except Exception as exc:
        raise DecryptionError(
            "RSA-OAEP decryption failed, wrong key or corrupted ciphertext."
        ) from exc

# ── ECC hybrid encryption ─────────────────────────────────────────────────────

def ecc_hybrid_encrypt(plaintext: bytes, recipient_pub: EllipticCurvePublicKey) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral ECDH + AES-GCM."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "Encrypting zero bytes produces a ciphertext containing only the "
            "authentication tag and carries no useful information."
        )
    if len(plaintext) > _HYBRID_MAX_PLAINTEXT:
        raise InputValidationError(
            f"Plaintext ({len(plaintext):,} bytes) exceeds the "
            f"{_HYBRID_MAX_PLAINTEXT // (1024 * 1024)} MiB limit for in-memory "
            "hybrid encryption. Use file_crypto.encrypt_file_with_password for "
            "large payloads, it streams data in 64 KiB chunks."
        )
    _assert_secp256r1(recipient_pub, "hybrid encryption")

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        shared_secret_bytes = ephemeral_priv.exchange(ECDH(), recipient_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _ECC_ZERO_SECRET):
            raise EncryptionError(
                "ECDH key exchange produced a zero shared secret, "
                "the recipient public key may be degenerate. "
                "Verify that the key is a valid SECP256R1 point."
            )

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        recipient_pub_bytes = recipient_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        _aad = _ASYM_ECC_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, _aad)

        return _ASYM_ECC_HEADER + ephemeral_pub_bytes + nonce + ciphertext

    except (EncryptionError, InputValidationError):
        raise
    except Exception as exc:
        raise EncryptionError("ECC hybrid encryption failed.") from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)   # reliable ctypes.memset wipe of bytearray
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)

def ecc_hybrid_decrypt(envelope: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Decrypt an envelope produced by :func:`ecc_hybrid_encrypt`."""
    _assert_secp256r1(private_key, "hybrid decryption")

    if len(envelope) < _ECC_MIN_ENVELOPE:
        raise DecryptionError(
            f"ECC envelope is too short ({len(envelope)} bytes); "
            f"minimum expected is {_ECC_MIN_ENVELOPE} bytes."
        )

    magic_len = len(ASYM_MAGIC)
    if envelope[:magic_len] != ASYM_MAGIC:
        raise DecryptionError("Envelope format not recognised (missing ASYM_MAGIC).")
    if envelope[magic_len : magic_len + 1] != ENVELOPE_VERSION:
        raise DecryptionError("Envelope version not supported.")
    if envelope[magic_len + 1 : magic_len + 2] != ASYM_ECC_TAG:
        raise DecryptionError(
            "Envelope algorithm tag mismatch: expected ECC (0x01). "
            "Ensure you are using ecc_hybrid_decrypt for ECC-encrypted data, "
            "not x25519_hybrid_decrypt."
        )

    offset = _ASYM_HEADER_LEN
    ephemeral_pub_bytes = envelope[offset : offset + _ECC_UNCOMPRESSED_PUB_LEN]
    if ephemeral_pub_bytes[0] != _UNCOMPRESSED_POINT_PREFIX:
        raise DecryptionError(
            f"ECC envelope contains an invalid ephemeral public key "
            f"expected uncompressed point marker 0x04, "
            f"got 0x{ephemeral_pub_bytes[0]:02x}. "
            "The envelope may be corrupt or use an unsupported point encoding."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        nonce_start = offset + _ECC_UNCOMPRESSED_PUB_LEN
        nonce = envelope[nonce_start : nonce_start + AES_NONCE_SIZE]
        ciphertext = envelope[nonce_start + AES_NONCE_SIZE :]

        ephemeral_pub = EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_bytes
        )

        shared_secret_bytes = private_key.exchange(ECDH(), ephemeral_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _ECC_ZERO_SECRET):
            raise DecryptionError(
                "ECDH key exchange produced a zero shared secret, "
                "the ephemeral public key in the envelope is degenerate. "
                "The envelope must be rejected."
            )

        recipient_pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_ECC_HKDF_INFO + recipient_pub_bytes,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        _aad = _ASYM_ECC_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            return cipher.decrypt(nonce, ciphertext, _aad)

    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(
            "ECC hybrid decryption failed, wrong key or corrupted data."
        ) from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)

# ── X25519 hybrid encryption ──────────────────────────────────────────────────

def x25519_hybrid_encrypt(
    plaintext: bytes,
    recipient_pub: x25519.X25519PublicKey,
) -> bytes:
    """Encrypt *plaintext* for *recipient_pub* using ephemeral X25519 + AES-GCM."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "Encrypting zero bytes produces a ciphertext containing only the "
            "authentication tag and carries no useful information."
        )
    if len(plaintext) > _HYBRID_MAX_PLAINTEXT:
        raise InputValidationError(
            f"Plaintext ({len(plaintext):,} bytes) exceeds the "
            f"{_HYBRID_MAX_PLAINTEXT // (1024 * 1024)} MiB limit for in-memory "
            "hybrid encryption. Use file_crypto.encrypt_file_with_password for "
            "large payloads, it streams data in 64 KiB chunks."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()

        shared_secret_bytes = ephemeral_priv.exchange(recipient_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _X25519_ZERO_SECRET):
            raise EncryptionError(
                "X25519 key exchange produced a zero shared secret "
                "the recipient public key is a low-order point and must be "
                "rejected. Verify that the recipient's public key is valid."
            )

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        recipient_pub_raw = recipient_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        _aad = _ASYM_X25519_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, _aad)

        return _ASYM_X25519_HEADER + ephemeral_pub_bytes + nonce + ciphertext

    except (EncryptionError, InputValidationError):
        raise
    except Exception as exc:
        raise EncryptionError("X25519 hybrid encryption failed.") from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)

def x25519_hybrid_decrypt(
    envelope: bytes,
    private_key: x25519.X25519PrivateKey,
) -> bytes:
    """Decrypt an envelope produced by :func:`x25519_hybrid_encrypt`."""
    if len(envelope) < _X25519_MIN_ENVELOPE:
        raise DecryptionError(
            f"X25519 envelope is too short ({len(envelope)} bytes); "
            f"minimum expected is {_X25519_MIN_ENVELOPE} bytes."
        )

    magic_len = len(ASYM_MAGIC)
    if envelope[:magic_len] != ASYM_MAGIC:
        raise DecryptionError("Envelope format not recognised (missing ASYM_MAGIC).")
    if envelope[magic_len : magic_len + 1] != ENVELOPE_VERSION:
        raise DecryptionError("Envelope version not supported.")
    if envelope[magic_len + 1 : magic_len + 2] != ASYM_X25519_TAG:
        raise DecryptionError(
            "Envelope algorithm tag mismatch: expected X25519 (0x02). "
            "Ensure you are using x25519_hybrid_decrypt for X25519-encrypted data, "
            "not ecc_hybrid_decrypt."
        )

    shared_secret_bytes: bytes | None = None
    shared_secret_buf: bytearray | None = None
    aes_key_bytes: bytes | None = None
    aes_key_buf: bytearray | None = None
    try:
        offset = _ASYM_HEADER_LEN
        ephemeral_pub_bytes = envelope[offset : offset + _X25519_PUB_LEN]
        nonce_start = offset + _X25519_PUB_LEN
        nonce = envelope[nonce_start : nonce_start + AES_NONCE_SIZE]
        ciphertext = envelope[nonce_start + AES_NONCE_SIZE :]

        ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

        shared_secret_bytes = private_key.exchange(ephemeral_pub)
        shared_secret_buf = bytearray(shared_secret_bytes)

        if hmac.compare_digest(shared_secret_bytes, _X25519_ZERO_SECRET):
            raise DecryptionError(
                "X25519 key exchange produced a zero shared secret "
                "the ephemeral public key is a low-order point and the "
                "envelope must be rejected."
            )

        recipient_pub_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        aes_key_bytes = _hkdf_derive(
            shared_secret_bytes,
            salt=ephemeral_pub_bytes,
            info=_X25519_HKDF_INFO + recipient_pub_raw,
        )
        aes_key_buf = bytearray(aes_key_bytes)

        _aad = _ASYM_X25519_HEADER + ephemeral_pub_bytes
        with aesgcm_context(aes_key_buf) as cipher:
            return cipher.decrypt(nonce, ciphertext, _aad)

    except (InputValidationError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(
            "X25519 hybrid decryption failed, wrong key or corrupted data."
        ) from exc
    finally:
        if shared_secret_bytes is not None:
            zero_bytes_buffer(shared_secret_bytes)
            shared_secret_bytes = None
        if shared_secret_buf is not None:
            zero_key(shared_secret_buf)
        if aes_key_bytes is not None:
            zero_bytes_buffer(aes_key_bytes)
            aes_key_bytes = None
        if aes_key_buf is not None:
            zero_key(aes_key_buf)