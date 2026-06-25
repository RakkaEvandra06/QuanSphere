from __future__ import annotations

__all__ = ["password_encrypt", "password_decrypt"]

import base64
import secrets
import struct

from crypto_toolkit.core._aead_utils import aesgcm_context
from crypto_toolkit.core.constants import (
    AEAD_MIN_CIPHERTEXT,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_PARAMS_LEN,
    ARGON2_PARAMS_STRUCT,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    AES_NONCE_SIZE,
    DECRYPT_MAX_ARGON2_MEMORY_COST as _DECRYPT_MAX_ARGON2_MEMORY_COST,
    DECRYPT_MAX_ARGON2_PARALLELISM as _DECRYPT_MAX_ARGON2_PARALLELISM,
    DECRYPT_MAX_ARGON2_TIME_COST   as _DECRYPT_MAX_ARGON2_TIME_COST,
    ENVELOPE_VERSION,
    PASSWORD_MIN_LENGTH,
    PBE_MAGIC as _PBE_MAGIC,
    PBKDF2_HASH_TO_TAG as _PBKDF2_HASH_TO_TAG,
    PBKDF2_SALT_LEN,
    PBKDF2_TAG_TO_HASH as _PBKDF2_TAG_TO_HASH,
    PBKDF2_MAX_ITERATIONS as _PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS as _PBKDF2_MIN_ITERATIONS,
)
from crypto_toolkit.core.exceptions import (
    CryptoToolkitError,
    DecryptionError,
    EncryptionError,
    InputValidationError,
)
from crypto_toolkit.core.kdf import (
    derive_key_argon2,
    derive_key_pbkdf2,
    zero_key,
)

_KDF_ARGON2: bytes = b"\x01"
_KDF_PBKDF2: bytes = b"\x02"

_DECRYPT_MAX_TIME_COST: int    = _DECRYPT_MAX_ARGON2_TIME_COST
_DECRYPT_MAX_MEMORY_COST: int  = _DECRYPT_MAX_ARGON2_MEMORY_COST
_DECRYPT_MAX_PARALLELISM: int  = _DECRYPT_MAX_ARGON2_PARALLELISM

# Lower-bound sanity checks (unchanged from original).
_DECRYPT_MIN_TIME_COST: int    = 1
_DECRYPT_MIN_MEMORY_COST: int  = 8_192    # 8 MiB in KiB
_DECRYPT_MIN_PARALLELISM: int  = 1
_MIN_PASSWORD_LENGTH: int = PASSWORD_MIN_LENGTH

# Both salts must be the same length so the PBE parser can use a single offset.
if ARGON2_SALT_LEN != PBKDF2_SALT_LEN:
    raise RuntimeError(
        f"Invariant violated: ARGON2_SALT_LEN ({ARGON2_SALT_LEN}) != "
        f"PBKDF2_SALT_LEN ({PBKDF2_SALT_LEN}). "
        "Both salt lengths must be equal for the single-offset PBE envelope "
        "parser in password_decrypt to work correctly. "
        "Update _build_aad_* and password_decrypt to use per-KDF offsets "
        "if the two constants must differ."
    )
_SALT_LEN: int = ARGON2_SALT_LEN

# ── Minimum envelope lengths ──────────────────────────────────────────────────

# magic (7) + version (1) + kdf_tag (1) = 9 bytes
_HEADER_PREFIX_LEN: int = len(_PBE_MAGIC) + 1 + 1

# Argon2 envelope: magic + version + kdf_tag + salt + argon2_params + nonce + ciphertext
_ARGON2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + ARGON2_PARAMS_LEN + AES_NONCE_SIZE
    + AEAD_MIN_CIPHERTEXT
)

# PBKDF2 envelope: magic + version + kdf_tag + salt + hash_tag + iterations(4) + nonce + ciphertext
_PBKDF2_ITERATIONS_FIELD_LEN: int = 4
_PBKDF2_MIN_ENVELOPE: int = (
    len(_PBE_MAGIC) + 1 + 1 + _SALT_LEN + 1 + _PBKDF2_ITERATIONS_FIELD_LEN
    + AES_NONCE_SIZE + AEAD_MIN_CIPHERTEXT
)

# ── AAD builders ──────────────────────────────────────────────────────────────

def _build_aad_argon2(salt: bytes, argon2_params: bytes) -> bytes:
    """Return the AAD for an Argon2 envelope (all bytes before the nonce)."""
    return _PBE_MAGIC + ENVELOPE_VERSION + _KDF_ARGON2 + salt + argon2_params

def _build_aad_pbkdf2(salt: bytes, hash_tag: bytes, iterations: int) -> bytes:
    """Return the AAD for a PBKDF2 envelope (all bytes before the nonce)."""
    return (
        _PBE_MAGIC
        + ENVELOPE_VERSION
        + _KDF_PBKDF2
        + salt
        + hash_tag
        + struct.pack(">I", iterations)
    )

# ── Encryption helpers ────────────────────────────────────────────────────────

def _encrypt_argon2(
    plaintext: bytes,
    password: str,
    nonce: bytes,
    argon2_time_cost: int,
    argon2_memory_cost: int,
    argon2_parallelism: int,
) -> bytes:
    """Return the raw Argon2 PBE envelope (not yet base64-encoded)."""
    argon2_params = struct.pack(
        ARGON2_PARAMS_STRUCT, argon2_time_cost, argon2_memory_cost, argon2_parallelism
    )
    derived = derive_key_argon2(
        password,
        time_cost=argon2_time_cost,
        memory_cost=argon2_memory_cost,
        parallelism=argon2_parallelism,
    )
    try:
        aad = _build_aad_argon2(derived.salt, argon2_params)
        with aesgcm_context(derived.key) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
    finally:
        zero_key(derived.key)

    return (
        _PBE_MAGIC
        + ENVELOPE_VERSION
        + _KDF_ARGON2
        + derived.salt
        + argon2_params
        + nonce
        + ciphertext
    )

def _encrypt_pbkdf2(plaintext: bytes, password: str, nonce: bytes) -> bytes:
    """Return the raw PBKDF2 PBE envelope (not yet base64-encoded)."""
    derived = derive_key_pbkdf2(password)
    try:
        if derived.pbkdf2_iterations is None or derived.pbkdf2_hash is None:
            raise EncryptionError(
                "derive_key_pbkdf2 returned incomplete metadata "
                "(pbkdf2_iterations or pbkdf2_hash is None) "
                "cannot construct a valid PBKDF2 envelope."
            )

        hash_tag = _PBKDF2_HASH_TO_TAG.get(derived.pbkdf2_hash)
        if hash_tag is None:
            raise EncryptionError(
                f"Cannot encode PBKDF2 hash {derived.pbkdf2_hash!r} into envelope."
            )

        iterations_bytes = struct.pack(">I", derived.pbkdf2_iterations)
        aad = _build_aad_pbkdf2(derived.salt, hash_tag, derived.pbkdf2_iterations)
        with aesgcm_context(derived.key) as cipher:
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
        # Return inside the try block so the finally still executes before
        # the value is handed back to the caller.
        return (
            _PBE_MAGIC
            + ENVELOPE_VERSION
            + _KDF_PBKDF2
            + derived.salt
            + hash_tag
            + iterations_bytes
            + nonce
            + ciphertext
        )
    finally:
        zero_key(derived.key)

# ── Public API ────────────────────────────────────────────────────────────────

def password_encrypt(
    plaintext: bytes,
    password: str,
    *,
    use_argon2: bool = True,
    argon2_time_cost: int = ARGON2_TIME_COST,
    argon2_memory_cost: int = ARGON2_MEMORY_COST,
    argon2_parallelism: int = ARGON2_PARALLELISM,
) -> str:
    """Encrypt *plaintext* with *password* using Argon2id (default) or PBKDF2 + AES-256-GCM."""
    if not plaintext:
        raise InputValidationError(
            "Plaintext must not be empty. "
            "Encrypting zero bytes produces a ciphertext that contains only the "
            "authentication tag and carries no useful information."
        )
    if not password:
        raise InputValidationError("Password must not be empty.")
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise InputValidationError(
            f"Password is too short ({len(password)} character(s)); "
            f"minimum is {_MIN_PASSWORD_LENGTH} characters. "
            "A short password remains vulnerable to targeted offline attacks "
            "even with Argon2id key stretching."
        )

    if use_argon2 and (
        argon2_time_cost > _DECRYPT_MAX_TIME_COST
        or argon2_memory_cost > _DECRYPT_MAX_MEMORY_COST
        or argon2_parallelism > _DECRYPT_MAX_PARALLELISM
    ):
        raise InputValidationError(
            f"Argon2 parameters exceed this toolkit's own decrypt-time "
            f"ceiling (time_cost<={_DECRYPT_MAX_TIME_COST}, "
            f"memory_cost<={_DECRYPT_MAX_MEMORY_COST} KiB, "
            f"parallelism<={_DECRYPT_MAX_PARALLELISM}); received "
            f"time_cost={argon2_time_cost}, memory_cost={argon2_memory_cost}, "
            f"parallelism={argon2_parallelism}. Data encrypted above this "
            "ceiling can never be decrypted by password_decrypt(), because "
            "decrypt-time bounds are intentionally tighter than "
            "encrypt-time bounds as a DoS guard against untrusted "
            "envelopes. Lower the parameters, or raise DECRYPT_MAX_ARGON2_* "
            "in constants.py if you control both ends and accept the "
            "tradeoff."
        )

    try:
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        if use_argon2:
            envelope = _encrypt_argon2(
                plaintext, password, nonce,
                argon2_time_cost, argon2_memory_cost, argon2_parallelism,
            )
        else:
            envelope = _encrypt_pbkdf2(plaintext, password, nonce)

        return base64.urlsafe_b64encode(envelope).decode()
    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise EncryptionError("Password-based encryption failed.") from exc

def password_decrypt(token: str, password: str) -> bytes:
    """Decrypt a token produced by :func:`password_encrypt`."""
    if not password:
        raise InputValidationError("Password must not be empty.")

    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode())
        magic_len = len(_PBE_MAGIC)

        if len(raw) < _HEADER_PREFIX_LEN:
            raise DecryptionError(
                f"Token is too short to be a valid envelope "
                f"({len(raw)} bytes; minimum header prefix is {_HEADER_PREFIX_LEN} bytes). "
                "The token is likely truncated or corrupted."
            )
        if raw[:magic_len] != _PBE_MAGIC:
            raise DecryptionError("Envelope format not recognized.")
        if raw[magic_len : magic_len + 1] != ENVELOPE_VERSION:
            raise DecryptionError("Envelope version not supported.")

        kdf_tag = raw[magic_len + 1 : magic_len + 2]
        if kdf_tag not in (_KDF_ARGON2, _KDF_PBKDF2):
            raise DecryptionError("Unrecognized KDF tag inside envelope.")

        min_len = _ARGON2_MIN_ENVELOPE if kdf_tag == _KDF_ARGON2 else _PBKDF2_MIN_ENVELOPE
        kdf_name = "Argon2" if kdf_tag == _KDF_ARGON2 else "PBKDF2"
        if len(raw) < min_len:
            raise DecryptionError(
                f"{kdf_name} envelope is too short ({len(raw)} bytes; "
                f"minimum expected is {min_len}). "
                "The token is likely truncated or corrupted."
            )

        # Cursor advances past magic + version + kdf_tag.
        offset = magic_len + 2
        salt = raw[offset : offset + _SALT_LEN]
        offset += _SALT_LEN

        from crypto_toolkit.core.kdf import DerivedKey  # local import avoids circular
        derived: DerivedKey | None = None

        if kdf_tag == _KDF_ARGON2:
            argon2_params_raw = raw[offset : offset + ARGON2_PARAMS_LEN]
            offset += ARGON2_PARAMS_LEN
            time_cost, memory_cost, parallelism = struct.unpack(
                ARGON2_PARAMS_STRUCT, argon2_params_raw
            )

            if (
                time_cost > _DECRYPT_MAX_TIME_COST
                or memory_cost > _DECRYPT_MAX_MEMORY_COST
                or parallelism > _DECRYPT_MAX_PARALLELISM
            ):
                raise DecryptionError(
                    f"Envelope Argon2 parameters exceed the maximum allowed "
                    f"(time_cost≤{_DECRYPT_MAX_TIME_COST}, "
                    f"memory_cost≤{_DECRYPT_MAX_MEMORY_COST} KiB, "
                    f"parallelism≤{_DECRYPT_MAX_PARALLELISM}); "
                    f"received time_cost={time_cost}, memory_cost={memory_cost}, "
                    f"parallelism={parallelism}. "
                    "The token may originate from an untrusted or malicious source."
                )

            if (
                time_cost < _DECRYPT_MIN_TIME_COST
                or memory_cost < _DECRYPT_MIN_MEMORY_COST
                or parallelism < _DECRYPT_MIN_PARALLELISM
            ):
                raise DecryptionError(
                    f"Envelope Argon2 parameters are below the minimum allowed "
                    f"(time_cost≥{_DECRYPT_MIN_TIME_COST}, "
                    f"memory_cost≥{_DECRYPT_MIN_MEMORY_COST} KiB, "
                    f"parallelism≥{_DECRYPT_MIN_PARALLELISM}); "
                    f"received time_cost={time_cost}, memory_cost={memory_cost}, "
                    f"parallelism={parallelism}. "
                    "The token is corrupt or originates from a malicious source."
                )

            nonce = raw[offset : offset + AES_NONCE_SIZE]
            offset += AES_NONCE_SIZE
            ciphertext = raw[offset:]

            derived = derive_key_argon2(
                password, salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            try:
                aad = _build_aad_argon2(salt, argon2_params_raw)
                with aesgcm_context(derived.key) as cipher:
                    plaintext = cipher.decrypt(nonce, ciphertext, aad)
            finally:
                zero_key(derived.key)

        else:  # kdf_tag == _KDF_PBKDF2
            hash_tag_byte = raw[offset : offset + 1]
            pbkdf2_hash = _PBKDF2_TAG_TO_HASH.get(hash_tag_byte)
            if pbkdf2_hash is None:
                raise DecryptionError(
                    f"Unrecognized PBKDF2 hash tag in envelope: {hash_tag_byte!r}."
                )
            offset += 1  # consume hash_tag byte
            (pbkdf2_iterations,) = struct.unpack(">I", raw[offset : offset + 4])
            offset += 4  # consume 4-byte iterations field

            pbkdf2_max = _PBKDF2_MAX_ITERATIONS.get(pbkdf2_hash, 10_000_000)
            if pbkdf2_iterations > pbkdf2_max:
                raise DecryptionError(
                    f"PBKDF2 iteration count {pbkdf2_iterations:,} exceeds the "
                    f"maximum allowed ({pbkdf2_max:,}) for {pbkdf2_hash!r}. "
                    "The token may originate from an untrusted or malicious source."
                )

            pbkdf2_min = _PBKDF2_MIN_ITERATIONS.get(pbkdf2_hash, 1)
            if pbkdf2_iterations < pbkdf2_min:
                raise DecryptionError(
                    f"PBKDF2 iteration count {pbkdf2_iterations:,} is below the "
                    f"minimum allowed ({pbkdf2_min:,}) for {pbkdf2_hash!r}. "
                    "The token is corrupt or originates from a malicious source."
                )

            nonce = raw[offset : offset + AES_NONCE_SIZE]
            offset += AES_NONCE_SIZE
            ciphertext = raw[offset:]

            derived = derive_key_pbkdf2(
                password, salt=salt,
                iterations=pbkdf2_iterations,
                hash_algorithm=pbkdf2_hash,
            )
            try:
                aad = _build_aad_pbkdf2(salt, hash_tag_byte, pbkdf2_iterations)
                with aesgcm_context(derived.key) as cipher:
                    plaintext = cipher.decrypt(nonce, ciphertext, aad)
            finally:
                zero_key(derived.key)

        return plaintext

    except CryptoToolkitError:
        raise
    except Exception as exc:
        raise DecryptionError(
            "Password-based decryption failed, incorrect password or corrupted data."
        ) from exc