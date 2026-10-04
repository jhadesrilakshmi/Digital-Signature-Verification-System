"""
crypto_core.py
--------------
Core cryptographic primitives for the Digital Signature Verification System.

Provides:
  - RSA key-pair generation (2048+ bits, optional password protection)
  - SHA-256 hashing
  - RSA-PSS signing and verification
  - Signature package construction and parsing
  - Replay-attack protection (in-memory nonce store)
"""

import base64
import hashlib
import json
import os
import secrets
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

try:
    import config as _cfg
    PACKAGE_VERSION         = _cfg.PACKAGE_VERSION
    ALGORITHM_LABEL         = _cfg.ALGORITHM_LABEL
    MIN_KEY_BITS            = _cfg.MIN_KEY_SIZE
    DEFAULT_MAX_AGE_SECONDS = _cfg.MAX_SIGNATURE_AGE
except ImportError:
    # Fallback if config.py is not present (e.g. isolated import)
    PACKAGE_VERSION         = 1
    ALGORITHM_LABEL         = "RSA-PSS-SHA256"
    MIN_KEY_BITS            = 2048
    DEFAULT_MAX_AGE_SECONDS = 300

SIGNED_CONTENT_PREFIX = b"DSVS1"
_nonce_store: set = set()       # in-memory; cleared on restart


# ──────────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────────

def generate_key_pair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair.  key_size must be >= 2048."""
    if key_size < MIN_KEY_BITS:
        raise ValueError(f"Key size must be at least {MIN_KEY_BITS} bits, got {key_size}.")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def serialize_private_key(
    private_key: RSAPrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    """Serialize an RSA private key to PEM format (optionally encrypted)."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize an RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes, password: Optional[bytes] = None) -> RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem_data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key.")
    key_size = key.key_size
    if key_size < MIN_KEY_BITS:
        raise ValueError(f"Key size {key_size} bits is below the minimum {MIN_KEY_BITS} bits.")
    return key


def load_public_key(pem_data: bytes) -> RSAPublicKey:
    """Load an RSA public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("Loaded key is not an RSA public key.")
    return key


# ──────────────────────────────────────────────
# Hashing
# ──────────────────────────────────────────────

def sha256_digest(data: bytes) -> bytes:
    """Return the raw SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ──────────────────────────────────────────────
# Signed-content builder
# ──────────────────────────────────────────────

def _build_signed_content(
    message_hash_hex: str,
    timestamp: int,
    nonce: str,
) -> bytes:
    """Build the byte string that is actually fed to the RSA signer.

    Format: b"DSVS1" | timestamp (8 bytes big-endian) | nonce (32 bytes) | hash (32 bytes)
    """
    ts_bytes  = timestamp.to_bytes(8, "big")
    nonce_bytes = nonce.encode("ascii")
    hash_bytes  = bytes.fromhex(message_hash_hex)
    return SIGNED_CONTENT_PREFIX + ts_bytes + nonce_bytes + hash_bytes


# ──────────────────────────────────────────────
# PSS padding helper
# ──────────────────────────────────────────────

def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


# ──────────────────────────────────────────────
# Signing
# ──────────────────────────────────────────────

def sign_message(
    message: bytes,
    private_key: RSAPrivateKey,
    filename: str = "",
) -> dict:
    """Sign *message* and return a signature package (dict).

    The package is JSON-serialisable and contains everything a receiver
    needs to verify the signature.
    """
    timestamp = int(time.time())
    nonce     = secrets.token_hex(16)   # 32 hex chars = 128 bits of entropy

    message_hash_hex = sha256_hex(message)
    signed_content   = _build_signed_content(message_hash_hex, timestamp, nonce)

    signature = private_key.sign(signed_content, _pss_padding(), hashes.SHA256())

    public_key_pem = serialize_public_key(private_key.public_key()).decode("ascii")

    return {
        "version":       PACKAGE_VERSION,
        "algorithm":     ALGORITHM_LABEL,
        "filename":      filename,
        "timestamp":     timestamp,
        "nonce":         nonce,
        "message_sha256": message_hash_hex,
        "message_b64":   base64.b64encode(message).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_key_pem,
    }


# ──────────────────────────────────────────────
# Verification
# ──────────────────────────────────────────────

class VerificationResult:
    """Holds the outcome of a verification attempt."""

    VALID    = "VALID"
    INVALID  = "INVALID"
    REJECTED = "REJECTED"

    def __init__(self, status: str, reason: str = ""):
        self.status = status
        self.reason = reason
        self.ok = (status == self.VALID)

    def __repr__(self):
        return f"VerificationResult({self.status!r}, {self.reason!r})"

    def __str__(self):
        if self.reason:
            return f"{self.status}: {self.reason}"
        return self.status


def verify_package(
    package: dict,
    trusted_public_key: Optional[RSAPublicKey] = None,
    check_replay: bool = False,
    max_age: Optional[int] = None,
) -> VerificationResult:
    """Verify a signature package.

    Parameters
    ----------
    package:            The decoded JSON package dict.
    trusted_public_key: If given, the embedded public key must match this one.
    check_replay:       If True, reject duplicate nonces.
    max_age:            Maximum allowed age of the signature in seconds.
                        Uses DEFAULT_MAX_AGE_SECONDS if check_replay is True
                        and max_age is None.
    """
    # ── 1. Basic structure check ──────────────────────────────────────
    required_fields = {
        "version", "algorithm", "timestamp", "nonce",
        "message_sha256", "message_b64", "signature_b64", "public_key_pem",
    }
    missing = required_fields - set(package.keys())
    if missing:
        return VerificationResult(
            VerificationResult.INVALID,
            f"Package is missing fields: {', '.join(sorted(missing))}",
        )

    if package.get("version") != PACKAGE_VERSION:
        return VerificationResult(
            VerificationResult.INVALID,
            f"Unknown package version: {package.get('version')}",
        )

    # ── 2. Decode fields ──────────────────────────────────────────────
    try:
        message_bytes = base64.b64decode(package["message_b64"])
        signature     = base64.b64decode(package["signature_b64"])
        timestamp     = int(package["timestamp"])
        nonce         = str(package["nonce"])
    except Exception as exc:
        return VerificationResult(VerificationResult.INVALID, f"Decode error: {exc}")

    # ── 3. Age check ──────────────────────────────────────────────────
    if max_age is not None:
        age = int(time.time()) - timestamp
        if age > max_age:
            return VerificationResult(
                VerificationResult.REJECTED,
                f"Signature is {age}s old (max allowed: {max_age}s).",
            )
    elif check_replay:
        age = int(time.time()) - timestamp
        if age > DEFAULT_MAX_AGE_SECONDS:
            return VerificationResult(
                VerificationResult.REJECTED,
                f"Signature is {age}s old (max allowed: {DEFAULT_MAX_AGE_SECONDS}s).",
            )

    # ── 4. Replay check ───────────────────────────────────────────────
    if check_replay:
        if nonce in _nonce_store:
            return VerificationResult(
                VerificationResult.REJECTED,
                "Replay detected: nonce has already been used.",
            )

    # ── 5. Load the embedded public key ──────────────────────────────
    try:
        embedded_pub = load_public_key(package["public_key_pem"].encode("ascii"))
    except Exception as exc:
        return VerificationResult(VerificationResult.INVALID, f"Bad public key: {exc}")

    # ── 6. Compare with trusted key (if provided) ────────────────────
    if trusted_public_key is not None:
        trusted_pem  = serialize_public_key(trusted_public_key)
        embedded_pem = serialize_public_key(embedded_pub)
        if trusted_pem != embedded_pem:
            return VerificationResult(
                VerificationResult.INVALID,
                "Embedded public key does not match the trusted key.",
            )

    # ── 7. Re-compute the message hash ───────────────────────────────
    computed_hash = sha256_hex(message_bytes)
    if computed_hash != package["message_sha256"]:
        return VerificationResult(
            VerificationResult.INVALID,
            "Message SHA-256 mismatch — message has been tampered with.",
        )

    # ── 8. Rebuild signed content and verify signature ───────────────
    signed_content = _build_signed_content(
        package["message_sha256"], timestamp, nonce
    )

    try:
        embedded_pub.verify(signature, signed_content, _pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return VerificationResult(
            VerificationResult.INVALID,
            "Signature verification failed.",
        )
    except Exception as exc:
        return VerificationResult(VerificationResult.INVALID, f"Verification error: {exc}")

    # ── 9. Record nonce now that everything is valid ─────────────────
    if check_replay:
        _nonce_store.add(nonce)

    return VerificationResult(VerificationResult.VALID)


# ──────────────────────────────────────────────
# Replay store helpers
# ──────────────────────────────────────────────

def clear_nonce_store() -> None:
    """Clear the in-memory nonce store (useful in tests)."""
    _nonce_store.clear()


def nonce_count() -> int:
    """Return the number of recorded nonces."""
    return len(_nonce_store)
