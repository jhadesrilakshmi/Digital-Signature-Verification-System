"""
config.py
---------
Central configuration for the Digital Signature Verification System.
All tuneable parameters live here so that no magic numbers are scattered
across the codebase.
"""

import os

# ──────────────────────────────────────────────
# Directories (resolved relative to this file)
# ──────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR     = os.path.join(BASE_DIR, "keys")
CERTS_DIR    = os.path.join(BASE_DIR, "certs")
SAMPLES_DIR  = os.path.join(BASE_DIR, "samples")
RECEIVED_DIR = os.path.join(BASE_DIR, "received")
LOGS_DIR     = os.path.join(BASE_DIR, "logs")

# ──────────────────────────────────────────────
# Cryptography
# ──────────────────────────────────────────────

DEFAULT_KEY_SIZE   = 2048          # bits
MIN_KEY_SIZE       = 2048          # bits — keys below this are rejected
HASH_ALGORITHM     = "SHA-256"
PADDING_SCHEME     = "RSA-PSS"
ALGORITHM_LABEL    = "RSA-PSS-SHA256"
PACKAGE_VERSION    = 1

# ──────────────────────────────────────────────
# Replay protection
# ──────────────────────────────────────────────

MAX_SIGNATURE_AGE  = 300           # seconds (5 minutes)
NONCE_SIZE_BYTES   = 16            # 128-bit random nonce

# ──────────────────────────────────────────────
# Networking
# ──────────────────────────────────────────────

SERVER_HOST        = "0.0.0.0"
SERVER_PORT        = 5050
CLIENT_HOST        = "127.0.0.1"
CLIENT_PORT        = 5050
SOCKET_TIMEOUT     = 30            # seconds
MAX_MESSAGE_BYTES  = 50 * 1024 * 1024   # 50 MB

# ──────────────────────────────────────────────
# TLS (self-signed demo cert)
# ──────────────────────────────────────────────

TLS_CERT_PATH      = os.path.join(CERTS_DIR, "server.crt")
TLS_KEY_PATH       = os.path.join(CERTS_DIR, "server.key")
CERT_DAYS_VALID    = 365

# ──────────────────────────────────────────────
# Web interface
# ──────────────────────────────────────────────

WEB_HOST           = "127.0.0.1"
WEB_PORT           = 5000
WEB_DEBUG          = True
WEB_MAX_UPLOAD_MB  = 50

# ──────────────────────────────────────────────
# Audit log
# ──────────────────────────────────────────────

AUDIT_LOG_FILE     = os.path.join(LOGS_DIR, "audit.jsonl")
AUDIT_LOG_ENABLED  = True
