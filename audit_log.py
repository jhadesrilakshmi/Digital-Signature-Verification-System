"""
audit_log.py
------------
Append-only audit log for the Digital Signature Verification System.

Every verification attempt — whether it comes from the web API, the CLI
tool, or the TCP server — can be recorded here as a JSON-Lines entry.

Log location: logs/audit.jsonl  (created automatically)

Each entry has the fields:
    timestamp_utc  ISO-8601 UTC time of the event
    event          "VERIFY" | "SIGN" | "KEYGEN" | "ERROR" | "ATTACK"
    source         "web" | "cli" | "server" | "test" | "attack-lab"
    status         "VALID" | "INVALID" | "REJECTED" | "OK" | "ERROR" | "DETECTED"
    reason         human-readable detail (empty string if none)
    peer           network peer address (server only, otherwise "")
    filename       signed file name (empty if text message)
    sha256         message hash (hex string, empty on error)
    nonce          nonce from the package (empty on error)
    algorithm      algorithm label from the package
"""

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import config as cfg

_lock = threading.Lock()


def _ensure_log_dir():
    os.makedirs(cfg.LOGS_DIR, exist_ok=True)


def _write(entry: dict):
    if not cfg.AUDIT_LOG_ENABLED:
        return
    _ensure_log_dir()
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    with _lock:
        with open(cfg.AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def log_verify(
    status: str,
    reason: str = "",
    source: str = "cli",
    peer: str = "",
    filename: str = "",
    sha256: str = "",
    nonce: str = "",
    algorithm: str = cfg.ALGORITHM_LABEL,
):
    """Record a verification attempt."""
    _write({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event":     "VERIFY",
        "source":    source,
        "status":    status,
        "reason":    reason,
        "peer":      peer,
        "filename":  filename,
        "sha256":    sha256,
        "nonce":     nonce,
        "algorithm": algorithm,
    })


def log_sign(
    source: str = "cli",
    filename: str = "",
    sha256: str = "",
    nonce: str = "",
    algorithm: str = cfg.ALGORITHM_LABEL,
):
    """Record a signing operation."""
    _write({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event":     "SIGN",
        "source":    source,
        "status":    "OK",
        "reason":    "",
        "peer":      "",
        "filename":  filename,
        "sha256":    sha256,
        "nonce":     nonce,
        "algorithm": algorithm,
    })


def log_keygen(source: str = "cli", key_size: int = cfg.DEFAULT_KEY_SIZE):
    """Record a key-generation event."""
    _write({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event":     "KEYGEN",
        "source":    source,
        "status":    "OK",
        "reason":    f"RSA-{key_size}",
        "peer":      "",
        "filename":  "",
        "sha256":    "",
        "nonce":     "",
        "algorithm": cfg.ALGORITHM_LABEL,
    })


def log_error(source: str, reason: str):
    """Record an error event."""
    _write({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event":     "ERROR",
        "source":    source,
        "status":    "ERROR",
        "reason":    reason,
        "peer":      "",
        "filename":  "",
        "sha256":    "",
        "nonce":     "",
        "algorithm": "",
    })


def log_attack(
    attack_name: str,
    status: str,
    reason: str = "",
    nonce: str = "",
    sha256: str = "",
):
    """Record an Attack Lab simulation event.

    status should be one of: "DETECTED", "INVALID", "REJECTED".
    These events appear in the audit log and contribute to dashboard stats.
    """
    _write({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event":     "ATTACK",
        "source":    "attack-lab",
        "status":    status,
        "reason":    f"[{attack_name}] {reason}",
        "peer":      "",
        "filename":  "",
        "sha256":    sha256,
        "nonce":     nonce,
        "algorithm": "RSA-PSS-SHA256",
    })


def read_log(last_n: int = 50) -> list[dict]:
    """Return the last *last_n* audit log entries as a list of dicts."""
    try:
        with open(cfg.AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        entries = [json.loads(l) for l in lines if l.strip()]
        return entries[-last_n:]
    except FileNotFoundError:
        return []
    except Exception:
        return []
