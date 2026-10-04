"""
app.py
------
Flask web application for the Digital Signature Verification System.

Endpoints:
  GET  /               Web UI
  POST /api/keygen     Generate RSA key pair (in-memory only)
  POST /api/sign       Sign a message or uploaded file
  POST /api/verify     Verify a signature package
  GET  /api/audit      Return recent audit log entries (JSON)
  GET  /api/stats      Return summary statistics from audit log
  POST /api/transfer   Save a signed package to the receiver inbox
  GET  /api/inbox      List packages waiting in the receiver inbox

Usage:
    python app.py
    Open http://127.0.0.1:5000
"""

import base64
import hashlib
import json
import os
import sys
import traceback
import time

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(__file__))

import config as cfg
import audit_log
from crypto_core import (
    generate_key_pair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_message,
    verify_package,
)
from cryptography.hazmat.primitives import serialization as _serialization

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = cfg.WEB_MAX_UPLOAD_MB * 1024 * 1024

# Directory used by the transfer simulation
INBOX_DIR = os.path.join(cfg.RECEIVED_DIR, "inbox")


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _err(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


def _human_error(exc: Exception, context: str = "") -> str:
    """Convert common crypto exceptions to user-friendly messages."""
    msg = str(exc).lower()
    if "could not deserialize" in msg or "pem" in msg or "der" in msg:
        return "The uploaded file is not a valid PEM key. Please upload a valid RSA private or public key."
    if "password" in msg or "bad decrypt" in msg or "decryption" in msg:
        return "Incorrect passphrase. The private key could not be decrypted with the supplied passphrase."
    if "key size" in msg and "minimum" in msg:
        return "The RSA key is too small. This system requires a minimum of 2048-bit RSA keys."
    if "not an rsa" in msg:
        return "The uploaded key is not an RSA key. Only RSA keys are supported."
    return f"{context}: {exc}" if context else str(exc)


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/keygen", methods=["POST"])
def api_keygen():
    """Generate RSA key pair. Keys are returned to the browser — never saved server-side."""
    data = request.get_json(silent=True) or {}
    try:
        bits = int(data.get("bits", cfg.DEFAULT_KEY_SIZE))
    except (ValueError, TypeError):
        return _err("Invalid bits value. Must be an integer (2048, 3072, or 4096).")

    try:
        private_key, public_key = generate_key_pair(bits)
    except ValueError as exc:
        audit_log.log_error("web", str(exc))
        return _err(_human_error(exc))
    except Exception as exc:
        audit_log.log_error("web", f"keygen failed: {exc}")
        return _err("Key generation failed. Please try again.", 500)

    priv_pem = serialize_private_key(private_key).decode("ascii")
    pub_pem  = serialize_public_key(public_key).decode("ascii")

    audit_log.log_keygen(source="web", key_size=bits)
    return jsonify({
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem,
        "private_key": priv_pem,
        "public_key": pub_pem,
        "bits": bits,
    })


@app.route("/api/sign", methods=["POST"])
def api_sign():
    """Sign a message or uploaded file. Returns the signature package only — does NOT verify."""
    if request.content_type and "application/json" in request.content_type:
        data = request.get_json(silent=True) or {}
        priv_pem_str = data.get("private_key_pem", "")
        message_text = data.get("message")
        file_b64     = data.get("file_b64")
        filename     = data.get("filename", "")
        password_str = data.get("password") or data.get("passphrase", "")

        if message_text is None and file_b64 is None:
            return _err("Please provide a text message or upload a file to sign.")

        if file_b64:
            try:
                message_bytes = base64.b64decode(file_b64)
            except Exception as exc:
                return _err(f"Invalid base64 in file: {exc}")
        else:
            message_bytes = message_text.encode("utf-8")
    else:
        priv_pem_str = request.form.get("private_key_pem", "")
        message_text = request.form.get("message")
        password_str = request.form.get("password") or request.form.get("passphrase", "")
        filename     = ""
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            message_bytes = uploaded.read()
            filename = uploaded.filename
        elif message_text is not None:
            message_bytes = message_text.encode("utf-8")
        else:
            return _err("Please provide a text message or upload a file to sign.")

    if not priv_pem_str:
        return _err("A private key is required. Please upload your PEM private key.")

    password = password_str.encode() if password_str else None

    try:
        private_key = load_private_key(priv_pem_str.encode("ascii"), password=password)
    except Exception as exc:
        audit_log.log_error("web", f"bad private key: {exc}")
        return _err(_human_error(exc, "Invalid Private Key"))

    try:
        package = sign_message(message_bytes, private_key, filename=filename)
    except Exception as exc:
        audit_log.log_error("web", f"signing failed: {exc}")
        return _err(f"Signing failed: {exc}", 500)

    audit_log.log_sign(
        source="web",
        filename=package.get("filename", ""),
        sha256=package.get("message_sha256", ""),
        nonce=package.get("nonce", ""),
    )
    # Return the package and key size — do NOT verify
    key_bits = private_key.key_size
    resp = {"package": package, "key_bits": key_bits}
    for k, v in package.items():
        if k not in resp:
            resp[k] = v
    return jsonify(resp)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """Verify a signature package. This endpoint is only called by the Receiver."""
    data = request.get_json(silent=True)
    if not data:
        return _err("JSON body required.")

    package = data.get("package")
    if not package:
        return _err("'package' field is required.")

    trusted_pub = None
    tpub_pem = data.get("trusted_public_key_pem", "").strip()
    if tpub_pem:
        try:
            trusted_pub = load_public_key(tpub_pem.encode("ascii"))
        except Exception as exc:
            return _err(_human_error(exc, "Invalid Trusted Public Key"))

    max_age = data.get("check_age")
    if max_age is not None:
        try:
            max_age = int(max_age)
        except (ValueError, TypeError):
            return _err("check_age must be an integer (seconds).")

    check_replay = bool(data.get("check_replay", False))

    try:
        result = verify_package(
            package,
            trusted_public_key=trusted_pub,
            max_age=max_age,
            check_replay=check_replay,
        )
    except Exception as exc:
        traceback.print_exc()
        audit_log.log_error("web", f"verify error: {exc}")
        return _err(f"Verification error: {exc}", 500)

    audit_log.log_verify(
        status=result.status,
        reason=result.reason,
        source="web",
        filename=package.get("filename", ""),
        sha256=package.get("message_sha256", ""),
        nonce=package.get("nonce", ""),
        algorithm=package.get("algorithm", ""),
    )

    # Determine which specific check failed for detailed UI feedback
    checks = _build_check_details(result, package, trusted_pub is not None)

    return jsonify({
        "status": result.status,
        "reason": result.reason,
        "checks": checks,
    })


def _build_check_details(result, package, has_trusted_key: bool) -> dict:
    """Build a per-check breakdown for the UI result display."""
    ok = result.status == "VALID"
    reason = result.reason.lower()

    checks = {
        "structure":  True,
        "hash":       True,
        "trusted_key": True,
        "signature":  True,
        "freshness":  True,
        "replay":     True,
    }

    if result.status == "INVALID":
        if "missing fields" in reason or "package" in reason or "version" in reason or "decode" in reason:
            checks["structure"] = False
        elif "sha-256 mismatch" in reason or "tampered" in reason:
            checks["hash"] = False
        elif "trusted key" in reason or "public key does not match" in reason:
            checks["trusted_key"] = False
        elif "signature" in reason:
            checks["signature"] = False
        else:
            checks["signature"] = False
    elif result.status == "REJECTED":
        if "replay" in reason or "nonce" in reason:
            checks["replay"] = False
        elif "old" in reason or "age" in reason or "expired" in reason:
            checks["freshness"] = False

    if not has_trusted_key:
        checks["trusted_key"] = None  # Not checked

    return checks


@app.route("/api/audit", methods=["GET"])
def api_audit():
    """Return the last N audit log entries."""
    try:
        n = int(request.args.get("n", 100))
    except ValueError:
        n = 100
    event_filter  = request.args.get("event", "")
    status_filter = request.args.get("status", "")

    entries = audit_log.read_log(last_n=n)

    if event_filter:
        entries = [e for e in entries if e.get("event") == event_filter.upper()]
    if status_filter:
        entries = [e for e in entries if e.get("status") == status_filter.upper()]

    return jsonify({"entries": entries, "total": len(entries)})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return summary statistics derived from the audit log."""
    all_entries = audit_log.read_log(last_n=10000)

    stats = {
        "total_events":       len(all_entries),
        "signatures_created": sum(1 for e in all_entries if e.get("event") == "SIGN"),
        "keys_generated":     sum(1 for e in all_entries if e.get("event") == "KEYGEN"),
        "verifications": {
            "valid":    sum(1 for e in all_entries if e.get("event") == "VERIFY" and e.get("status") == "VALID"),
            "invalid":  sum(1 for e in all_entries if e.get("event") == "VERIFY" and e.get("status") == "INVALID"),
            "rejected": sum(1 for e in all_entries if e.get("event") == "VERIFY" and e.get("status") == "REJECTED"),
        },
        "errors": sum(1 for e in all_entries if e.get("event") == "ERROR"),
        "attack_tests_run": sum(1 for e in all_entries if e.get("event") == "ATTACK"),
    }
    stats["total_verifications"] = (
        stats["verifications"]["valid"]
        + stats["verifications"]["invalid"]
        + stats["verifications"]["rejected"]
    )
    return jsonify(stats)


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    """
    Transfer Simulation: save a signed package to the receiver inbox.
    The package is stored in received/inbox/ so the Receiver page can load it.
    This does NOT verify — it only simulates handing the package over.
    """
    data = request.get_json(silent=True)
    if not data or "package" not in data:
        return _err("'package' field is required.")

    package = data["package"]
    os.makedirs(INBOX_DIR, exist_ok=True)

    nonce    = str(package.get("nonce", "unknown"))[:16]
    filename = f"inbox_{nonce}.sig.json"
    filepath = os.path.join(INBOX_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2)

    return jsonify({
        "success": True,
        "filename": filename,
        "message": "Package transferred to Receiver inbox. Open the Receiver / Verify page to verify it.",
    })


@app.route("/api/inbox", methods=["GET"])
def api_inbox():
    """List packages currently in the receiver inbox."""
    os.makedirs(INBOX_DIR, exist_ok=True)
    files = []
    for fname in sorted(os.listdir(INBOX_DIR)):
        if fname.endswith(".sig.json"):
            fpath = os.path.join(INBOX_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                files.append({
                    "filename":  fname,
                    "algorithm": pkg.get("algorithm", ""),
                    "timestamp": pkg.get("timestamp", 0),
                    "sha256":    pkg.get("message_sha256", "")[:16] + "...",
                    "original_filename": pkg.get("filename", "(text)"),
                })
            except Exception:
                pass
    return jsonify({"inbox": files})


@app.route("/api/inbox/<filename>", methods=["GET"])
def api_inbox_get(filename):
    """Return a specific package from the inbox."""
    # Safety: prevent directory traversal
    safe_name = os.path.basename(filename)
    fpath = os.path.join(INBOX_DIR, safe_name)
    if not os.path.isfile(fpath):
        return _err("Package not found in inbox.", 404)
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            pkg = json.load(f)
        return jsonify({"package": pkg, "filename": safe_name})
    except Exception as exc:
        return _err(f"Could not read package: {exc}", 500)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

@app.route("/api/fingerprint", methods=["POST"])
def api_fingerprint():
    """Compute SHA-256 fingerprint of a public key (colon-separated hex pairs).
    
    The fingerprint is SHA-256 of the DER-encoded SubjectPublicKeyInfo (SPKI),
    which is the standard way to fingerprint RSA public keys.
    """
    data = request.get_json(silent=True) or {}
    pub_pem = data.get("public_key_pem", "").strip()
    if not pub_pem:
        return _err("'public_key_pem' is required.")
    try:
        public_key = load_public_key(pub_pem.encode("ascii"))
        der_bytes = public_key.public_bytes(
            encoding=_serialization.Encoding.DER,
            format=_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der_bytes).hexdigest()
        # Format as colon-separated pairs: AA:BB:CC:...
        fingerprint = ":".join(digest[i:i+2].upper() for i in range(0, len(digest), 2))
        return jsonify({"fingerprint": fingerprint, "algorithm": "SHA-256"})
    except Exception as exc:
        return _err(_human_error(exc, "Fingerprint error"))


@app.route("/api/log_attack", methods=["POST"])
def api_log_attack():
    """Record an Attack Lab simulation event in the audit log.
    
    The Attack Lab runs in the browser JS. To ensure attack events appear in
    the real audit log and dashboard stats, JS calls this endpoint after each
    attack execution.
    """
    data = request.get_json(silent=True) or {}
    attack_name = str(data.get("attack_name", "Unknown Attack"))[:100]
    status = str(data.get("status", "DETECTED")).upper()
    reason = str(data.get("reason", ""))[:500]
    nonce = str(data.get("nonce", ""))[:64]
    sha256 = str(data.get("sha256", ""))[:64]

    # Only allow known statuses to avoid log injection
    allowed_statuses = {"DETECTED", "INVALID", "REJECTED", "VALID"}
    if status not in allowed_statuses:
        status = "DETECTED"

    audit_log.log_attack(
        attack_name=attack_name,
        status=status,
        reason=reason,
        nonce=nonce,
        sha256=sha256,
    )
    return jsonify({"logged": True, "attack_name": attack_name, "status": status})


if __name__ == "__main__":
    print(f"DSVS Web Interface -- http://{cfg.WEB_HOST}:{cfg.WEB_PORT}")
    app.run(debug=cfg.WEB_DEBUG, host=cfg.WEB_HOST, port=cfg.WEB_PORT)
