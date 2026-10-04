#!/usr/bin/env bash
# run_demo.sh
# -----------
# End-to-end command-line demo for the Digital Signature Verification System.
# Run from the digital_signature_system/ directory.
#
# Usage:  ./run_demo.sh
#         bash run_demo.sh   (on Windows Git-Bash or WSL)

set -euo pipefail

PYTHON="${PYTHON:-python}"
KEYS_DIR="keys"
SAMPLES_DIR="samples"

SEP="══════════════════════════════════════════════════════════"

echo ""
echo "$SEP"
echo "  Digital Signature Verification System — End-to-end Demo"
echo "$SEP"

# ── 0. Install dependencies ───────────────────────────────────────
echo ""
echo "▶ Installing dependencies …"
$PYTHON -m pip install -q -r requirements.txt
echo "  Done."

# ── 1. Key generation ─────────────────────────────────────────────
echo ""
echo "▶ [1] Generating Alice's RSA-2048 key pair …"
$PYTHON keygen.py --name alice --keys-dir "$KEYS_DIR"

# ── 2. Sign a text message ────────────────────────────────────────
echo ""
echo "▶ [2] Signing a text message …"
$PYTHON sign.py --key "$KEYS_DIR/alice_private.pem" --text "Pay Bob 100 dollars." \
       --out "$SAMPLES_DIR/text_signed.sig.json"

# ── 3. Verify valid signature ─────────────────────────────────────
echo ""
echo "▶ [3] Verifying signature (should be VALID) …"
$PYTHON verify.py --package "$SAMPLES_DIR/text_signed.sig.json" \
                  --pub "$KEYS_DIR/alice_public.pem"

# ── 4. Sign a file ────────────────────────────────────────────────
echo ""
echo "▶ [4] Signing samples/message.txt …"
$PYTHON sign.py --key "$KEYS_DIR/alice_private.pem" \
       --file "$SAMPLES_DIR/message.txt"

# ── 5. Verify the file signature ─────────────────────────────────
echo ""
echo "▶ [5] Verifying file signature (should be VALID) …"
$PYTHON verify.py --package "$SAMPLES_DIR/message.txt.sig.json" \
                  --pub "$KEYS_DIR/alice_public.pem"

# ── 6. Tamper simulation ──────────────────────────────────────────
echo ""
echo "▶ [6] Tampering with the package (should be INVALID) …"
$PYTHON - <<'EOF'
import json, base64, sys
with open("samples/text_signed.sig.json") as f:
    pkg = json.load(f)
# Tamper with message
tampered = base64.b64decode(pkg["message_b64"]).replace(b"100", b"999")
pkg["message_b64"] = base64.b64encode(tampered).decode()
with open("samples/tampered.sig.json", "w") as f:
    json.dump(pkg, f, indent=2)
print("  Tampered package written to samples/tampered.sig.json")
EOF
$PYTHON verify.py --package "$SAMPLES_DIR/tampered.sig.json" \
                  --pub "$KEYS_DIR/alice_public.pem" || true

# ── 7. Replay simulation ──────────────────────────────────────────
echo ""
echo "▶ [7] Replay attack simulation (second verification should be REJECTED) …"
$PYTHON - <<'EOF'
import json, sys
sys.path.insert(0, ".")
from crypto_core import generate_key_pair, sign_message, verify_package, clear_nonce_store, VerificationResult
from crypto_core import load_public_key, serialize_public_key

priv, pub = generate_key_pair(2048)
pkg = sign_message(b"Replay attack demo", priv)

r1 = verify_package(pkg, trusted_public_key=pub, check_replay=True)
print(f"  First  verification: {r1.status}")

r2 = verify_package(pkg, trusted_public_key=pub, check_replay=True)
print(f"  Second verification: {r2.status}")
assert r2.status == VerificationResult.REJECTED, "Replay should be REJECTED!"
print("  Replay attack correctly detected.")
EOF

# ── 8. TLS certificate ────────────────────────────────────────────
echo ""
echo "▶ [8] Generating TLS certificate for demo …"
$PYTHON gen_cert.py

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo "$SEP"
echo "  All demo steps completed successfully."
echo "  Run tests: $PYTHON -m unittest discover -s tests -v"
echo "$SEP"
echo ""
