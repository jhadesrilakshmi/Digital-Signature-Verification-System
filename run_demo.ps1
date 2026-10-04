# run_demo.ps1
# ------------
# Windows PowerShell end-to-end demo for the Digital Signature Verification System.
# Run from the digital_signature_system\ directory.
#
# Usage:
#   cd digital_signature_system
#   .\run_demo.ps1
#   .\run_demo.ps1 -Python "C:\Python312\python.exe"

param(
    [string]$Python = ""
)

# ── Find Python ───────────────────────────────────────────────────────────────
if (-not $Python) {
    $candidates = @(
        "python",
        "python3",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe",
        (Get-ChildItem "$PSScriptRoot\.." -Recurse -Filter "python.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notlike "*WindowsApps*" } |
            Select-Object -First 1 -ExpandProperty FullName)
    )
    foreach ($c in $candidates) {
        if ($c -and (Get-Command $c -ErrorAction SilentlyContinue)) {
            $Python = $c; break
        }
        if ($c -and (Test-Path $c)) {
            $Python = $c; break
        }
    }
}

if (-not $Python) {
    Write-Error "Python not found. Install Python 3.9+ or pass -Python <path>."
    exit 1
}

Write-Host ""
Write-Host ("=" * 60)
Write-Host "  Digital Signature Verification System — PowerShell Demo"
Write-Host ("=" * 60)
Write-Host "  Python: $Python"
Write-Host ""

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Run-Step {
    param([string]$Title, [string]$Script)
    Write-Host ""
    Write-Host "▶  $Title"
    Write-Host ("-" * 50)
    & $Python -c $Script
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Step failed: $Title"
        exit 1
    }
}

# ── 0. Install dependencies ───────────────────────────────────────────────────
Write-Host "▶  Installing dependencies …"
& $Python -m pip install -q -r requirements.txt
Write-Host "   Done."

# ── 1. Key generation ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [1] Generating Alice's RSA-2048 key pair …"
& $Python keygen.py --name alice_ps --keys-dir keys
if ($LASTEXITCODE -ne 0) { Write-Error "keygen failed"; exit 1 }

# ── 2. Sign a text message ────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [2] Signing text message …"
& $Python sign.py --key keys/alice_ps_private.pem --text "Pay Bob 100 dollars (PS demo)." --out samples/ps_signed.sig.json
if ($LASTEXITCODE -ne 0) { Write-Error "sign failed"; exit 1 }

# ── 3. Verify the signature ───────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [3] Verifying signature (should be VALID) …"
& $Python verify.py --package samples/ps_signed.sig.json --pub keys/alice_ps_public.pem
if ($LASTEXITCODE -ne 0) { Write-Error "verify failed"; exit 1 }

# ── 4. Sign the sample file ───────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [4] Signing samples/message.txt …"
& $Python sign.py --key keys/alice_ps_private.pem --file samples/message.txt
if ($LASTEXITCODE -ne 0) { Write-Error "sign file failed"; exit 1 }

# ── 5. Verify file signature ──────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [5] Verifying file signature (should be VALID) …"
& $Python verify.py --package samples/message.txt.sig.json --pub keys/alice_ps_public.pem
if ($LASTEXITCODE -ne 0) { Write-Error "verify file failed"; exit 1 }

# ── 6. Tamper simulation ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [6] Tamper simulation (should be INVALID) …"
$tamperScript = @"
import json, base64, sys
sys.path.insert(0, '.')
with open('samples/ps_signed.sig.json') as f:
    pkg = json.load(f)
msg = base64.b64decode(pkg['message_b64'])
pkg['message_b64'] = base64.b64encode(msg.replace(b'100', b'999')).decode()
with open('samples/ps_tampered.sig.json', 'w') as f:
    json.dump(pkg, f)
print('  Tampered package written.')
"@
& $Python -c $tamperScript

& $Python verify.py --package samples/ps_tampered.sig.json --pub keys/alice_ps_public.pem
if ($LASTEXITCODE -eq 0) {
    Write-Error "ERROR: Tampered package should have failed verification!"
    exit 1
}
Write-Host "  ✔ Tamper correctly detected (exit code $LASTEXITCODE)."

# ── 7. Replay simulation ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [7] Replay attack simulation …"
$replayScript = @"
import sys
sys.path.insert(0, '.')
from crypto_core import generate_key_pair, sign_message, verify_package, clear_nonce_store, VerificationResult

priv, pub = generate_key_pair(2048)
pkg = sign_message(b'Replay demo', priv)

r1 = verify_package(pkg, trusted_public_key=pub, check_replay=True)
r2 = verify_package(pkg, trusted_public_key=pub, check_replay=True)

print(f'  First  verification: {r1.status}')
print(f'  Second verification: {r2.status}')

assert r1.status == VerificationResult.VALID,    f'Expected VALID, got {r1.status}'
assert r2.status == VerificationResult.REJECTED, f'Expected REJECTED, got {r2.status}'
print('  ✔ Replay attack correctly detected.')
"@
& $Python -c $replayScript
if ($LASTEXITCODE -ne 0) { Write-Error "replay test failed"; exit 1 }

# ── 8. TLS certificate ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [8] Generating TLS certificate …"
& $Python gen_cert.py
if ($LASTEXITCODE -ne 0) { Write-Error "cert generation failed"; exit 1 }

# ── 9. Run unit tests ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶  [9] Running all unit tests …"
& $Python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { Write-Error "tests failed"; exit 1 }

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 60)
Write-Host "  All demo steps completed successfully!"
Write-Host "  Launch web UI: $Python app.py"
Write-Host ("=" * 60)
Write-Host ""
