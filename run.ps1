# run.ps1 — PowerShell launcher for the Digital Signature Verification System
# Usage (from inside digital_signature_system\):
#   .\run.ps1              → Start web UI
#   .\run.ps1 demo         → Run end-to-end demo
#   .\run.ps1 test         → Run all 46 unit tests
#   .\run.ps1 keygen alice → Generate Alice's key pair
#   .\run.ps1 sign   keys\alice_private.pem samples\message.txt
#   .\run.ps1 verify samples\message.txt.sig.json keys\alice_public.pem
#   .\run.ps1 cert         → Generate TLS certificate

param([string]$Command = "web", [string]$Arg1 = "", [string]$Arg2 = "", [string]$Arg3 = "")

$PYTHON = "C:\Users\jhade\OneDrive\Desktop\ai-interviewer\backend\venv\Scripts\python.exe"

if (-not (Test-Path $PYTHON)) {
    Write-Error "Python not found at: $PYTHON"
    Write-Host "Install Python 3.9+ from https://python.org and re-run."
    exit 1
}

Write-Host "Using Python: $PYTHON" -ForegroundColor Cyan
Write-Host ""

switch ($Command.ToLower()) {
    "web" {
        Write-Host "Starting web UI at http://127.0.0.1:5000 ..." -ForegroundColor Green
        & $PYTHON app.py
    }
    "demo" {
        Write-Host "Running end-to-end demo ..." -ForegroundColor Green
        & $PYTHON run_demo.py
    }
    "test" {
        Write-Host "Running all unit tests ..." -ForegroundColor Green
        & $PYTHON -m unittest discover -s tests -v
    }
    "keygen" {
        if (-not $Arg1) { Write-Error "Usage: .\run.ps1 keygen <name>"; exit 1 }
        & $PYTHON keygen.py --name $Arg1
    }
    "sign" {
        if (-not $Arg1 -or -not $Arg2) { Write-Error "Usage: .\run.ps1 sign <key> <file>"; exit 1 }
        & $PYTHON sign.py --key $Arg1 --file $Arg2
    }
    "verify" {
        if (-not $Arg1) { Write-Error "Usage: .\run.ps1 verify <package> [pubkey]"; exit 1 }
        if ($Arg2) {
            & $PYTHON verify.py --package $Arg1 --pub $Arg2
        } else {
            & $PYTHON verify.py --package $Arg1
        }
    }
    "server" {
        if (-not $Arg1) { Write-Error "Usage: .\run.ps1 server <pubkey>"; exit 1 }
        & $PYTHON server.py --pub $Arg1
    }
    "client" {
        if (-not $Arg1 -or -not $Arg2) { Write-Error "Usage: .\run.ps1 client <key> <file>"; exit 1 }
        & $PYTHON client.py --key $Arg1 --file $Arg2
    }
    "cert" {
        Write-Host "Generating TLS certificate ..." -ForegroundColor Green
        & $PYTHON gen_cert.py
    }
    default {
        Write-Host ""
        Write-Host "  DSVS Launcher - Digital Signature Verification System" -ForegroundColor Cyan
        Write-Host "  -------------------------------------------------------"
        Write-Host "  .\run.ps1 web                    Start web UI (http://127.0.0.1:5000)"
        Write-Host "  .\run.ps1 demo                   Run full end-to-end demo"
        Write-Host "  .\run.ps1 test                   Run all 46 unit tests"
        Write-Host "  .\run.ps1 keygen <name>          Generate RSA key pair"
        Write-Host "  .\run.ps1 sign   <key> <file>    Sign a file"
        Write-Host "  .\run.ps1 verify <pkg> [pubkey]  Verify a package"
        Write-Host "  .\run.ps1 server <pubkey>        Start TCP receiver"
        Write-Host "  .\run.ps1 client <key> <file>    Send signed file via TCP"
        Write-Host "  .\run.ps1 cert                   Generate TLS certificate"
        Write-Host ""
    }
}
