@echo off
REM ─────────────────────────────────────────────────────────────
REM  DSVS Launcher — run from the digital_signature_system folder
REM  Usage:  Double-click this file, OR open CMD here and type:
REM          run.bat web
REM          run.bat demo
REM          run.bat test
REM          run.bat keygen alice
REM          run.bat sign   keys\alice_private.pem samples\message.txt
REM          run.bat verify samples\message.txt.sig.json keys\alice_public.pem
REM ─────────────────────────────────────────────────────────────

SET PYTHON=C:\Users\jhade\OneDrive\Desktop\ai-interviewer\backend\venv\Scripts\python.exe

IF NOT EXIST "%PYTHON%" (
    echo ERROR: Python not found at %PYTHON%
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

IF "%1"=="" GOTO web
IF "%1"=="web"    GOTO web
IF "%1"=="demo"   GOTO demo
IF "%1"=="test"   GOTO test
IF "%1"=="keygen" GOTO keygen
IF "%1"=="sign"   GOTO sign
IF "%1"=="verify" GOTO verify
IF "%1"=="server" GOTO server
IF "%1"=="client" GOTO client
IF "%1"=="cert"   GOTO cert
GOTO usage

:web
echo Starting DSVS Web Interface at http://127.0.0.1:5000 ...
"%PYTHON%" app.py
GOTO end

:demo
echo Running end-to-end demo ...
"%PYTHON%" run_demo.py
GOTO end

:test
echo Running all unit tests ...
"%PYTHON%" -m unittest discover -s tests -v
GOTO end

:keygen
IF "%2"=="" (echo Usage: run.bat keygen ^<name^> && GOTO end)
"%PYTHON%" keygen.py --name %2 %3 %4 %5
GOTO end

:sign
IF "%2"=="" (echo Usage: run.bat sign ^<key^> ^<file^> && GOTO end)
"%PYTHON%" sign.py --key %2 --file %3 %4 %5
GOTO end

:verify
IF "%2"=="" (echo Usage: run.bat verify ^<package^> [pubkey] && GOTO end)
IF "%3"=="" (
    "%PYTHON%" verify.py --package %2
) ELSE (
    "%PYTHON%" verify.py --package %2 --pub %3
)
GOTO end

:server
IF "%2"=="" (echo Usage: run.bat server ^<pubkey^> && GOTO end)
"%PYTHON%" server.py --pub %2 %3 %4 %5
GOTO end

:client
IF "%2"=="" (echo Usage: run.bat client ^<key^> ^<file_or_--text^> && GOTO end)
"%PYTHON%" client.py --key %2 %3 %4 %5 %6
GOTO end

:cert
echo Generating self-signed TLS certificate ...
"%PYTHON%" gen_cert.py
GOTO end

:usage
echo.
echo  DSVS Launcher — Digital Signature Verification System
echo  -------------------------------------------------------
echo  run.bat web                                  Start web UI (http://127.0.0.1:5000)
echo  run.bat demo                                 Run full end-to-end demo
echo  run.bat test                                 Run all 46 unit tests
echo  run.bat keygen ^<name^>                        Generate key pair
echo  run.bat sign   ^<key^> ^<file^>                  Sign a file
echo  run.bat verify ^<package^> [pubkey]            Verify a package
echo  run.bat server ^<pubkey^>                      Start TCP receiver server
echo  run.bat client ^<key^> ^<file^>                  Send signed file via TCP
echo  run.bat cert                                 Generate TLS certificate
echo.

:end
pause
