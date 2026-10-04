@echo off
REM ─────────────────────────────────────────────────────────────────────────
REM  start_web.bat  —  Launch DSVS Web Interface
REM  Double-click this file to open http://127.0.0.1:5000
REM ─────────────────────────────────────────────────────────────────────────

SET PYTHON=C:\Users\jhade\OneDrive\Desktop\ai-interviewer\backend\venv\Scripts\python.exe
SET PATH=C:\Users\jhade\OneDrive\Desktop\ai-interviewer\backend\venv\Scripts;%PATH%

echo.
echo  ================================================
echo   Digital Signature Verification System
echo   Web Interface starting at http://127.0.0.1:5000
echo  ================================================
echo.
echo  Press CTRL+C to stop the server.
echo.

"%PYTHON%" app.py
pause
