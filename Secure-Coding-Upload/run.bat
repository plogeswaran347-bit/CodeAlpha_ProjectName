@echo off
cd /d "%~dp0"
echo ======================================================================
echo Launching CodeAlpha Task 3: Secure Coding Suite
echo ======================================================================
py run_all.py
if errorlevel 1 (
    .\secure_app\venv\Scripts\python.exe run_all.py
)
pause
