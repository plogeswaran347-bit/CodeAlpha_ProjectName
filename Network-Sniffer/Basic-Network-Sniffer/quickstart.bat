@echo off
echo === Basic Network Sniffer Quickstart (Windows) ===
where py >nul 2>nul
if %errorlevel% equ 0 (
    set PYCMD=py
) else (
    set PYCMD=python
)

%PYCMD% -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt
echo.
echo Make sure Npcap is installed from https://npcap.com/
echo (Check "Install Npcap in WinPcap API-compatible Mode" during installation)
echo.
echo To run the sniffer, open Command Prompt or PowerShell as Administrator and run:
echo %PYCMD% sniffer.py
pause
