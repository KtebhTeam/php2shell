@echo off
chcp 65001 >nul
title Installer Pkg's.
color 0F
cls
echo.
echo  ============================================
echo   Install Req Now , 1min bro :(* .
echo  ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python not found. Install from python.org
    pause & exit /b 1
)

if not exist "1337Requirements.txt" (
    echo [!] 1337Requirements.txt missing.
    pause & exit /b 1
)

python -m pip install --upgrade pip --quiet
python -m pip install -r 1337Requirements.txt
if errorlevel 1 (
    echo [!] Install failed. Check internet / proxy.
    pause & exit /b 1
)

python -c "import requests, rich, bs4, urllib3, colorama; print('[+] OK')"
echo.
start "" "https://t.me/alktebh"
echo [+] Done. Run: python 1337scanner.py  OR  python 1337assessor.py
start notepad README.md
echo.
pause
