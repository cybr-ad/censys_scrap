@echo off
title Censys Host IP Scraper
cd /d "%~dp0"

:: Always clean Python cache and disable output buffering
set PYTHONDONTWRITEBYTECODE=1
set PYTHONUNBUFFERED=1
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" 2>nul
del /s /q *.pyc 2>nul

echo ===================================================
echo           Censys Host IP Scraper (Windows)
echo ===================================================
echo.

python -u -B censys_scraper.py %*

echo.
pause
