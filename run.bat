@echo off
title Censys Host IP Scraper
cd /d "%~dp0"

echo ===================================================
echo           Censys Host IP Scraper (Windows)
echo ===================================================
echo.

python censys_scraper.py %*

echo.
pause
