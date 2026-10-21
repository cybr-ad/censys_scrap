#!/usr/bin/env bash
# ==============================================================================
# Censys Host IP Scraper - Debian / Ubuntu / Kali Linux Runner
# ==============================================================================
# Sets up a Python virtual environment to avoid PEP 668 externally-managed
# environment restrictions, ensures Playwright dependencies are met, and runs the scraper.
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SUDO_CMD=""
if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
    SUDO_CMD="sudo"
fi

echo "[+] Checking Debian system dependencies..."

# Ensure python3, python3-venv, and python3-pip are present
MISSING_PKGS=()
for pkg in python3 python3-venv python3-pip; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "[+] Installing required system packages: ${MISSING_PKGS[*]}..."
    $SUDO_CMD apt-get update -qq
    $SUDO_CMD apt-get install -y "${MISSING_PKGS[@]}"
fi

# Remove buggy distro python3-playwright package if present (fixes Kali Linux conflicts)
if dpkg -s python3-playwright &>/dev/null; then
    echo "[!] Removing conflicting distro package python3-playwright..."
    $SUDO_CMD apt-get remove -y python3-playwright 2>/dev/null || true
fi

# Create virtual environment if missing
if [ ! -f ".venv/bin/activate" ]; then
    echo "[+] Creating virtual environment in .venv..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install / update Playwright inside .venv
if ! python3 -c "import playwright" &>/dev/null; then
    echo "[+] Installing Playwright in virtual environment..."
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    echo "[+] Installing Playwright Chromium browser and OS libraries..."
    python3 -m playwright install --with-deps chromium
fi

echo "[+] Starting Censys Scraper..."
python3 censys_scraper.py "$@"
