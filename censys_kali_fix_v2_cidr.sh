#!/usr/bin/env bash
# Censys Platform CLI setup/check for Kali Linux. V2 auto-detects the current public IPv4
# address and scopes the prepared query to that single address (/32).
# Keeps the legacy Python package (/usr/bin/censys) untouched.
# The script does NOT attempt a Platform API search, because the user's Free account may
# be blocked from that endpoint (403); instead it prepares the query for the Platform UI.
set -Eeuo pipefail

REPO='https://github.com/Censys/cencli'
MODULE='github.com/censys/cencli/cmd/cencli@latest'
INSTALL_DIR="${HOME}/.local/censys-platform/bin"
CLI="${INSTALL_DIR}/censys"

info() { printf '\n[+] %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*" >&2; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

info 'Checking Kali/Linux environment'
[[ -r /etc/os-release ]] || die 'Cannot identify the operating system.'
. /etc/os-release
if [[ "${ID:-}" != 'kali' && "${ID_LIKE:-}" != *'debian'* ]]; then
  warn "This script was written for Kali/Debian; detected ${PRETTY_NAME:-unknown OS}."
fi
if [[ "$(id -u)" -eq 0 ]]; then
  warn 'Running as root means the CLI login and configuration belong to /root, not another desktop user.'
fi

# Install basic dependencies only when required.
missing=()
for c in curl jq tar sha256sum python3; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
if ((${#missing[@]})); then
  command -v apt-get >/dev/null 2>&1 || die "Missing required tools (${missing[*]}) and apt-get is unavailable."
  [[ "$(id -u)" -eq 0 ]] || die "Install these dependencies as root: ${missing[*]}"
  info "Installing required packages: ${missing[*]}"
  apt-get update
  apt-get install -y ca-certificates curl jq tar coreutils python3
fi

mkdir -p "$INSTALL_DIR"

# Reuse the working new CLI; install only if it is missing or lacks OAuth support.
NEED_INSTALL=0
if [[ ! -x "$CLI" ]]; then
  NEED_INSTALL=1
elif ! "$CLI" auth --help >/dev/null 2>&1; then
  warn 'The executable at the expected path does not expose the Platform auth command; reinstalling it.'
  NEED_INSTALL=1
fi

if ((NEED_INSTALL)); then
  TMP_DIR="$(mktemp -d -t censys-platform-install.XXXXXX)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  LOG_FILE='/tmp/censys-platform-go-install.log'
  GO_BIN=''
  if [[ -x /usr/local/go/bin/go ]]; then
    GO_BIN='/usr/local/go/bin/go'
  elif command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  fi
  CANDIDATE=''
  if [[ -n "$GO_BIN" ]]; then
    info "Found Go: $($GO_BIN version 2>&1)"
    info 'Installing the official Censys Platform CLI with Go'
    if GOTOOLCHAIN=auto GOBIN="$TMP_DIR/gobin" "$GO_BIN" install "$MODULE" >"$LOG_FILE" 2>&1; then
      [[ -x "$TMP_DIR/gobin/cencli" ]] && CANDIDATE="$TMP_DIR/gobin/cencli"
    else
      warn "Go installation failed; details are in $LOG_FILE. Trying an official GitHub release binary."
    fi
  else
    warn 'Go was not found; trying an official GitHub release binary.'
  fi

  if [[ -z "$CANDIDATE" ]]; then
    case "$(uname -m)" in
      x86_64|amd64) ASSET_ARCH='amd64' ;;
      aarch64|arm64) ASSET_ARCH='arm64' ;;
      *) die "Unsupported CPU architecture. See ${REPO}/releases" ;;
    esac
    API_JSON="$TMP_DIR/release.json"
    curl --fail --silent --show-error --location \
      -H 'Accept: application/vnd.github+json' \
      'https://api.github.com/repos/Censys/cencli/releases/latest' -o "$API_JSON" \
      || die 'Could not contact GitHub Releases; check your network.'
    ASSET_NAME="$(jq -r --arg arch "$ASSET_ARCH" '.assets[]?.name | select(test("linux.*" + $arch + ".*\\.tar\\.gz$"; "i"))' "$API_JSON" | head -n 1)"
    ASSET_URL="$(jq -r --arg name "$ASSET_NAME" '.assets[]? | select(.name == $name) | .browser_download_url' "$API_JSON" | head -n 1)"
    CHECKSUM_NAME="$(jq -r '.assets[]?.name | select(test("checksums.*\\.txt$"; "i"))' "$API_JSON" | head -n 1)"
    CHECKSUM_URL="$(jq -r --arg name "$CHECKSUM_NAME" '.assets[]? | select(.name == $name) | .browser_download_url' "$API_JSON" | head -n 1)"
    [[ -n "$ASSET_NAME" && -n "$ASSET_URL" ]] || die "No Linux $ASSET_ARCH archive found. See ${REPO}/releases"
    [[ -n "$CHECKSUM_NAME" && -n "$CHECKSUM_URL" ]] || die 'No release checksum file found; refusing an unverified binary download.'
    curl --fail --silent --show-error --location "$ASSET_URL" -o "$TMP_DIR/$ASSET_NAME" || die 'Failed to download the official release archive.'
    curl --fail --silent --show-error --location "$CHECKSUM_URL" -o "$TMP_DIR/$CHECKSUM_NAME" || die 'Failed to download the release checksums.'
    (cd "$TMP_DIR" && grep -F "  $ASSET_NAME" "$CHECKSUM_NAME" | sha256sum --check --status) || die 'Checksum verification failed.'
    mkdir -p "$TMP_DIR/unpacked"
    tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR/unpacked" || die 'Could not extract the release archive.'
    CANDIDATE="$(find "$TMP_DIR/unpacked" -type f \( -name cencli -o -name censys \) -print -quit)"
    [[ -n "$CANDIDATE" && -f "$CANDIDATE" ]] || die 'No cencli executable found in the release archive.'
  fi

  [[ ! -e "$CLI" ]] || cp -p "$CLI" "${CLI}.backup.$(date +%Y%m%d%H%M%S)"
  install -m 0755 "$CANDIDATE" "$CLI"
  "$CLI" auth --help >/dev/null 2>&1 || die 'Installed binary does not expose `auth`; refusing to continue.'
  info "Installed Platform CLI to $CLI"
fi

# Ensure the new CLI wins over /usr/bin/censys in future shells.
SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
case "$SHELL_NAME" in
  zsh) RC_FILE="${HOME}/.zshrc" ;;
  bash) RC_FILE="${HOME}/.bashrc" ;;
  *) RC_FILE="${HOME}/.profile" ;;
esac
PATH_LINE='export PATH="$HOME/.local/censys-platform/bin:$PATH"'
if [[ ! -f "$RC_FILE" ]] || ! grep -Fqx "$PATH_LINE" "$RC_FILE"; then
  {
    printf '\n# Censys Platform CLI (separate from the legacy Python package)\n'
    printf '%s\n' "$PATH_LINE"
  } >> "$RC_FILE"
fi
export PATH="$INSTALL_DIR:$PATH"

info 'Checking Censys browser-based authentication'
if ! "$CLI" auth status; then
  info 'No active Platform login was confirmed; opening browser-based OAuth login.'
  "$CLI" auth login || die 'OAuth login did not complete. Retry later with: '"$CLI"' auth login'
  "$CLI" auth status || die 'Login status could not be confirmed after OAuth.'
else
  info 'Existing browser-based login is active; no new login needed.'
fi

info 'Checking available credits (informational only)'
if ! "$CLI" credits; then
  warn 'Could not retrieve credits. Authentication may still be active.'
fi

# Auto-detect the current public IPv4 address and limit the query to that one IP (/32).
# This is the internet egress IP seen by these services; behind NAT/shared ISP it may not
# uniquely identify a machine you own. The script never broadens it into a subnet.
info 'Detecting the current public IPv4 address for a single-IP (/32) query'
PUBLIC_IP=''
for IP_ENDPOINT in \
  'https://api.ipify.org' \
  'https://checkip.amazonaws.com' \
  'https://icanhazip.com'; do
  CANDIDATE="$(curl --ipv4 --fail --silent --show-error --location --max-time 10 "$IP_ENDPOINT" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ -n "$CANDIDATE" ]] && python3 - "$CANDIDATE" <<'PYIP'
import ipaddress, sys
try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if address.version != 4 or not address.is_global:
    raise SystemExit(1)
PYIP
  then
    PUBLIC_IP="$CANDIDATE"
    break
  fi
done

[[ -n "$PUBLIC_IP" ]] || die 'Could not determine a globally routable public IPv4 address. Check internet connectivity or your network proxy.'
NORMALIZED_CIDR="${PUBLIC_IP}/32"
printf '\nDetected public IPv4: %s\n' "$PUBLIC_IP"
printf 'Using single-address CIDR: %s\n' "$NORMALIZED_CIDR"
printf '[NOTE] If your ISP uses shared NAT, this can be your shared egress IP rather than an address assigned exclusively to you.\n'

QUERY="host.services.port: 88 and host.services.port: 389 and host.ip: \"${NORMALIZED_CIDR}\""
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_FILE="${SCRIPT_DIR}/censys_authorized_query_v2.txt"
printf '%s\n' "$QUERY" > "$OUT_FILE"

info 'Prepared the Censys query for the detected public IP (/32)'
printf '\n%s\n' "$QUERY"
printf '\nSaved query to: %s\n' "$OUT_FILE"

COPIED=0
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  if command -v xclip >/dev/null 2>&1 && printf '%s' "$QUERY" | xclip -selection clipboard >/dev/null 2>&1; then
    COPIED=1
  elif command -v xsel >/dev/null 2>&1 && printf '%s' "$QUERY" | xsel --clipboard --input >/dev/null 2>&1; then
    COPIED=1
  fi
fi
if ((COPIED)); then
  info 'Query copied to clipboard; paste it into the Censys Platform Hosts search bar.'
else
  info 'If clipboard integration is unavailable, copy the query above or open the saved query file.'
fi

URL='https://platform.censys.io/'
if command -v xdg-open >/dev/null 2>&1; then
  if xdg-open "$URL" >/dev/null 2>&1; then
    info "Opened $URL. Paste the prepared query into the Hosts search bar and run it there."
  else
    warn "Could not open a browser automatically. Visit: $URL"
  fi
else
  warn "xdg-open is unavailable. Visit: $URL"
fi

printf '\n[IMPORTANT] This script does not run a Platform API search. Your earlier 403 response means the free-account API endpoint is restricted; using a /32 does not remove that entitlement restriction. The query is prepared for the Platform UI instead.\n'
printf '[INFO] Legacy Python package /usr/bin/censys was not uninstalled or modified.\n'
printf '[INFO] Official CLI project: %s\n' "$REPO"
