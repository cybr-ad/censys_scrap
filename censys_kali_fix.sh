#!/usr/bin/env bash
# Install Censys Platform CLI alongside Kali's legacy Python `censys` package,
# then launch the official browser-based OAuth login.
set -Eeuo pipefail

REPO='https://github.com/Censys/cencli'
MODULE='github.com/censys/cencli/cmd/cencli@latest'
INSTALL_DIR="${HOME}/.local/censys-platform/bin"
CLI="${INSTALL_DIR}/censys"
TMP_DIR="$(mktemp -d -t censys-platform-install.XXXXXX)"
LOG_FILE="/tmp/censys-platform-go-install.log"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

info() { printf '\n[+] %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*" >&2; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

info 'Checking Kali Linux and required tools'
[[ -r /etc/os-release ]] || die 'Cannot identify the operating system.'
# Do not require Kali specifically, but warn if this is another OS.
. /etc/os-release
if [[ "${ID:-}" != 'kali' && "${ID_LIKE:-}" != *'debian'* ]]; then
  warn "This script was written for Kali/Debian; detected ${PRETTY_NAME:-unknown OS}."
fi

if [[ "$(id -u)" -eq 0 ]]; then
  warn 'You are running as root. The CLI and OAuth session will be installed for root in /root/.local and /root/.config.'
fi

# The script needs curl/jq/tar for its official-release fallback.
missing=()
for c in curl jq tar sha256sum; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
if ((${#missing[@]})); then
  command -v apt-get >/dev/null 2>&1 || die "Missing required tools (${missing[*]}) and apt-get is unavailable."
  [[ "$(id -u)" -eq 0 ]] || die "Install these dependencies first as root: ${missing[*]}"
  info "Installing required packages: ${missing[*]}"
  apt-get update
  # Debian/Kali package names are the same for these dependencies.
  apt-get install -y ca-certificates curl jq tar coreutils
fi

# Prefer the Go toolchain already installed on this Kali system.
GO_BIN=''
if [[ -x /usr/local/go/bin/go ]]; then
  GO_BIN='/usr/local/go/bin/go'
elif command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
fi

mkdir -p "$TMP_DIR/gobin" "$INSTALL_DIR"
CANDIDATE=''
if [[ -n "$GO_BIN" ]]; then
  info "Found Go: $($GO_BIN version 2>&1)"
  info 'Attempting official Censys Go installation (automatic toolchain selection enabled)'
  if GOTOOLCHAIN=auto GOBIN="$TMP_DIR/gobin" "$GO_BIN" install "$MODULE" >"$LOG_FILE" 2>&1; then
    if [[ -x "$TMP_DIR/gobin/cencli" ]]; then
      CANDIDATE="$TMP_DIR/gobin/cencli"
    fi
  else
    warn "Go installation did not complete; details are in $LOG_FILE. Trying the official GitHub release binary."
  fi
else
  warn 'Go was not found; will try the official GitHub release binary.'
fi

# Fallback to a release published by the official Censys/cencli repository.
if [[ -z "$CANDIDATE" ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ASSET_ARCH='amd64' ;;
    aarch64|arm64) ASSET_ARCH='arm64' ;;
    *) die "Unsupported CPU architecture: $ARCH. Use the official release page: https://github.com/Censys/cencli/releases" ;;
  esac

  info 'Querying the official Censys/cencli latest-release metadata'
  API_JSON="$TMP_DIR/release.json"
  curl --fail --silent --show-error --location \
    -H 'Accept: application/vnd.github+json' \
    'https://api.github.com/repos/Censys/cencli/releases/latest' -o "$API_JSON" \
    || die 'Could not contact GitHub Releases. Check your internet connection and try again.'

  ASSET_NAME="$(jq -r --arg arch "$ASSET_ARCH" '.assets[]?.name | select(test("linux.*" + $arch + ".*\\.tar\\.gz$"; "i"))' "$API_JSON" | head -n 1)"
  ASSET_URL="$(jq -r --arg name "$ASSET_NAME" '.assets[]? | select(.name == $name) | .browser_download_url' "$API_JSON" | head -n 1)"
  CHECKSUM_NAME="$(jq -r '.assets[]?.name | select(test("checksums.*\\.txt$"; "i"))' "$API_JSON" | head -n 1)"
  CHECKSUM_URL="$(jq -r --arg name "$CHECKSUM_NAME" '.assets[]? | select(.name == $name) | .browser_download_url' "$API_JSON" | head -n 1)"

  [[ -n "$ASSET_NAME" && -n "$ASSET_URL" ]] || die "No Linux $ASSET_ARCH release archive was found. Check https://github.com/Censys/cencli/releases"
  [[ -n "$CHECKSUM_NAME" && -n "$CHECKSUM_URL" ]] || die 'The release did not expose a checksum file; refusing an unverified binary download.'

  ARCHIVE="$TMP_DIR/$ASSET_NAME"
  CHECKSUMS="$TMP_DIR/$CHECKSUM_NAME"
  curl --fail --silent --show-error --location "$ASSET_URL" -o "$ARCHIVE" \
    || die 'Failed to download the official release archive.'
  curl --fail --silent --show-error --location "$CHECKSUM_URL" -o "$CHECKSUMS" \
    || die 'Failed to download the official release checksums.'

  (cd "$TMP_DIR" && grep -F "  $ASSET_NAME" "$CHECKSUMS" | sha256sum --check --status) \
    || die 'Release archive checksum verification failed; refusing to install it.'

  mkdir -p "$TMP_DIR/unpacked"
  tar -xzf "$ARCHIVE" -C "$TMP_DIR/unpacked" \
    || die 'Could not extract the official release archive.'
  CANDIDATE="$(find "$TMP_DIR/unpacked" -type f \( -name cencli -o -name censys \) -print -quit)"
  [[ -n "$CANDIDATE" && -f "$CANDIDATE" ]] || die 'The downloaded release archive did not contain a cencli executable.'
fi

# Preserve an existing install just in case, then install without touching
# /usr/bin/censys or uninstalling Python's `censys` module used by theHarvester.
if [[ -e "$CLI" ]]; then
  cp -p "$CLI" "${CLI}.backup.$(date +%Y%m%d%H%M%S)"
fi
install -m 0755 "$CANDIDATE" "$CLI"

info 'Verifying the new CLI has browser authentication support'
if ! "$CLI" auth --help >/dev/null 2>&1; then
  rm -f "$CLI"
  die 'Installed binary does not expose the expected `auth` command. No legacy package was removed.'
fi
"$CLI" --help | sed -n '1,35p'

# Put the isolated CLI directory at the front of PATH for future shells. This
# lets `censys` refer to the new CLI while leaving /usr/bin/censys intact.
SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
case "$SHELL_NAME" in
  zsh) RC_FILE="${HOME}/.zshrc" ;;
  bash) RC_FILE="${HOME}/.bashrc" ;;
  *) RC_FILE="${HOME}/.profile" ;;
esac
mkdir -p "$(dirname "$RC_FILE")"
PATH_LINE='export PATH="$HOME/.local/censys-platform/bin:$PATH"'
if [[ ! -f "$RC_FILE" ]] || ! grep -Fqx "$PATH_LINE" "$RC_FILE"; then
  {
    printf '\n# Censys Platform CLI (installed separately from the legacy Python CLI)\n'
    printf '%s\n' "$PATH_LINE"
  } >> "$RC_FILE"
fi

info 'Starting browser-based Censys OAuth login'
printf 'A browser should open. Sign in if needed and approve the Censys authorization.\n'
printf 'The CLI will store OAuth credentials locally; do not paste passwords or tokens into this terminal.\n\n'
if ! "$CLI" auth login; then
  warn 'OAuth login did not complete. Check whether a browser opened and whether local TCP port 5555 is free.'
  warn "You can retry later with: $CLI auth login"
  exit 1
fi

info 'Checking authentication status'
"$CLI" auth status

printf '\n[SUCCESS] Censys Platform CLI is installed at:\n  %s\n' "$CLI"
printf '\nTo use `censys` in this current terminal, run:\n'
printf '  export PATH="%s:$PATH"\n  hash -r\n' "$INSTALL_DIR"
printf '\nYour next shell will use the updated PATH from %s.\n' "$RC_FILE"
printf 'Legacy Python Censys package and /usr/bin/censys were not uninstalled or modified.\n'
printf 'Official project: %s\n' "$REPO"
