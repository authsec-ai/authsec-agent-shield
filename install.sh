#!/usr/bin/env bash
# AuthSec Agent Shield — one-click installer for Linux/macOS
# Usage:
#   curl -fsSL https://get.authsec.ai/shield | bash
#   or: ./install.sh

set -euo pipefail

REPO="authsec-ai/authsec-agent-shield"
INSTALL_DIR="/usr/local/bin"
BINARY="authsec-shield"
TMPDIR_SHIELD=""
SRCDIR=""

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[shield]${RESET} $*"; }
ok()      { echo -e "${GREEN}[shield]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[shield]${RESET} $*"; }
die()     { echo -e "${RED}[shield] ERROR${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}$*${RESET}"; }

# ── detect OS/arch ──────────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) die "Unsupported OS: $OS. Use install.ps1 on Windows." ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"

if [[ "$OS" == "linux" ]]; then
  TOTAL_STEPS=3
else
  TOTAL_STEPS=2
fi

header "AuthSec Agent Shield — Installer"
echo "  OS:   $OS"
echo "  Arch: $ARCH"
echo ""

# ── check dependencies ───────────────────────────────────────────────────────
for dep in curl; do
  command -v "$dep" &>/dev/null || die "'$dep' is required but not installed."
done

PROTECTIONS_INSTALLED=0
interrupted() {
  echo ""
  if [[ "${PROTECTIONS_INSTALLED:-0}" -eq 0 ]]; then
    warn "Install interrupted before OS protections completed."
    warn "Resume with: ./install.sh"
  else
    warn "Install interrupted (protections already installed)."
  fi
  if command -v "${INSTALL_DIR}/${BINARY}" &>/dev/null; then
    warn "Check health with: authsec-shield doctor"
  fi
  exit 130
}
trap interrupted INT TERM
trap 'rm -rf ${TMPDIR_SHIELD:+"$TMPDIR_SHIELD"} ${SRCDIR:+"$SRCDIR"}' EXIT

# ── download / build binary ──────────────────────────────────────────────────
header "Step 1/${TOTAL_STEPS}: Downloading binary"

TMPDIR_SHIELD="$(mktemp -d)"
DOWNLOAD_URL=""

if command -v curl &>/dev/null; then
  LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || true)
fi

if [[ -n "${LATEST:-}" ]]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
  info "Downloading version ${LATEST} from GitHub..."
  if ! curl -fsSL --progress-bar -o "${TMPDIR_SHIELD}/${BINARY}" "$DOWNLOAD_URL"; then
    warn "GitHub download failed, trying source build..."
    DOWNLOAD_URL=""
  fi
fi

if [[ -z "$DOWNLOAD_URL" ]] || [[ ! -f "${TMPDIR_SHIELD}/${BINARY}" ]]; then
  if command -v go &>/dev/null; then
    info "Building from source (Go $(go version | awk '{print $3}'))..."
    SRCDIR="$(mktemp -d)"
    if [[ -f "$(dirname "$0")/go.mod" ]]; then
      (cd "$(dirname "$0")" && go build -o "${TMPDIR_SHIELD}/${BINARY}" ./cmd/shield/)
    else
      die "Cannot download binary and no source tree found. Install Go and clone the repo."
    fi
  else
    die "Cannot download binary and Go is not installed."
  fi
fi

chmod +x "${TMPDIR_SHIELD}/${BINARY}"

if [[ -w "$INSTALL_DIR" ]]; then
  cp "${TMPDIR_SHIELD}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  info "Need sudo to write to ${INSTALL_DIR}..."
  sudo cp "${TMPDIR_SHIELD}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi
ok "Installed: ${INSTALL_DIR}/${BINARY}"

# ── build + install kernel exec monitor (Linux only) ─────────────────────────
if [[ "$OS" == "linux" ]]; then
  header "Step 2/${TOTAL_STEPS}: Building kernel exec monitor (fanotify + eBPF)"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  EXECMON_DIR="${SCRIPT_DIR}/kernel/linux/execmon"

  if [[ -d "$EXECMON_DIR" ]]; then
    info "Checking build dependencies..."
    MISSING_DEPS=()
    command -v clang   &>/dev/null || MISSING_DEPS+=("clang")
    command -v gcc     &>/dev/null || MISSING_DEPS+=("gcc")
    pkg-config --exists libcurl 2>/dev/null || MISSING_DEPS+=("libcurl-dev")
    pkg-config --exists libbpf  2>/dev/null || MISSING_DEPS+=("libbpf-dev")

    if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
      warn "Missing dependencies for exec monitor: ${MISSING_DEPS[*]}"
      info "Installing missing packages..."
      if command -v apt-get &>/dev/null; then
        sudo apt-get install -y clang gcc libcurl4-openssl-dev libbpf-dev linux-headers-"$(uname -r)" 2>/dev/null \
          || warn "apt-get install failed — exec monitor may not build"
      elif command -v yum &>/dev/null; then
        sudo yum install -y clang gcc libcurl-devel libbpf-devel kernel-headers 2>/dev/null \
          || warn "yum install failed — exec monitor may not build"
      fi
    fi

    info "Building exec monitor daemon artifacts (service starts after login)..."
    if (cd "$EXECMON_DIR" && sudo make install-artifacts 2>&1); then
      ok "Exec monitor artifacts installed: /usr/local/sbin/authsec-shield-execmon"
      ok "Service will start automatically after: authsec-shield login"
    else
      warn "Exec monitor build failed — running without kernel-level exec interception"
      warn "Re-run: cd ${EXECMON_DIR} && sudo make install-artifacts"
    fi
  else
    warn "Exec monitor source not found at ${EXECMON_DIR} — skipping"
  fi
fi

# ── install shims + hooks ────────────────────────────────────────────────────
if [[ "$OS" == "linux" ]]; then
  header "Step 3/${TOTAL_STEPS}: Installing OS protections (requires sudo)"
else
  header "Step 2/${TOTAL_STEPS}: Installing OS protections (requires sudo)"
fi

if [[ "$OS" == "linux" || "$OS" == "darwin" ]]; then
  sudo "${INSTALL_DIR}/${BINARY}" install
else
  "${INSTALL_DIR}/${BINARY}" install
fi
PROTECTIONS_INSTALLED=1

# ── done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}AuthSec Agent Shield installed successfully!${RESET}"
echo ""
echo -e "  ${BOLD}Next step: authenticate${RESET}"
echo ""
echo "    authsec-shield login"
echo ""
echo "  This will open a browser to complete authentication."
echo "  All protections activate automatically after login."
echo ""
echo "  Other commands:"
echo "    authsec-shield status    — show current state"
echo "    authsec-shield doctor    — health check"
echo "    authsec-shield pause 1h  — pause for 1 hour"
echo "    authsec-shield uninstall — remove everything"
echo ""
echo "  Restart your shell or run: source ~/.bashrc"
echo ""
