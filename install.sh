#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SecureLink Installer — Debian Linux & Termux
# Run: bash install.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

R='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
CYN='\033[96m'; GRN='\033[92m'; YLW='\033[93m'; RED='\033[91m'

info()  { echo -e "  ${GRN}●${R} $*"; }
warn()  { echo -e "  ${YLW}⚠${R}  $*"; }
error() { echo -e "  ${RED}✗${R} $*" >&2; exit 1; }

echo ""
echo -e "${CYN}${BOLD}  ╔══════════════════════════════════════════╗"
echo -e "  ║     SecureLink — Installer             ║"
echo -e "  ╚══════════════════════════════════════════╝${R}"
echo ""

# ── Detect environment ────────────────────────────────────────────────────────
if command -v pkg &>/dev/null && [ -d /data/data/com.termux ]; then
    ENV="termux"
elif [ -f /etc/debian_version ]; then
    ENV="debian"
else
    ENV="linux"
fi

info "Detected environment: ${ENV}"

# ── Private venv location ─────────────────────────────────────────────────────
VENV_DIR="$HOME/.securelink/venv"

# ── Install Python and WireGuard tools ────────────────────────────────────────
case $ENV in
    termux)
        info "Updating Termux packages…"
        pkg update -y 2>/dev/null

        info "Installing Python…"
        pkg install -y python 2>/dev/null || true

        info "Installing python-cryptography (pre-built Termux package)…"
        pkg install -y python-cryptography 2>/dev/null \
            || error "Failed to install python-cryptography. Run 'pkg install python-cryptography' manually."

        info "Installing wireguard-tools…"
        pkg install -y wireguard-tools 2>/dev/null \
            || warn "WireGuard install failed — may not be supported on this Android version"

        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        PYTHON_CMD="python"
        ;;

    debian)
        info "Updating apt…"
        sudo apt-get update -qq

        info "Installing Python3, pip, and venv…"
        sudo apt-get install -y python3 python3-pip python3-venv curl 2>/dev/null

        INSTALL_DIR="/usr/local/bin"
        PYTHON_CMD="python3"
        ;;

    *)
        info "Generic Linux — checking for pip3…"
        command -v pip3 &>/dev/null || error "pip3 not found. Install python3-pip manually."

        INSTALL_DIR="$HOME/.local/bin"
        PYTHON_CMD="python3"
        ;;
esac

# ── Create SecureLink's private virtual environment ───────────────────────────
info "Creating private SecureLink environment at ${VENV_DIR}…"
mkdir -p "$(dirname "$VENV_DIR")"
$PYTHON_CMD -m venv "$VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Upgrading pip inside the private environment…"
"$VENV_PIP" install --upgrade pip --quiet

# ── Install cryptography ──────────────────────────────────────────────────────
if [ "$ENV" = "termux" ]; then
    # On Termux, cryptography is already installed system-wide via pkg above.
    # Make it visible inside the venv by symlinking the site-packages.
    info "Linking system cryptography into the private environment…"
    SYSTEM_SITE="$(python -c 'import site; print(site.getsitepackages()[0])')"
    VENV_SITE="$("$VENV_PYTHON" -c 'import site; print(site.getsitepackages()[0])')"
    # Enable system site-packages access in the venv
    "$VENV_PYTHON" -m pip install --quiet cryptography \
        --find-links "$SYSTEM_SITE" --no-index 2>/dev/null \
        || {
            # Fallback: recreate venv with system site-packages access
            warn "Direct link failed — recreating venv with --system-site-packages…"
            rm -rf "$VENV_DIR"
            $PYTHON_CMD -m venv "$VENV_DIR" --system-site-packages
        }
else
    info "Installing cryptography into the private environment…"
    "$VENV_PIP" install cryptography --quiet
fi

info "Cryptography installed: $("$VENV_PYTHON" -c 'import cryptography; print(cryptography.__version__)')"

# ── Copy files ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info "Installing securelink to ${INSTALL_DIR}…"
mkdir -p "$INSTALL_DIR"

cp "$SCRIPT_DIR/securelink.py"      "$INSTALL_DIR/securelink"
chmod +x "$INSTALL_DIR/securelink"

cp "$SCRIPT_DIR/setup_wireguard.sh" "$INSTALL_DIR/securelink-wg"
chmod +x "$INSTALL_DIR/securelink-wg"

# Point shebang at the private-environment Python so the script always uses
# the isolated interpreter that has cryptography available.
sed -i "1s|.*|#!${VENV_PYTHON}|" "$INSTALL_DIR/securelink"

# ── PATH fix for Termux ───────────────────────────────────────────────────────
if [ "$ENV" = "termux" ]; then
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        info "Added ~/.local/bin to PATH in .bashrc"
    fi
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
if "$INSTALL_DIR/securelink" --whoami 2>/dev/null | grep -q fingerprint; then
    info "Installation successful!"
else
    info "Files installed. Run 'securelink --whoami' to verify."
fi

echo ""
echo -e "  ${CYN}${BOLD}Quick Start:${R}"
echo ""
echo -e "  ${GRN}1. Setup WireGuard (optional but recommended):${R}"
echo -e "     ${DIM}securelink-wg server   # on device A${R}"
echo -e "     ${DIM}securelink-wg client   # on device B${R}"
echo ""
echo -e "  ${GRN}2. Start the listener on device A:${R}"
echo -e "     ${DIM}securelink --listen --host 10.8.0.1 --psk yourpassword${R}"
echo ""
echo -e "  ${GRN}3. Connect from device B:${R}"
echo -e "     ${DIM}securelink --host 10.8.0.1 --psk yourpassword${R}"
echo ""
echo -e "  ${GRN}4. View your device fingerprint:${R}"
echo -e "     ${DIM}securelink --whoami${R}"
echo ""
echo -e "  ${DIM}Keys stored at:    ~/.securelink/identity.key${R}"
echo -e "  ${DIM}Private venv at:   ${VENV_DIR}${R}"
echo ""
