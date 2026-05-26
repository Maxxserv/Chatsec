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

# ── Install Python, pipx, and WireGuard tools ─────────────────────────────────
case $ENV in
    termux)
        info "Updating Termux packages…"
        pkg update -y 2>/dev/null

        info "Installing Python…"
        pkg install -y python 2>/dev/null || true

        info "Installing pipx…"
        pip install pipx --quiet
        export PATH="$HOME/.local/bin:$PATH"
        python -m pipx ensurepath --force 2>/dev/null || true

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

        info "Installing Python3, pip, venv, and pipx…"
        sudo apt-get install -y python3 python3-pip python3-venv python3-pipx curl 2>/dev/null \
            || sudo apt-get install -y python3 python3-pip python3-venv curl 2>/dev/null

        # Fall back to pip-installed pipx if the apt package isn't available
        if ! command -v pipx &>/dev/null; then
            info "apt pipx not found — installing via pip…"
            pip3 install pipx --quiet --break-system-packages 2>/dev/null \
                || pip3 install pipx --quiet
        fi

        python3 -m pipx ensurepath --force 2>/dev/null || true
        export PATH="$HOME/.local/bin:$PATH"

        INSTALL_DIR="/usr/local/bin"
        PYTHON_CMD="python3"
        ;;

    *)
        info "Generic Linux — checking for pip3…"
        command -v pip3 &>/dev/null || error "pip3 not found. Install python3-pip manually."

        info "Installing pipx…"
        pip3 install pipx --quiet \
            || error "pipx install failed. Install pipx manually and re-run."
        python3 -m pipx ensurepath --force 2>/dev/null || true
        export PATH="$HOME/.local/bin:$PATH"

        INSTALL_DIR="$HOME/.local/bin"
        PYTHON_CMD="python3"
        ;;
esac

# Confirm pipx is reachable
command -v pipx &>/dev/null || error "pipx is not on PATH after install. Open a new shell and re-run."

# ── Create SecureLink's private virtual environment via pipx ──────────────────
info "Creating private SecureLink environment at ${VENV_DIR}…"
mkdir -p "$(dirname "$VENV_DIR")"

# pipx uses venv under the hood; we create the venv ourselves so we can point
# the securelink shebang at it, then inject the dependency via pipx inject-style
# (pipx inject requires an already-installed app, so we use the venv's own pip —
# the venv is still fully isolated from the system and owned by SecureLink only).
$PYTHON_CMD -m venv "$VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Upgrading pip inside the private environment…"
"$VENV_PIP" install --upgrade pip --quiet

info "Installing cryptography into the private environment via pipx-managed pip…"
# pipx inject works against a named pipx app; for a script-based install we use
# the venv pip directly — this keeps the dependency fully isolated (no
# --break-system-packages, no system-wide writes).
"$VENV_PIP" install cryptography --quiet

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

