#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SecureLink — One-shot launcher
#
# Usage after git clone:
#   bash run.sh                          # interactive mode (prompts for role)
#   bash run.sh --listen --psk secret    # server
#   bash run.sh --host 10.8.0.1 --psk secret   # client
#
# One-line install + launch from GitHub:
#   bash <(curl -fsSL https://raw.githubusercontent.com/USER/securelink/main/run.sh)
#
# Or the classic clone-and-run:
#   git clone https://github.com/USER/securelink && cd securelink && bash run.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

R='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
CYN='\033[96m'; GRN='\033[92m'; YLW='\033[93m'; RED='\033[91m'

info()  { echo -e "  ${GRN}●${R} $*"; }
warn()  { echo -e "  ${YLW}⚠${R}  $*"; }
error() { echo -e "  ${RED}✗${R} $*" >&2; exit 1; }
step()  { echo -e "\n${CYN}${BOLD}── $* ${R}"; }

# ─────────────────────────────────────────────────────────────────────────────
# When piped through curl (curl ... | bash), stdin is the script itself, not
# a terminal.  Detect this so we can skip interactive prompts and just install.
# ─────────────────────────────────────────────────────────────────────────────
PIPED=false
[ ! -t 0 ] && PIPED=true

# ── Locate the repo root ──────────────────────────────────────────────────────
# Works whether the user cloned the repo, downloaded a zip, or runs via curl.
if [ "$PIPED" = "true" ]; then
    # Running via curl — download the repo into a temp dir first
    step "Downloading SecureLink…"
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    if command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/USER/securelink "$TMP_DIR/securelink" 2>/dev/null \
            || error "git clone failed. Check the repo URL or download manually."
    elif command -v curl &>/dev/null; then
        curl -fsSL https://github.com/USER/securelink/archive/refs/heads/main.tar.gz \
            | tar -xz -C "$TMP_DIR"
        mv "$TMP_DIR"/securelink-main "$TMP_DIR/securelink" 2>/dev/null || true
    else
        error "Neither git nor curl found. Install one and re-run."
    fi
    REPO_DIR="$TMP_DIR/securelink"
else
    # Running from inside the cloned repo
    REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

SECURELINK_PY="$REPO_DIR/securelink.py"
INSTALL_SH="$REPO_DIR/install.sh"
VENV_DIR="$HOME/.securelink/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
STAMP_FILE="$HOME/.securelink/.installed"   # written after successful install

[ -f "$SECURELINK_PY" ] || error "securelink.py not found in $REPO_DIR"
[ -f "$INSTALL_SH"    ] || error "install.sh not found in $REPO_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Install (skipped if the stamp file exists and the venv is healthy)
# ─────────────────────────────────────────────────────────────────────────────
needs_install() {
    # Re-install if stamp is missing, venv is gone, or cryptography is absent
    [ ! -f "$STAMP_FILE" ]  && return 0
    [ ! -x "$VENV_PYTHON" ] && return 0
    "$VENV_PYTHON" -c "import cryptography" 2>/dev/null || {
        warn "cryptography missing — installing via pip..."
        "$VENV_PYTHON" -m pip install cryptography
    }
    return 1
}

if needs_install; then
    step "Installing dependencies…"
    bash "$INSTALL_SH"
    # Write stamp so we skip the install on the next run
    mkdir -p "$(dirname "$STAMP_FILE")"
    date -u > "$STAMP_FILE"
    info "Dependencies installed — stamp written to $STAMP_FILE"
else
    info "Already installed — skipping dependency setup"
    info "  (delete $STAMP_FILE to force a reinstall)"
fi

# ── Confirm the venv python is present after install ─────────────────────────
[ -x "$VENV_PYTHON" ] || error "Venv python not found at $VENV_PYTHON. Try deleting $STAMP_FILE and re-running."

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Parse / forward arguments
# Any flag that run.sh doesn't recognise is passed straight to securelink.
# ─────────────────────────────────────────────────────────────────────────────
FORWARD_ARGS=("$@")   # everything passed to run.sh goes to securelink

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — If no args given and we're in a live terminal, prompt for role
# ─────────────────────────────────────────────────────────────────────────────
if [ ${#FORWARD_ARGS[@]} -eq 0 ] && [ "$PIPED" = "false" ]; then
    echo ""
    echo -e "  ${CYN}${BOLD}How do you want to run SecureLink?${R}"
    echo ""
    echo -e "  ${GRN}1)${R} Server  — listen for an incoming connection"
    echo -e "  ${GRN}2)${R} Client  — connect to a server"
    echo -e "  ${GRN}3)${R} Whoami  — just print my fingerprint and exit"
    echo ""
    read -rp "  Choice [1/2/3]: " choice

    case "$choice" in
        1)
            read -rp "  Bind host (default 0.0.0.0): " bind_host
            bind_host="${bind_host:-0.0.0.0}"
            read -rp "  Port (default 55000): " bind_port
            bind_port="${bind_port:-55000}"
            read -rsp "  Pre-shared password (leave blank for none): " psk_val
            echo ""
            FORWARD_ARGS=(--listen --host "$bind_host" --port "$bind_port")
            [ -n "$psk_val" ] && FORWARD_ARGS+=(--psk "$psk_val")
            ;;
        2)
            read -rp "  Server host/IP: " server_host
            [ -z "$server_host" ] && error "Host cannot be empty."
            read -rp "  Port (default 55000): " server_port
            server_port="${server_port:-55000}"
            read -rsp "  Pre-shared password (leave blank for none): " psk_val
            echo ""
            FORWARD_ARGS=(--host "$server_host" --port "$server_port")
            [ -n "$psk_val" ] && FORWARD_ARGS+=(--psk "$psk_val")
            ;;
        3)
            FORWARD_ARGS=(--whoami)
            ;;
        *)
            warn "Unrecognised choice — launching with --whoami"
            FORWARD_ARGS=(--whoami)
            ;;
    esac
fi

# If we got here via curl with no args, just print the fingerprint as a
# sanity-check that the install worked; user can run manually next time.
if [ ${#FORWARD_ARGS[@]} -eq 0 ]; then
    FORWARD_ARGS=(--whoami)
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Launch
# ─────────────────────────────────────────────────────────────────────────────
step "Launching SecureLink…"
echo -e "  ${DIM}Command: $VENV_PYTHON $SECURELINK_PY ${FORWARD_ARGS[*]:-}${R}"
echo ""

exec "$VENV_PYTHON" "$SECURELINK_PY" "${FORWARD_ARGS[@]}"
