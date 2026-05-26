#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SecureLink — WireGuard Setup Helper
# Supports: Debian/Ubuntu Linux, Termux (Android)
# Usage:
#   ./setup_wireguard.sh server   → configure this device as the WG server
#   ./setup_wireguard.sh client   → configure this device as the WG client
#   ./setup_wireguard.sh status   → show WireGuard status
#   ./setup_wireguard.sh down     → bring the interface down
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
CYN='\033[96m'; GRN='\033[92m'; YLW='\033[93m'; RED='\033[91m'

info()  { echo -e "  ${GRN}●${R} $*"; }
warn()  { echo -e "  ${YLW}⚠${R}  $*"; }
error() { echo -e "  ${RED}✗${R} $*"; exit 1; }
title() { echo -e "\n${CYN}${BOLD}$*${R}\n"; }

# ── Detect environment ────────────────────────────────────────────────────────
detect_env() {
    if command -v pkg &>/dev/null && [ -d /data/data/com.termux ]; then
        echo "termux"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif uname -r | grep -q android; then
        echo "termux"
    else
        echo "linux"
    fi
}

ENV=$(detect_env)
WG_DIR=""
WG_IF="wg0"

case $ENV in
    termux)
        WG_DIR="$HOME/.wireguard"
        ;;
    *)
        WG_DIR="/etc/wireguard"
        ;;
esac

# ── Configuration (edit these) ────────────────────────────────────────────────
SERVER_WG_IP="10.8.0.1/24"
CLIENT_WG_IP="10.8.0.2/24"
WG_PORT=51820
SERVER_PUBLIC_IP=""   # Fill in server's real IP for client config

# ── Install WireGuard ─────────────────────────────────────────────────────────
install_wireguard() {
    title "Installing WireGuard"
    case $ENV in
        termux)
            info "Termux detected — installing wireguard-tools"
            pkg update -y
            pkg install -y wireguard-tools
            ;;
        debian)
            info "Debian detected — installing wireguard"
            if [ "$(id -u)" != "0" ]; then
                warn "Need root. Re-running with sudo…"
                sudo apt-get update -qq
                sudo apt-get install -y wireguard wireguard-tools
            else
                apt-get update -qq
                apt-get install -y wireguard wireguard-tools
            fi
            ;;
        *)
            warn "Unknown system — attempting apt-get"
            sudo apt-get install -y wireguard wireguard-tools || \
                error "Cannot install WireGuard. Install it manually."
            ;;
    esac
    info "WireGuard installed."
}

# ── Key generation ────────────────────────────────────────────────────────────
generate_keys() {
    local name="$1"
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"

    local priv_file="$WG_DIR/${name}_private.key"
    local pub_file="$WG_DIR/${name}_public.key"

    if [ ! -f "$priv_file" ]; then
        wg genkey | tee "$priv_file" | wg pubkey > "$pub_file"
        chmod 600 "$priv_file"
        info "Generated keys → $WG_DIR/${name}_*.key"
    else
        info "Keys already exist at $priv_file"
    fi

    PRIV_KEY=$(cat "$priv_file")
    PUB_KEY=$(cat "$pub_file")
}

# ── Server config ─────────────────────────────────────────────────────────────
setup_server() {
    title "SecureLink — WireGuard Server Setup"
    install_wireguard
    generate_keys "server"

    local conf="$WG_DIR/${WG_IF}.conf"

    cat > "$conf" << EOF
# SecureLink WireGuard Server Config
# Generated: $(date)
# ─────────────────────────────────────────────
[Interface]
Address = ${SERVER_WG_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${PRIV_KEY}
SaveConfig = true

# Uncomment for IP forwarding (optional):
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# ─────────────────────────────────────────────
# Add peers below using: wg set wg0 peer <CLIENT_PUB_KEY> allowed-ips <CLIENT_WG_IP>/32
# Or add manually:
# [Peer]
# PublicKey = <CLIENT_PUBLIC_KEY>
# AllowedIPs = 10.8.0.2/32
# ─────────────────────────────────────────────
EOF

    chmod 600 "$conf"
    info "Config written to $conf"

    echo ""
    echo -e "  ${CYN}${BOLD}Server Public Key (share with client):${R}"
    echo -e "  ${YLW}${PUB_KEY}${R}"
    echo ""
    echo -e "  ${GRN}To start:${R}"

    if [ "$ENV" = "termux" ]; then
        echo -e "    ${DIM}wg-quick up $conf${R}"
    else
        echo -e "    ${DIM}sudo wg-quick up $WG_IF${R}"
        echo -e "    ${DIM}sudo systemctl enable wg-quick@${WG_IF}  # auto-start on boot${R}"
    fi

    echo ""
    echo -e "  ${GRN}To add a client peer:${R}"
    echo -e "    ${DIM}sudo wg set ${WG_IF} peer <CLIENT_PUBKEY> allowed-ips 10.8.0.2/32${R}"
    echo ""

    # Enable IP forwarding on Debian
    if [ "$ENV" = "debian" ] && [ "$(id -u)" = "0" ]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        info "IP forwarding enabled"
    fi
}

# ── Client config ─────────────────────────────────────────────────────────────
setup_client() {
    title "SecureLink — WireGuard Client Setup"
    install_wireguard
    generate_keys "client"

    # Prompt for server info
    echo -e "  ${CYN}Enter your SERVER's public IP address:${R} "
    read -r server_ip
    SERVER_PUBLIC_IP="${server_ip}"

    echo -e "  ${CYN}Enter your SERVER's WireGuard public key:${R} "
    read -r server_pubkey

    local conf="$WG_DIR/${WG_IF}.conf"

    cat > "$conf" << EOF
# SecureLink WireGuard Client Config
# Generated: $(date)
# ─────────────────────────────────────────────
[Interface]
Address = ${CLIENT_WG_IP}
PrivateKey = ${PRIV_KEY}
DNS = 1.1.1.1

[Peer]
PublicKey = ${server_pubkey}
Endpoint = ${SERVER_PUBLIC_IP}:${WG_PORT}
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
EOF

    chmod 600 "$conf"
    info "Config written to $conf"

    echo ""
    echo -e "  ${CYN}${BOLD}Client Public Key (share with server):${R}"
    echo -e "  ${YLW}${PUB_KEY}${R}"
    echo ""
    echo -e "  ${GRN}To start:${R}"
    if [ "$ENV" = "termux" ]; then
        echo -e "    ${DIM}wg-quick up $conf${R}"
    else
        echo -e "    ${DIM}sudo wg-quick up $WG_IF${R}"
    fi
    echo ""
    echo -e "  ${GRN}Once connected, run SecureLink:${R}"
    echo -e "    ${DIM}python3 securelink.py --host 10.8.0.1 --psk yoursharedsecret${R}"
    echo ""
}

# ── Status ────────────────────────────────────────────────────────────────────
show_status() {
    title "WireGuard Status"
    if command -v wg &>/dev/null; then
        if [ "$ENV" = "debian" ]; then
            sudo wg show 2>/dev/null || info "No active interfaces"
        else
            wg show 2>/dev/null || info "No active interfaces"
        fi
    else
        error "wg not found. Run setup first."
    fi
}

# ── Bring down ────────────────────────────────────────────────────────────────
bring_down() {
    title "Bringing down WireGuard"
    if [ "$ENV" = "debian" ]; then
        sudo wg-quick down "$WG_IF" && info "Interface ${WG_IF} down"
    else
        wg-quick down "$WG_DIR/${WG_IF}.conf" && info "Interface down"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYN}${BOLD}  ╔══════════════════════════════════╗"
    echo -e "  ║  SecureLink WireGuard Setup     ║"
    echo -e "  ╚══════════════════════════════════╝${R}"
    echo -e "  ${DIM}Environment: ${ENV}${R}\n"

    local cmd="${1:-help}"
    case "$cmd" in
        server) setup_server ;;
        client) setup_client ;;
        status) show_status ;;
        down)   bring_down ;;
        *)
            echo -e "  Usage: $0 {server|client|status|down}"
            echo ""
            echo -e "    ${GRN}server${R}  — Set this device up as WireGuard server"
            echo -e "    ${GRN}client${R}  — Set this device up as WireGuard client"
            echo -e "    ${GRN}status${R}  — Show active WireGuard connections"
            echo -e "    ${GRN}down${R}    — Bring WireGuard interface down"
            echo ""
            ;;
    esac
}

main "${1:-help}"

