# SecureLink

**Encrypted CLI Messenger + File Transfer + Remote Shell**  
Works on Debian Linux and Termux (Android). Connects over WireGuard VPN or any IP network.

---

## Features

| Feature | Detail |
|---|---|
| **End-to-End Encryption** | X25519 ECDH key exchange → AES-256-GCM per message |
| **Mutual Authentication** | Pre-shared password (PSK) + HMAC challenge-response |
| **Encrypted Messaging** | Real-time chat with timestamps and peer fingerprints |
| **File Transfer** | Send any file with progress bar and speed display |
| **Remote Shell** | Interactive or single-command remote execution |
| **Auto-Reconnect** | Client retries indefinitely on disconnect |
| **WireGuard Support** | Built-in setup helper for WireGuard VPN tunnels |
| **Peer Trust Store** | Save and name trusted peers by fingerprint |
| **IPv4 + IPv6** | Works on both address families |

---

## Install

```bash
# Clone or download the files, then:
bash install.sh
```

Works on:
- Debian / Ubuntu / Raspberry Pi OS
- Termux (Android) — install Termux from F-Droid

---

## WireGuard Setup (Recommended)

WireGuard provides an encrypted VPN tunnel **before** SecureLink even connects.  
This gives you two independent layers of encryption.

```bash
# On Device A (server)
securelink-wg server

# On Device B (client)
securelink-wg client
# → Enter Device A's real IP and public key when prompted

# Check status
securelink-wg status
```

After setup, your WireGuard IPs will be:
- Device A (server): `10.8.0.1`
- Device B (client): `10.8.0.2`

---

## Usage

### Start listener on Device A
```bash
securelink --listen --host 10.8.0.1 --port 55000 --psk yourpassword
```

### Connect from Device B
```bash
securelink --host 10.8.0.1 --port 55000 --psk yourpassword
```

### Over direct IP (no WireGuard)
```bash
# Device A
securelink --listen --host 0.0.0.0 --psk yourpassword

# Device B
securelink --host <device_A_ip> --psk yourpassword
```

### View your fingerprint
```bash
securelink --whoami
```

---

## In-Chat Commands

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/file /path/to/file` | Send a file |
| `/shell` | Open interactive remote shell |
| `/shell ls -la` | Run a single remote command |
| `/peers` | List trusted peers |
| `/trust alice` | Name and trust the current peer |
| `/clear` | Clear the terminal |
| `/quit` | Disconnect |

---

## Security Architecture

```
Device A                              Device B
────────                              ────────
WireGuard Layer (optional, UDP)  ←──────────────→  WireGuard Layer
         ↓                                                ↓
TCP Socket (over WG tunnel or raw IP)
         ↓                                                ↓
X25519 ECDH Key Exchange         ←──────────────→  X25519 ECDH
         ↓                                                ↓
HKDF-SHA256 → 2x AES-256-GCM keys (send + receive)
         ↓                                                ↓
PSK HMAC Challenge-Response Auth ←──────────────→  PSK Auth
         ↓                                                ↓
Encrypted framed messages (nonce-per-message)
```

- **No key reuse**: each session generates fresh ephemeral keys
- **Forward secrecy**: compromise of long-term keys doesn't expose past sessions
- **Nonce counter**: nonces are sequential counters, preventing replay attacks
- **Frame length hiding**: all messages wrapped in uniform frames

---

## All Options

```
securelink [options]

  --listen / -l        Listen for incoming connections (server mode)
  --host / -H          IP to bind (server) or connect to (client)
  --port / -p          Port number (default: 55000)
  --psk / -k           Pre-shared password for authentication
  --downloads / -d     Directory for received files (default: ~/Downloads)
  --whoami             Print your identity fingerprint and exit
```

---

## Files

| Path | Description |
|---|---|
| `~/.securelink/identity.key` | Your persistent X25519 private key (chmod 600) |
| `~/.securelink/peers.json` | Trusted peer fingerprints |
| `~/.wireguard/wg0.conf` | WireGuard config (Termux) |
| `/etc/wireguard/wg0.conf` | WireGuard config (Debian) |

---

## Termux Notes

- Install Termux from **F-Droid** (not Google Play — that version is outdated)
- WireGuard on Termux requires Android 5+ kernel support
- If WireGuard isn't available, SecureLink still works directly over IP
- Grant storage permission: `termux-setup-storage`
- Files are received to `~/storage/downloads` by default on Termux

# Chatsec
