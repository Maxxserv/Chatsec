#!/usr/bin/env python3
"""
SecureLink - Secure CLI Messaging, File Transfer & Remote Shell
Works on Debian Linux and Termux (Android)
Transport: WireGuard VPN / Direct IP
Encryption: X25519 ECDH key exchange + AES-256-GCM
"""

import os, sys, socket, threading, json, time, base64, hashlib
import subprocess, readline, shutil, struct, signal, argparse
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
VERSION        = "1.0.0"
DEFAULT_PORT   = 55000
CHUNK_SIZE     = 65536
RECONNECT_WAIT = 5
MAX_RETRIES    = 999
RECV_TIMEOUT   = 300

# Message types
MT_CHAT      = b'\x01'
MT_FILE      = b'\x02'
MT_SHELL     = b'\x03'
MT_SHELL_D   = b'\x04'
MT_PING      = b'\x05'
MT_PONG      = b'\x06'
MT_HANDSHAKE = b'\x07'
MT_AUTH      = b'\x08'
MT_AUTH_OK   = b'\x09'
MT_FILE_ACK  = b'\x0A'

# ─── ANSI COLORS ──────────────────────────────────────────────────────────────
R='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
CYAN='\033[96m'; GREEN='\033[92m'; YELLOW='\033[93m'
RED='\033[91m'; MAGENTA='\033[95m'; BLUE='\033[94m'; WHITE='\033[97m'
BG_DARK='\033[40m'

def clr(color, text): return f"{color}{text}{R}"
def ts(): return datetime.now().strftime("%H:%M:%S")

# ─── KEY STORE ────────────────────────────────────────────────────────────────
CONFIG_DIR = Path.home() / ".securelink"
KEY_FILE   = CONFIG_DIR / "identity.key"
PEERS_FILE = CONFIG_DIR / "peers.json"

def ensure_config_dir():
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)

def load_or_create_identity():
    ensure_config_dir()
    if KEY_FILE.exists():
        raw = KEY_FILE.read_bytes()
        private_key = X25519PrivateKey.from_private_bytes(raw)
    else:
        private_key = X25519PrivateKey.generate()
        KEY_FILE.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )
        )
        KEY_FILE.chmod(0o600)
    pub_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = hashlib.sha256(pub_raw).hexdigest()[:16]
    return private_key, pub_raw, fingerprint

def load_peers():
    if PEERS_FILE.exists():
        return json.loads(PEERS_FILE.read_text())
    return {}

def save_peer(alias, fingerprint, pubkey_hex):
    peers = load_peers()
    peers[alias] = {"fingerprint": fingerprint, "pubkey": pubkey_hex}
    PEERS_FILE.write_text(json.dumps(peers, indent=2))

# ─── CRYPTO ENGINE ────────────────────────────────────────────────────────────
class CryptoSession:
    """X25519 ECDH + HKDF → AES-256-GCM per-message with nonce rotation.

    Key assignment is direction-aware so that:
      initiator send_key  == responder recv_key  (material[:32])
      initiator recv_key  == responder send_key  (material[32:])
    Both sides derive identical material from the shared secret; the 'initiator'
    flag just controls which half is used for which direction.
    """

    def __init__(self, private_key: X25519PrivateKey, peer_pub_raw: bytes,
                 initiator: bool):
        shared = private_key.exchange(_load_x25519_pub(peer_pub_raw))
        material = HKDF(
            algorithm=hashes.SHA256(), length=64,
            salt=None, info=b"securelink-v1",
            backend=default_backend()
        ).derive(shared)
        # Initiator uses material[:32] to send, material[32:] to recv.
        # Responder is the mirror image — so each side decrypts what the other encrypts.
        if initiator:
            self.send_key = AESGCM(material[:32])
            self.recv_key = AESGCM(material[32:])
        else:
            self.send_key = AESGCM(material[32:])
            self.recv_key = AESGCM(material[:32])
        self._send_ctr = 0
        self._lock = threading.Lock()

    def encrypt(self, plaintext: bytes) -> bytes:
        with self._lock:
            nonce = self._send_ctr.to_bytes(12, 'big')
            self._send_ctr += 1
        ct = self.send_key.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        nonce, ct = data[:12], data[12:]
        return self.recv_key.decrypt(nonce, ct, None)

def _load_x25519_pub(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(raw)

# ─── FRAMING ──────────────────────────────────────────────────────────────────
def send_frame(sock: socket.socket, msg_type: bytes, payload: bytes):
    """Frame: [1B type][4B length][payload]"""
    frame = msg_type + struct.pack(">I", len(payload)) + payload
    total = len(frame)
    sent = 0
    while sent < total:
        n = sock.send(frame[sent:])
        if n == 0:
            raise ConnectionResetError("Socket closed")
        sent += n

def recv_frame(sock: socket.socket):
    """Returns (msg_type_byte, payload_bytes) or raises"""
    def recv_exact(n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("Socket closed")
            buf += chunk
        return buf
    header = recv_exact(5)
    msg_type = header[:1]
    length = struct.unpack(">I", header[1:])[0]
    if length > 100 * 1024 * 1024:  # 100MB max
        raise ValueError(f"Frame too large: {length}")
    payload = recv_exact(length) if length > 0 else b''
    return msg_type, payload

# ─── SECURE CHANNEL ───────────────────────────────────────────────────────────
class SecureChannel:
    """Wraps a socket with E2E encryption, framing, and heartbeat"""

    def __init__(self, sock: socket.socket, crypto: CryptoSession):
        self.sock = sock
        self.crypto = crypto
        self._lock = threading.Lock()

    def send(self, msg_type: bytes, payload: bytes):
        encrypted = self.crypto.encrypt(msg_type + payload)
        with self._lock:
            send_frame(self.sock, MT_HANDSHAKE, encrypted)  # all frames wrapped

    def recv(self):
        _, raw = recv_frame(self.sock)
        plain = self.crypto.decrypt(raw)
        return plain[:1], plain[1:]

    def close(self):
        try: self.sock.close()
        except: pass

# ─── BANNER ───────────────────────────────────────────────────────────────────
def print_banner(fingerprint, role, peer_fp=None):
    w = shutil.get_terminal_size((80, 24)).columns
    line = "─" * w
    print(f"\n{CYAN}{BOLD}{'▄' * w}{R}")
    print(f"{CYAN}{BG_DARK}{'':^{w}}{R}")
    title = "  SecureLink  v" + VERSION
    print(f"{CYAN}{BG_DARK}{BOLD}{title:^{w}}{R}")
    sub = "End-to-End Encrypted • WireGuard/IP • CLI Messenger"
    print(f"{CYAN}{BG_DARK}{DIM}{sub:^{w}}{R}")
    print(f"{CYAN}{BG_DARK}{'':^{w}}{R}")
    print(f"{CYAN}{'▀' * w}{R}\n")
    print(f"  {GREEN}●{R} Role       : {BOLD}{role.upper()}{R}")
    print(f"  {GREEN}●{R} Your ID    : {YELLOW}{fingerprint}{R}")
    if peer_fp:
        print(f"  {GREEN}●{R} Peer ID    : {CYAN}{peer_fp}{R}")
    print(f"  {GREEN}●{R} Encryption : AES-256-GCM + X25519 ECDH")
    print(f"  {GREEN}●{R} Commands   : {DIM}/help  /file  /shell  /peers  /quit{R}")
    print(f"\n{DIM}{line}{R}\n")

def print_help():
    print(f"""
{CYAN}{BOLD}  SecureLink Commands{R}
  {GREEN}/help{R}              — Show this help
  {GREEN}/file <path>{R}       — Send a file to the peer
  {GREEN}/shell{R}             — Open interactive remote shell
  {GREEN}/shell <cmd>{R}       — Execute a single remote command
  {GREEN}/peers{R}             — List known/trusted peers
  {GREEN}/trust <alias>{R}     — Trust and name current peer
  {GREEN}/clear{R}             — Clear screen
  {GREEN}/quit{R}  or Ctrl+C   — Disconnect and exit
  {DIM}Everything else is sent as an encrypted message.{R}
""")

# ─── HANDSHAKE ────────────────────────────────────────────────────────────────
def do_handshake(sock: socket.socket, my_priv, my_pub_raw, my_fp,
                 psk: bytes = None, initiator: bool = True):
    """
    1. Exchange raw X25519 public keys
    2. Optionally verify PSK (pre-shared secret for mutual auth)
    3. Return SecureChannel + peer fingerprint

    initiator=True  → client (connects first, sends pubkey first)
    initiator=False → server (accepts connection, receives pubkey first)
    """
    # Send our pubkey
    send_frame(sock, MT_HANDSHAKE, my_pub_raw)
    # Receive peer pubkey
    _, peer_pub_raw = recv_frame(sock)
    if len(peer_pub_raw) != 32:
        raise ValueError("Invalid peer public key length")
    peer_fp = hashlib.sha256(peer_pub_raw).hexdigest()[:16]

    # Build crypto session — direction-aware
    crypto = CryptoSession(my_priv, peer_pub_raw, initiator=initiator)
    chan = SecureChannel(sock, crypto)

    # PSK-based mutual authentication (HMAC challenge-response)
    if psk:
        my_challenge = os.urandom(32)
        chan.send(MT_AUTH, my_challenge)
        _, peer_data = chan.recv()
        peer_challenge = peer_data[:32]
        peer_response  = peer_data[32:]
        expected = hashlib.sha256(psk + my_challenge).digest()
        if not hmac_compare(peer_response, expected):
            chan.close()
            raise PermissionError("PSK authentication FAILED — untrusted peer")
        my_response = hashlib.sha256(psk + peer_challenge).digest()
        chan.send(MT_AUTH_OK, my_response)
    else:
        # No PSK: basic liveness check
        chan.send(MT_PING, b'securelink-hello')
        _, pong = chan.recv()
        if pong != b'securelink-hello':
            raise ConnectionError("Handshake liveness check failed")

    return chan, peer_fp

def hmac_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b): return False
    result = 0
    for x, y in zip(a, b): result |= x ^ y
    return result == 0

# ─── FILE TRANSFER ────────────────────────────────────────────────────────────
def send_file(chan: SecureChannel, filepath: str):
    path = Path(filepath).expanduser()
    if not path.exists():
        print(f"  {RED}✗ File not found: {path}{R}")
        return
    size = path.stat().st_size
    name = path.name
    fname_b = name.encode()
    header = struct.pack(">H", len(fname_b)) + fname_b + struct.pack(">Q", size)
    chan.send(MT_FILE, header)
    print(f"  {CYAN}↑ Sending {BOLD}{name}{R}{CYAN} ({_fmt_size(size)}){R}")
    sent = 0
    t0 = time.time()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk: break
            chan.send(MT_FILE, chunk)
            sent += len(chunk)
            pct = sent / size * 100 if size else 100
            bar = _progress_bar(pct)
            print(f"\r  {bar} {pct:.1f}% ({_fmt_size(sent)}/{_fmt_size(size)})", end='', flush=True)
    chan.send(MT_FILE, b'__EOF__')
    elapsed = time.time() - t0
    speed = size / elapsed if elapsed > 0 else 0
    print(f"\r  {GREEN}✓ Sent {name} in {elapsed:.1f}s @ {_fmt_size(speed)}/s{' '*20}{R}")

def receive_file(chan: SecureChannel, header_payload: bytes, download_dir: Path):
    fname_len = struct.unpack(">H", header_payload[:2])[0]
    fname = header_payload[2:2+fname_len].decode()
    fsize = struct.unpack(">Q", header_payload[2+fname_len:2+fname_len+8])[0]
    dest = download_dir / fname
    download_dir.mkdir(exist_ok=True)
    print(f"\n  {CYAN}↓ Receiving {BOLD}{fname}{R}{CYAN} ({_fmt_size(fsize)}){R}")
    received = 0
    with open(dest, 'wb') as f:
        while True:
            _, chunk = chan.recv()
            if chunk == b'__EOF__': break
            f.write(chunk)
            received += len(chunk)
            pct = received / fsize * 100 if fsize else 100
            bar = _progress_bar(pct)
            print(f"\r  {bar} {pct:.1f}%", end='', flush=True)
    print(f"\r  {GREEN}✓ Saved to {dest}{' '*30}{R}")

def _fmt_size(n):
    for unit in ['B','KB','MB','GB']:
        if n < 1024: return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def _progress_bar(pct, width=20):
    filled = int(width * pct / 100)
    return f"{GREEN}[{'█'*filled}{'░'*(width-filled)}]{R}"

# ─── REMOTE SHELL ─────────────────────────────────────────────────────────────
def handle_shell_command(chan: SecureChannel, cmd: str):
    """Execute a shell command and stream output back"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        out = result.stdout + result.stderr
        chan.send(MT_SHELL_D, out.encode())
    except subprocess.TimeoutExpired:
        chan.send(MT_SHELL_D, b"[timeout: command exceeded 60s]")
    except Exception as e:
        chan.send(MT_SHELL_D, f"[error: {e}]".encode())

def interactive_shell_session(chan: SecureChannel):
    """Multiplexed interactive shell — sends commands, prints responses"""
    print(f"\n  {YELLOW}Remote Shell — type 'exit' to return to chat{R}\n")
    while True:
        try:
            cmd = input(f"{MAGENTA}remote$ {R}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd.lower() in ('exit', 'quit', ':q'):
            break
        if not cmd: continue
        chan.send(MT_SHELL, cmd.encode())
        try:
            t, data = chan.recv()
            if t == MT_SHELL_D:
                print(data.decode(errors='replace'))
        except Exception:
            break
    print(f"\n  {DIM}Returned to chat.{R}")

# ─── RECEIVE LOOP ─────────────────────────────────────────────────────────────
def recv_loop(chan: SecureChannel, peer_fp: str, download_dir: Path,
              shell_queue: list, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            chan.sock.settimeout(RECV_TIMEOUT)
            msg_type, payload = chan.recv()

            if msg_type == MT_CHAT:
                msg = payload.decode(errors='replace')
                print(f"\r{' '*80}\r  {CYAN}{BOLD}[{peer_fp[:8]}]{R} {DIM}{ts()}{R}  {WHITE}{msg}{R}")
                print(f"{GREEN}you>{R} ", end='', flush=True)

            elif msg_type == MT_FILE:
                receive_file(chan, payload, download_dir)
                print(f"{GREEN}you>{R} ", end='', flush=True)

            elif msg_type == MT_SHELL:
                cmd = payload.decode(errors='replace')
                handle_shell_command(chan, cmd)

            elif msg_type == MT_SHELL_D:
                shell_queue.append(payload)

            elif msg_type == MT_PING:
                chan.send(MT_PONG, payload)

            elif msg_type == MT_PONG:
                pass  # heartbeat response

        except socket.timeout:
            try:
                chan.send(MT_PING, b'keepalive')
            except:
                stop_event.set()
                break
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n  {RED}✗ Connection lost: {e}{R}")
            stop_event.set()
            break

# ─── MAIN CHAT LOOP ───────────────────────────────────────────────────────────
def chat_loop(chan: SecureChannel, peer_fp: str, download_dir: Path):
    stop = threading.Event()
    shell_queue = []

    rx = threading.Thread(target=recv_loop,
                          args=(chan, peer_fp, download_dir, shell_queue, stop),
                          daemon=True)
    rx.start()

    print(f"  {GREEN}✓ Secure channel established with peer {CYAN}{peer_fp}{R}\n")
    print(f"  {DIM}Type a message or /help for commands.{R}\n")

    try:
        while not stop.is_set():
            try:
                line = input(f"{GREEN}you>{R} ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line: continue

            if line == '/help':
                print_help()
            elif line == '/quit':
                break
            elif line == '/clear':
                os.system('clear')
            elif line == '/peers':
                peers = load_peers()
                if peers:
                    for alias, info in peers.items():
                        print(f"  {YELLOW}{alias}{R}: {info['fingerprint']}")
                else:
                    print(f"  {DIM}No trusted peers yet. Use /trust <alias>{R}")
            elif line.startswith('/trust '):
                alias = line[7:].strip()
                save_peer(alias, peer_fp, "")
                print(f"  {GREEN}✓ Peer trusted as '{alias}'{R}")
            elif line.startswith('/file '):
                path = line[6:].strip()
                threading.Thread(target=send_file, args=(chan, path), daemon=True).start()
            elif line == '/shell':
                interactive_shell_session(chan)
            elif line.startswith('/shell '):
                cmd = line[7:].strip()
                chan.send(MT_SHELL, cmd.encode())
                waited = 0
                while waited < 100 and not shell_queue:
                    time.sleep(0.1)
                    waited += 1
                if shell_queue:
                    print(shell_queue.pop(0).decode(errors='replace'))
                else:
                    print(f"  {YELLOW}⚠ No response (timeout){R}")
            else:
                try:
                    chan.send(MT_CHAT, line.encode())
                except Exception as e:
                    print(f"  {RED}✗ Send failed: {e}{R}")
                    break
    finally:
        stop.set()
        chan.close()

# ─── SERVER MODE ──────────────────────────────────────────────────────────────
def run_server(host: str, port: int, psk: bytes, my_priv, my_pub, my_fp, download_dir: Path):
    sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    print(f"  {GREEN}●{R} Listening on {BOLD}{host}:{port}{R}")
    print(f"  {DIM}Waiting for peer to connect…{R}\n")
    conn, addr = sock.accept()
    sock.close()
    conn.settimeout(30)
    print(f"  {YELLOW}⚡ Incoming from {addr[0]}:{addr[1]} — performing handshake…{R}")
    # Server is the responder (initiator=False)
    chan, peer_fp = do_handshake(conn, my_priv, my_pub, my_fp, psk, initiator=False)
    conn.settimeout(None)
    print_banner(my_fp, "server", peer_fp)
    chat_loop(chan, peer_fp, download_dir)

# ─── CLIENT MODE ──────────────────────────────────────────────────────────────
def run_client(host: str, port: int, psk: bytes, my_priv, my_pub, my_fp, download_dir: Path):
    retries = 0
    while retries < MAX_RETRIES:
        try:
            af = socket.AF_INET6 if ':' in host else socket.AF_INET
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(10)
            print(f"  {DIM}Connecting to {host}:{port}…{R}", end='', flush=True)
            sock.connect((host, port))
            sock.settimeout(30)
            print(f"  {GREEN}connected{R}")
            print(f"  {YELLOW}⚡ Performing encrypted handshake…{R}")
            # Client is the initiator (initiator=True)
            chan, peer_fp = do_handshake(sock, my_priv, my_pub, my_fp, psk, initiator=True)
            sock.settimeout(None)
            print_banner(my_fp, "client", peer_fp)
            chat_loop(chan, peer_fp, download_dir)
            break  # clean exit
        except PermissionError as e:
            print(f"\n  {RED}✗ AUTH FAILED: {e}{R}")
            sys.exit(1)
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            retries += 1
            print(f"\r  {YELLOW}⚠ Cannot reach {host}:{port} — retry {retries} in {RECONNECT_WAIT}s…{R}  ", end='', flush=True)
            time.sleep(RECONNECT_WAIT)
        except Exception as e:
            print(f"\n  {RED}✗ Unexpected error: {e}{R}")
            retries += 1
            time.sleep(RECONNECT_WAIT)

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        prog="securelink",
        description="SecureLink — Encrypted CLI Messenger + File Transfer + Remote Shell",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Server (listen):   securelink --listen --host 10.0.0.1 --port 55000 --psk mysecret
  Client (connect):  securelink --host 10.0.0.1 --port 55000 --psk mysecret
  Over WireGuard:    securelink --host 10.8.0.1 --psk mysecret
  IPv6:              securelink --host fd00::1 --psk mysecret
        """
    )
    p.add_argument('--listen',    '-l', action='store_true', help='Run as server (listen mode)')
    p.add_argument('--host',      '-H', default='0.0.0.0',   help='IP address to bind/connect')
    p.add_argument('--port',      '-p', type=int, default=DEFAULT_PORT, help=f'Port (default: {DEFAULT_PORT})')
    p.add_argument('--psk',       '-k', default='',           help='Pre-shared secret for mutual auth')
    p.add_argument('--downloads', '-d', default=str(Path.home()/'Downloads'), help='Directory for received files')
    p.add_argument('--whoami',          action='store_true',  help='Print your identity fingerprint and exit')
    args = p.parse_args()

    my_priv, my_pub, my_fp = load_or_create_identity()
    download_dir = Path(args.downloads)

    if args.whoami:
        print(f"\n  {GREEN}Your SecureLink fingerprint:{R} {YELLOW}{my_fp}{R}")
        pub_hex = my_pub.hex()
        print(f"  {DIM}Public key: {pub_hex}{R}\n")
        return

    psk = args.psk.encode() if args.psk else None

    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n  {YELLOW}Interrupted{R}"), sys.exit(0)))

    if args.listen:
        print_banner(my_fp, "server")
        run_server(args.host, args.port, psk, my_priv, my_pub, my_fp, download_dir)
    else:
        print_banner(my_fp, "client")
        run_client(args.host, args.port, psk, my_priv, my_pub, my_fp, download_dir)

if __name__ == '__main__':
    main()
