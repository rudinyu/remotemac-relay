**English** | [繁體中文](README.zh-TW.md)

# RemoteMac self-hosted relay

Two Python scripts that together form a complete remote-control system — with no need to open any inbound port on the machine being controlled.

| File | Role | Where it runs |
|---|---|---|
| `relay.py` | Rendezvous server (blind pipe) | A VPS / home box you control |
| `remote_desktop.py` | Encrypted transport + remote desktop + SOCKS5 proxy (five modes) | Mac / Linux |

```
 Machine A  ──outbound──►  YOUR RELAY  ◄──outbound──  Machine B
  (client)    (encrypted)    (blind)     (encrypted)    (host)
```

---

## Architecture

### relay.py — the blind pipe

The relay does exactly one thing: pair two outbound TCP connections and forward bytes in both directions. It **never sees plaintext**, because encryption and decryption happen at the two endpoints.

- No database, stores nothing
- Runs as `nobody` (the systemd unit is preconfigured)
- Built-in DoS protection: max 5 concurrent connections per IP, max 10,000 registered hosts

### remote_desktop.py — encrypted channel + remote desktop

Once the relay has bridged the two connections, `remote_desktop.py` runs a **mutually authenticated + encrypted** protocol on top:

```
[relay bridge established → 'P']
        │
        ▼
① Exchange random nonces (32 bytes each)
        │
        ▼
② scrypt key derivation
   master = scrypt(PSK, salt=nonce_h‖nonce_c, N=16384, r=8, p=1)
   → 5 independent subkeys (enc_h2c, enc_c2h, mac_h2c, mac_c2h, auth)
        │
        ▼
③ Mutual token exchange
   token = HMAC-SHA256(auth_key, role‖nonce_h‖nonce_c)
   Both sides verify with compare_digest → abort if either lacks the PSK
        │
        ▼
④ Data transfer (per frame)
   ┌──────────┬──────────────────────┬────────────────────┐
   │ 4 B len  │ 32 B HMAC-SHA256 MAC │ N B ciphertext     │
   └──────────┴──────────────────────┴────────────────────┘
   Encryption: SHAKE-256 XOF counter-mode (111 MB/s, one Keccak call/frame)
   Integrity:  HMAC-SHA256(mac_key, seq_num‖ciphertext); seq_num prevents replay
```

---

## Security summary

| Threat | Mitigation |
|---|---|
| Eavesdropping relay traffic | SHAKE-256 encryption; the relay only sees ciphertext |
| Man-in-the-middle impersonation | Mutual token verification; both sides must know the PSK |
| Weak-PSK brute force | scrypt(N=16384) makes each guess cost ~50 ms + 16 MB RAM |
| Frame forgery / tampering | HMAC-SHA256 per-frame MAC, constant-time comparison |
| Replay attacks | Monotonic 64-bit sequence number, independent per direction |
| Frame flooding | Receiver caps at 5,000 frames/s |
| Connection squatting | 30 s auth timeout; idle connections dropped after 120 s |
| Giant frames exhausting memory | 4 MB per-frame limit |

> **Note**: the encryption layer in remote_desktop.py is unrelated to the RemoteMac app's TLS-PSK — they are independent encryption layers. remote_desktop.py is a standalone remote-desktop / encrypted-tunnel tool, not a replacement for the app.

---

## Requirements

- Python 3.8+ (no pip packages required for the relay / pipe / gateway / socks modes)
- The relay server must be reachable from the internet (a VPS, or a home box with port forwarding)

---

## 1. Set up relay.py (server side)

### 0. Check the Python version

```bash
python3 --version   # needs 3.8+
```

If it's missing:

```bash
# Debian / Ubuntu / Raspberry Pi OS
sudo apt update && sudo apt install -y python3

# Fedora / RHEL / CentOS / Rocky / Alma
sudo dnf install -y python3

# Arch / Manjaro
sudo pacman -S --noconfirm python

# Alpine
sudo apk add python3
```

### 1. Copy the files to the server

```bash
scp relay.py remotemac-relay.service you@YOUR_SERVER:~/
```

### 2. Test first (foreground)

```bash
ssh you@YOUR_SERVER
python3 relay.py 21118
# you should see: RemoteMac relay listening on 0.0.0.0:21118
```

Confirm the port is listening:

```bash
ss -tlnp | grep 21118
```

Press **Ctrl-C** to stop.

### 3. Install as a systemd service (recommended)

```bash
sudo mkdir -p /opt/remotemac
sudo cp relay.py /opt/remotemac/
sudo cp remotemac-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotemac-relay
sudo systemctl status remotemac-relay        # confirm active (running)
```

Watch the live log:

```bash
journalctl -u remotemac-relay -f
# host registered → Mac has connected
# bridging        → a session is in progress
```

Without systemd (Alpine / container / WSL):

```bash
nohup python3 /opt/remotemac/relay.py 21118 > /var/log/remotemac-relay.log 2>&1 &
```

To change the port: edit `ExecStart=` in `/etc/systemd/system/remotemac-relay.service`, then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart remotemac-relay
```

### 4. Open the firewall

```bash
# ufw (Debian/Ubuntu)
sudo ufw allow 21118/tcp

# firewalld (Fedora/RHEL)
sudo firewall-cmd --add-port=21118/tcp --permanent && sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 21118 -j ACCEPT
```

Cloud VMs (AWS / GCP / Azure / DigitalOcean) also need 21118/tcp opened for inbound traffic in the console's security-group / firewall rules.

### 5. Verify external reachability

```bash
# find the public IP on the server
curl -s https://api.ipify.org; echo

# test from another machine (e.g. your Mac)
nc -vz YOUR_RELAY_IP 21118     # should print succeeded / open
```

### Managing the service

```bash
sudo systemctl restart remotemac-relay
sudo systemctl stop remotemac-relay
sudo systemctl disable --now remotemac-relay
journalctl -u remotemac-relay -e          # view recent logs
```

Update the relay:

```bash
sudo cp relay.py /opt/remotemac/ && sudo systemctl restart remotemac-relay
```

Remove completely:

```bash
sudo systemctl disable --now remotemac-relay
sudo rm /etc/systemd/system/remotemac-relay.service /opt/remotemac/relay.py
sudo systemctl daemon-reload
```

---

## 2. Configure the RemoteMac app (Mac + iPad)

### On the Mac

```bash
echo "YOUR_RELAY_IP:21118" > ~/.config/remotemac/relay
pkill -9 -f "RemoteMac Host.app"
open -W "/Applications/RemoteMac Host.app"
```

The relay log should show: `host registered id=...`

### On the iPad

**Settings ▸ Relay server** → enter `YOUR_RELAY_IP:21118`.

### Connection flow

1. Enter the Device Code on the iPad.
2. Same Wi-Fi → direct LAN connection (fastest); the relay is not used.
3. Different networks / cellular → both sides connect to the relay → bridged → connected.

---

## 3. Using remote_desktop.py

`remote_desktop.py` bundles the encrypted transport, remote desktop, and encrypted proxy features, with five modes:

| Mode | Description | Dependencies |
|---|---|---|
| `host` | Controlled side: streams the screen + receives injected keyboard/mouse | `mss Pillow pynput` |
| `viewer` | Controlling side: displays the screen + sends keyboard/mouse | `Pillow` (with tkinter) |
| `pipe` | stdin/stdout encrypted bridge, no GUI | none (Python stdlib) |
| `gateway` | Exit node: opens outbound TCP/UDP on behalf of the client | none (Python stdlib) |
| `socks` | Local SOCKS5 proxy entry point; sends other apps' traffic through the encrypted tunnel | none (Python stdlib) |

### Install dependencies (host / viewer modes)

```bash
pip install mss Pillow pynput
```

### macOS permissions

| Side | Permission needed |
|---|---|
| host | **Screen Recording** (System Preferences > Privacy > Screen Recording) |
| host | **Accessibility** (System Preferences > Privacy > Accessibility) — for keyboard/mouse injection |

### Starting remote control

```bash
# 1. Run the host side first (the controlled machine, waits for a peer)
python3 remote_desktop.py host relay.example.com:21118 mydevice --psk "strong-passphrase"

# 2. Run the viewer side (the controlling machine)
python3 remote_desktop.py viewer relay.example.com:21118 mydevice --psk "strong-passphrase"
```

Host mode is **persistent by default**: after a viewer disconnects it re-registers with the relay and waits for the next connection; if it can't reach the relay it retries with exponential backoff (2s → 30s). Add `--once` to restore the "exit after a single session" behavior.

> **Security note**: a value passed via `--psk` can be seen on Linux with `ps aux`. Safer options:
> - Omit `--psk` — the program prompts interactively (not echoed to the screen)
> - Or set an environment variable: `export REMOTEMAC_PSK="your-passphrase"`, then omit `--psk`

On success:
```
[remotemac] relay: registered — waiting for peer…    ← host side
[remotemac] auth: mutual authentication succeeded ✓

[remotemac] relay: bridge established                 ← viewer side
[remotemac] auth: mutual authentication succeeded ✓
```

The viewer opens a window showing the host's screen; your mouse and keyboard input are relayed to the host in real time.

### Options

| Option | Modes | Description | Default |
|---|---|---|---|
| `--fps N` | host | Capture frame rate | 15 |
| `--quality N` | host | JPEG quality 20–95 | 75 |
| `--once` | host | Exit after a single session (default: persistent re-registration) | off |
| `--no-clip` | host / viewer | Disable bidirectional clipboard sync | off (sync on) |

```bash
# High quality (needs a good network)
python3 remote_desktop.py host relay.example.com:21118 myid "pw" --fps 30 --quality 85

# Save bandwidth
python3 remote_desktop.py host relay.example.com:21118 myid "pw" --fps 10 --quality 60
```

### Supported input

| Type | Notes |
|---|---|
| Mouse movement | Full-screen coordinates normalized; auto-adapts to different resolutions |
| Left / right / middle button | Press and release |
| Scroll wheel | Works on macOS / Linux / Windows |
| Keyboard | Regular characters + F1–F12 + Ctrl / Alt / Shift / ⌘ / arrow keys, etc. |
| Clipboard | Bidirectional auto-sync (plain text, polled every second; disable with `--no-clip`) |

### Pipe mode (CLI tools / script integration)

No GUI — just a stdin/stdout bridge, ideal for file transfer, remote command execution, etc.:

```bash
# Transfer a file (host side sends to client side)
cat file.bin | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk "pw"
python3 remote_desktop.py pipe relay.example.com:21118 myid client --psk "pw" > output.bin

# Remote bash
bash | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk "pw"
python3 remote_desktop.py pipe relay.example.com:21118 myid client --psk "pw"
```

### Encrypted SOCKS5 proxy (gateway / socks modes)

Beyond remote desktop, you can route other apps' traffic on the client machine (browser, curl, …) **out through the host over the encrypted tunnel** — a self-hosted, encrypted `ssh -D`. Many connections are multiplexed over a single relay bridge, all using the same crypto (scrypt auth + SHAKE-256 + HMAC); the relay still only sees ciphertext.

```bash
# 1. gateway (the exit machine, e.g. your Mac at home; persistent, auto-reconnects)
python3 remote_desktop.py gateway relay.example.com:21118 myproxy --psk "pw"

# 2. socks (your local machine, opens a local SOCKS5 proxy)
python3 remote_desktop.py socks relay.example.com:21118 myproxy --psk "pw" --port 1080

# 3. Send apps through the proxy (socks5h → DNS resolution also goes remote)
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org        # shows the gateway's public IP
ALL_PROXY=socks5h://127.0.0.1:1080 curl https://example.com
```

Point a browser at SOCKS5 host `127.0.0.1`, port `1080` to route everything through the tunnel.

- **Supported**: TCP (SOCKS5 CONNECT) + UDP (SOCKS5 UDP associate, e.g. DNS/QUIC); domain names are resolved on the gateway side.
- **Security**: anyone connecting into the gateway must pass mutual PSK authentication or the connection is dropped, so it won't become an open proxy.

| Option | Modes | Description | Default |
|---|---|---|---|
| `--port N` | socks | Local SOCKS5 listen port | 1080 |
| `--bind ADDR` | socks | Local bind address | 127.0.0.1 |
| `--allow HOST/CIDR` | gateway | Allowlist (domain suffix or IP/CIDR), repeatable; omit to allow all | none (allow all) |
| `--once` | gateway | Exit after a single session (default: persistent reconnect) | off |

> **Defense in depth**: `socks` binds only to `127.0.0.1` by default, so other machines can't piggyback on your proxy; think twice before exposing it with `--bind 0.0.0.0`. To tighten the `gateway` further, use `--allow` (e.g. `--allow example.com --allow 10.0.0.0/8`) to restrict reachable targets — anything not listed is rejected.

### Choosing a PSK

| Strength | Example |
|---|---|
| Weak (not recommended) | `1234`, `password` |
| Acceptable | `correct-horse-battery-staple` |
| Strong (recommended) | `python3 -c "import secrets; print(secrets.token_hex(24))"` |

---

## 4. Mesh overlay (experimental — Phase 1)

Beyond the 1:1 remote-desktop model, `coordinator.py` + `mesh.py` grow the system
into a **mesh** (a self-hosted, Tailscale-lite network): many nodes join one
network, each gets a stable overlay IP, and node↔node traffic is end-to-end
encrypted. Requires `cryptography` (`pip install cryptography`).

```bash
# Coordinator (on your reachable host — control plane only, sees ciphertext)
python3 coordinator.py 21200 --token "network-secret"

# Each node joins the network
python3 mesh.py up coord.example.com:21200 --token "network-secret" --name laptop
python3 mesh.py up coord.example.com:21200 --token "network-secret" --name mac

# Prove the encrypted path between two nodes
python3 mesh.py up coord.example.com:21200 --token "network-secret" --ping mac
```

- Each node has a persistent X25519 identity (`~/.config/remotemac/mesh/key`,
  overridable with `$REMOTEMAC_MESH_KEY`); the coordinator assigns overlay IPs
  from `100.64.0.0/10`.
- Node↔node handshake is mutually authenticated and forward-secret (X25519
  triple-DH → HKDF-SHA256 → ChaCha20-Poly1305); the coordinator only relays
  **ciphertext** (DERP fallback).

**Status / roadmap.** Phase 1 (this release) delivers the control plane, per-node
identity, the host pool + selection, and an encrypted data path relayed through
the coordinator — no root needed. Still to come: **Phase 2** — direct P2P via UDP
NAT hole punching (relay stays as fallback for symmetric-NAT pairs); **Phase 3** —
a TUN overlay device with automatic routing and exit-node selection (full VPN;
needs root). Data-plane throughput is modest (pure-Python), fine for typical use.

---

## Performance

Encryption throughput measured on a typical dev machine (4 MB frame):

| Item | Speed |
|---|---|
| XOR (big-integer) | ~140 MB/s |
| SHAKE-256 encryption | ~111 MB/s |
| Auth handshake (scrypt) | ~50 ms (one-time) |
| Typical remote-desktop bandwidth | 1–8 MB/s (JPEG @75, 1080p, 15fps) |

Encryption overhead is far below the actual streaming bandwidth — the bottleneck is the network, not the CPU.

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| iPad shows "Mac … is offline" | No `host registered` in the relay log → the Mac's `~/.config/remotemac/relay` is wrong, or the Mac can't reach the relay |
| `nc -vz` times out from outside | Firewall / security group / router port forwarding not open |
| Works on Wi-Fi but not cellular | The relay has no real public path (home box without port forwarding) |
| Service fails to start | `journalctl -u remotemac-relay -e` → usually a wrong Python path or the port is in use |
| auth failed: peer does not know the PSK | PSKs differ between the two sides, or the device_id is different |
| relay: host slot occupied | Same device_id already registered from a different IP; use another device_id or wait for the old connection to time out |
| MAC verification failed | Someone tampered with packets in transit, or version mismatch |
| remote_desktop screen is black | Host lacks Screen Recording permission |
| remote_desktop keyboard/mouse unresponsive | Host lacks Accessibility permission |
| remote_desktop disconnects right after connecting | Check the PSK matches on both sides; look at stderr output |
| socks / gateway can't connect | device_id and PSK must match on both sides; the gateway must start and register with the relay first |
| curl through the proxy fails to resolve | Use `socks5h://` (the h means remote DNS), not `socks5://` |

---

## File list

| File | Description |
|---|---|
| `relay.py` | Rendezvous server, Python 3.8+, no dependencies |
| `remote_desktop.py` | Encrypted transport + remote desktop + SOCKS5 proxy (host / viewer / pipe / gateway / socks — five modes) |
| `coordinator.py` | Mesh control plane (Phase 1) — node registry, overlay-IP assignment, DERP relay. Needs `cryptography` |
| `mesh.py` | Mesh node — X25519 identity, joins a network, encrypted node↔node data path. Needs `cryptography` |
| `remotemac-relay.service` | systemd unit that auto-starts relay.py on boot |
