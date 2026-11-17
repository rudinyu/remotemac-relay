**English** | [繁體中文](INSTALL.zh-TW.md)

# Install & Deploy

A task-oriented guide to getting RemoteMac running. Pick the pieces you need:

| You want to… | Deploy | Needs |
|---|---|---|
| Relay for remote desktop / proxy | `relay.py` | a reachable host (VPS / port-forwarded box) |
| A mesh (Tailscale-lite VPN) | `coordinator.py` + `mesh.py` nodes | a reachable host for the coordinator |
| Remote-desktop a Mac/Linux box | `remote_desktop.py` (host + viewer) | the relay above |

The **relay** and **coordinator** are servers you run once on a reachable host.
Everything else (mesh nodes, remote desktop) connects *outbound* to them.

---

## 1. Prerequisites

- **Python 3.8+** wherever a Python component runs (`python3 --version`). The
  Swift native viewer instead needs macOS and a Swift toolchain to build.
- The **relay/coordinator host** must be reachable from the internet — a VPS, or a
  home box with the port forwarded.
- **Mesh nodes and the coordinator** need `pip install cryptography` (the coordinator
  uses X25519 for the registration proof-of-possession). The relay and the
  remote-desktop `pipe`/`gateway`/`socks` modes are **pure stdlib** (no pip). The
  remote-desktop `host` needs `mss Pillow pynput`, while `viewer` needs `Pillow`
  and tkinter. Install these on their respective machines. Docker and
  `scripts/install-linux.sh` install the coordinator's
  `cryptography` dependency; they do not install desktop dependencies.
- **Docker** (optional) for the one-command server deploy: Docker Engine + the
  Compose plugin.

---

## 2. Get the code

```bash
git clone https://github.com/rudinyu/remotemac-relay.git
cd remotemac-relay
```

Keep the checkout on mesh nodes, or copy its Python modules together: `mesh.py`
imports `remote_desktop.py` and loads `tun.py`, `netroute.py`, `nat.py`,
`macnat.py`, and `meshdns.py` for optional features. The coordinator needs
`coordinator.py` and `remote_desktop.py`; `relay.py` runs on its own.

---

## 3. Deploy the servers

You need a **relay** (for remote desktop / proxy) and/or a **coordinator** (for the
mesh). Pick one method.

### Option A — Docker (recommended)

Brings up the relay **and** the mesh coordinator as non-root containers with one
command:

```bash
cp docker/.env.example .env          # then edit .env and set REMOTEMAC_MESH_TOKEN
docker compose up -d --build
docker compose logs -f               # watch both
```

- Generate a strong token: `openssl rand -base64 24` → put it in `.env`.
- Ports: **relay 21118/tcp**, **coordinator 21200/tcp + 21200/udp** (STUN shares the
  port). Open them (see §7).
- Coordinator overlay-IP assignments persist in the `coordinator-state` volume.
- Stop with `docker compose down` (add `-v` to also drop the state volume).

If you only want the relay, run just that service:
`docker compose up -d --build relay`.

### Option B — one-shot script (systemd, Linux)

Install the relay + coordinator as hardened systemd services in one command:

```bash
sudo ./scripts/install-linux.sh                        # both; prompts for / generates a token
sudo ./scripts/install-linux.sh --relay-only           # just the relay
sudo ./scripts/install-linux.sh --coord-only --open-firewall
```

It copies the code to `/opt/remotemac`, writes systemd units (relay as `nobody`;
coordinator with a `StateDirectory` for its overlay-IP state and the token in a
root-only `EnvironmentFile`), enables + starts them, and — with `--open-firewall`
— opens the ports via ufw/firewalld. Re-run it to update, passing the existing
mesh token again so nodes keep access. `--help` lists all flags
(`--relay-port`, `--coord-port`, `--token`, `--prefix`). If you don't pass a token,
it generates one and prints it — give that same value to every node.

### Option C — manual

**Relay** (as a systemd service):

```bash
sudo mkdir -p /opt/remotemac
sudo cp relay.py /opt/remotemac/
sudo cp remotemac-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotemac-relay
sudo systemctl status remotemac-relay        # active (running)
journalctl -u remotemac-relay -f             # live log
```

To change the port, edit `ExecStart=` in the unit, then
`sudo systemctl daemon-reload && sudo systemctl restart remotemac-relay`.

**Coordinator** (mesh control plane):

```bash
# foreground test
REMOTEMAC_MESH_TOKEN="your-strong-secret" python3 coordinator.py 21200

# or as a background service (example)
sudo cp coordinator.py remote_desktop.py /opt/remotemac/
mkdir -p ~/.local/state/remotemac
REMOTEMAC_MESH_TOKEN="your-strong-secret" \
  nohup python3 /opt/remotemac/coordinator.py 21200 \
  --state ~/.local/state/remotemac/coordinator-state.json \
  > ~/.local/state/remotemac/coordinator.log 2>&1 &
```

The token can come from `--token` or `REMOTEMAC_MESH_TOKEN`; prefer the env var so
it isn't visible in `ps`. `--state PATH` persists overlay-IP assignments.

Without systemd (Alpine / container / WSL), run the relay with a log path your
user can write: `mkdir -p ~/.local/state/remotemac` then
`nohup python3 /opt/remotemac/relay.py 21118 > ~/.local/state/remotemac/relay.log 2>&1 &`.

---

## 4. Join the mesh (nodes)

On each machine that should join the network (`pip install cryptography` first):

```bash
# Basic node: control channel only, proves the encrypted path with --ping
python3 mesh.py up coord.example.com:21200 --token "your-strong-secret" --name laptop
python3 mesh.py up coord.example.com:21200 --token "your-strong-secret" --ping gw
```

Each node gets a stable IPv4 overlay IP from `100.64.0.0/10` and an IPv6 ULA
address from the coordinator's persisted per-mesh prefix. Both appear in the
node log. `--name` defaults to the system hostname. The token must match the
coordinator's.

**VPN data plane** — reach peers by overlay IP with real apps (needs root):

```bash
sudo python3 mesh.py up coord.example.com:21200 --token "…" --name laptop --tun
ping 100.64.0.3        # another node's overlay IP; log shows [direct] or [derp]
```

**Subnet router** — expose a LAN behind a Linux or macOS node:

```bash
# On gw, run `sudo python3 mesh.py key` and copy the full public key.
sudo python3 mesh.py up coord…:21200 --token "…" --name gw --tun --advertise-routes 192.168.1.0/24
# on a client:
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --accept-route GW_PUBKEY,192.168.1.0/24
```

**IPv4 exit node** — send IPv4 default traffic through a Linux or macOS exit (opt-in):

```bash
# On exit, run `sudo python3 mesh.py key` and copy the full public key.
sudo python3 mesh.py up coord…:21200 --token "…" --name exit   --tun --exit
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --exit-node EXIT_PUBKEY
curl https://ifconfig.me   # shows the exit's public IP
```

The IPv4 exit refuses to start when an IPv6 default route exists. Use
`--allow-ipv6-bypass` only if direct IPv6 traffic is acceptable.
Upgrade the coordinator before enabling a macOS gateway with this node version;
macOS gateway status is published after forwarding and NAT setup succeeds.

**split-DNS** — reach peers by name (`ssh laptop.mesh`):

```bash
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --dns
```

Linux automatic setup uses systemd-resolved (`resolvectl`) for only the `.mesh`
domain. If unavailable, the local DNS server still starts and prints a manual
`dig @127.0.0.1` check; it does not rewrite `/etc/resolv.conf`.

> `--tun` and the routing/DNS features need **root**. On Linux a subnet/exit node
> also needs `nftables` (or `iptables`) and IP forwarding — the tool sets these up.
> In a container, a mesh node additionally needs `--cap-add=NET_ADMIN --device
> /dev/net/tun`. macOS gateways use PF NAT. See the mesh section of the
> [README](README.md#4-mesh-overlay-experimental--phase-10).

---

## 5. Remote desktop (optional)

For controlling a Mac/Linux desktop through the relay (`pip install mss Pillow pynput`):

```bash
# on the machine being controlled (host)
python3 remote_desktop.py host relay.example.com:21118 mydevice --psk "strong-passphrase"
# on the controlling machine (viewer)
python3 remote_desktop.py viewer relay.example.com:21118 mydevice --psk "strong-passphrase"
```

For Python hosts, set the same strong `REMOTEMAC_RELAY_HOST_TOKEN` on the relay
and host before starting them. The relay then authenticates host registrations
before reserving device IDs. The existing Mac/iPad host app uses the legacy relay
protocol, so leave this variable unset when using that app.
For Docker, set it in `.env`; for systemd, put
`REMOTEMAC_RELAY_HOST_TOKEN=<strong secret>` in `/etc/remotemac/relay.env`
(mode `0600`) and restart the relay. Set it in the Python host's environment too.

macOS host needs **Screen Recording** + **Accessibility** permissions. Prefer
`REMOTEMAC_PSK` over `--psk` so the secret isn't visible in `ps`. See the
[README](README.md#3-using-remote_desktoppy) for `gateway` / `socks` / `pipe` modes.
On macOS, a native Swift viewer is also available: run `./mac-native/build-app.sh`
to build `mac-native/dist/RemoteMac Viewer.app`. It connects to the Python host;
see the [native viewer guide](mac-native/README.md) for current limitations.

---

## 6. Verify

```bash
# relay reachable from outside
nc -vz YOUR_RELAY_IP 21118            # succeeded / open

# coordinator up (from a node host)
nc -vz YOUR_COORD_IP  21200

# mesh path works
python3 mesh.py up coord.example.com:21200 --token "…" --ping PEER_NAME   # "pong … [direct: …]" or "[derp…]"
```

Docker: `docker compose ps` shows both services `healthy`.

---

## 7. Ports & firewall

| Service | Port | Notes |
|---|---|---|
| relay | `21118/tcp` | inbound from clients |
| coordinator | `21200/tcp` | mesh control channel |
| coordinator | `21200/udp` | STUN (endpoint discovery) |
| mesh node | UDP (random, or `--udp-port`) | outbound; forward it for best P2P, else DERP fallback |

Open the relay/coordinator ports on the host **and** in any cloud security group:

```bash
sudo ufw allow 21118/tcp
sudo ufw allow 21200/tcp
sudo ufw allow 21200/udp
```

Mesh nodes connect **outbound** and need no inbound port; forwarding a fixed
`--udp-port` only improves the odds of a direct P2P path.

---

## 8. Upgrade & uninstall

**Docker:** `git pull && docker compose up -d --build`. Uninstall:
`docker compose down -v` and remove the images.

**systemd relay:** `sudo cp relay.py /opt/remotemac/ && sudo systemctl restart remotemac-relay`.
Uninstall:

```bash
sudo systemctl disable --now remotemac-relay
sudo rm /etc/systemd/system/remotemac-relay.service /opt/remotemac/relay.py
sudo systemctl daemon-reload
```

**Mesh node:** stop the process (Ctrl-C). A `--tun` node restores its routes / DNS
/ NAT on exit. Its identity key lives at `~/.config/remotemac/mesh/key` (delete to
forget the node); the coordinator's overlay-IP map lives in its `--state` file /
Docker volume.

---

See the [README](README.md) for architecture, the security model, and full flag
reference.
