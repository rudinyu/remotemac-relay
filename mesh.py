#!/usr/bin/env python3
"""
mesh.py — a node in the remotemac mesh (Tailscale-lite).

Each node has a persistent X25519 identity key. It connects to the coordinator
(`coordinator.py`) over a token-authenticated encrypted control channel, is
assigned a stable overlay IP, and learns the other nodes. Node-to-node traffic
is end-to-end encrypted with a mutually authenticated, forward-secret handshake
(X25519 triple-DH → HKDF-SHA256 → ChaCha20-Poly1305); the coordinator only ever
relays ciphertext.

Phases 1–5: identity + token-authenticated control channel + peer map; an
encrypted data path that is **UDP peer-to-peer** where the network allows (NAT
hole punching, Phase 2) and transparently falls back to a coordinator relay
(DERP); a **TUN overlay** (Phase 3, `--tun`) so real apps reach peers by overlay
IP; **subnet routing** (Phase 4, `--advertise-routes`/`--accept-routes`) to reach
LANs behind a peer; and an opt-in **full-tunnel exit node** (Phase 5, `--exit` /
`--exit-node`, with `--lan-routes` to keep extra local subnets off the tunnel).
Only `--tun` and the routing features need root; everything else runs unprivileged.

Requires: pip install cryptography

Usage
-----
    python3 mesh.py up <coord:port> --token <network-token> [--name NAME] [--exit]
    python3 mesh.py up <coord:port> --token <token> --ping <peer-name-or-ip>
    sudo python3 mesh.py up <coord:port> --token <token> --tun   # VPN data plane
    sudo python3 mesh.py up <coord:port> --token <token> --tun --advertise-routes 192.168.1.0/24
    sudo python3 mesh.py up <coord:port> --token <token> --tun --exit-node <peer>   # full-tunnel
"""
import argparse
import base64
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remote_desktop import SecureChannel, _auth  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("mesh mode requires the 'cryptography' package:\n  pip install cryptography")

__version__ = "1.7.0"

_HS_INFO   = b"remotemac-mesh-v1"
_KEY_PATH  = os.path.expanduser("~/.config/remotemac/mesh/key")

# mesh application message types (first byte of the decrypted payload)
MESH_PING = 0x01
MESH_PONG = 0x02
MESH_IP   = 0x03   # a tunnelled raw IP packet (Phase 3 TUN overlay)
# internal liveness probe over an established direct path (not surfaced to apps)
MESH_KEEPALIVE     = 0x04
MESH_KEEPALIVE_ACK = 0x05

# handshake stages (first byte of an "hs" body — transport-agnostic)
_HS_INIT  = 0x01
_HS_RESP  = 0x02

# UDP data-plane packet types (first byte of a datagram)
_PKT_PUNCH = 0x01   # empty — opens/keeps a NAT mapping
_PKT_HS    = 0x02   # [32B sender_static][hs body]
_PKT_DATA  = 0x03   # [4B receiver_index][Session packet]

# STUN-lite endpoint discovery (distinct 4-byte magics; never collide with the
# 1-byte packet types above, whose first byte is 0x01–0x03).
_STUN_REQ = b"MSTU"   # node → coordinator: [magic][32B static]
_STUN_RES = b"MSTR"   # coordinator → node: [magic]["ip:port" of the observed source]


def _local_ipv4s():
    """Best-effort list of this host's IPv4 addresses (for endpoint candidates)."""
    ips = {"127.0.0.1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # no packets sent; just picks the primary route
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(ips)


def _rand_index() -> int:
    return struct.unpack(">I", os.urandom(4))[0] or 1


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _log(msg: str):
    print(f"[mesh] {msg}", file=sys.stderr, flush=True)

# ─── subnet routing (Phase 4) ────────────────────────────────────────────────────

_OVERLAY_NET = ipaddress.ip_network("100.64.0.0/10")


def parse_cidrs(spec):
    """Parse a comma-separated CIDR list into normalized IPv4 network strings,
    skipping malformed entries (with a warning). Used for --advertise-routes."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            _log(f"ignoring invalid route CIDR: {part!r}")
            continue
        if net.version != 4:
            _log(f"ignoring non-IPv4 route CIDR: {part!r}")
            continue
        out.append(str(net))
    return out


def route_is_safe(cidr, coord_ip, endpoint_ips):
    """Whether a peer's advertised subnet route is safe to accept: IPv4, not
    overlapping the overlay net, and not containing the coordinator IP or any
    peer's UDP endpoint IP — otherwise mesh transport packets would be pulled
    back into the tunnel and loop."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if net.version != 4 or net.overlaps(_OVERLAY_NET):
        return False
    for ip in (coord_ip, *endpoint_ips):
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in net:
                return False
        except ValueError:
            pass
    return True


def build_route_table(peers, coord_ip):
    """Return [(ip_network, pubkey)] for every safe advertised route in the peer
    map, sorted by prefix length descending (longest-prefix match wins)."""
    endpoint_ips = []
    for info in peers.values():
        for ep in info.get("endpoints", []):
            host = ep.rpartition(":")[0]
            if host:
                endpoint_ips.append(host)
    table = []
    for pk, info in peers.items():
        for cidr in info.get("routes", []):
            if route_is_safe(cidr, coord_ip, endpoint_ips):
                table.append((ipaddress.ip_network(cidr, strict=False), pk))
    table.sort(key=lambda t: t[0].prefixlen, reverse=True)
    return table


def match_route(table, dst_ip):
    """Longest-prefix-match a destination IP against a route table → pubkey/None."""
    try:
        addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return None
    for net, pk in table:
        if addr in net:
            return pk
    return None

# ─── identity ──────────────────────────────────────────────────────────────────

def load_or_create_identity(path: str = None) -> X25519PrivateKey:
    """Load the node's static X25519 key, generating and persisting it if absent.

    Path resolves to the argument, else $REMOTEMAC_MESH_KEY, else the default.
    The env override lets several nodes run on one machine (distinct identities).
    """
    if path is None:
        path = os.environ.get("REMOTEMAC_MESH_KEY", _KEY_PATH)
    try:
        with open(path, "rb") as f:
            return X25519PrivateKey.from_private_bytes(f.read())
    except FileNotFoundError:
        key = X25519PrivateKey.generate()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        raw = key.private_bytes_raw()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        return key


def pub_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()

# ─── handshake + session crypto ────────────────────────────────────────────────

def _derive(static: X25519PrivateKey, my_static_pub: bytes, peer_static_pub: bytes,
            eph: X25519PrivateKey, my_eph_pub: bytes, peer_eph_pub: bytes,
            *, initiator: bool):
    """Triple-DH → two directional keys. Both peers derive the same pair.

    ee = DH(eph_i, eph_r), se = DH(static_i, eph_r), es = DH(eph_i, static_r).
    Only holders of the respective static keys can compute se/es, so agreeing on
    the keys mutually authenticates both static identities.
    """
    peer_eph = X25519PublicKey.from_public_bytes(peer_eph_pub)
    peer_stat = X25519PublicKey.from_public_bytes(peer_static_pub)
    if initiator:
        ee = eph.exchange(peer_eph)
        se = static.exchange(peer_eph)
        es = eph.exchange(peer_stat)
        i_static_pub, r_static_pub = my_static_pub, peer_static_pub
        i_eph_pub, r_eph_pub = my_eph_pub, peer_eph_pub
    else:
        ee = eph.exchange(peer_eph)
        se = eph.exchange(peer_stat)          # DH(static_i, eph_r) from R's view
        es = static.exchange(peer_eph)        # DH(eph_i, static_r) from R's view
        i_static_pub, r_static_pub = peer_static_pub, my_static_pub
        i_eph_pub, r_eph_pub = peer_eph_pub, my_eph_pub

    transcript = i_static_pub + r_static_pub + i_eph_pub + r_eph_pub
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
                    info=_HS_INFO + transcript).derive(ee + se + es)
    k_i2r, k_r2i = material[:32], material[32:]
    if initiator:
        return k_i2r, k_r2i   # (tx, rx)
    return k_r2i, k_i2r


class Session:
    """Directional AEAD channel. Packet = 8-byte counter ‖ ChaCha20-Poly1305 ct."""

    _WINDOW = 1024   # sliding replay window (UDP delivery is unordered/lossy)
    _MASK   = (1 << 1024) - 1

    def __init__(self, tx_key: bytes, rx_key: bytes):
        self._tx = ChaCha20Poly1305(tx_key)
        self._rx = ChaCha20Poly1305(rx_key)
        self._tx_ctr = 0
        self._rx_max = -1
        self._rx_bits = 0        # bitmask of seen counters at/below _rx_max
        self._lock = threading.Lock()

    @staticmethod
    def _nonce(ctr: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack(">Q", ctr)

    def encrypt(self, plaintext: bytes) -> bytes:
        with self._lock:
            ctr = self._tx_ctr
            self._tx_ctr += 1
        return struct.pack(">Q", ctr) + self._tx.encrypt(self._nonce(ctr), plaintext, None)

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 8:
            raise ValueError("short mesh packet")
        ctr = struct.unpack(">Q", packet[:8])[0]
        # AEAD-verify first (only authentic packets touch replay state).
        pt = self._rx.decrypt(self._nonce(ctr), packet[8:], None)
        with self._lock:
            if ctr > self._rx_max:
                shift = ctr - self._rx_max
                self._rx_bits = ((self._rx_bits << shift) | 1) & self._MASK
                self._rx_max = ctr
            else:
                offset = self._rx_max - ctr
                if offset >= self._WINDOW:
                    raise ValueError("stale packet outside replay window")
                bit = 1 << offset
                if self._rx_bits & bit:
                    raise ValueError("replayed mesh packet")
                self._rx_bits |= bit
        return pt

# ─── per-peer connection ────────────────────────────────────────────────────────

class PeerConn:
    """State for talking to one peer: the AEAD session, the demux indices, and the
    chosen transport (direct UDP endpoint, or DERP relay via the coordinator)."""

    def __init__(self, peer_pk: str, peer_static: bytes):
        self.peer_pk      = peer_pk        # base64 static pubkey
        self.peer_static  = peer_static    # raw 32B
        self.session      = None
        self.local_index  = _rand_index()  # peers stamp this on UDP DATA sent to me
        self.remote_index = 0              # I stamp this on UDP DATA sent to the peer
        self.endpoint     = None           # chosen direct (ip, port)
        self.transport    = "connecting"   # connecting | direct | derp
        self.eph          = None           # my ephemeral while initiating
        self.resp_eph_pub = None           # my ephemeral pub as responder (resend on upgrade)
        self.initiated    = False
        self.queued       = []             # payloads awaiting a session
        self.last_rx      = time.monotonic()  # last authenticated packet from peer
        self.last_ka      = 0.0            # last keepalive we sent (monotonic)
        self.last_retry   = 0.0           # last direct re-punch attempt (monotonic)
        self.lock         = threading.Lock()

    def bind_transport(self, via, addr):
        if via == "udp" and addr is not None:
            self.transport = "direct"
            self.endpoint  = addr
        else:
            self.transport = "derp"

    def flush(self):
        q, self.queued = self.queued, []
        return q


# ─── node ──────────────────────────────────────────────────────────────────────

class MeshNode:
    def __init__(self, identity: X25519PrivateKey, hostname: str, is_exit: bool = False,
                 bind_host: str = "0.0.0.0", udp_port: int = 0, advertise_routes=None):
        self._id      = identity
        self._pub     = pub_bytes(identity)
        self.pubkey_b64 = _b64(self._pub)
        self.hostname = hostname
        self.is_exit  = is_exit
        self._bind_host = bind_host
        self._udp_port  = udp_port
        self.advertise_routes = list(advertise_routes or [])   # CIDRs I route to
        self.accept_routes = False        # opt in to peers' advertised subnet routes
        self._route_table = []            # [(ip_network, pubkey)], longest-prefix first
        self.exit_node_name = None        # peer name/IP to full-tunnel through (CLI)
        self.exit_node_pk = None          # resolved once the peer is in the map
        self.lan_routes = []              # extra local subnets to keep off the tunnel
        self.ch       = None
        self.udp      = None
        self._coord_udp = None       # (host, port) for STUN probes
        self._stun_done = threading.Event()
        self.local_endpoints = []
        self.overlay_ip = None
        self.peers    = {}         # pubkey_b64 -> {ip, hostname, exit, endpoints}
        self._conns   = {}         # pubkey_b64 -> PeerConn
        self._by_index = {}        # local_index (int) -> PeerConn  (UDP DATA demux)
        self._lock     = threading.Lock()
        self._send_lock = threading.Lock()   # serialize control-channel writes
        self._done     = threading.Event()
        # keepalive / direct-path liveness (seconds; tests override for speed)
        self._ka_tick          = 1.0     # how often the keepalive loop wakes
        self.keepalive_interval = 15.0   # send a keepalive on an idle direct path
        self.direct_timeout     = 45.0   # silence before a direct path is failed
        self.direct_retry_interval = 30.0  # re-punch cadence for a relayed path
        self.on_message = None     # optional callback(peer_pk_b64, msg_type, body)
        self.on_ip_packet = None   # optional callback(peer_pk_b64, raw_ip_packet) for MESH_IP
        self.on_routes_changed = None  # optional callback(added_cidrs, removed_cidrs)
        self.on_transport_ips_changed = None  # optional callback(set_of_transport_ips)

    # -- control channel --------------------------------------------------------

    def connect(self, coord_addr: str, token: bytes):
        host, _, port = coord_addr.rpartition(":")
        sock = socket.create_connection((host, int(port)), timeout=15)
        sock.settimeout(30)
        self.ch = _auth(sock, token, is_host=False)
        sock.settimeout(None)
        # Resolve to an IP so we can match the STUN reply's source address.
        try:
            coord_ip = socket.gethostbyname(host)
        except Exception:
            coord_ip = host
        self._coord_udp = (coord_ip, int(port))
        self._start_udp()
        self._send({"t": "register", "pubkey": self.pubkey_b64,
                    "hostname": self.hostname, "exit": self.is_exit,
                    "endpoints": self.local_endpoints,
                    "routes": self.advertise_routes})
        # Discover our public (post-NAT) endpoint via the coordinator's STUN
        # responder, then re-advertise it so peers can hole-punch to us.
        threading.Thread(target=self._discover_endpoint, daemon=True).start()
        # Keep NAT mappings warm on direct paths and fail silent ones over to DERP.
        threading.Thread(target=self._keepalive_loop, daemon=True).start()

    def _discover_endpoint(self):
        if not self._coord_udp:
            return
        probe = _STUN_REQ + self._pub
        for _ in range(6):
            if self._stun_done.is_set() or self._done.is_set():
                return
            try:
                self.udp.sendto(probe, self._coord_udp)
            except Exception:
                pass
            self._stun_done.wait(0.5)

    def _add_endpoint(self, ep: str):
        with self._lock:
            if ep in self.local_endpoints:
                return
            self.local_endpoints.append(ep)
            eps = list(self.local_endpoints)
        try:
            self._send({"t": "endpoints", "endpoints": eps})
        except Exception:
            pass

    def _start_udp(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((self._bind_host, self._udp_port))
        port = self.udp.getsockname()[1]
        self.local_endpoints = [f"{ip}:{port}" for ip in _local_ipv4s()]
        threading.Thread(target=self._udp_recv_loop, daemon=True).start()

    def _udp_recv_loop(self):
        while not self._done.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except Exception:
                if self._done.is_set():
                    return
                continue
            try:
                self._on_udp(data, addr)
            except Exception as exc:
                _log(f"udp error: {exc}")

    def _send(self, obj: dict):
        # Several worker threads relay through the coordinator concurrently;
        # serialize so SecureChannel frames don't interleave.
        with self._send_lock:
            self.ch.send(json.dumps(obj, separators=(",", ":")).encode())

    def run(self):
        """Read control messages until the channel closes (blocking)."""
        try:
            while not self._done.is_set():
                msg = json.loads(self.ch.recv().decode())
                # A malformed message from a peer (relayed via the coordinator)
                # must not tear down the whole control channel.
                try:
                    self._dispatch(msg)
                except Exception as exc:
                    _log(f"dispatch error: {exc}")
        except Exception as exc:
            if not self._done.is_set():
                _log(f"control channel closed: {exc}")
        finally:
            self._done.set()

    def close(self):
        self._done.set()
        if self.ch:
            self.ch.close()
        if self.udp:
            try:
                self.udp.close()
            except Exception:
                pass

    def _dispatch(self, msg: dict):
        t = msg.get("t")
        if t == "map":
            self._on_map(msg)
        elif t == "from":
            self._on_from(msg)

    def _on_map(self, msg: dict):
        self.overlay_ip = (msg.get("self") or {}).get("ip") or self.overlay_ip
        peers = {}
        for p in msg.get("peers", []):
            peers[p["pubkey"]] = {"ip": p.get("ip"), "hostname": p.get("hostname"),
                                  "exit": p.get("exit", False),
                                  "endpoints": p.get("endpoints", []),
                                  "routes": p.get("routes", [])}
        with self._lock:
            self.peers = peers
        if self.accept_routes:
            self._refresh_routes()
        if self.exit_node_name:
            self._resolve_exit_node()
        if self.on_transport_ips_changed:
            self.on_transport_ips_changed(self.transport_ips())

    def _resolve_exit_node(self):
        """(Re)validate --exit-node NAME against the current map: set exit_node_pk
        when the named peer is present AND advertises as an exit, and clear it if
        the peer disappears or stops advertising (full-tunnel routing then pauses
        rather than sending to a peer that can't forward)."""
        pk = self.resolve(self.exit_node_name)
        if not pk or not (self.peers.get(pk) or {}).get("exit"):
            if self.exit_node_pk is not None:
                _log(f"exit node '{self.exit_node_name}' is gone or no longer advertising as "
                     f"an exit — full-tunnel routing paused")
            self.exit_node_pk = None
            return
        if self.exit_node_pk != pk:
            self.exit_node_pk = pk
            _log(f"full-tunnel: routing all traffic through exit '{self.exit_node_name}' ({pk[:16]}…)")

    def transport_ips(self):
        """IPs that must keep bypassing the tunnel (coordinator + every peer's UDP
        endpoints + a live direct exit endpoint), so full-tunnel doesn't loop the
        mesh's own transport back into itself."""
        ips = set()
        if self._coord_udp:
            ips.add(self._coord_udp[0])
        with self._lock:
            peers = dict(self.peers)
            exit_pc = self._conns.get(self.exit_node_pk) if self.exit_node_pk else None
        for info in peers.values():
            for ep in info.get("endpoints", []):
                host = ep.rpartition(":")[0]
                if host:
                    ips.add(host)
        if exit_pc and exit_pc.transport == "direct" and exit_pc.endpoint:
            ips.add(exit_pc.endpoint[0])
        return ips

    def _refresh_routes(self):
        """Rebuild the accepted subnet-route table from the peer map and notify
        the TUN layer of any CIDRs to add/remove from the OS routing table.

        The safety guard uses a snapshot: `coord_ip` was resolved once at connect
        time, and endpoint IPs are whatever the map currently holds — so an
        endpoint not yet learned isn't checked until the next map update reruns
        this. Not live-tracked; don't assume otherwise. The new table is built
        then swapped in atomically (single writer), so data-plane readers in
        route_for/src_permitted always see a whole, consistent list without a lock."""
        coord_ip = self._coord_udp[0] if self._coord_udp else None
        old = {str(net) for net, _ in self._route_table}
        self._route_table = build_route_table(self.peers, coord_ip)
        new = {str(net) for net, _ in self._route_table}
        if self.on_routes_changed and old != new:
            self.on_routes_changed(new - old, old - new)

    # -- peer lookup ------------------------------------------------------------

    def resolve(self, name_or_ip: str):
        """Return a peer pubkey_b64 by hostname or overlay IP, or None."""
        with self._lock:
            for pk, info in self.peers.items():
                if info.get("hostname") == name_or_ip or info.get("ip") == name_or_ip:
                    return pk
        return None

    def route_for(self, dst_ip: str):
        """Peer that should carry a packet to dst_ip: an overlay peer (matches a
        node's own overlay IP), else a subnet router advertising a matching route,
        else — if a full-tunnel exit node is selected — the exit (catch-all for
        the whole internet). None if unroutable."""
        pk = self.resolve(dst_ip)
        if pk:
            return pk
        pk = match_route(self._route_table, dst_ip)
        if pk:
            return pk
        return self.exit_node_pk        # None unless --exit-node is in effect

    def src_permitted(self, src_pk: str, src_ip: str) -> bool:
        """Anti-spoof for an inbound tunnelled packet: a peer may source its own
        overlay IP, or — if it is a subnet router whose route we accepted — any
        IP within one of those accepted routes (so LAN-sourced replies pass). Our
        selected exit node may source anything (it relays the whole internet).
        A non-IPv4/unparseable source isn't blocked here (handled elsewhere)."""
        if src_ip is None:
            return True
        if src_pk == self.exit_node_pk:
            return True
        info = self.peers.get(src_pk) or {}
        if src_ip == info.get("ip"):
            return True
        try:
            addr = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        for net, pk in self._route_table:
            if pk == src_pk and addr in net:
                return True
        return False

    def _peer_static(self, pk_b64: str) -> bytes:
        return _unb64(pk_b64)

    # -- peer connections -------------------------------------------------------

    def _get_conn(self, peer_pk: str):
        with self._lock:
            pc = self._conns.get(peer_pk)
            if pc is None:
                pc = PeerConn(peer_pk, self._peer_static(peer_pk))
                self._conns[peer_pk] = pc
                self._by_index[pc.local_index] = pc
            return pc

    def _peer_endpoints(self, peer_pk: str):
        with self._lock:
            info = self.peers.get(peer_pk)
        eps = []
        for s in (info or {}).get("endpoints", []):
            host, _, port = s.rpartition(":")
            try:
                eps.append((host, int(port)))
            except ValueError:
                pass
        return eps

    def _hs_body(self, stage: int, eph_pub: bytes, index: int) -> bytes:
        # transport-agnostic: [1B stage][32B ephemeral][4B sender index]
        return bytes([stage]) + eph_pub + struct.pack(">I", index)

    def _relay_to(self, dst_pk: str, kind: str, body: bytes):
        self._send({"t": "to", "dst": dst_pk, "kind": kind, "body": _b64(body)})

    # -- inbound: DERP relay (over the control channel) -------------------------

    def _on_from(self, msg: dict):
        src = msg.get("src")
        kind = msg.get("kind")
        body = _unb64(msg.get("body", "") or "")
        if not src or src not in self.peers:
            return
        if kind == "connect":
            # Peer wants a path to us: start punching (opens our NAT) and, if we
            # are the designated initiator, drive the handshake.
            self._ensure_connecting(self._get_conn(src))
        elif kind == "hs" and len(body) >= 37:
            stage, eph, index = body[0], body[1:33], struct.unpack(">I", body[33:37])[0]
            self._handle_hs(src, self._peer_static(src), stage, eph, index, "derp", None)
        elif kind == "data" and body:
            pc = self._conns.get(src)
            if pc and pc.session:
                self._recv_data(pc, body)

    # -- inbound: UDP data plane ------------------------------------------------

    def _on_udp(self, data: bytes, addr):
        if not data:
            return
        if data[:4] == _STUN_RES:
            # Only trust a STUN reply that actually came from the coordinator —
            # otherwise anyone could inject a bogus endpoint into the mesh.
            if addr != self._coord_udp:
                return
            observed = data[4:].decode("ascii", "ignore").strip()
            if observed:
                self._stun_done.set()
                self._add_endpoint(observed)
            return
        t = data[0]
        if t == _PKT_PUNCH:
            return
        if t == _PKT_HS and len(data) >= 33 + 37:
            static = data[1:33]
            peer_pk = _b64(static)
            if peer_pk not in self.peers:
                return
            body = data[33:]
            stage, eph, index = body[0], body[1:33], struct.unpack(">I", body[33:37])[0]
            self._handle_hs(peer_pk, static, stage, eph, index, "udp", addr)
        elif t == _PKT_DATA and len(data) >= 5:
            index = struct.unpack(">I", data[1:5])[0]
            pc = self._by_index.get(index)
            if pc and pc.session:
                self._recv_data(pc, data[5:])

    # -- handshake state machine (shared by both transports) --------------------

    def _handle_hs(self, peer_pk, peer_static, stage, peer_eph, peer_index, via, addr):
        pc = self._get_conn(peer_pk)
        if stage == _HS_INIT:
            with pc.lock:
                if pc.session is None:
                    eph = X25519PrivateKey.generate()
                    tx, rx = _derive(self._id, self._pub, peer_static,
                                     eph, pub_bytes(eph), peer_eph, initiator=False)
                    pc.session = Session(tx, rx)
                    pc.remote_index = peer_index
                    pc.resp_eph_pub = pub_bytes(eph)
                    pc.bind_transport(via, addr)
                    queued = pc.flush()
                else:
                    # Session already up (likely over DERP). A retransmitted INIT
                    # arriving over UDP proves a working direct path — upgrade.
                    self._upgrade_if_udp(pc, via, addr)
                    queued = []
                resp_eph_pub = pc.resp_eph_pub
            # Answer with the real responder ephemeral so the peer can (re)derive
            # or re-confirm the path. If we never acted as responder for this peer
            # (resp_eph_pub is None — e.g. an unexpected INIT toward the initiator),
            # drop it rather than fabricate a meaningless key.
            if resp_eph_pub is not None:
                self._send_hs(pc, self._hs_body(_HS_RESP, resp_eph_pub, pc.local_index), via, addr)
            for payload in queued:
                self._transmit(pc, payload)
        elif stage == _HS_RESP:
            with pc.lock:
                if pc.session is None:
                    if pc.eph is None:
                        return
                    tx, rx = _derive(self._id, self._pub, peer_static,
                                     pc.eph, pub_bytes(pc.eph), peer_eph, initiator=True)
                    pc.session = Session(tx, rx)
                    pc.remote_index = peer_index
                    pc.bind_transport(via, addr)
                    queued = pc.flush()
                else:
                    self._upgrade_if_udp(pc, via, addr)
                    queued = []
            for payload in queued:
                self._transmit(pc, payload)
        # If the exit peer's transport just changed (e.g. a newly punched direct
        # endpoint), re-pin transport promptly instead of waiting for the resync.
        if self.on_transport_ips_changed and peer_pk == self.exit_node_pk:
            self.on_transport_ips_changed(self.transport_ips())

    @staticmethod
    def _upgrade_if_udp(pc, via, addr):
        """Confirm a working direct endpoint for an already-established session,
        transparently switching a DERP-relayed path over to UDP. Caller holds pc.lock."""
        if via == "udp" and addr is not None:
            pc.endpoint = addr
            pc.transport = "direct"
            pc.last_rx = time.monotonic()   # fresh direct path — don't instantly re-fail

    def _recv_data(self, pc, body):
        try:
            pt = pc.session.decrypt(body)
        except Exception as exc:
            _log(f"data decrypt from {pc.peer_pk[:12]}…: {exc}")
            return
        pc.last_rx = time.monotonic()   # authenticated traffic ⇒ path is alive
        if not pt:
            return
        mtype, payload = pt[0], pt[1:]
        if mtype == MESH_KEEPALIVE:
            self.send(pc.peer_pk, MESH_KEEPALIVE_ACK, b"")
            return
        if mtype == MESH_KEEPALIVE_ACK:
            return   # internal liveness only — not surfaced to the app
        if mtype == MESH_IP:
            # A tunnelled IP packet (Phase 3): hand it straight to the TUN pump,
            # not to the generic on_message path.
            if self.on_ip_packet:
                self.on_ip_packet(pc.peer_pk, payload)
            return
        if mtype == MESH_PING:
            self.send(pc.peer_pk, MESH_PONG, payload)
        if self.on_message:
            self.on_message(pc.peer_pk, mtype, payload)

    # -- outbound ---------------------------------------------------------------

    def _send_hs(self, pc, body, via, addr):
        if via == "udp" and addr is not None:
            self.udp.sendto(bytes([_PKT_HS]) + self._pub + body, addr)
        else:
            self._relay_to(pc.peer_pk, "hs", body)

    def _transmit(self, pc, data: bytes):
        packet = pc.session.encrypt(data)
        if pc.transport == "direct" and pc.endpoint:
            try:
                self.udp.sendto(bytes([_PKT_DATA]) + struct.pack(">I", pc.remote_index) + packet,
                                pc.endpoint)
            except Exception:
                pass
        else:
            self._relay_to(pc.peer_pk, "data", packet)

    def send(self, dst_pk: str, mtype: int, payload: bytes = b""):
        """Send an encrypted mesh message to a peer, handshaking if needed."""
        data = bytes([mtype]) + payload
        pc = self._get_conn(dst_pk)
        with pc.lock:
            ready = pc.session is not None
            if not ready and len(pc.queued) < 32:
                pc.queued.append(data)
        if ready:
            self._transmit(pc, data)
        else:
            self._ensure_connecting(pc)

    def _am_initiator(self, peer_static: bytes) -> bool:
        """Deterministic role tie-break: the smaller static pubkey initiates. Both
        peers agree, so glare (simultaneous initiation) can't produce two sessions."""
        return self._pub < peer_static

    def _ensure_connecting(self, pc):
        """Start (once) the connect worker that punches and drives the handshake."""
        with pc.lock:
            if pc.initiated:
                return
            pc.initiated = True
        threading.Thread(target=self._connect_worker, args=(pc,), daemon=True).start()

    def _connect_worker(self, pc):
        """Establish a path to the peer: nudge it to punch back, spray PUNCH + (if
        we are the designated initiator) HS at every candidate endpoint, and fall
        back to a DERP-relayed handshake if no direct path forms in time."""
        am_init = self._am_initiator(pc.peer_static)
        # Nudge the peer to start punching toward us (opens their NAT mapping).
        try:
            self._relay_to(pc.peer_pk, "connect", b"")
        except Exception:
            pass
        init_body = None
        if am_init:
            with pc.lock:
                if pc.eph is None:
                    pc.eph = X25519PrivateKey.generate()
                init_body = self._hs_body(_HS_INIT, pub_bytes(pc.eph), pc.local_index)

        start = time.monotonic()
        derp_sent = False
        while not self._done.is_set():
            elapsed = time.monotonic() - start
            if pc.transport == "direct":
                return                          # direct path locked in — done
            eps = self._peer_endpoints(pc.peer_pk)
            for ep in eps:
                try:
                    self.udp.sendto(bytes([_PKT_PUNCH]), ep)   # keep NAT mapping open
                except Exception:
                    pass
                if am_init:
                    try:
                        self.udp.sendto(bytes([_PKT_HS]) + self._pub + init_body, ep)
                    except Exception:
                        pass
            # DERP fallback: if direct is impossible (no endpoints) or just slow
            # (>3s), establish a relayed session so queued data isn't stuck.
            if (am_init and not derp_sent and pc.session is None
                    and (not eps or elapsed >= 3.0)):
                self._relay_to(pc.peer_pk, "hs", init_body)
                derp_sent = True
            if elapsed >= 6.0:
                break
            self._done.wait(0.25)

        # Gave up on establishing/restoring a direct path. Re-arm so a later
        # _ensure_connecting() (fresh send, or a keepalive-loop retry) can try
        # again. This must NOT be gated on session state: after a failover the
        # session is deliberately reused (non-None), yet the direct path still
        # needs to be retryable. Only a brand-new handshake needs a fresh
        # ephemeral, so clear eph only when there is no session.
        if pc.transport != "direct":
            with pc.lock:
                pc.initiated = False
                if pc.session is None:
                    pc.eph = None

    def _keepalive_loop(self):
        """Keep established direct paths warm, and fail silent ones over to DERP.

        On a direct path we send a keepalive when it goes idle (holds the NAT
        mapping open and probes liveness). If nothing authenticated arrives for
        `direct_timeout`, the path is presumed dead: we drop back to the DERP
        relay (reusing the same session) and re-arm hole punching to try direct
        again."""
        while not self._done.wait(self._ka_tick):
            now = time.monotonic()
            with self._lock:
                conns = list(self._conns.values())
            for pc in conns:
                if pc.session is None:
                    continue
                if pc.transport == "direct":
                    if now - pc.last_rx > self.direct_timeout:
                        _log(f"direct path to {pc.peer_pk[:12]}… went silent — failing over to DERP")
                        with pc.lock:
                            pc.transport = "derp"
                            pc.initiated = False
                            pc.eph = None
                        pc.last_retry = now
                        self._ensure_connecting(pc)   # immediately try to restore direct
                    elif now - pc.last_ka >= self.keepalive_interval:
                        pc.last_ka = now
                        self.send(pc.peer_pk, MESH_KEEPALIVE, b"")
                elif pc.transport == "derp":
                    # Periodically re-attempt hole punching so a relayed path can
                    # upgrade to direct once connectivity allows (NAT reopens, etc).
                    if now - pc.last_retry >= self.direct_retry_interval:
                        pc.last_retry = now
                        self._ensure_connecting(pc)

# ─── CLI ────────────────────────────────────────────────────────────────────────

def _run_tun(node, mtu, name, egress=None):
    """Bring up a TUN overlay interface and pump packets between it and the mesh.

    Blocks until the node is torn down (Ctrl-C). Needs root — it creates a
    virtual interface and installs the overlay route. The root check is done
    earlier (in _cmd_up), before we ever touch the network."""
    import tun

    # Wait a little longer for the coordinator to assign our overlay IP.
    for _ in range(50):
        if node.overlay_ip or node._done.is_set():
            break
        time.sleep(0.1)
    if not node.overlay_ip:
        sys.exit("error: no overlay IP assigned yet — cannot bring up the TUN interface")

    try:
        dev = tun.TunDevice(name=name, mtu=mtu).open()
    except (tun.TunError, OSError) as exc:
        sys.exit(f"error: could not open TUN: {exc}")
    try:
        dev.configure(node.overlay_ip)
    except (OSError, subprocess.CalledProcessError) as exc:
        dev.close()                            # don't leak the interface/socket
        sys.exit(f"error: could not configure TUN {dev.name}: {exc}")
    _log(f"TUN up: {dev.name}  ip={node.overlay_ip}  mtu={mtu}  (overlay {tun.OVERLAY_CIDR})")

    # Subnet router OR exit node: enable IP forwarding + NAT masquerade so
    # forwarded traffic egresses. The masquerade rule (overlay saddr → egress) is
    # the same for both; an exit node just forwards to any destination, not only
    # advertised subnets.
    snat = None
    if node.advertise_routes or node.is_exit:
        role = "exit node" if node.is_exit else "subnet router"
        if sys.platform.startswith("linux"):
            import nat
            try:
                snat = nat.SubnetNat(tun.OVERLAY_CIDR, egress).apply()
            except nat.NatError as exc:
                dev.close()
                sys.exit(f"error: {role} NAT setup failed: {exc}")
            extra = (f" for routes {','.join(node.advertise_routes)}"
                     if node.advertise_routes else " (full-tunnel)")
            _log(f"{role}: masquerading {tun.OVERLAY_CIDR} out {snat.egress}{extra}")
        else:
            _log(f"note: running as {role}, but NAT egress is Linux-only — "
                 f"traffic won't be forwarded on {sys.platform}")

    _last_warn = [0.0]
    def _warn(msg):
        now = time.monotonic()
        if now - _last_warn[0] > 5.0:          # rate-limit so a loop can't spam
            _last_warn[0] = now
            _log(msg)

    def _to_tun(src_pk, pkt):
        # Anti-spoof: a peer may only inject packets whose IPv4 source is its own
        # overlay IP, or (for an accepted subnet router) an IP within a route we
        # accepted from it. Stops a peer forging traffic as another identity.
        src = tun.parse_ipv4_src(pkt)
        if not node.src_permitted(src_pk, src):
            _warn(f"drop spoofed packet: src {src} not permitted for {src_pk[:12]}…")
            return
        try:
            dev.write(pkt)
        except OSError:
            pass
    node.on_ip_packet = _to_tun

    # Client subnet routes: install/remove OS routes for accepted CIDRs as the
    # peer map changes, and sync whatever is already accepted right now.
    if node.accept_routes:
        def _sync_routes(added, removed):
            for cidr in added:
                dev.add_route(cidr)
                _log(f"route + {cidr} via mesh")
            for cidr in removed:
                dev.del_route(cidr)
                _log(f"route - {cidr}")
        node.on_routes_changed = _sync_routes
        for net, _pk in list(node._route_table):
            dev.add_route(str(net))
            _log(f"route + {net} via mesh")

    def _from_tun():
        while not node._done.is_set():
            pkt = dev.read()                   # bounded wait; b"" on timeout
            if not pkt:
                continue
            dst = tun.parse_ipv4_dst(pkt)
            if not dst:
                continue                       # non-IPv4 / truncated → drop
            pk = node.route_for(dst)           # overlay peer, or accepted subnet router
            if pk:
                node.send(pk, MESH_IP, pkt)
            else:
                _warn(f"drop packet to {dst}: no mesh peer or accepted route for it")
    reader = threading.Thread(target=_from_tun, daemon=True)
    reader.start()

    # Everything below runs under try/finally so any early exit (including the
    # full-tunnel setup errors) still tears down NAT / routes / the device.
    ftr = None
    try:
        # Full-tunnel: pin mesh transport to the physical gateway, then redirect
        # the default route through the exit. Opt-in (only with --exit-node).
        if node.exit_node_name:
            import netroute
            gw, iface = netroute.default_route()
            if not gw or not iface:
                sys.exit("error: could not detect the physical default route for full-tunnel")
            ftr = netroute.FullTunnelRoutes(dev.name, gw, iface)
            # Wait for the exit peer to resolve before redirecting, so we never
            # blackhole traffic to an exit that isn't routable yet.
            for _ in range(100):
                if node.exit_node_pk or node._done.is_set():
                    break
                time.sleep(0.1)
            if not node.exit_node_pk:
                sys.exit(f"error: exit node '{node.exit_node_name}' not found or not advertising as an exit")
            # Pin transport, THEN wire the callback (so the first pin can't race
            # a map-driven callback), THEN redirect the default route.
            ftr.sync_pins(node.transport_ips())
            node.on_transport_ips_changed = ftr.sync_pins   # re-pin as endpoints change
            if node.lan_routes:                        # keep extra local subnets off the tunnel
                ftr.install_lan_routes(node.lan_routes)
            ftr.install_split_default()                # default → TUN → exit
            _log(f"full-tunnel: default route → exit '{node.exit_node_name}' via {dev.name} "
                 f"(transport pinned to {gw} dev {iface})")

            def _resync():                             # backstop for endpoints punched between maps
                while not node._done.wait(2.0):
                    ftr.sync_pins(node.transport_ips())
            threading.Thread(target=_resync, daemon=True).start()

        _log("running — Ctrl-C to leave the mesh")
        while not node._done.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        node.on_transport_ips_changed = None       # stop re-pinning during teardown
        node.close()                               # sets _done → reader unblocks
        reader.join(timeout=2)                     # let it exit before we close the fd
        if ftr:
            ftr.teardown()                         # restore default route + unpin transport
        if snat:
            snat.cleanup()
        dev.close()
        _log("TUN down")


def _cmd_up(args):
    advertise = parse_cidrs(getattr(args, "advertise_routes", None))
    accept = getattr(args, "accept_routes", False)
    exit_node = getattr(args, "exit_node", None)
    lan_routes = parse_cidrs(getattr(args, "lan_routes", None))
    if exit_node and advertise:
        sys.exit("error: --exit-node and --advertise-routes are mutually exclusive")
    if lan_routes and not exit_node:
        sys.exit("error: --lan-routes only applies with --exit-node (full-tunnel)")
    if getattr(args, "tun", False):
        if args.ping:
            sys.exit("error: --tun and --ping are mutually exclusive")
        # Fail fast, before any token prompt / coordinator join, if not root.
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            sys.exit("error: --tun needs root (creates a virtual interface + routes). Re-run with sudo.")
    elif advertise or accept or exit_node:
        sys.exit("error: --advertise-routes / --accept-routes / --exit-node require --tun")

    token = args.token or os.environ.get("REMOTEMAC_MESH_TOKEN")
    if not token:
        import getpass
        token = getpass.getpass("Network token: ")

    identity = load_or_create_identity()
    name = args.name or socket.gethostname()
    node = MeshNode(identity, name, is_exit=args.exit,
                    bind_host=args.bind, udp_port=args.udp_port,
                    advertise_routes=advertise)
    node.accept_routes = accept
    node.exit_node_name = exit_node
    node.lan_routes = lan_routes

    pong_event = threading.Event()
    pong_at = {}

    def on_msg(src, mtype, payload):
        if mtype == MESH_PONG:
            pong_at["t"] = time.monotonic()
            pong_event.set()
    node.on_message = on_msg

    try:
        node.connect(args.coord_addr, token.encode())
    except (ConnectionError, PermissionError, OSError) as exc:
        sys.exit(f"error: cannot join mesh: {exc}")

    threading.Thread(target=node.run, daemon=True).start()
    time.sleep(1.0)   # let the first map arrive

    _log(f"joined as {name}  overlay_ip={node.overlay_ip}  pubkey={node.pubkey_b64[:16]}…")
    with node._lock:
        peers = list(node.peers.items())
    if peers:
        _log("peers:")
        for pk, info in peers:
            tag = " (exit)" if info.get("exit") else ""
            _log(f"  {info.get('ip'):<15} {info.get('hostname')}{tag}  {pk[:16]}…")
    else:
        _log("peers: (none yet)")

    if args.ping:
        dst = node.resolve(args.ping)
        if not dst:
            _log(f"ping: no peer named/addressed '{args.ping}'")
        else:
            t0 = time.monotonic()
            node.send(dst, MESH_PING, b"hello")
            if pong_event.wait(10):
                pc = node._conns.get(dst)
                path = pc.transport if pc else "?"
                where = f"direct {pc.endpoint[0]}:{pc.endpoint[1]}" if pc and pc.transport == "direct" else "via coordinator (DERP)"
                _log(f"ping {args.ping}: pong in {(pong_at['t'] - t0) * 1000:.1f} ms  [{path}: {where}]")
            else:
                _log(f"ping {args.ping}: timeout")
        node.close()
        return

    if getattr(args, "tun", False):
        _run_tun(node, args.tun_mtu, args.tun_name, egress=getattr(args, "egress", None))
        return

    _log("running — Ctrl-C to leave the mesh")
    try:
        while not node._done.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        node.close()


def main():
    p = argparse.ArgumentParser(prog="mesh.py", description="A node in the remotemac mesh.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="join the mesh")
    up.add_argument("coord_addr", metavar="coord:port")
    up.add_argument("--token", help="network join token (or set REMOTEMAC_MESH_TOKEN)")
    up.add_argument("--name", help="hostname to advertise (default: system hostname)")
    up.add_argument("--exit", action="store_true",
                    help="advertise as a full-tunnel exit node (with --tun on Linux: IP forwarding + NAT)")
    up.add_argument("--bind", default="0.0.0.0", help="UDP data-plane bind address (default 0.0.0.0)")
    up.add_argument("--udp-port", type=int, default=0, help="UDP data-plane port (default: random)")
    up.add_argument("--ping", metavar="PEER", help="ping a peer (name or overlay IP) then exit")
    up.add_argument("--tun", action="store_true",
                    help="bring up a TUN overlay interface so real apps reach peers by overlay IP (needs root)")
    up.add_argument("--tun-mtu", type=int, default=1280, help="TUN interface MTU (default 1280)")
    up.add_argument("--tun-name", default="remotemac0",
                    help="TUN interface name on Linux (default remotemac0; ignored on macOS)")
    up.add_argument("--advertise-routes", metavar="CIDR[,CIDR…]",
                    help="act as a subnet router for these CIDRs (needs --tun; NAT egress on Linux)")
    up.add_argument("--accept-routes", action="store_true",
                    help="route peers' advertised subnet CIDRs through the mesh (needs --tun)")
    up.add_argument("--exit-node", metavar="PEER",
                    help="full-tunnel: route ALL traffic through this exit peer (name or overlay IP; needs --tun)")
    up.add_argument("--lan-routes", metavar="CIDR[,CIDR…]",
                    help="full-tunnel: keep these extra local subnets on the physical gateway (needs --exit-node)")
    up.add_argument("--egress", metavar="IFACE",
                    help="egress interface for subnet NAT (default: the system default route's device)")
    up.set_defaults(func=_cmd_up)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
