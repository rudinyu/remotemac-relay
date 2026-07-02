#!/usr/bin/env python3
"""
mesh.py — a node in the remotemac mesh (Tailscale-lite).

Each node has a persistent X25519 identity key. It connects to the coordinator
(`coordinator.py`) over a token-authenticated encrypted control channel, is
assigned a stable overlay IP, and learns the other nodes. Node-to-node traffic
is end-to-end encrypted with a mutually authenticated, forward-secret handshake
(X25519 triple-DH → HKDF-SHA256 → ChaCha20-Poly1305); the coordinator only ever
relays ciphertext.

Phase 1 (this file): identity + control channel + peer map + an encrypted data
path relayed through the coordinator (DERP), with a built-in ping to prove the
tunnel works. No UDP / NAT hole punching (Phase 2) and no TUN overlay (Phase 3)
yet, so this needs no root.

Requires: pip install cryptography

Usage
-----
    python3 mesh.py up <coord:port> --token <network-token> [--name NAME] [--exit]
    python3 mesh.py up <coord:port> --token <token> --ping <peer-name-or-ip>
"""
import argparse
import base64
import json
import os
import socket
import struct
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

__version__ = "1.1.0"

_HS_INFO   = b"remotemac-mesh-v1"
_KEY_PATH  = os.path.expanduser("~/.config/remotemac/mesh/key")

# mesh application message types (first byte of the decrypted payload)
MESH_PING = 0x01
MESH_PONG = 0x02
MESH_IP   = 0x03   # reserved for Phase 3 (TUN packets)

# handshake stages (first byte of an "hs" body — transport-agnostic)
_HS_INIT  = 0x01
_HS_RESP  = 0x02

# UDP data-plane packet types (first byte of a datagram)
_PKT_PUNCH = 0x01   # empty — opens/keeps a NAT mapping
_PKT_HS    = 0x02   # [32B sender_static][hs body]
_PKT_DATA  = 0x03   # [4B receiver_index][Session packet]


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
        self.initiated    = False
        self.queued       = []             # payloads awaiting a session
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
                 bind_host: str = "0.0.0.0", udp_port: int = 0):
        self._id      = identity
        self._pub     = pub_bytes(identity)
        self.pubkey_b64 = _b64(self._pub)
        self.hostname = hostname
        self.is_exit  = is_exit
        self._bind_host = bind_host
        self._udp_port  = udp_port
        self.ch       = None
        self.udp      = None
        self.local_endpoints = []
        self.overlay_ip = None
        self.peers    = {}         # pubkey_b64 -> {ip, hostname, exit, endpoints}
        self._conns   = {}         # pubkey_b64 -> PeerConn
        self._by_index = {}        # local_index (int) -> PeerConn  (UDP DATA demux)
        self._lock     = threading.Lock()
        self._done     = threading.Event()
        self.on_message = None     # optional callback(peer_pk_b64, msg_type, body)

    # -- control channel --------------------------------------------------------

    def connect(self, coord_addr: str, token: bytes):
        host, _, port = coord_addr.rpartition(":")
        sock = socket.create_connection((host, int(port)), timeout=15)
        sock.settimeout(30)
        self.ch = _auth(sock, token, is_host=False)
        sock.settimeout(None)
        self._start_udp()
        self._send({"t": "register", "pubkey": self.pubkey_b64,
                    "hostname": self.hostname, "exit": self.is_exit,
                    "endpoints": self.local_endpoints})

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
                                  "endpoints": p.get("endpoints", [])}
        with self._lock:
            self.peers = peers

    # -- peer lookup ------------------------------------------------------------

    def resolve(self, name_or_ip: str):
        """Return a peer pubkey_b64 by hostname or overlay IP, or None."""
        with self._lock:
            for pk, info in self.peers.items():
                if info.get("hostname") == name_or_ip or info.get("ip") == name_or_ip:
                    return pk
        return None

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
        body = _unb64(msg.get("body", ""))
        if not src or not body or src not in self.peers:
            return
        if kind == "hs" and len(body) >= 37:
            stage, eph, index = body[0], body[1:33], struct.unpack(">I", body[33:37])[0]
            self._handle_hs(src, self._peer_static(src), stage, eph, index, "derp", None)
        elif kind == "data":
            pc = self._conns.get(src)
            if pc and pc.session:
                self._recv_data(pc, body)

    # -- inbound: UDP data plane ------------------------------------------------

    def _on_udp(self, data: bytes, addr):
        if not data:
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
            eph = X25519PrivateKey.generate()
            tx, rx = _derive(self._id, self._pub, peer_static,
                             eph, pub_bytes(eph), peer_eph, initiator=False)
            with pc.lock:
                if pc.session is None:
                    pc.session = Session(tx, rx)
                    pc.remote_index = peer_index
                    pc.bind_transport(via, addr)
                queued = pc.flush()
            self._send_hs(pc, self._hs_body(_HS_RESP, pub_bytes(eph), pc.local_index), via, addr)
            for payload in queued:
                self._transmit(pc, payload)
        elif stage == _HS_RESP:
            with pc.lock:
                if pc.eph is None or pc.session is not None:
                    return
                tx, rx = _derive(self._id, self._pub, peer_static,
                                 pc.eph, pub_bytes(pc.eph), peer_eph, initiator=True)
                pc.session = Session(tx, rx)
                pc.remote_index = peer_index
                pc.bind_transport(via, addr)
                queued = pc.flush()
            for payload in queued:
                self._transmit(pc, payload)

    def _recv_data(self, pc, body):
        try:
            pt = pc.session.decrypt(body)
        except Exception as exc:
            _log(f"data decrypt from {pc.peer_pk[:12]}…: {exc}")
            return
        if not pt:
            return
        mtype, payload = pt[0], pt[1:]
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
        start = False
        with pc.lock:
            ready = pc.session is not None
            if not ready:
                pc.queued.append(data)
                if not pc.initiated:
                    pc.initiated = True
                    start = True
        if ready:
            self._transmit(pc, data)
        elif start:
            self._initiate(pc)

    def _initiate(self, pc):
        eps = self._peer_endpoints(pc.peer_pk)
        with pc.lock:
            pc.eph = X25519PrivateKey.generate()
            body = self._hs_body(_HS_INIT, pub_bytes(pc.eph), pc.local_index)
        if eps:
            # Direct path first — send the handshake to every candidate endpoint.
            for ep in eps:
                try:
                    self.udp.sendto(bytes([_PKT_HS]) + self._pub + body, ep)
                except Exception:
                    pass
        else:
            self._relay_to(pc.peer_pk, "hs", body)

# ─── CLI ────────────────────────────────────────────────────────────────────────

def _cmd_up(args):
    token = args.token or os.environ.get("REMOTEMAC_MESH_TOKEN")
    if not token:
        import getpass
        token = getpass.getpass("Network token: ")

    identity = load_or_create_identity()
    name = args.name or socket.gethostname()
    node = MeshNode(identity, name, is_exit=args.exit,
                    bind_host=args.bind, udp_port=args.udp_port)

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
    up.add_argument("--exit", action="store_true", help="advertise as an exit node (Phase 3)")
    up.add_argument("--bind", default="0.0.0.0", help="UDP data-plane bind address (default 0.0.0.0)")
    up.add_argument("--udp-port", type=int, default=0, help="UDP data-plane port (default: random)")
    up.add_argument("--ping", metavar="PEER", help="ping a peer (name or overlay IP) then exit")
    up.set_defaults(func=_cmd_up)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
