#!/usr/bin/env python3
"""
coordinator.py — control plane for the remotemac mesh (Tailscale-lite).

Run this on a host reachable from the internet (a VPS, or a box with its port
forwarded). Nodes (`mesh.py`) connect *outbound* to the coordinator over an
encrypted, token-authenticated control channel. The coordinator:

  • authenticates each node with a shared **network token** (via the same
    SecureChannel handshake used by remote_desktop.py),
  • assigns each node a stable overlay IP from 100.64.0.0/10 (persisted),
  • distributes the network map (peers: pubkey, overlay IP, hostname, exit flag)
    and pushes updates as nodes join/leave,
  • relays handshake + data messages between nodes (DERP fallback). It only ever
    sees ciphertext for data — node↔node traffic is end-to-end encrypted.

Run
---
    python3 coordinator.py 21200 --token "network-secret"
    #   token may also come from REMOTEMAC_MESH_TOKEN
Open that TCP port in the firewall / security group.

This is Phase 1 of the mesh: no UDP / NAT hole punching (Phase 2) and no TUN
overlay (Phase 3) yet. The data path here is relayed over the control channel.
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remote_desktop import SecureChannel, _auth  # noqa: E402

__version__ = "1.2.0"

OVERLAY_NET = ipaddress.ip_network("100.64.0.0/10")
MAX_NODES = 1024

# ─── control-channel JSON framing (one JSON object per SecureChannel frame) ────

def send_json(ch: SecureChannel, obj: dict):
    ch.send(json.dumps(obj, separators=(",", ":")).encode())


def recv_json(ch: SecureChannel) -> dict:
    return json.loads(ch.recv().decode())


# ─── overlay-IP allocator (persisted so a node keeps its IP across restarts) ───

class IPAllocator:
    def __init__(self, state_path: str):
        self._path = state_path
        self._lock = threading.Lock()
        self._map = {}            # pubkey (b64) -> overlay ip str
        self._load()

    def _load(self):
        try:
            with open(self._path) as f:
                self._map = json.load(f).get("overlay_ips", {})
        except (FileNotFoundError, ValueError):
            self._map = {}

    def _save(self):
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"overlay_ips": self._map}, f, indent=2)
            os.replace(tmp, self._path)
        except OSError as exc:
            print(f"[coord] warning: could not persist state: {exc}", flush=True)

    def get(self, pubkey: str) -> str:
        with self._lock:
            if pubkey in self._map:
                return self._map[pubkey]
            used = set(self._map.values())
            # .1 is reserved as a conventional gateway anchor; hand out from .2 up.
            for host in OVERLAY_NET.hosts():
                ip = str(host)
                if ip.endswith(".0") or ip.endswith(".255"):
                    continue
                if ip not in used and host != next(OVERLAY_NET.hosts()):
                    self._map[pubkey] = ip
                    self._save()
                    return ip
            raise RuntimeError("overlay address space exhausted")


class Coordinator:
    def __init__(self, token: bytes, allocator: IPAllocator):
        self._token = token
        self._alloc = allocator
        self._lock = threading.Lock()
        self._nodes = {}          # pubkey (b64) -> node record

    # -- map distribution -------------------------------------------------------

    def _map_for(self, pubkey: str) -> dict:
        with self._lock:
            me = self._nodes.get(pubkey)
            peers = [
                {"pubkey": pk, "ip": n["ip"], "hostname": n["hostname"],
                 "exit": n["exit"], "endpoints": n.get("endpoints", []), "online": True}
                for pk, n in self._nodes.items() if pk != pubkey
            ]
        self_info = {"pubkey": pubkey, "ip": me["ip"]} if me else {}
        return {"t": "map", "self": self_info, "peers": peers}

    def _push_all(self):
        with self._lock:
            targets = list(self._nodes.items())
        for pk, n in targets:
            try:
                send_json(n["ch"], self._map_for(pk))
            except Exception:
                pass

    # -- per-connection handler -------------------------------------------------

    def handle(self, conn: socket.socket, addr):
        try:
            ch = _auth(conn, self._token, is_host=True)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            return

        pk = None
        record = None
        try:
            reg = recv_json(ch)
            if reg.get("t") != "register" or not reg.get("pubkey"):
                return
            pk = reg["pubkey"]
            with self._lock:
                if len(self._nodes) >= MAX_NODES and pk not in self._nodes:
                    pk = None   # not admitted; nothing to clean up
                    return
            ip = self._alloc.get(pk)
            endpoints = [str(e)[:64] for e in (reg.get("endpoints") or [])][:16]
            record = {"ch": ch, "hostname": reg.get("hostname", "node")[:64],
                      "exit": bool(reg.get("exit")), "ip": ip, "endpoints": endpoints}
            with self._lock:
                old = self._nodes.get(pk)
                if old:
                    try:
                        old["ch"].close()
                    except Exception:
                        pass
                self._nodes[pk] = record
            print(f"[coord] node up hostname={record['hostname']} ip={ip} from {addr[0]}", flush=True)
            self._push_all()

            while True:
                msg = recv_json(ch)
                mt = msg.get("t")
                if mt == "to":
                    self._relay(pk, msg)
                elif mt == "endpoints":
                    eps = [str(e)[:64] for e in (msg.get("endpoints") or [])][:16]
                    with self._lock:
                        if self._nodes.get(pk) is record:
                            record["endpoints"] = eps
                    self._push_all()
                # unknown control types are ignored
        except Exception:
            pass
        finally:
            if pk and record is not None:
                with self._lock:
                    if self._nodes.get(pk) is record:
                        self._nodes.pop(pk, None)
                print(f"[coord] node down ip={record['ip']}", flush=True)
                self._push_all()
            try:
                conn.close()
            except Exception:
                pass

    def _relay(self, src_pk: str, msg: dict):
        dst = msg.get("dst")
        with self._lock:
            peer = self._nodes.get(dst)
        if not peer:
            return
        try:
            send_json(peer["ch"], {"t": "from", "src": src_pk,
                                   "kind": msg.get("kind"), "body": msg.get("body")})
        except Exception:
            pass


_STUN_REQ = b"MSTU"
_STUN_RES = b"MSTR"


def _stun_responder(host: str, port: int):
    """Stateless STUN-lite: reply to each probe with the source's observed ip:port,
    so a node behind NAT learns its public endpoint. Shares the TCP control port."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        u.bind((host, port))
    except OSError as exc:
        print(f"[coord] warning: STUN UDP bind failed on {port}: {exc}", flush=True)
        u.close()
        return
    while True:
        try:
            data, addr = u.recvfrom(2048)
        except OSError:
            return
        if data[:4] == _STUN_REQ:
            try:
                u.sendto(_STUN_RES + f"{addr[0]}:{addr[1]}".encode(), addr)
            except OSError:
                pass


def serve(host: str, port: int, token: bytes, state_path: str):
    coord = Coordinator(token, IPAllocator(state_path))
    threading.Thread(target=_stun_responder, args=(host, port), daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    print(f"RemoteMac mesh coordinator listening on {host}:{port} (TCP control + UDP STUN)", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=coord.handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


def main():
    p = argparse.ArgumentParser(prog="coordinator.py",
                                description="Control plane for the remotemac mesh.")
    p.add_argument("port", nargs="?", type=int, default=21200)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--token", help="network join token (or set REMOTEMAC_MESH_TOKEN)")
    p.add_argument("--state", default=os.path.expanduser("~/.config/remotemac/coordinator-state.json"),
                   help="path for persisted overlay-IP assignments")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args()

    if not (1 <= args.port <= 65535):
        p.error("port must be 1–65535")
    token = args.token or os.environ.get("REMOTEMAC_MESH_TOKEN")
    if not token:
        import getpass
        token = getpass.getpass("Network token: ")

    os.makedirs(os.path.dirname(args.state), exist_ok=True)
    serve(args.host, args.port, token.encode(), args.state)


if __name__ == "__main__":
    main()
