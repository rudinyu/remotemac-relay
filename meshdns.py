#!/usr/bin/env python3
"""
meshdns.py — a tiny split-DNS resolver for the remotemac mesh (Phase 8).

Answers `<name>.<suffix>` (default `<name>.mesh`) with the peer's overlay IP and
forwards every other query to the real upstream resolver, so mesh hosts can be
reached by name (`ssh laptop.mesh`) instead of overlay IP. Pure stdlib.

The server binds the node's overlay IP on port 53 (so it needs the TUN up and
root). The OS resolver is pointed at it separately (see the ResolverConfig in a
later step); for a quick manual check you can query it directly:

    dig @<overlay-ip> gw.mesh
"""
import socket
import struct
import subprocess
import sys
import threading

QTYPE_A = 1
QTYPE_AAAA = 28
_QCLASS_IN = 1


class DNSError(ValueError):
    pass


def parse_query(data: bytes):
    """Parse a DNS query → (qid_bytes, qname_lowercase, qtype). Raises DNSError on
    a malformed / unsupported packet (compressed question name, truncation)."""
    if len(data) < 12:
        raise DNSError("short DNS packet")
    qid = data[:2]
    qdcount = struct.unpack(">H", data[4:6])[0]
    if qdcount < 1:
        raise DNSError("no question")
    off = 12
    labels = []
    while True:
        if off >= len(data):
            raise DNSError("truncated name")
        ln = data[off]
        off += 1
        if ln == 0:
            break
        if ln & 0xC0:                       # queries don't compress the question name
            raise DNSError("compressed question name")
        if off + ln > len(data):
            raise DNSError("truncated label")
        labels.append(data[off:off + ln].decode("ascii", "ignore").lower())
        off += ln
    if off + 4 > len(data):
        raise DNSError("truncated question")
    qtype = struct.unpack(">H", data[off:off + 2])[0]
    return qid, ".".join(labels), qtype


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("ascii", "ignore")[:63]
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def build_response(qid: bytes, qname: str, qtype: int, ip: str = None, rcode: int = 0) -> bytes:
    """Build a response to a query. With `ip`, an A answer; else a no-answer
    response with the given RCODE (0 = NODATA, 3 = NXDOMAIN). The query's EDNS
    OPT record, if any, is intentionally dropped."""
    flags = 0x8580 | (rcode & 0x0F)         # QR=1, AA=1, RD=1, RA=1
    ancount = 1 if ip else 0
    header = qid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", qtype, _QCLASS_IN)
    answer = b""
    if ip:
        answer = (b"\xc0\x0c"               # pointer to the question name at offset 12
                  + struct.pack(">HHIH", QTYPE_A, _QCLASS_IN, 60, 4)
                  + socket.inet_aton(ip))
    return header + question + answer


def answer_for(qid, qname, qtype, suffix, lookup):
    """Response bytes for a mesh query, or None meaning 'forward this upstream'.

    A `.suffix` name resolves via `lookup(host)`:
      • qtype A + hit → A answer with the overlay IP;
      • hit but non-A (e.g. AAAA) → NOERROR/NODATA (don't stall the client);
      • miss → NXDOMAIN.
    Anything not under `suffix` returns None (forward)."""
    dotted = "." + suffix
    if qname != suffix and not qname.endswith(dotted):
        return None
    host = qname[:-len(dotted)] if qname.endswith(dotted) else ""
    ip = lookup(host) if host else None
    if qtype == QTYPE_A and ip:
        return build_response(qid, qname, qtype, ip=ip)
    if ip:
        return build_response(qid, qname, qtype)            # NODATA
    return build_response(qid, qname, qtype, rcode=3)       # NXDOMAIN


# ─── upstream detection ──────────────────────────────────────────────────────

def _first_nameserver_resolvconf(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def _first_nameserver_scutil(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("nameserver[") and ":" in line:
            return line.split(":", 1)[1].strip()
    return None


def detect_upstream():
    """Best-effort: the system's current first upstream nameserver (or None).
    Read before we rewrite the resolver, so it captures the real upstream."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=3).stdout
            return _first_nameserver_scutil(out)
        with open("/etc/resolv.conf") as f:
            return _first_nameserver_resolvconf(f.read())
    except Exception:
        return None


# ─── server ──────────────────────────────────────────────────────────────────

class MeshDNSServer:
    """UDP DNS server: answers `.suffix` names from `lookup`, forwards the rest to
    `upstream`. Runs on a daemon thread until stop()."""

    def __init__(self, bind_ip, port, suffix, lookup, upstream=None, upstream_port=53):
        self.bind_ip = bind_ip
        self.port = port
        self.suffix = suffix.strip(".").lower()
        self.lookup = lookup
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.udp = None
        self._done = threading.Event()

    def start(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((self.bind_ip, self.port))
        threading.Thread(target=self._loop, daemon=True).start()
        return self

    @property
    def address(self):
        return self.udp.getsockname() if self.udp else (self.bind_ip, self.port)

    def _loop(self):
        while not self._done.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except OSError:
                if self._done.is_set():
                    return
                continue
            try:
                self._handle(data, addr)
            except Exception:
                pass

    def _handle(self, data, addr):
        try:
            qid, qname, qtype = parse_query(data)
        except DNSError:
            return                          # ignore malformed queries
        resp = answer_for(qid, qname, qtype, self.suffix, self.lookup)
        if resp is not None:
            self.udp.sendto(resp, addr)
        else:
            self._forward(data, addr)

    def _forward(self, data, addr):
        if not self.upstream:
            return
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(3)
            u.sendto(data, (self.upstream, self.upstream_port))
            resp, _ = u.recvfrom(65535)
            u.close()
            self.udp.sendto(resp, addr)
        except OSError:
            pass

    def stop(self):
        self._done.set()
        if self.udp:
            try:
                self.udp.close()
            except Exception:
                pass
