#!/usr/bin/env python3
"""
meshdns.py — a tiny split-DNS resolver for the remotemac mesh (Phase 8).

Answers `<name>.<suffix>` (default `<name>.mesh`) with the peer's overlay IP and
forwards every other query to the real upstream resolver, so mesh hosts can be
reached by name (`ssh laptop.mesh`) instead of overlay IP. Pure stdlib.

The server binds loopback (127.0.0.1) on port 53 — local-only, so a peer can't
reach it through the TUN and use it as an open forwarder (needs root for :53).
The OS resolver is pointed at it via ResolverConfig; for a quick manual check:

    dig @127.0.0.1 gw.mesh
"""
import os
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


class ResolverError(RuntimeError):
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


def linux_resolvconf(dns_ip: str, upstream: str) -> str:
    """The /etc/resolv.conf body: our resolver first, the real upstream kept as a
    fallback so a crash degrades (timeout → upstream) rather than breaking DNS."""
    lines = [f"nameserver {dns_ip}\n"]
    if upstream and upstream != dns_ip:
        lines.append(f"nameserver {upstream}\n")
    return "".join(lines)


def macos_resolver_file(suffix: str) -> str:
    """Path of the macOS per-domain resolver file for `suffix`."""
    return f"/etc/resolver/{suffix}"


class ResolverConfig:
    """Point the OS resolver at our split-DNS server and restore it on exit.

    macOS uses a per-domain `/etc/resolver/<suffix>` file, so ONLY `.<suffix>`
    queries go to us and the global resolver is untouched. Linux rewrites
    `/etc/resolv.conf` (our server first, the real upstream as a fallback),
    backing up the original. (On a systemd-resolved / NetworkManager host,
    `/etc/resolv.conf` may be re-managed; the original bytes are restored on a
    clean exit.) Needs root."""

    def __init__(self, suffix: str, dns_ip: str, upstream: str = None):
        self.suffix = suffix.strip(".").lower()
        self.dns_ip = dns_ip
        self.upstream = upstream
        self._is_mac = (sys.platform == "darwin")
        self._applied = False
        self._backup = None            # Linux: original resolv.conf bytes
        self._path = None

    def apply(self):
        if self._is_mac:
            os.makedirs("/etc/resolver", exist_ok=True)
            self._path = macos_resolver_file(self.suffix)
            with open(self._path, "w") as f:
                f.write(f"nameserver {self.dns_ip}\n")
        elif sys.platform.startswith("linux"):
            self._path = "/etc/resolv.conf"
            try:
                with open(self._path, "rb") as f:
                    self._backup = f.read()
            except OSError:
                self._backup = None
            with open(self._path, "w") as f:
                f.write(linux_resolvconf(self.dns_ip, self.upstream))
        else:
            raise ResolverError(f"resolver auto-config is unsupported on {sys.platform}")
        self._applied = True
        return self

    def restore(self):
        if not self._applied:
            return
        if self._is_mac:
            try:
                os.unlink(self._path)
            except OSError:
                pass
        elif self._backup is not None:
            try:
                with open(self._path, "wb") as f:
                    f.write(self._backup)
            except OSError:
                pass
        self._applied = False


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
        self._thread = None

    def start(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((self.bind_ip, self.port))
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
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
        # Skip if there's no upstream, or the upstream is our own address —
        # forwarding to ourselves would loop each query back in (leaking a socket
        # per hop). Compare host AND port (a different local port is a real resolver).
        if not self.upstream or (self.upstream, self.upstream_port) == (self.bind_ip, self.port):
            return
        try:
            # Context manager closes the socket on every path, incl. timeouts
            # (socket.timeout is an OSError → the old close() was being skipped).
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.settimeout(3)
                u.sendto(data, (self.upstream, self.upstream_port))
                resp, _ = u.recvfrom(65535)
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
        if self._thread:
            self._thread.join(timeout=2)
