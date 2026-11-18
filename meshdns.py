#!/usr/bin/env python3
"""
meshdns.py — a tiny split-DNS resolver for the remotemac mesh (Phase 8).

Answers key-bound `<name>.<suffix>` (default `<name>.mesh`) with the peer's
overlay IPs. Other queries are forwarded only for explicit global DNS fallback.
Pure stdlib.

The server binds loopback (127.0.0.1) on port 53 — local-only, so a peer can't
reach it through the TUN and use it as an open forwarder (needs root for :53).
The OS resolver is pointed at it via ResolverConfig; for a quick manual check:

    dig @127.0.0.1 gw.mesh
"""
import ipaddress
import os
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

QTYPE_A = 1
QTYPE_AAAA = 28
_QCLASS_IN = 1


class DNSError(ValueError):
    pass


class ResolverError(RuntimeError):
    pass


_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def validate_suffix(suffix):
    """Return a safe, normalized DNS suffix for OS resolver configuration."""
    value = (suffix or "").strip(".").lower()
    if not value or len(value) > 253 or not all(_DNS_LABEL.fullmatch(p)
                                                  for p in value.split(".")):
        raise ValueError(f"invalid DNS suffix: {suffix!r}")
    return value


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
    """Build a response to a query. With `ip`, an A or AAAA answer; else a no-answer
    response with the given RCODE (0 = NODATA, 3 = NXDOMAIN). The query's EDNS
    OPT record, if any, is intentionally dropped."""
    flags = 0x8580 | (rcode & 0x0F)         # QR=1, AA=1, RD=1, RA=1
    ancount = 1 if ip else 0
    header = qid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", qtype, _QCLASS_IN)
    answer = b""
    if ip:
        family = socket.AF_INET6 if qtype == QTYPE_AAAA else socket.AF_INET
        packed = socket.inet_pton(family, ip)
        answer = (b"\xc0\x0c"               # pointer to the question name at offset 12
                  + struct.pack(">HHIH", qtype, _QCLASS_IN, 60, len(packed))
                  + packed)
    return header + question + answer


def answer_for(qid, qname, qtype, suffix, lookup, lookup_v6=None):
    """Response bytes for a mesh query, or None meaning 'forward this upstream'.

    A `.suffix` name resolves via `lookup(host)`:
      • qtype A + hit → A answer with the overlay IP;
      • qtype AAAA + IPv6 hit → AAAA answer;
      • hit but no record of the requested type → NOERROR/NODATA;
      • miss → NXDOMAIN.
    Anything not under `suffix` returns None (outside the mesh domain)."""
    dotted = "." + suffix
    if qname != suffix and not qname.endswith(dotted):
        return None
    host = qname[:-len(dotted)] if qname.endswith(dotted) else ""
    ip = lookup(host) if host else None
    ip6 = lookup_v6(host) if host and lookup_v6 else None
    if qtype == QTYPE_A and ip:
        return build_response(qid, qname, qtype, ip=ip)
    if qtype == QTYPE_AAAA and ip6:
        return build_response(qid, qname, qtype, ip=ip6)
    if ip or ip6:
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


def macos_resolver_file(suffix: str) -> str:
    """Path of the macOS per-domain resolver file for `suffix`."""
    return f"/etc/resolver/{suffix}"


class ResolverConfig:
    """Route only the mesh DNS suffix to our loopback resolver by default.

    macOS uses a per-domain resolver file, Linux uses systemd-resolved's
    route-only domain, and Windows uses NRPT. A Linux static resolv.conf can
    be rewritten only with explicit allow_global_fallback. Needs root/admin."""

    def __init__(self, suffix: str, dns_ip: str, upstream: str = None, interface: str = None,
                 resolv_path="/etc/resolv.conf", state_path="/run/remotemac-resolv.json",
                 allow_global_fallback=False):
        self.suffix = validate_suffix(suffix)
        self.dns_ip = dns_ip
        self.upstream = upstream
        self.interface = interface
        self.resolv_path = resolv_path
        self.state_path = state_path
        self.allow_global_fallback = allow_global_fallback
        self._is_mac = (sys.platform == "darwin")
        self._is_win = (sys.platform == "win32")
        self._applied = False
        self._path = None
        self._mac_installed = None
        self._backend = None
        self._windows = None

    @property
    def uses_global_fallback(self):
        return self._backend == "file"

    def _restore_file(self):
        with open(self.state_path) as f:
            state = json.load(f)
        if not isinstance(state, dict) or not all(isinstance(state.get(k), str)
                                                  for k in ("original", "installed")):
            raise ResolverError("invalid saved resolver state")
        if os.path.islink(self.resolv_path):
            raise ResolverError("resolver path became a symlink; refusing to overwrite it")
        with open(self.resolv_path) as f:
            current = f.read()
        if current == state["original"]:
            # A prior run may have crashed after saving state but before the
            # atomic resolver replacement. There is nothing to restore.
            os.unlink(self.state_path)
            return
        if current != state["installed"]:
            raise ResolverError("resolver changed while mesh was running; saved state kept")
        self._replace_file(state["original"])
        os.unlink(self.state_path)

    def _replace_file(self, content):
        st = os.stat(self.resolv_path)
        fd, tmp = tempfile.mkstemp(prefix=".remotemac-resolv-",
                                   dir=os.path.dirname(self.resolv_path) or ".")
        try:
            with os.fdopen(fd, "w") as f:
                os.fchmod(f.fileno(), st.st_mode & 0o777)
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.resolv_path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def _apply_file(self):
        if not self.allow_global_fallback:
            raise ResolverError("global DNS fallback requires explicit opt-in")
        if not self.upstream:
            raise ResolverError("static resolver fallback needs a known upstream DNS server")
        try:
            ipaddress.ip_address(self.upstream)
        except ValueError as exc:
            raise ResolverError("upstream DNS must be an IP address") from exc
        if self.upstream == self.dns_ip:
            raise ResolverError("upstream DNS points to the local mesh resolver")
        if os.path.islink(self.resolv_path):
            raise ResolverError("managed resolv.conf symlink; cannot safely auto-configure DNS")
        if os.path.exists(self.state_path):
            self._restore_file()  # recover a crashed previous run first
        with open(self.resolv_path) as f:
            original = f.read()
        if any(marker in original[:1024].lower()
               for marker in ("networkmanager", "resolvconf", "systemd-resolved")):
            raise ResolverError("resolv.conf is managed by another service; cannot safely replace it")
        keep = [line for line in original.splitlines()
                if line.startswith(("search ", "domain ", "options "))]
        installed = ("# remotemac temporary DNS; non-mesh names use the saved upstream\n"
                     f"nameserver {self.dns_ip}\n" +
                     ("\n".join(keep) + "\n" if keep else ""))
        fd = os.open(self.state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"original": original, "installed": installed}, f)
                f.flush()
                os.fsync(f.fileno())
            self._replace_file(installed)
        except Exception:
            # If the resolver was not touched, discard the state so the next
            # run can retry. Otherwise retain it for crash recovery.
            with open(self.resolv_path) as f:
                if f.read() == original:
                    os.unlink(self.state_path)
            raise
        self._backend = "file"

    def apply(self):
        if self._applied:
            raise ResolverError("DNS configuration is already active")
        try:
            if not ipaddress.ip_address(self.dns_ip).is_loopback:
                raise ValueError("DNS server must use a loopback address")
        except ValueError as exc:
            raise ResolverError(str(exc)) from exc
        if self._is_mac:
            os.makedirs("/etc/resolver", exist_ok=True)
            self._path = macos_resolver_file(self.suffix)
            self._mac_installed = f"nameserver {self.dns_ip}\n"
            created = False
            try:
                with open(self._path, "x") as f:
                    created = True
                    f.write(self._mac_installed)
            except OSError:
                if created:
                    try:
                        os.unlink(self._path)
                    except OSError:
                        pass
                raise
            self._backend = "mac"
        elif sys.platform.startswith("linux"):
            if not self.interface:
                raise ResolverError("Linux split-DNS needs a TUN interface")
            dns_set = False
            try:
                subprocess.run(["resolvectl", "dns", self.interface, self.dns_ip],
                               check=True, capture_output=True, text=True)
                dns_set = True
                subprocess.run(["resolvectl", "domain", self.interface, "~" + self.suffix],
                               check=True, capture_output=True, text=True)
                subprocess.run(["resolvectl", "default-route", self.interface, "no"],
                               check=True, capture_output=True, text=True)
                self._backend = "resolvectl"
            except (OSError, subprocess.CalledProcessError) as exc:
                if dns_set or not isinstance(exc, FileNotFoundError):
                    try:
                        subprocess.run(["resolvectl", "revert", self.interface],
                                       check=True, capture_output=True, text=True)
                    except (OSError, subprocess.CalledProcessError) as revert_exc:
                        raise ResolverError("systemd-resolved failed and its DNS changes "
                                            f"could not be reverted: {revert_exc}") from revert_exc
                if not self.allow_global_fallback:
                    raise ResolverError(f"systemd-resolved failed ({exc}); "
                                        "system DNS unchanged (use --dns-global-fallback "
                                        "only if global DNS forwarding is acceptable)") from exc
                try:
                    self._apply_file()
                except (OSError, ValueError, ResolverError) as fallback_exc:
                    raise ResolverError(f"systemd-resolved failed ({exc}); "
                                        f"static fallback failed ({fallback_exc})") from fallback_exc
        elif self._is_win:
            import windns
            try:
                self._windows = windns.NrptConfig(self.suffix, self.dns_ip).apply()
            except windns.WindnsError as exc:
                raise ResolverError(str(exc)) from exc
            self._backend = "nrpt"
        else:
            raise ResolverError(f"resolver auto-config is unsupported on {sys.platform}")
        self._applied = True
        return self

    def restore(self):
        if not self._applied:
            return
        if self._backend == "mac":
            try:
                with open(self._path) as f:
                    current = f.read()
                if current != self._mac_installed:
                    raise ResolverError("macOS resolver changed while mesh was running; "
                                        "refusing to remove it")
                os.unlink(self._path)
            except FileNotFoundError:
                pass
        elif self._backend == "file":
            self._restore_file()
        elif self._backend == "resolvectl" and self.interface:
            try:
                subprocess.run(["resolvectl", "revert", self.interface],
                               check=True, capture_output=True, text=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                raise ResolverError(f"could not restore systemd-resolved DNS: {exc}") from exc
        elif self._backend == "nrpt" and self._windows:
            import windns
            try:
                self._windows.restore()
            except windns.WindnsError as exc:
                raise ResolverError(str(exc)) from exc
        self._applied = False
        self._backend = None


def detect_upstream(resolv_path="/etc/resolv.conf", state_path="/run/remotemac-resolv.json"):
    """Best-effort: the system's current first upstream nameserver (or None).
    Read before we rewrite the resolver, so it captures the real upstream."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=3).stdout
            return _first_nameserver_scutil(out)
        with open(resolv_path) as f:
            current = f.read()
        if os.path.exists(state_path):
            with open(state_path) as f:
                state = json.load(f)
            if current == state.get("installed"):
                return _first_nameserver_resolvconf(state["original"])
        return _first_nameserver_resolvconf(current)
    except Exception:
        return None


# ─── server ──────────────────────────────────────────────────────────────────

class MeshDNSServer:
    """UDP DNS server: answers `.suffix` names from `lookup`. An explicit
    upstream is used only for global DNS fallback. Runs until stop()."""

    def __init__(self, bind_ip, port, suffix, lookup, upstream=None, upstream_port=53,
                 lookup_v6=None):
        self.bind_ip = bind_ip
        self.port = port
        self.suffix = suffix.strip(".").lower()
        self.lookup = lookup
        self.lookup_v6 = lookup_v6
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.udp = None
        self._done = threading.Event()
        self._thread = None
        self._workers = None
        self._slots = threading.BoundedSemaphore(64)

    def start(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((self.bind_ip, self.port))
        self._workers = ThreadPoolExecutor(max_workers=16, thread_name_prefix="meshdns")
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
            if self._slots.acquire(blocking=False):
                try:
                    self._workers.submit(self._handle_safely, data, addr)
                except RuntimeError:
                    self._slots.release()  # stop() shut down the executor
                    return

    def _handle_safely(self, data, addr):
        try:
            self._handle(data, addr)
        except Exception:
            pass
        finally:
            self._slots.release()

    def _handle(self, data, addr):
        try:
            qid, qname, qtype = parse_query(data)
        except DNSError:
            return                          # ignore malformed queries
        resp = answer_for(qid, qname, qtype, self.suffix, self.lookup, self.lookup_v6)
        if resp is not None:
            self.udp.sendto(resp, addr)
        elif not self.upstream:
            self.udp.sendto(build_response(qid, qname, qtype, rcode=5), addr)
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
            family = socket.AF_INET6 if ":" in self.upstream else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as u:
                u.settimeout(3)
                u.connect((self.upstream, self.upstream_port))
                u.send(data)
                resp = u.recv(65535)
                if len(resp) >= 12 and resp[:2] == data[:2] and (resp[2] & 0x80):
                    try:
                        _, reply_name, reply_type = parse_query(resp)
                        _, query_name, query_type = parse_query(data)
                    except DNSError:
                        return
                    if (reply_name, reply_type) == (query_name, query_type):
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
        if self._workers:
            self._workers.shutdown(wait=True)
