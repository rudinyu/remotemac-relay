#!/usr/bin/env python3
"""
tun.py — a TUN virtual interface for the remotemac mesh overlay (Phase 3).

Bridges the OS network stack to the mesh data plane: raw IP packets read from
the TUN device are routed to peers by overlay IP (`mesh.send(pk, MESH_IP, pkt)`),
and packets arriving from peers are written back to the device. This turns the
IPv4 and IPv6 overlays into usable networks for real apps (ping / ssh / http),
rather than only the built-in `--ping`.

Platforms
---------
- **macOS**: `utun` via the stdlib `AF_SYSTEM` / `SYSPROTO_CONTROL` socket — no
  third-party kext. Packets carry a 4-byte address-family header we add/strip.
  The interface name (`utunN`) is assigned by the kernel; `--tun-name` is ignored.
- **Linux**: `/dev/net/tun` with `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`) — raw IP, no
  prefix. The interface name is honoured (default `remotemac0`).
- **Windows**: Wintun via the official `wintun.dll`, supplied separately. The
  interface name is honoured (default `remotemac0`).

Creating the interface and setting routes needs root or Windows Administrator.

This module only handles the device + its addressing/route; the TUN↔mesh pump and
CLI live in `mesh.py`.
"""
import os
import select
import socket
import struct
import subprocess
import sys

OVERLAY_CIDR = "100.64.0.0/10"

# macOS utun control plumbing.
_CTLIOCGINFO = 0xC0644E03                     # _IOWR('N', 3, struct ctl_info)
_UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
_UTUN_OPT_IFNAME = 2                          # getsockopt(SYSPROTO_CONTROL, …)

# Linux tun plumbing.
_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001
_IFF_NO_PI = 0x1000


class TunError(RuntimeError):
    pass


def _ipv4_addr(pkt: bytes, offset: int):
    """Dotted-quad address at `offset` of a raw IPv4 packet, or None if the buffer
    is not a well-formed IPv4 header (wrong version or too short)."""
    if pkt is None or len(pkt) < 20:
        return None
    if (pkt[0] >> 4) != 4:          # IP version nibble
        return None
    return ".".join(str(b) for b in pkt[offset:offset + 4])


def parse_ipv4_dst(pkt: bytes):
    """Destination address of a raw IPv4 packet (or None). IPv6/truncated → None
    so the caller can safely drop them."""
    return _ipv4_addr(pkt, 16)


def parse_ipv4_src(pkt: bytes):
    """Source address of a raw IPv4 packet (or None), for anti-spoofing checks."""
    return _ipv4_addr(pkt, 12)


def _ipv6_addr(pkt: bytes, offset: int):
    """Address from a complete IPv6 base header, or None for invalid packets."""
    if pkt is None or len(pkt) < 40 or (pkt[0] >> 4) != 6:
        return None
    payload_len = struct.unpack_from(">H", pkt, 4)[0]
    if payload_len and len(pkt) < 40 + payload_len:
        return None
    return socket.inet_ntop(socket.AF_INET6, pkt[offset:offset + 16])


def parse_ip_dst(pkt: bytes):
    """Destination of an IPv4 or IPv6 packet; None for malformed packets."""
    if not pkt:
        return None
    if (pkt[0] >> 4) == 4:
        return parse_ipv4_dst(pkt)
    if (pkt[0] >> 4) == 6:
        return _ipv6_addr(pkt, 24)
    return None


def parse_ip_src(pkt: bytes):
    """Source of an IPv4 or IPv6 packet; None for malformed packets."""
    if not pkt:
        return None
    if (pkt[0] >> 4) == 4:
        return parse_ipv4_src(pkt)
    if (pkt[0] >> 4) == 6:
        return _ipv6_addr(pkt, 8)
    return None


def mac_encap(pkt: bytes) -> bytes:
    """Prepend the macOS utun address-family header for the IP packet."""
    if parse_ip_dst(pkt) is None:
        raise ValueError("invalid IP packet")
    family = socket.AF_INET6 if (pkt[0] >> 4) == 6 else socket.AF_INET
    return struct.pack(">I", family) + pkt


def mac_decap(data: bytes) -> bytes:
    """Strip a matching macOS utun address-family header."""
    if len(data) < 5:
        return b""
    family = struct.unpack(">I", data[:4])[0]
    pkt = data[4:]
    expected = socket.AF_INET6 if (pkt[0] >> 4) == 6 else socket.AF_INET
    return pkt if family == expected and parse_ip_dst(pkt) is not None else b""


def _run(cmd):
    subprocess.run(cmd, check=True)


class TunDevice:
    """A TUN interface presenting raw IPv4 and IPv6 packets via read()/write()."""

    def __init__(self, name: str = None, mtu: int = 1280):
        self._name_req = name
        self.mtu = mtu
        self.name = None
        self._fd = None        # Linux file descriptor
        self._sock = None      # macOS utun control socket
        self._is_mac = (sys.platform == "darwin")
        self._is_win = (sys.platform == "win32")
        self._win = None       # Windows Wintun adapter/session
        self._cidr6 = None     # macOS IPv6 route installed by configure()

    # -- lifecycle --------------------------------------------------------------

    def open(self):
        if self._is_mac:
            self._open_macos()
        elif sys.platform.startswith("linux"):
            self._open_linux()
        elif self._is_win:
            import wintun
            try:
                self._win = wintun.WintunDevice(self._name_req, self.mtu).open()
            except wintun.WintunError as exc:
                raise TunError(str(exc)) from exc
            self.name = self._win.name
        else:
            raise TunError(f"TUN overlay is not supported on {sys.platform}")
        return self

    def _open_macos(self):
        import fcntl
        s = socket.socket(socket.AF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
        info = struct.pack("<I96s", 0, _UTUN_CONTROL_NAME)
        ctl_id = struct.unpack("<I96s", fcntl.ioctl(s, _CTLIOCGINFO, info))[0]
        try:
            s.connect((ctl_id, 0))       # unit 0 → kernel picks the lowest free utunN
        except PermissionError:
            s.close()
            raise TunError("opening a utun device needs root — re-run with sudo")
        name = s.getsockopt(socket.SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, 256)
        self.name = name.split(b"\x00", 1)[0].decode()
        self._sock = s

    def _open_linux(self):
        import fcntl
        name = (self._name_req or "remotemac0")[:15]
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR)
        except PermissionError:
            raise TunError("opening /dev/net/tun needs root — re-run with sudo")
        except FileNotFoundError:
            raise TunError("/dev/net/tun not present — is the tun module loaded?")
        ifr = struct.pack("16sH", name.encode(), _IFF_TUN | _IFF_NO_PI)
        fcntl.ioctl(fd, _TUNSETIFF, ifr)
        self.name = name
        self._fd = fd

    # -- addressing + route (root) ---------------------------------------------

    def configure(self, overlay_ip: str, cidr: str = OVERLAY_CIDR,
                  overlay_ip6: str = None, cidr6: str = None):
        """Assign overlay addresses and route their networks to this interface."""
        if self._is_win:
            import wintun
            try:
                self._win.configure(overlay_ip, cidr, overlay_ip6, cidr6)
            except wintun.WintunError as exc:
                raise TunError(str(exc)) from exc
        elif self._is_mac:
            # utun is point-to-point: address == destination is the usual idiom.
            _run(["ifconfig", self.name, "inet", overlay_ip, overlay_ip, "up"])
            _run(["ifconfig", self.name, "mtu", str(self.mtu)])
            _run(["route", "-n", "add", "-net", cidr, "-interface", self.name])
            if overlay_ip6 and cidr6:
                # A /128 address avoids an implicit connected /64 route; install
                # the explicit route below, as for the IPv4 point-to-point utun.
                _run(["ifconfig", self.name, "inet6", overlay_ip6, "prefixlen", "128"])
                _run(["route", "-n", "add", "-inet6", "-net", cidr6,
                      "-interface", self.name])
                self._cidr6 = cidr6
        else:
            prefix = cidr.split("/")[1]
            _run(["ip", "addr", "add", f"{overlay_ip}/{prefix}", "dev", self.name])
            _run(["ip", "link", "set", "dev", self.name, "up", "mtu", str(self.mtu)])
            if overlay_ip6 and cidr6:
                prefix6 = cidr6.split("/")[1]
                _run(["ip", "-6", "addr", "add", f"{overlay_ip6}/{prefix6}",
                      "dev", self.name])

    def teardown(self, cidr: str = OVERLAY_CIDR):
        """Best-effort route cleanup. On close the interface itself disappears."""
        if self.name and self._is_mac:
            if self._cidr6:
                subprocess.run(["route", "-n", "delete", "-inet6", "-net", self._cidr6,
                                "-interface", self.name], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._cidr6 = None
            subprocess.run(["route", "-n", "delete", "-net", cidr, "-interface", self.name],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add_route(self, cidr: str):
        """Route an extra CIDR into this interface (accepted subnet routes).
        Tolerant of an already-present route so re-syncs don't fail."""
        if self._is_win:
            self._win.add_route(cidr)
            return
        if self._is_mac:
            import ipaddress
            family = ["-inet6"] if ipaddress.ip_network(cidr).version == 6 else []
            cmd = ["route", "-n", "add"] + family + ["-net", cidr, "-interface", self.name]
        elif ":" in cidr:
            cmd = ["ip", "-6", "route", "add", cidr, "dev", self.name]
        else:
            cmd = ["ip", "route", "add", cidr, "dev", self.name]
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def del_route(self, cidr: str):
        if self._is_win:
            self._win.del_route(cidr)
            return
        if self._is_mac:
            import ipaddress
            family = ["-inet6"] if ipaddress.ip_network(cidr).version == 6 else []
            cmd = ["route", "-n", "delete"] + family + ["-net", cidr, "-interface", self.name]
        elif ":" in cidr:
            cmd = ["ip", "-6", "route", "del", cidr, "dev", self.name]
        else:
            cmd = ["ip", "route", "del", cidr, "dev", self.name]
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # -- I/O (raw IP) -----------------------------------------------------------

    def read(self, timeout: float = 0.5) -> bytes:
        """Return one raw IP packet, or b"" if none arrives within `timeout`.

        The bounded wait lets a pump loop poll a shutdown flag instead of blocking
        forever in the kernel — so the fd/socket is never closed out from under a
        thread still parked in read(). The buffer is intentionally MTU-independent
        (the kernel hands us at most one interface-MTU frame per read for a TUN).
        """
        if self._is_win:
            if not self._win:
                return b""
            import wintun
            try:
                return self._win.read(timeout)
            except wintun.WintunError as exc:
                raise TunError(str(exc)) from exc
        handle = self._sock if self._is_mac else self._fd
        if handle is None:
            return b""
        try:
            ready, _, _ = select.select([handle], [], [], timeout)
        except (OSError, ValueError):
            return b""
        if not ready:
            return b""
        if self._is_mac:
            return mac_decap(self._sock.recv(65535 + 4))
        return os.read(self._fd, 65535)

    def write(self, pkt: bytes):
        if self._is_win:
            import wintun
            try:
                self._win.write(pkt)
            except wintun.WintunError as exc:
                raise OSError(str(exc)) from exc
        elif self._is_mac:
            self._sock.send(mac_encap(pkt))
        else:
            os.write(self._fd, pkt)

    def close(self):
        self.teardown()
        if self._win is not None:
            self._win.close()
            self._win = None
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:
            pass
        try:
            if self._fd is not None:
                os.close(self._fd)
        except Exception:
            pass
        self._sock = self._fd = None
