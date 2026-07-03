#!/usr/bin/env python3
"""
tun.py — a TUN virtual interface for the remotemac mesh overlay (Phase 3).

Bridges the OS network stack to the mesh data plane: raw IPv4 packets read from
the TUN device are routed to peers by overlay IP (`mesh.send(pk, MESH_IP, pkt)`),
and packets arriving from peers are written back to the device. This turns the
`100.64.0.0/10` overlay into a usable network for real apps (ping / ssh / http),
rather than only the built-in `--ping`.

Platforms
---------
- **macOS**: `utun` via the stdlib `AF_SYSTEM` / `SYSPROTO_CONTROL` socket — no
  third-party kext. Packets carry a 4-byte address-family header we add/strip.
  The interface name (`utunN`) is assigned by the kernel; `--tun-name` is ignored.
- **Linux**: `/dev/net/tun` with `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`) — raw IP, no
  prefix. The interface name is honoured (default `remotemac0`).

Creating the interface and setting routes needs **root**.

This module only handles the device + its addressing/route; the TUN↔mesh pump and
CLI live in `mesh.py`.
"""
import os
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


def parse_ipv4_dst(pkt: bytes):
    """Destination address (dotted-quad) of a raw IPv4 packet, or None if the
    buffer is not a well-formed IPv4 header (wrong version or too short).

    IPv6 and truncated packets return None so the caller can safely drop them.
    """
    if pkt is None or len(pkt) < 20:
        return None
    if (pkt[0] >> 4) != 4:          # IP version nibble
        return None
    return ".".join(str(b) for b in pkt[16:20])


def mac_encap(pkt: bytes) -> bytes:
    """Prepend the macOS utun 4-byte address-family header (AF_INET, big-endian)."""
    return struct.pack(">I", socket.AF_INET) + pkt


def mac_decap(data: bytes) -> bytes:
    """Strip the macOS utun 4-byte address-family header."""
    return data[4:]


def _run(cmd):
    subprocess.run(cmd, check=True)


class TunDevice:
    """A TUN interface presenting raw IPv4 packets via read()/write()."""

    def __init__(self, name: str = None, mtu: int = 1280):
        self._name_req = name
        self.mtu = mtu
        self.name = None
        self._fd = None        # Linux file descriptor
        self._sock = None      # macOS utun control socket
        self._is_mac = (sys.platform == "darwin")

    # -- lifecycle --------------------------------------------------------------

    def open(self):
        if self._is_mac:
            self._open_macos()
        elif sys.platform.startswith("linux"):
            self._open_linux()
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

    def configure(self, overlay_ip: str, cidr: str = OVERLAY_CIDR):
        """Assign the overlay IP to the interface and route the overlay net to it."""
        if self._is_mac:
            # utun is point-to-point: address == destination is the usual idiom.
            _run(["ifconfig", self.name, "inet", overlay_ip, overlay_ip, "up"])
            _run(["ifconfig", self.name, "mtu", str(self.mtu)])
            _run(["route", "-n", "add", "-net", cidr, "-interface", self.name])
        else:
            prefix = cidr.split("/")[1]
            _run(["ip", "addr", "add", f"{overlay_ip}/{prefix}", "dev", self.name])
            _run(["ip", "link", "set", "dev", self.name, "up", "mtu", str(self.mtu)])

    def teardown(self, cidr: str = OVERLAY_CIDR):
        """Best-effort route cleanup. On close the interface itself disappears."""
        if self.name and self._is_mac:
            subprocess.run(["route", "-n", "delete", "-net", cidr, "-interface", self.name],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # -- I/O (raw IPv4) ---------------------------------------------------------

    def read(self) -> bytes:
        if self._is_mac:
            return mac_decap(self._sock.recv(65535 + 4))
        return os.read(self._fd, 65535)

    def write(self, pkt: bytes):
        if self._is_mac:
            self._sock.send(mac_encap(pkt))
        else:
            os.write(self._fd, pkt)

    def close(self):
        self.teardown()
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
