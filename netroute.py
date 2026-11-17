#!/usr/bin/env python3
"""
netroute.py — physical default-route detection + full-tunnel route management.

For a full-tunnel client (`mesh.py --exit-node`), mesh transport sockets are
bound to the physical interface. Two /1 routes then send other IPv4 traffic to
the TUN. No destination-wide host routes are installed: application traffic to
a peer endpoint must not bypass the exit. Route setup fails if either /1 cannot
be installed. macOS + Linux.
"""
import socket
import subprocess
import sys
import threading

SPLIT_DEFAULT = ["0.0.0.0/1", "128.0.0.0/1"]


class RouteError(RuntimeError):
    pass


def parse_linux_default(output: str):
    """Parse `ip route show default` → (gateway, iface) or (None, None)."""
    parts = output.split()
    gw = iface = None
    if "via" in parts:
        i = parts.index("via")
        if i + 1 < len(parts):
            gw = parts[i + 1]
    if "dev" in parts:
        i = parts.index("dev")
        if i + 1 < len(parts):
            iface = parts[i + 1]
    return gw, iface


def parse_macos_default(output: str):
    """Parse `route -n get default` → (gateway, iface) or (None, None)."""
    gw = iface = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
    return gw, iface


def default_route():
    """The system's physical default route as (gateway, iface), or (None, None)."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=3).stdout
            return parse_macos_default(out)
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3).stdout
        return parse_linux_default(out)
    except Exception:
        return None, None


def _run(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        raise RouteError(f"could not run {' '.join(cmd)}: {exc}") from exc
    if result.returncode:
        raise RouteError(f"{' '.join(cmd)} failed: {result.stderr.strip() or result.returncode}")


def _cleanup(cmd):
    """Best-effort teardown after a route has already been installed."""
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def bind_socket(sock: socket.socket, iface: str):
    """Restrict a mesh transport socket to the physical interface before use."""
    try:
        if sys.platform == "darwin":
            sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(iface))  # IP_BOUND_IF
        elif sys.platform.startswith("linux"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
        else:
            raise RouteError(f"binding transport is unsupported on {sys.platform}")
    except OSError as exc:
        raise RouteError(f"could not bind mesh transport to {iface}: {exc}") from exc


def ipv6_default_route_present():
    """Full-tunnel mode is IPv4-only; detect an IPv6 default before enabling it."""
    cmd = (["netstat", "-rn", "-f", "inet6"] if sys.platform == "darwin"
           else ["ip", "-6", "route", "show", "default"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RouteError(f"could not check IPv6 routes: {exc}") from exc
    if result.returncode:
        raise RouteError(f"could not check IPv6 routes: {result.stderr.strip() or result.returncode}")
    if sys.platform == "darwin":
        return any(line.split()[:1] == ["default"] for line in result.stdout.splitlines())
    return bool(result.stdout.strip())


class FullTunnelRoutes:
    """Redirect the IPv4 default route through a TUN device. macOS + Linux."""

    def __init__(self, tun_name: str, gateway: str, phys_iface: str):
        self.tun_name = tun_name
        self.gateway = gateway
        self.phys_iface = phys_iface
        self._is_mac = (sys.platform == "darwin")
        self._lan = set()             # extra LAN CIDRs kept on the physical gateway
        self._split = False
        self._lock = threading.Lock()

    # -- extra LAN routes (kept on the physical gateway) ------------------------

    def install_lan_routes(self, cidrs):
        """Keep `cidrs` (local subnets reached via the LAN router) on the physical
        gateway during full-tunnel. They are more specific than the /1 split, so
        they win. The directly-connected subnet already stays local via its own
        connected route and needs no entry here."""
        with self._lock:
            for cidr in cidrs:
                if cidr in self._lan:
                    continue
                if self._is_mac:
                    _run(["route", "-n", "add", "-net", cidr, self.gateway])
                else:
                    _run(["ip", "route", "add", cidr, "via", self.gateway, "dev", self.phys_iface])
                self._lan.add(cidr)

    # -- split default via the TUN ----------------------------------------------

    def install_split_default(self):
        with self._lock:
            added = []
            try:
                for cidr in SPLIT_DEFAULT:
                    if self._is_mac:
                        _run(["route", "-n", "add", "-net", cidr, "-interface", self.tun_name])
                    else:
                        _run(["ip", "route", "add", cidr, "dev", self.tun_name])
                    added.append(cidr)
            except RouteError:
                for cidr in reversed(added):
                    if self._is_mac:
                        _cleanup(["route", "-n", "delete", "-net", cidr, "-interface", self.tun_name])
                    else:
                        _cleanup(["ip", "route", "del", cidr])
                raise
            self._split = True

    def teardown(self):
        """Remove routes we installed, even when the exit path is already down."""
        with self._lock:
            if self._split:
                for cidr in SPLIT_DEFAULT:
                    if self._is_mac:
                        _cleanup(["route", "-n", "delete", "-net", cidr, "-interface", self.tun_name])
                    else:
                        _cleanup(["ip", "route", "del", cidr])
                self._split = False
            for cidr in list(self._lan):
                if self._is_mac:
                    _cleanup(["route", "-n", "delete", "-net", cidr, self.gateway])
                else:
                    _cleanup(["ip", "route", "del", cidr])
            self._lan.clear()
