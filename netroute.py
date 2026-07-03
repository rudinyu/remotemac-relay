#!/usr/bin/env python3
"""
netroute.py — physical default-route detection + full-tunnel route management.

For a full-tunnel client (`mesh.py --exit-node`) all traffic must go through the
exit, EXCEPT the mesh's own transport (or the encrypted packets would recurse
into the tunnel and deadlock). We achieve that with two layers of routes:

  1. **Pin transport** — add /32 host routes for the coordinator and every peer
     UDP endpoint via the *physical* default gateway. These are the most specific
     routes, so mesh transport keeps using the real interface.
  2. **Redirect the default** — add `0.0.0.0/1` and `128.0.0.0/1` via the TUN.
     Two /1 routes are more specific than `0.0.0.0/0`, so they capture everything
     else and hand it to the exit, without deleting the real default route.

Teardown removes both. The /1 routes vanish when the TUN closes (so a crash
self-heals the default route), but the host-route pins live on the physical
interface and must be removed explicitly. macOS + Linux.
"""
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
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class FullTunnelRoutes:
    """Redirect the default route through a TUN device while pinning mesh
    transport to the physical gateway. Idempotent; macOS + Linux."""

    def __init__(self, tun_name: str, gateway: str, phys_iface: str):
        self.tun_name = tun_name
        self.gateway = gateway
        self.phys_iface = phys_iface
        self._is_mac = (sys.platform == "darwin")
        self._pinned = set()          # transport IPs currently pinned to the phys gw
        self._lan = set()             # extra LAN CIDRs kept on the physical gateway
        self._split = False
        self._lock = threading.Lock()

    # -- transport pins (host routes → physical gateway) ------------------------

    def _pin(self, ip):
        if self._is_mac:
            _run(["route", "-n", "add", "-host", ip, self.gateway])
        else:
            _run(["ip", "route", "add", f"{ip}/32", "via", self.gateway, "dev", self.phys_iface])

    def _unpin(self, ip):
        if self._is_mac:
            _run(["route", "-n", "delete", "-host", ip, self.gateway])
        else:
            _run(["ip", "route", "del", f"{ip}/32"])

    def sync_pins(self, desired_ips):
        """Add/remove host-route pins so exactly `desired_ips` bypass the tunnel."""
        desired = {ip for ip in desired_ips if ip}
        with self._lock:
            for ip in desired - self._pinned:
                self._pin(ip)
                self._pinned.add(ip)
            for ip in self._pinned - desired:
                self._unpin(ip)
                self._pinned.discard(ip)

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
            for cidr in SPLIT_DEFAULT:
                if self._is_mac:
                    _run(["route", "-n", "add", "-net", cidr, "-interface", self.tun_name])
                else:
                    _run(["ip", "route", "add", cidr, "dev", self.tun_name])
            self._split = True

    def teardown(self):
        """Remove the split-default routes, then unpin all transport host routes."""
        with self._lock:
            if self._split:
                for cidr in SPLIT_DEFAULT:
                    if self._is_mac:
                        _run(["route", "-n", "delete", "-net", cidr, "-interface", self.tun_name])
                    else:
                        _run(["ip", "route", "del", cidr])
                self._split = False
            for ip in list(self._pinned):
                self._unpin(ip)
            self._pinned.clear()
            for cidr in list(self._lan):
                if self._is_mac:
                    _run(["route", "-n", "delete", "-net", cidr, self.gateway])
                else:
                    _run(["ip", "route", "del", cidr])
            self._lan.clear()
