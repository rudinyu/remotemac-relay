#!/usr/bin/env python3
"""
nat.py — Linux NAT egress for a mesh subnet router (Phase 4).

When a node advertises subnet routes (`mesh.py --advertise-routes`), it must
forward mesh traffic to those subnets and **masquerade** it, so LAN hosts reply
to the router's own address rather than to the (unroutable, unknown) overlay
source. This module enables IP forwarding and installs an nftables masquerade
rule set in a dedicated table (`remotemac`) so teardown is a single delete.

Linux only (nftables), needs root. NAT egress on macOS (pf) and an iptables
fallback are deferred to a later phase.
"""
import shutil
import subprocess
import sys

_TABLE = "remotemac"


class NatError(RuntimeError):
    pass


def nft_ruleset(overlay_cidr: str, egress: str) -> str:
    """The nftables ruleset (for `nft -f -`) that masquerades overlay-sourced
    traffic out `egress`.

    We deliberately install ONLY a scoped masquerade rule and do not add a
    `forward` base chain: a base forward chain with `policy drop` would also drop
    unrelated forwarding on the host (Docker, another VPN, a second NIC), and one
    with the default `policy accept` would be a no-op. Forwarding itself is gated
    by `net.ipv4.ip_forward` (which we enable) plus the host's existing FORWARD
    policy — on a host with a restrictive FORWARD policy, add an allow rule for
    the overlay net manually."""
    return (
        f"table ip {_TABLE} {{\n"
        f"    chain postrouting {{\n"
        f"        type nat hook postrouting priority srcnat;\n"
        f'        ip saddr {overlay_cidr} oifname "{egress}" masquerade\n'
        f"    }}\n"
        f"}}\n"
    )


def _egress_from_ip_route(output: str):
    """Parse `ip route show default` output → the default route's device name."""
    parts = output.split()
    if "dev" in parts:
        i = parts.index("dev")
        if i + 1 < len(parts):
            return parts[i + 1]
    return None


def default_egress():
    """Best-effort: the interface of the system default route (or None)."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return None
    return _egress_from_ip_route(out)


def _sysctl_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def _read_sysctl(key: str):
    try:
        with open(_sysctl_path(key)) as f:
            return f.read().strip()
    except OSError:
        return None


def _write_sysctl(key: str, value: str):
    with open(_sysctl_path(key), "w") as f:
        f.write(value)


class SubnetNat:
    """Enable IP forwarding + nftables masquerade for a subnet router, and
    restore the previous state on cleanup()."""

    def __init__(self, overlay_cidr: str, egress: str = None):
        self.overlay_cidr = overlay_cidr
        self.egress = egress
        self._prev_forward = None
        self._applied = False

    def apply(self):
        if not sys.platform.startswith("linux"):
            raise NatError("subnet NAT egress is currently Linux-only")
        if shutil.which("nft") is None:
            raise NatError("nftables (nft) not found — install it, or advertise routes on a host with nft")
        egress = self.egress or default_egress()
        if not egress:
            raise NatError("could not determine the egress interface — pass --egress")
        self.egress = egress

        self._prev_forward = _read_sysctl("net.ipv4.ip_forward")
        try:
            _write_sysctl("net.ipv4.ip_forward", "1")
        except OSError as exc:
            raise NatError(f"could not enable IP forwarding: {exc}")

        # Replace any stale table from a previous crashed run, then install fresh.
        # Assumes a single subnet-router process per host (no PID lock); two
        # concurrent apply() calls against the same host would race on this table.
        subprocess.run(["nft", "delete", "table", "ip", _TABLE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            subprocess.run(["nft", "-f", "-"], input=nft_ruleset(self.overlay_cidr, egress),
                           text=True, check=True)
        except subprocess.CalledProcessError as exc:
            self.cleanup()
            raise NatError(f"failed to install nftables rules: {exc}")
        self._applied = True
        return self

    def cleanup(self):
        if self._applied:
            subprocess.run(["nft", "delete", "table", "ip", _TABLE],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._applied = False
        if self._prev_forward is not None:
            try:
                _write_sysctl("net.ipv4.ip_forward", self._prev_forward)
            except OSError:
                pass                      # best-effort restore
            self._prev_forward = None
