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
_COMMENT = "remotemac"     # identifies our iptables rule for cleanup


class NatError(RuntimeError):
    pass


def iptables_rule_args(overlay_cidr: str, egress: str, action: str):
    """iptables argv for the overlay masquerade rule. `action` is '-A' (append)
    or '-D' (delete); the rule is tagged with a comment so cleanup can find it."""
    return ["iptables", "-t", "nat", action, "POSTROUTING",
            "-s", overlay_cidr, "-o", egress, "-j", "MASQUERADE",
            "-m", "comment", "--comment", _COMMENT]


def _nat_backend():
    """Which NAT backend to use: 'nft' (preferred), else 'iptables', else None."""
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return None


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
        self._backend = None       # 'nft' or 'iptables', chosen at apply()

    def apply(self):
        if not sys.platform.startswith("linux"):
            raise NatError("subnet NAT egress is currently Linux-only")
        backend = _nat_backend()
        if backend is None:
            raise NatError("no supported NAT backend found — install nftables (nft) or iptables")
        egress = self.egress or default_egress()
        if not egress:
            raise NatError("could not determine the egress interface — pass --egress")
        self.egress = egress
        self._backend = backend

        self._prev_forward = _read_sysctl("net.ipv4.ip_forward")
        try:
            _write_sysctl("net.ipv4.ip_forward", "1")
        except OSError as exc:
            raise NatError(f"could not enable IP forwarding: {exc}")

        try:
            if backend == "nft":
                self._apply_nft(egress)
            else:
                self._apply_iptables(egress)
        except NatError:
            self.cleanup()             # restore ip_forward (nothing installed on failure)
            raise
        self._applied = True
        return self

    def _apply_nft(self, egress):
        # Replace any stale table from a previous crashed run, then install fresh.
        # Assumes a single subnet-router process per host (no PID lock); two
        # concurrent apply() calls against the same host would race on this table.
        subprocess.run(["nft", "delete", "table", "ip", _TABLE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            subprocess.run(["nft", "-f", "-"], input=nft_ruleset(self.overlay_cidr, egress),
                           text=True, check=True)
        except subprocess.CalledProcessError as exc:
            raise NatError(f"failed to install nftables rules: {exc}")

    def _apply_iptables(self, egress):
        # Drop any stale copies of our rule (best-effort), then add exactly one.
        for _ in range(8):
            r = subprocess.run(iptables_rule_args(self.overlay_cidr, egress, "-D"),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode != 0:
                break
        try:
            subprocess.run(iptables_rule_args(self.overlay_cidr, egress, "-A"),
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as exc:
            raise NatError(f"failed to install iptables rule: {exc}")

    def cleanup(self):
        if self._applied:
            if self._backend == "iptables":
                subprocess.run(iptables_rule_args(self.overlay_cidr, self.egress, "-D"),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["nft", "delete", "table", "ip", _TABLE],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._applied = False
        if self._prev_forward is not None:
            try:
                _write_sysctl("net.ipv4.ip_forward", self._prev_forward)
            except OSError:
                pass                      # best-effort restore
            self._prev_forward = None
