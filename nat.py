#!/usr/bin/env python3
"""
nat.py — Linux NAT egress for a mesh subnet router (Phase 4).

When a node advertises subnet routes (`mesh.py --advertise-routes`), it must
forward mesh traffic to those subnets and **masquerade** it, so LAN hosts reply
to the router's own address rather than to the (unroutable, unknown) overlay
source. This module enables IP forwarding and installs nftables masquerade
rules in dedicated IPv4 and optional IPv6 tables for scoped teardown.

Linux only (nftables or iptables), needs root. macOS PF egress lives in
``macnat.py``.
"""
import os
import re
import shutil
import subprocess
import sys

_TABLE = "remotemac"
_TABLE6 = "remotemac6"
_COMMENT = "remotemac"     # identifies our iptables rule for cleanup


class NatError(RuntimeError):
    pass


def iptables_rule_args(overlay_cidr: str, egress: str, action: str):
    """iptables argv for the overlay masquerade rule. `action` is '-A' (append)
    or '-D' (delete); the rule is tagged with a comment so cleanup can find it."""
    return ["iptables", "-t", "nat", action, "POSTROUTING",
            "-s", overlay_cidr, "-o", egress, "-j", "MASQUERADE",
            "-m", "comment", "--comment", _COMMENT]


def ip6tables_rule_args(overlay_cidr: str, egress: str, action: str):
    return ["ip6tables", "-t", "nat", action, "POSTROUTING",
            "-s", overlay_cidr, "-o", egress, "-j", "MASQUERADE",
            "-m", "comment", "--comment", _COMMENT]


def _nat_backend():
    """Which NAT backend to use: 'nft' (preferred), else 'iptables', else None."""
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return None


def nft_ruleset(overlay_cidr: str, egress: str, overlay_cidr6: str = None) -> str:
    """The nftables ruleset (for `nft -f -`) that masquerades overlay-sourced
    traffic out `egress`.

    We deliberately install ONLY a scoped masquerade rule and do not add a
    `forward` base chain: a base forward chain with `policy drop` would also drop
    unrelated forwarding on the host (Docker, another VPN, a second NIC), and one
    with the default `policy accept` would be a no-op. Forwarding itself is gated
    by `net.ipv4.ip_forward` (which we enable) plus the host's existing FORWARD
    policy — on a host with a restrictive FORWARD policy, add an allow rule for
    the overlay net manually."""
    rules = (
        f"table ip {_TABLE} {{\n"
        f"    chain postrouting {{\n"
        f"        type nat hook postrouting priority srcnat;\n"
        f'        ip saddr {overlay_cidr} oifname "{egress}" masquerade\n'
        f"    }}\n"
        f"}}\n"
    )
    if overlay_cidr6:
        rules += (f"table ip6 {_TABLE6} {{\n"
                  f"    chain postrouting {{\n"
                  f"        type nat hook postrouting priority srcnat;\n"
                  f'        ip6 saddr {overlay_cidr6} oifname "{egress}" masquerade\n'
                  f"    }}\n"
                  f"}}\n")
    return rules


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


def _accept_ra_path(egress):
    if egress in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", egress or ""):
        raise NatError(f"invalid egress interface: {egress!r}")
    return os.path.join("/proc/sys/net/ipv6/conf", egress, "accept_ra")


def _read_accept_ra(egress):
    try:
        with open(_accept_ra_path(egress)) as f:
            return f.read().strip()
    except OSError:
        return None


def _write_accept_ra(egress, value):
    with open(_accept_ra_path(egress), "w") as f:
        f.write(value)


class SubnetNat:
    """Enable IP forwarding + nftables masquerade for a subnet router, and
    restore the previous state on cleanup()."""

    def __init__(self, overlay_cidr: str, egress: str = None, overlay_cidr6: str = None):
        self.overlay_cidr = overlay_cidr
        self.overlay_cidr6 = overlay_cidr6
        self.egress = egress
        self._prev_forward = None
        self._prev_forward6 = None
        self._prev_accept_ra = None
        self._applied = False
        self._backend = None       # 'nft' or 'iptables', chosen at apply()

    def apply(self):
        if not sys.platform.startswith("linux"):
            raise NatError("subnet NAT egress is currently Linux-only")
        backend = _nat_backend()
        if backend is None:
            raise NatError("no supported NAT backend found — install nftables (nft) or iptables")
        if self.overlay_cidr6 and backend == "iptables" and not shutil.which("ip6tables"):
            raise NatError("IPv6 gateway NAT needs ip6tables or nftables")
        egress = self.egress or default_egress()
        if not egress:
            raise NatError("could not determine the egress interface — pass --egress")
        _accept_ra_path(egress)  # also validate the name before nft rule interpolation
        self.egress = egress
        self._backend = backend

        self._prev_forward = _read_sysctl("net.ipv4.ip_forward")
        if self.overlay_cidr6:
            self._prev_forward6 = _read_sysctl("net.ipv6.conf.all.forwarding")
            previous_ra = _read_accept_ra(egress)
            if previous_ra not in ("0", "1", "2"):
                raise NatError("could not read egress IPv6 accept_ra state")
            # Linux stops accepting Router Advertisements when forwarding is
            # enabled. Preserve an RA-learned IPv6 default route on the egress.
            if self._prev_forward6 == "0" and previous_ra == "1":
                self._prev_accept_ra = previous_ra
        if self._prev_forward not in ("0", "1") or (self.overlay_cidr6 and
                                                    self._prev_forward6 not in ("0", "1")):
            raise NatError("could not read IP forwarding state; refusing to change it")
        try:
            _write_sysctl("net.ipv4.ip_forward", "1")
            if self.overlay_cidr6:
                if self._prev_accept_ra is not None:
                    _write_accept_ra(egress, "2")
                _write_sysctl("net.ipv6.conf.all.forwarding", "1")
            if backend == "nft":
                self._apply_nft(egress)
            else:
                self._apply_iptables(egress)
        except (NatError, OSError) as exc:
            try:
                self.cleanup()
            except NatError as cleanup_exc:
                raise NatError(f"gateway setup failed: {exc}; rollback failed: {cleanup_exc}") from exc
            raise NatError(f"could not enable gateway NAT/forwarding: {exc}") from exc
        self._applied = True
        return self

    def _apply_nft(self, egress):
        # Replace any stale table from a previous crashed run, then install fresh.
        # Assumes a single subnet-router process per host (no PID lock); two
        # concurrent apply() calls against the same host would race on this table.
        subprocess.run(["nft", "delete", "table", "ip", _TABLE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.overlay_cidr6:
            subprocess.run(["nft", "delete", "table", "ip6", _TABLE6],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            subprocess.run(["nft", "-f", "-"], input=nft_ruleset(self.overlay_cidr, egress,
                                                               self.overlay_cidr6),
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
            if self.overlay_cidr6:
                for _ in range(8):
                    r = subprocess.run(ip6tables_rule_args(self.overlay_cidr6, egress, "-D"),
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if r.returncode != 0:
                        break
                subprocess.run(ip6tables_rule_args(self.overlay_cidr6, egress, "-A"),
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, OSError) as exc:
            try:
                subprocess.run(iptables_rule_args(self.overlay_cidr, egress, "-D"),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass
            raise NatError(f"failed to install iptables rule: {exc}")

    def cleanup(self):
        errors = []
        if self._applied:
            if self._backend == "iptables":
                if self.overlay_cidr6:
                    commands = [ip6tables_rule_args(self.overlay_cidr6, self.egress, "-D")]
                else:
                    commands = []
                commands.append(iptables_rule_args(self.overlay_cidr, self.egress, "-D"))
            else:
                if self.overlay_cidr6:
                    commands = [["nft", "delete", "table", "ip6", _TABLE6]]
                else:
                    commands = []
                commands.append(["nft", "delete", "table", "ip", _TABLE])
            for cmd in commands:
                try:
                    subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                except OSError as exc:
                    errors.append(str(exc))
            if not errors:
                self._applied = False
        if self._prev_forward is not None:
            try:
                _write_sysctl("net.ipv4.ip_forward", self._prev_forward)
            except OSError as exc:
                errors.append(str(exc))
            else:
                self._prev_forward = None
        if self._prev_forward6 is not None:
            try:
                _write_sysctl("net.ipv6.conf.all.forwarding", self._prev_forward6)
            except OSError as exc:
                errors.append(str(exc))
            else:
                self._prev_forward6 = None
        if self._prev_accept_ra is not None:
            try:
                _write_accept_ra(self.egress, self._prev_accept_ra)
            except OSError as exc:
                errors.append(str(exc))
            else:
                self._prev_accept_ra = None
        if errors:
            raise NatError("gateway cleanup incomplete: " + "; ".join(errors))
