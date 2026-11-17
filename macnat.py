#!/usr/bin/env python3
"""Scoped IPv4 NAT for a macOS mesh gateway (subnet router or exit node).

The stock macOS PF ruleset evaluates ``com.apple/*`` NAT anchors. We load only
our own anchor, use PF's reference-counted enable token, and hold a process
lock so two mesh gateways cannot overwrite each other's rules. A small state
file lets the next run clean up after an ungraceful exit.
"""
import fcntl
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys


ANCHOR = "com.apple/remotemac"
STATE_PATH = "/var/run/remotemac-pf.json"
_FORWARD = "net.inet.ip.forwarding"


class MacNatError(RuntimeError):
    pass


def _run(argv, input_text=None):
    try:
        result = subprocess.run(argv, input=input_text, capture_output=True,
                                text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MacNatError(f"could not run {' '.join(argv)}: {exc}") from exc
    if result.returncode:
        raise MacNatError(f"{' '.join(argv)} failed: "
                          f"{result.stderr.strip() or result.stdout.strip() or result.returncode}")
    return result


def _rule(cidr, egress):
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise MacNatError(f"invalid overlay CIDR: {cidr}") from exc
    if net.version != 4:
        raise MacNatError("macOS gateway NAT supports IPv4 only")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", egress or ""):
        raise MacNatError(f"invalid egress interface: {egress!r}")
    return f"nat on {egress} inet from {net} to any -> ({egress})\n"


def _token_from(output):
    match = re.search(r"\bToken\s*:\s*([0-9]+)\b", output, re.IGNORECASE)
    if not match:
        raise MacNatError("pfctl enabled PF but did not return a release token")
    return match.group(1)


class MacNat:
    """Manage a single macOS PF NAT rule and IPv4 forwarding."""

    def __init__(self, overlay_cidr, egress=None, tun_name=None, state_path=STATE_PATH):
        self.overlay_cidr = overlay_cidr
        self.egress = egress
        self.tun_name = tun_name
        self.state_path = state_path
        self._lock_fd = None
        self._anchor_loaded = False
        self._token = None
        self._prev_forward = None
        self._state_written = False

    def _lock(self):
        if self._lock_fd is not None:
            raise MacNatError("macOS gateway NAT is already active")
        try:
            fd = os.open(self.state_path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if "fd" in locals():
                os.close(fd)
            raise MacNatError(f"another macOS mesh gateway is active or state lock failed: {exc}") from exc
        self._lock_fd = fd

    def _unlock(self):
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    def _forwarding(self):
        value = _run(["sysctl", "-n", _FORWARD]).stdout.strip()
        if value not in ("0", "1"):
            raise MacNatError(f"unexpected {_FORWARD} value: {value!r}")
        return value

    def _set_forwarding(self, value):
        _run(["sysctl", "-w", f"{_FORWARD}={value}"])

    def _recover(self):
        """Clear only a rule/token recorded by a previous crashed run."""
        try:
            with open(self.state_path) as f:
                old = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise MacNatError(f"cannot read prior PF state: {exc}") from exc
        if not isinstance(old, dict):
            raise MacNatError("invalid prior PF state; refusing to overwrite its anchor")
        token, prev = old.get("token"), old.get("previous_forwarding")
        if not isinstance(token, str) or not token.isdecimal() or prev not in ("0", "1"):
            raise MacNatError("invalid prior PF state; refusing to overwrite its anchor")
        _run(["pfctl", "-a", ANCHOR, "-F", "nat"])
        if self._forwarding() != prev:
            self._set_forwarding(prev)
        _run(["pfctl", "-X", token])
        os.unlink(self.state_path)
        return prev

    def apply(self):
        if sys.platform != "darwin":
            raise MacNatError("macOS PF NAT requires macOS")
        if self.egress is None:
            import netroute
            _gateway, self.egress = netroute.default_route()
        if self.egress == self.tun_name:
            raise MacNatError("egress interface cannot be the mesh TUN")
        rule = _rule(self.overlay_cidr, self.egress)
        try:
            socket.if_nametoindex(self.egress)
        except OSError as exc:
            raise MacNatError(f"egress interface {self.egress} does not exist: {exc}") from exc
        self._lock()
        try:
            previous = self._recover()
            nat_rules = _run(["pfctl", "-sn"]).stdout
            if not any(line.strip().startswith("nat-anchor ") and "com.apple/*" in line
                       for line in nat_rules.splitlines()):
                raise MacNatError("the active PF ruleset lacks the com.apple/* NAT anchor")
            if (_run(["pfctl", "-a", ANCHOR, "-sn"]).stdout.strip()
                    or _run(["pfctl", "-a", ANCHOR, "-sr"]).stdout.strip()):
                raise MacNatError(f"PF anchor {ANCHOR} already has rules")
            _run(["pfctl", "-n", "-a", ANCHOR, "-f", "-"], input_text=rule)
            current = self._forwarding()
            self._prev_forward = previous if previous is not None else current
            if current != "1":
                self._set_forwarding("1")
            _run(["pfctl", "-a", ANCHOR, "-f", "-"], input_text=rule)
            self._anchor_loaded = True
            enabled = _run(["pfctl", "-E"])
            self._token = _token_from(enabled.stdout + enabled.stderr)
            tmp = self.state_path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    os.chmod(tmp, 0o600)
                    json.dump({"token": self._token,
                               "previous_forwarding": self._prev_forward}, f)
                os.replace(tmp, self.state_path)
                self._state_written = True
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
            return self
        except Exception as exc:
            try:
                self.cleanup()
            except MacNatError as cleanup_exc:
                raise MacNatError(f"{exc}; rollback also failed: {cleanup_exc}") from exc
            if isinstance(exc, MacNatError):
                raise
            raise MacNatError(f"macOS NAT setup failed: {exc}") from exc

    def cleanup(self):
        """Restore only state this instance changed; keep state file on failure."""
        errors = []
        try:
            if self._anchor_loaded:
                try:
                    _run(["pfctl", "-a", ANCHOR, "-F", "nat"])
                    self._anchor_loaded = False
                except MacNatError as exc:
                    errors.append(str(exc))
            if self._prev_forward is not None and not self._anchor_loaded:
                try:
                    if self._forwarding() != self._prev_forward:
                        self._set_forwarding(self._prev_forward)
                    self._prev_forward = None
                except MacNatError as exc:
                    errors.append(str(exc))
            if self._token and not errors:
                try:
                    _run(["pfctl", "-X", self._token])
                    self._token = None
                except MacNatError as exc:
                    errors.append(str(exc))
            if self._state_written and not errors:
                try:
                    os.unlink(self.state_path)
                    self._state_written = False
                except OSError as exc:
                    errors.append(f"could not remove PF state: {exc}")
        finally:
            self._unlock()
        if errors:
            raise MacNatError("; ".join(errors))
