#!/usr/bin/env python3
"""Windows NRPT split-DNS configuration with crash recovery.

Only a rule owned by this process is removed. A saved rule tag allows the next
run to clean up after an abrupt exit without touching unrelated NRPT rules.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid


class WindnsError(RuntimeError):
    pass


_DISPLAY = "RemoteMac mesh DNS"
_TAG_RE = re.compile(r"remotemac-mesh-dns:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_SUFFIX_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _ps_quote(value):
    return "'" + value.replace("'", "''") + "'"


def _ps_run(script):
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Stop'; " + script],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WindnsError(f"Windows NRPT command failed: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise WindnsError(f"Windows NRPT command failed: {detail[:500]}")
    return result.stdout.strip()


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _namespace_conflicts(rule, namespace):
    """An exact or more-specific NRPT rule can intercept a mesh name."""
    return any(isinstance(value, str) and value.lower().rstrip(".").endswith(namespace)
               for value in _as_list(rule.get("Namespace")))


class NrptConfig:
    def __init__(self, suffix, dns_ip="127.0.0.1", state_path=None):
        suffix = suffix.strip(".").lower()
        if not suffix or len(suffix) > 253 or not all(_SUFFIX_RE.fullmatch(p)
                                                       for p in suffix.split(".")):
            raise WindnsError("invalid DNS suffix for NRPT")
        if dns_ip != "127.0.0.1" or not ipaddress.ip_address(dns_ip).is_loopback:
            raise WindnsError("Windows NRPT requires the local 127.0.0.1 resolver")
        self.namespace = "." + suffix
        self.dns_ip = dns_ip
        self.state_path = state_path or os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"), "RemoteMac", "dns-nrpt.json")
        self.lock_path = self.state_path + ".lock"
        self._lock_fd = None
        self._applied = False

    def _acquire_lock(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if sys.platform == "win32":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as exc:
            os.close(fd)
            raise WindnsError("another mesh process owns the Windows DNS rule") from exc
        self._lock_fd = fd

    def _release_lock(self):
        if self._lock_fd is None:
            return
        fd, self._lock_fd = self._lock_fd, None
        try:
            if sys.platform == "win32":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _rules(self):
        output = _ps_run("Get-DnsClientNrptRule | "
                         "Select-Object Name,Namespace,NameServers,Comment,DisplayName | "
                         "ConvertTo-Json -Compress -Depth 4")
        if not output:
            return []
        try:
            rules = _as_list(json.loads(output))
        except (ValueError, TypeError) as exc:
            raise WindnsError("invalid NRPT rule response") from exc
        if not all(isinstance(rule, dict) for rule in rules):
            raise WindnsError("invalid NRPT rule response")
        return rules

    def _read_state(self):
        if os.path.islink(self.state_path):
            raise WindnsError("NRPT state file is a symlink")
        try:
            with open(self.state_path) as f:
                state = json.load(f)
        except (OSError, ValueError) as exc:
            raise WindnsError("cannot read saved NRPT state") from exc
        if (not isinstance(state, dict) or not _TAG_RE.fullmatch(str(state.get("tag", "")))
                or not isinstance(state.get("namespace"), str)
                or not state["namespace"].startswith(".")
                or not all(_SUFFIX_RE.fullmatch(p) for p in state["namespace"][1:].split("."))
                or state.get("dns_ip") != "127.0.0.1"):
            raise WindnsError("invalid saved NRPT state")
        return state

    def _remove_saved_rule(self):
        if os.path.islink(self.state_path):
            raise WindnsError("NRPT state file is a symlink")
        if not os.path.exists(self.state_path):
            return
        state = self._read_state()
        tagged = [r for r in self._rules() if r.get("Comment") == state["tag"]]
        if len(tagged) > 1:
            raise WindnsError("multiple NRPT rules share the saved mesh tag")
        if tagged:
            rule = tagged[0]
            if (rule.get("DisplayName") != _DISPLAY
                    or [str(n).lower() for n in _as_list(rule.get("Namespace"))]
                       != [state["namespace"]]
                    or _as_list(rule.get("NameServers")) != [state["dns_ip"]]
                    or not isinstance(rule.get("Name"), str)):
                raise WindnsError("saved NRPT rule changed; refusing to remove it")
            _ps_run("Remove-DnsClientNrptRule -Name " + _ps_quote(rule["Name"]) +
                    " -Force | Out-Null")
        os.unlink(self.state_path)

    def apply(self):
        if self._applied:
            raise WindnsError("NRPT rule is already active")
        self._acquire_lock()
        try:
            self._remove_saved_rule()  # recover a rule left by a crashed process
            if any(_namespace_conflicts(r, self.namespace) for r in self._rules()):
                raise WindnsError(f"an NRPT rule already overlaps {self.namespace}")
            tag = "remotemac-mesh-dns:" + str(uuid.uuid4())
            if os.path.lexists(self.state_path):
                raise WindnsError("NRPT state file appeared while installing rule")
            fd, tmp = tempfile.mkstemp(prefix=".dns-nrpt-",
                                        dir=os.path.dirname(self.state_path))
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump({"tag": tag, "namespace": self.namespace,
                               "dns_ip": self.dns_ip}, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.state_path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            try:
                _ps_run("Add-DnsClientNrptRule -Namespace " + _ps_quote(self.namespace) +
                        " -NameServers " + _ps_quote(self.dns_ip) +
                        " -DisplayName " + _ps_quote(_DISPLAY) +
                        " -Comment " + _ps_quote(tag) + " | Out-Null")
            except WindnsError:
                self._remove_saved_rule()
                raise
            self._applied = True
            return self
        except Exception:
            self._release_lock()
            raise

    def restore(self):
        if not self._applied:
            return
        try:
            self._remove_saved_rule()
            self._applied = False
        finally:
            self._release_lock()
