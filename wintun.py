#!/usr/bin/env python3
"""Wintun packet I/O and temporary Windows overlay routes.

Install the official architecture-matched wintun.dll beside this file (or set
REMOTEMAC_WINTUN_DLL). This module does not bundle the third-party driver.
"""
import ctypes
import ipaddress
import os
import subprocess


_NO_MORE_ITEMS = 259
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xffffffff


class WintunError(RuntimeError):
    pass


def _run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WintunError(f"could not run {' '.join(argv)}: {exc}") from exc
    if result.returncode:
        raise WintunError(f"{' '.join(argv)} failed: "
                          f"{result.stderr.strip() or result.stdout.strip()}")


def _route_cmd(action, cidr, name):
    net = ipaddress.ip_network(cidr, strict=False)
    family = "ipv4" if net.version == 4 else "ipv6"
    return ["netsh", "interface", family, action, "route", f"prefix={net}",
            f"interface={name}", "store=active"]


class WintunDevice:
    def __init__(self, name="remotemac0", mtu=1280):
        self.name = name or "remotemac0"
        self.mtu = mtu
        self._dll = None
        self._adapter = None
        self._session = None
        self._wait = None
        self._routes = []

    def open(self):
        path = os.environ.get("REMOTEMAC_WINTUN_DLL") or os.path.join(
            os.path.dirname(__file__), "wintun.dll")
        if not os.path.isfile(path):
            raise WintunError("wintun.dll not found; put the official DLL beside wintun.py "
                              "or set REMOTEMAC_WINTUN_DLL")
        try:
            dll = ctypes.WinDLL(path, use_last_error=True)
            signatures = {
                "WintunCreateAdapter": ([ctypes.c_wchar_p, ctypes.c_wchar_p,
                                         ctypes.c_void_p], ctypes.c_void_p),
                "WintunCloseAdapter": ([ctypes.c_void_p], None),
                "WintunStartSession": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_void_p),
                "WintunEndSession": ([ctypes.c_void_p], None),
                "WintunGetReadWaitEvent": ([ctypes.c_void_p], ctypes.c_void_p),
                "WintunReceivePacket": ([ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)],
                                        ctypes.c_void_p),
                "WintunReleaseReceivePacket": ([ctypes.c_void_p, ctypes.c_void_p], None),
                "WintunAllocateSendPacket": ([ctypes.c_void_p, ctypes.c_uint32],
                                             ctypes.c_void_p),
                "WintunSendPacket": ([ctypes.c_void_p, ctypes.c_void_p], None),
            }
            for symbol, (args, result) in signatures.items():
                fn = getattr(dll, symbol)
                fn.argtypes, fn.restype = args, result
            adapter = dll.WintunCreateAdapter(self.name, "RemoteMac", None)
            if not adapter:
                raise WintunError(f"WintunCreateAdapter failed: {ctypes.get_last_error()}")
            self._dll, self._adapter = dll, adapter
            session = dll.WintunStartSession(adapter, 0x400000)
            if not session:
                raise WintunError(f"WintunStartSession failed: {ctypes.get_last_error()}")
            self._session = session
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            self._wait = kernel32.WaitForSingleObject
        except (OSError, AttributeError, WintunError) as exc:
            self.close()
            if isinstance(exc, WintunError):
                raise
            raise WintunError(f"could not load Wintun: {exc}") from exc
        return self

    def configure(self, ip4, cidr4, ip6=None, cidr6=None):
        if not self._session:
            raise WintunError("Wintun session is not open")
        if not (1 <= self.mtu <= 65535):
            raise WintunError("invalid Wintun MTU")
        _run(["netsh", "interface", "ipv4", "set", "subinterface", self.name,
              f"mtu={self.mtu}", "store=active"])
        _run(["netsh", "interface", "ipv4", "add", "address", f"name={self.name}",
              f"address={ipaddress.ip_address(ip4)}", "mask=255.255.255.255",
              "store=active"])
        self.add_route(cidr4, check=True)
        if ip6 and cidr6:
            _run(["netsh", "interface", "ipv6", "set", "subinterface", self.name,
                  f"mtu={self.mtu}", "store=active"])
            _run(["netsh", "interface", "ipv6", "add", "address", f"interface={self.name}",
                  f"address={ipaddress.ip_address(ip6)}/128", "store=active"])
            self.add_route(cidr6, check=True)

    def add_route(self, cidr, check=False):
        cmd = _route_cmd("add", cidr, self.name)
        if check:
            _run(cmd)
        else:
            try:
                if subprocess.run(cmd, capture_output=True).returncode:
                    return
            except OSError:
                return
        self._routes.append(str(ipaddress.ip_network(cidr, strict=False)))

    def del_route(self, cidr):
        net = str(ipaddress.ip_network(cidr, strict=False))
        if net in self._routes:
            try:
                subprocess.run(_route_cmd("delete", net, self.name), capture_output=True)
            except OSError:
                pass  # adapter teardown must still close the Wintun session
            finally:
                self._routes.remove(net)

    def read(self, timeout=0.5):
        if not self._session:
            return b""
        size = ctypes.c_uint32()
        ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(size))
        if not ptr and ctypes.get_last_error() == _NO_MORE_ITEMS:
            event = self._dll.WintunGetReadWaitEvent(self._session)
            result = self._wait(event, max(0, int(timeout * 1000)))
            if result == _WAIT_TIMEOUT:
                return b""
            if result == _WAIT_FAILED:
                raise WintunError(f"Wintun wait failed: {ctypes.get_last_error()}")
            ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(size))
        if not ptr:
            if ctypes.get_last_error() == _NO_MORE_ITEMS:
                return b""
            raise WintunError(f"Wintun receive failed: {ctypes.get_last_error()}")
        try:
            return ctypes.string_at(ptr, size.value)
        finally:
            self._dll.WintunReleaseReceivePacket(self._session, ptr)

    def write(self, packet):
        if not self._session:
            raise WintunError("Wintun session is closed")
        if not packet or len(packet) > 65535:
            raise WintunError("invalid IP packet length")
        ptr = self._dll.WintunAllocateSendPacket(self._session, len(packet))
        if not ptr:
            raise WintunError(f"Wintun send buffer unavailable: {ctypes.get_last_error()}")
        ctypes.memmove(ptr, packet, len(packet))
        self._dll.WintunSendPacket(self._session, ptr)

    def close(self):
        for cidr in list(reversed(self._routes)):
            self.del_route(cidr)
        if self._session:
            self._dll.WintunEndSession(self._session)
            self._session = None
        if self._adapter:
            self._dll.WintunCloseAdapter(self._adapter)
            self._adapter = None
