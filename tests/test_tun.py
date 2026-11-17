"""Root-free unit tests for the IPv4/IPv6 TUN overlay helpers.

The device itself (utun / /dev/net/tun) and OS routing need root, so those are
manual-verified; here we cover packet parsing, command generation, and macOS
AF-header framing.
"""

import socket
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import tun


def _ipv4(dst="100.64.0.7", src="100.64.0.2", payload=b""):
    """Minimal well-formed IPv4 header (20 bytes) with the given addresses."""
    ver_ihl = 0x45                         # version 4, IHL 5 (20-byte header)
    total = 20 + len(payload)
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        ver_ihl, 0, total, 0, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr + payload


def _ipv6(dst="fd12:3456:789a::7", src="fd12:3456:789a::2", payload=b""):
    hdr = struct.pack(">IHBB16s16s", 6 << 28, len(payload), 59, 64,
                      socket.inet_pton(socket.AF_INET6, src),
                      socket.inet_pton(socket.AF_INET6, dst))
    return hdr + payload


class TestParseIPv4Dst(unittest.TestCase):
    def test_extracts_destination(self):
        self.assertEqual(tun.parse_ipv4_dst(_ipv4(dst="100.64.0.7")), "100.64.0.7")
        self.assertEqual(tun.parse_ipv4_dst(_ipv4(dst="10.1.2.3")), "10.1.2.3")

    def test_extracts_with_payload(self):
        self.assertEqual(tun.parse_ipv4_dst(_ipv4(dst="100.127.255.254", payload=b"x" * 100)),
                         "100.127.255.254")

    def test_ipv6_is_rejected(self):
        # Version nibble 6 → not IPv4; must be dropped (None), never misparsed.
        v6 = bytes([0x60]) + b"\x00" * 39
        self.assertIsNone(tun.parse_ipv4_dst(v6))

    def test_truncated_is_rejected(self):
        self.assertIsNone(tun.parse_ipv4_dst(b""))
        self.assertIsNone(tun.parse_ipv4_dst(b"\x45" + b"\x00" * 10))   # < 20 bytes
        self.assertIsNone(tun.parse_ipv4_dst(None))

    def test_bytearray_accepted(self):
        self.assertEqual(tun.parse_ipv4_dst(bytearray(_ipv4(dst="100.64.9.9"))), "100.64.9.9")


class TestParseIPv4Src(unittest.TestCase):
    def test_extracts_source(self):
        self.assertEqual(tun.parse_ipv4_src(_ipv4(src="100.64.0.2")), "100.64.0.2")

    def test_rejects_non_ipv4(self):
        self.assertIsNone(tun.parse_ipv4_src(b"\x60" + b"\x00" * 39))
        self.assertIsNone(tun.parse_ipv4_src(b""))


class TestMacFraming(unittest.TestCase):
    def test_encap_prepends_af_inet_header(self):
        pkt = _ipv4()
        framed = tun.mac_encap(pkt)
        self.assertEqual(framed[:4], struct.pack(">I", socket.AF_INET))
        self.assertEqual(framed[4:], pkt)

    def test_roundtrip(self):
        pkt = _ipv4(dst="100.64.0.42", payload=b"hello")
        self.assertEqual(tun.mac_decap(tun.mac_encap(pkt)), pkt)

    def test_ipv6_family_and_roundtrip(self):
        pkt = _ipv6(payload=b"hello")
        framed = tun.mac_encap(pkt)
        self.assertEqual(framed[:4], struct.pack(">I", socket.AF_INET6))
        self.assertEqual(tun.mac_decap(framed), pkt)
        self.assertEqual(tun.mac_decap(struct.pack(">I", socket.AF_INET) + pkt), b"")


class TestIPv6Packets(unittest.TestCase):
    def test_source_and_destination(self):
        pkt = _ipv6()
        self.assertEqual(tun.parse_ip_src(pkt), "fd12:3456:789a::2")
        self.assertEqual(tun.parse_ip_dst(pkt), "fd12:3456:789a::7")
        self.assertEqual(tun.parse_ip_dst(_ipv4()), "100.64.0.7")

    def test_truncated_and_wrong_version_are_rejected(self):
        pkt = _ipv6(payload=b"payload")
        for bad in (None, b"", pkt[:39], pkt[:-1], b"\x70" + pkt[1:]):
            self.assertIsNone(tun.parse_ip_src(bad))
            self.assertIsNone(tun.parse_ip_dst(bad))


class TestDualStackConfigure(unittest.TestCase):
    def test_linux_adds_ipv6_address(self):
        dev = tun.TunDevice(name="remotemac0")
        dev._is_mac = False
        dev.name = "remotemac0"
        with mock.patch.object(tun, "_run") as run:
            dev.configure("100.64.0.2", overlay_ip6="fd12:3456:789a::2",
                          cidr6="fd12:3456:789a::/64")
        self.assertIn(["ip", "-6", "addr", "add", "fd12:3456:789a::2/64",
                       "dev", "remotemac0"], [call.args[0] for call in run.call_args_list])

    def test_macos_adds_and_removes_ipv6_route(self):
        dev = tun.TunDevice()
        dev._is_mac = True
        dev.name = "utun9"
        with mock.patch.object(tun, "_run") as run, \
             mock.patch.object(tun.subprocess, "run") as cleanup:
            dev.configure("100.64.0.2", overlay_ip6="fd12:3456:789a::2",
                          cidr6="fd12:3456:789a::/64")
            dev.teardown()
        self.assertIn(["ifconfig", "utun9", "inet6", "fd12:3456:789a::2",
                       "prefixlen", "128"], [call.args[0] for call in run.call_args_list])
        self.assertIn(["route", "-n", "add", "-inet6", "-net", "fd12:3456:789a::/64",
                       "-interface", "utun9"], [call.args[0] for call in run.call_args_list])
        self.assertIn(["route", "-n", "delete", "-inet6", "-net", "fd12:3456:789a::/64",
                       "-interface", "utun9"], [call.args[0] for call in cleanup.call_args_list])


class TestUnsupportedPlatform(unittest.TestCase):
    def test_open_raises_on_unknown_platform(self):
        real = sys.platform
        try:
            tun.sys.platform = "sunos5"
            dev = tun.TunDevice()
            dev._is_mac = False
            with self.assertRaises(tun.TunError):
                dev.open()
        finally:
            tun.sys.platform = real


if __name__ == "__main__":
    unittest.main()
