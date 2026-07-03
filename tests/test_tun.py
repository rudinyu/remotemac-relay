"""Root-free unit tests for the TUN overlay helpers (Phase 3).

The device itself (utun / /dev/net/tun) and OS routing need root, so those are
manual-verified; here we cover the pure packet logic: IPv4 destination parsing,
safe handling of non-IPv4 / truncated buffers, and the macOS AF-header framing.
"""

import socket
import struct
import sys
import unittest

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
