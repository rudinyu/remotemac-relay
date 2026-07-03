"""Root-free unit tests for the full-tunnel route manager (Phase 5).

Applying real routes needs root, so that's manual-verified; here we cover the
default-route parsers and the host-route pin diff logic.
"""

import sys
import unittest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import netroute


class TestDefaultRouteParsers(unittest.TestCase):
    def test_linux(self):
        self.assertEqual(
            netroute.parse_linux_default("default via 192.168.0.1 dev eth0 proto dhcp metric 100"),
            ("192.168.0.1", "eth0"))

    def test_linux_missing_parts(self):
        self.assertEqual(netroute.parse_linux_default(""), (None, None))
        self.assertEqual(netroute.parse_linux_default("default dev tun0"), (None, "tun0"))

    def test_macos(self):
        out = (
            "   route to: default\n"
            "destination: default\n"
            "       mask: default\n"
            "    gateway: 192.168.1.254\n"
            "  interface: en0\n"
            "      flags: <UP,GATEWAY,DONE,STATIC>\n"
        )
        self.assertEqual(netroute.parse_macos_default(out), ("192.168.1.254", "en0"))

    def test_macos_missing(self):
        self.assertEqual(netroute.parse_macos_default("route to: default\n"), (None, None))


class TestPinDiff(unittest.TestCase):
    def setUp(self):
        # Force a known platform and stub the actual route commands so no privilege
        # is needed; we only assert the tracked pin set converges to `desired`.
        self.ftr = netroute.FullTunnelRoutes("remotemac0", "10.0.0.1", "eth0")
        self.pinned_calls = []
        self.unpinned_calls = []
        self.ftr._pin = lambda ip: self.pinned_calls.append(ip)
        self.ftr._unpin = lambda ip: self.unpinned_calls.append(ip)

    def test_sync_adds_and_removes_incrementally(self):
        self.ftr.sync_pins({"1.1.1.1", "2.2.2.2"})
        self.assertEqual(sorted(self.pinned_calls), ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(self.ftr._pinned, {"1.1.1.1", "2.2.2.2"})

        # A second sync only touches the delta: drop 2.2.2.2, add 3.3.3.3.
        self.pinned_calls.clear()
        self.ftr.sync_pins({"1.1.1.1", "3.3.3.3"})
        self.assertEqual(self.pinned_calls, ["3.3.3.3"])
        self.assertEqual(self.unpinned_calls, ["2.2.2.2"])
        self.assertEqual(self.ftr._pinned, {"1.1.1.1", "3.3.3.3"})

    def test_sync_skips_falsy_ips(self):
        self.ftr.sync_pins({"1.1.1.1", "", None})
        self.assertEqual(self.ftr._pinned, {"1.1.1.1"})

    def test_teardown_unpins_all(self):
        self.ftr.sync_pins({"1.1.1.1", "2.2.2.2"})
        self.unpinned_calls.clear()
        self.ftr.teardown()
        self.assertEqual(sorted(self.unpinned_calls), ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(self.ftr._pinned, set())


if __name__ == "__main__":
    unittest.main()
