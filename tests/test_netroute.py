"""Root-free unit tests for the full-tunnel route manager (Phase 5).

Applying real routes needs root, so that's manual-verified; here we cover the
default-route parsers, failure rollback, and per-socket transport binding.
"""

import subprocess
import sys
import unittest
from unittest import mock

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


class TestFullTunnelSafety(unittest.TestCase):
    def setUp(self):
        self.ftr = netroute.FullTunnelRoutes("remotemac0", "10.0.0.1", "eth0")
        self.ftr._is_mac = False

    def test_command_failure_is_reported(self):
        failed = subprocess.CompletedProcess([], 1, "", "permission denied")
        with mock.patch.object(netroute.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(netroute.RouteError, "permission denied"):
                netroute._run(["ip", "route", "add", "0.0.0.0/1"])

    def test_partial_default_route_is_rolled_back(self):
        adds, cleanups = [], []

        def add(cmd):
            adds.append(cmd)
            if "128.0.0.0/1" in cmd:
                raise netroute.RouteError("second route failed")

        with mock.patch.object(netroute, "_run", side_effect=add), \
             mock.patch.object(netroute, "_cleanup", side_effect=cleanups.append):
            with self.assertRaises(netroute.RouteError):
                self.ftr.install_split_default()
        self.assertFalse(self.ftr._split)
        self.assertEqual(len(adds), 2)
        self.assertEqual(cleanups, [["ip", "route", "del", "0.0.0.0/1",
                                     "dev", "remotemac0"]])

    def test_ipv6_split_routes_are_installed_and_removed(self):
        adds, cleanups = [], []
        with mock.patch.object(netroute, "_run", side_effect=adds.append), \
             mock.patch.object(netroute, "_cleanup", side_effect=cleanups.append):
            self.ftr.install_split_default(ipv6=True)
            self.assertTrue(self.ftr._split6)
            self.ftr.teardown()
        self.assertEqual(len(adds), 4)
        self.assertIn(["ip", "-6", "route", "add", "::/1", "dev", "remotemac0"], adds)
        self.assertIn(["ip", "-6", "route", "del", "8000::/1", "dev", "remotemac0"], cleanups)

    def test_ipv6_route_failure_rolls_back_ipv4_and_ipv6(self):
        adds, cleanups = [], []
        def add(cmd):
            adds.append(cmd)
            if "8000::/1" in cmd:
                raise netroute.RouteError("last route failed")
        with mock.patch.object(netroute, "_run", side_effect=add), \
             mock.patch.object(netroute, "_cleanup", side_effect=cleanups.append):
            with self.assertRaises(netroute.RouteError):
                self.ftr.install_split_default(ipv6=True)
        self.assertFalse(self.ftr._split)
        self.assertEqual(len(adds), 4)
        self.assertEqual(cleanups[0], ["ip", "-6", "route", "del", "::/1",
                                       "dev", "remotemac0"])
        self.assertEqual(len(cleanups), 3)

    def test_transport_socket_binding_is_per_socket(self):
        sock = mock.Mock()
        with mock.patch.object(netroute.sys, "platform", "linux"), \
             mock.patch.object(netroute.socket, "SO_BINDTODEVICE", 25, create=True):
            netroute.bind_socket(sock, "eth0")
        sock.setsockopt.assert_called_once_with(netroute.socket.SOL_SOCKET, 25, b"eth0\0")

    def test_ipv6_default_is_detected(self):
        with mock.patch.object(netroute.sys, "platform", "linux"), \
             mock.patch.object(netroute.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "default via fe80::1", "")):
            self.assertTrue(netroute.ipv6_default_route_present())

    def test_macos_ipv6_route_check_fails_closed(self):
        with mock.patch.object(netroute.sys, "platform", "darwin"), \
             mock.patch.object(netroute.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1, "", "permission denied")):
            with self.assertRaisesRegex(netroute.RouteError, "permission denied"):
                netroute.ipv6_default_route_present()

    def test_macos_ipv6_default_from_routing_table(self):
        table = "Routing tables\nInternet6:\nDestination Gateway Flags Netif\n" \
                "default fe80::%en0 UGc en0\n::1 ::1 UHL lo0\n"
        with mock.patch.object(netroute.sys, "platform", "darwin"), \
             mock.patch.object(netroute.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, table, "")):
            self.assertTrue(netroute.ipv6_default_route_present())


class TestLanRoutes(unittest.TestCase):
    def setUp(self):
        self.ftr = netroute.FullTunnelRoutes("remotemac0", "10.0.0.1", "eth0")
        self.cmds = []
        # Capture the raw route commands without running them (no privilege).
        self.add_patch = mock.patch.object(netroute, "_run", side_effect=self.cmds.append)
        self.cleanup_patch = mock.patch.object(netroute, "_cleanup", side_effect=self.cmds.append)
        self.add_patch.start()
        self.cleanup_patch.start()

    def tearDown(self):
        self.add_patch.stop()
        self.cleanup_patch.stop()

    def test_install_is_idempotent_and_tracked(self):
        self.ftr.install_lan_routes(["10.0.0.0/8", "172.16.0.0/12"])
        n_after_first = len(self.cmds)
        self.ftr.install_lan_routes(["10.0.0.0/8"])          # already present → no-op
        self.assertEqual(len(self.cmds), n_after_first, "re-install issued a duplicate route")
        self.assertEqual(self.ftr._lan, {"10.0.0.0/8", "172.16.0.0/12"})
        # Each CIDR appears in exactly one "add" command, routed via the gateway.
        adds = [c for c in self.cmds if "add" in c]
        self.assertEqual(len(adds), 2)
        for cidr in ("10.0.0.0/8", "172.16.0.0/12"):
            self.assertTrue(any(cidr in c and "10.0.0.1" in c for c in adds))

    def test_teardown_removes_lan_routes(self):
        self.ftr.install_lan_routes(["10.0.0.0/8"])
        self.cmds.clear()
        self.ftr.teardown()
        self.assertEqual(self.ftr._lan, set())
        self.assertTrue(any("delete" in c or "del" in c for c in self.cmds))


if __name__ == "__main__":
    unittest.main()
