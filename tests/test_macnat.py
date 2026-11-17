"""Root-free checks for the macOS PF gateway setup and rollback."""
import os
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import macnat


class TestRule(unittest.TestCase):
    def test_rule_is_scoped_to_overlay_and_egress(self):
        self.assertEqual(macnat._rule("100.64.0.0/10", "en0"),
                         "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n")

    def test_egress_cannot_inject_pf_rules(self):
        with self.assertRaises(macnat.MacNatError):
            macnat._rule("100.64.0.0/10", "en0\npass all")
        with self.assertRaises(macnat.MacNatError):
            macnat._rule("fd12::/64", "en0")

    def test_ipv6_nat_rule_is_scoped_to_ula(self):
        self.assertIn("nat on en0 inet6 from fd12::/64 to any -> (en0)",
                      macnat._rule("100.64.0.0/10", "en0", "fd12::/64"))


class TestMacNatLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "pf.json")
        self.forwarding = "0"
        self.forwarding6 = "0"
        self.calls = []
        self.fail_on = None
        self.hook = True
        self.occupied = False

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, argv, input_text=None):
        self.calls.append((argv, input_text))
        if argv == self.fail_on:
            raise macnat.MacNatError("simulated pfctl failure")
        if argv == ["pfctl", "-sn"]:
            out = 'nat-anchor "com.apple/*" all\n' if self.hook else ""
        elif argv == ["pfctl", "-a", macnat.ANCHOR, "-sn"]:
            out = "nat on en0 from any to any -> (en0)\n" if self.occupied else ""
        elif argv == ["sysctl", "-n", "net.inet.ip.forwarding"]:
            out = self.forwarding + "\n"
        elif argv == ["sysctl", "-n", "net.inet6.ip6.forwarding"]:
            out = self.forwarding6 + "\n"
        elif argv[:2] == ["sysctl", "-w"]:
            if argv[-1].startswith("net.inet6.ip6.forwarding="):
                self.forwarding6 = argv[-1].rsplit("=", 1)[1]
            else:
                self.forwarding = argv[-1].rsplit("=", 1)[1]
            out = ""
        elif argv == ["pfctl", "-E"]:
            out = "Token : 12345\n"
        else:
            out = ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    def _make(self, cidr6=None):
        return macnat.MacNat("100.64.0.0/10", "en0", "utun9", self.state,
                             overlay_cidr6=cidr6)

    def _patches(self):
        return (mock.patch.object(macnat.sys, "platform", "darwin"),
                mock.patch.object(macnat.socket, "if_nametoindex", return_value=4),
                mock.patch.object(macnat, "_run", side_effect=self._run))

    def test_apply_and_cleanup_restore_forwarding_and_pf_reference(self):
        platform, iface, run = self._patches()
        with platform, iface, run:
            nat = self._make().apply()
            self.assertEqual(self.forwarding, "1")
            self.assertTrue(os.path.exists(self.state))
            nat.cleanup()
        self.assertEqual(self.forwarding, "0")
        self.assertFalse(os.path.exists(self.state))
        commands = [cmd for cmd, _ in self.calls]
        self.assertIn(["pfctl", "-n", "-a", macnat.ANCHOR, "-f", "-"], commands)
        self.assertIn(["pfctl", "-a", macnat.ANCHOR, "-f", "-"], commands)
        self.assertIn(["pfctl", "-a", macnat.ANCHOR, "-F", "nat"], commands)
        self.assertIn(["pfctl", "-X", "12345"], commands)
        self.assertFalse(any(cmd == ["pfctl", "-d"] or cmd == ["pfctl", "-F", "all"]
                             for cmd in commands))

    def test_failed_enable_rolls_back_rule_and_forwarding(self):
        self.fail_on = ["pfctl", "-E"]
        platform, iface, run = self._patches()
        with platform, iface, run:
            with self.assertRaisesRegex(macnat.MacNatError, "simulated"):
                self._make().apply()
        commands = [cmd for cmd, _ in self.calls]
        self.assertIn(["pfctl", "-a", macnat.ANCHOR, "-F", "nat"], commands)
        self.assertEqual(self.forwarding, "0")
        self.assertFalse(os.path.exists(self.state))

    def test_dual_stack_nat_restores_ipv6_forwarding(self):
        platform, iface, run = self._patches()
        with platform, iface, run:
            gateway = self._make("fd12::/64").apply()
            self.assertEqual((self.forwarding, self.forwarding6), ("1", "1"))
            with open(self.state) as f:
                self.assertEqual(json.load(f)["previous_forwarding6"], "0")
            gateway.cleanup()
        self.assertEqual((self.forwarding, self.forwarding6), ("0", "0"))
        self.assertTrue(any(text and "inet6 from fd12::/64" in text
                            for _, text in self.calls))

    def test_missing_nat_anchor_fails_before_changing_system_state(self):
        self.hook = False
        platform, iface, run = self._patches()
        with platform, iface, run:
            with self.assertRaisesRegex(macnat.MacNatError, "lacks"):
                self._make().apply()
        self.assertFalse(any(cmd[:2] == ["sysctl", "-w"] for cmd, _ in self.calls))

    def test_existing_anchor_is_not_overwritten(self):
        self.occupied = True
        platform, iface, run = self._patches()
        with platform, iface, run:
            with self.assertRaisesRegex(macnat.MacNatError, "already has rules"):
                self._make().apply()
        self.assertFalse(any(cmd == ["pfctl", "-a", macnat.ANCHOR, "-f", "-"]
                             for cmd, _ in self.calls))

    def test_stale_state_is_recovered_before_new_rule(self):
        with open(self.state, "w") as f:
            json.dump({"token": "99999", "previous_forwarding": "0"}, f)
        self.forwarding = "1"
        platform, iface, run = self._patches()
        with platform, iface, run:
            nat = self._make().apply()
            nat.cleanup()
        commands = [cmd for cmd, _ in self.calls]
        self.assertLess(commands.index(["pfctl", "-X", "99999"]),
                        commands.index(["pfctl", "-E"]))
        self.assertEqual(self.forwarding, "0")
        self.assertFalse(os.path.exists(self.state))

    def test_failed_cleanup_keeps_state_for_next_run(self):
        platform, iface, run = self._patches()
        with platform, iface, run:
            nat = self._make().apply()
            self.fail_on = ["pfctl", "-a", macnat.ANCHOR, "-F", "nat"]
            with self.assertRaises(macnat.MacNatError):
                nat.cleanup()
            self.assertTrue(os.path.exists(self.state))
            self.fail_on = None
            self._make().apply().cleanup()
        self.assertFalse(os.path.exists(self.state))


if __name__ == "__main__":
    unittest.main()
