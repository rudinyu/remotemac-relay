"""Root-free unit tests for the Linux subnet-NAT helpers (Phase 4).

Applying the rules needs root + nftables, so that path is manual-verified; here
we cover the pure ruleset generator and the egress-interface parser.
"""

import sys
import subprocess
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import nat


class TestNftRuleset(unittest.TestCase):
    def test_contains_dedicated_table_and_masquerade(self):
        rs = nat.nft_ruleset("100.64.0.0/10", "eth0")
        self.assertIn("table ip remotemac", rs)
        self.assertIn("type nat hook postrouting priority srcnat", rs)
        self.assertIn('ip saddr 100.64.0.0/10 oifname "eth0" masquerade', rs)

    def test_has_no_forward_base_chain(self):
        # A forward base chain would either be a no-op (policy accept) or would
        # drop unrelated host forwarding (policy drop) — we install neither.
        self.assertNotIn("hook forward", nat.nft_ruleset("100.64.0.0/10", "eth0"))

    def test_egress_is_interpolated(self):
        self.assertIn('oifname "wg-egress" masquerade',
                      nat.nft_ruleset("100.64.0.0/10", "wg-egress"))

    def test_ipv6_masquerade_is_scoped_to_ula(self):
        rs = nat.nft_ruleset("100.64.0.0/10", "eth0", "fd12:3456:789a::/64")
        self.assertIn("table ip6 remotemac6", rs)
        self.assertIn('ip6 saddr fd12:3456:789a::/64 oifname "eth0" masquerade', rs)


class TestEgressParse(unittest.TestCase):
    def test_parses_dev_from_default_route(self):
        self.assertEqual(
            nat._egress_from_ip_route("default via 192.168.0.1 dev eth0 proto dhcp metric 100"),
            "eth0")

    def test_handles_missing_dev(self):
        self.assertIsNone(nat._egress_from_ip_route("something unexpected"))
        self.assertIsNone(nat._egress_from_ip_route(""))
        self.assertIsNone(nat._egress_from_ip_route("default via 10.0.0.1 dev"))  # trailing dev


class TestIptablesFallback(unittest.TestCase):
    def test_rule_args_add_and_delete(self):
        add = nat.iptables_rule_args("100.64.0.0/10", "eth0", "-A")
        self.assertEqual(add[:5], ["iptables", "-t", "nat", "-A", "POSTROUTING"])
        self.assertIn("MASQUERADE", add)
        self.assertEqual(add[add.index("-s") + 1], "100.64.0.0/10")
        self.assertEqual(add[add.index("-o") + 1], "eth0")
        self.assertEqual(add[-1], "remotemac")            # comment tag for cleanup
        # The delete form is identical except the action verb.
        dele = nat.iptables_rule_args("100.64.0.0/10", "eth0", "-D")
        self.assertEqual(dele, ["-D" if a == "-A" else a for a in add])
        self.assertEqual(nat.ip6tables_rule_args("fd12::/64", "eth0", "-A")[:5],
                         ["ip6tables", "-t", "nat", "-A", "POSTROUTING"])

    def test_backend_selection(self):
        real = nat.shutil.which
        try:
            nat.shutil.which = lambda cmd: "/usr/sbin/nft" if cmd == "nft" else None
            self.assertEqual(nat._nat_backend(), "nft")
            nat.shutil.which = lambda cmd: "/sbin/iptables" if cmd == "iptables" else None
            self.assertEqual(nat._nat_backend(), "iptables")   # nft absent → iptables
            nat.shutil.which = lambda cmd: None
            self.assertIsNone(nat._nat_backend())              # neither → None
        finally:
            nat.shutil.which = real


class TestSubnetNatPlatformGuard(unittest.TestCase):
    def test_apply_rejects_non_linux(self):
        real = sys.platform
        try:
            nat.sys.platform = "darwin"
            with self.assertRaises(nat.NatError):
                nat.SubnetNat("100.64.0.0/10", "en0").apply()
        finally:
            nat.sys.platform = real

    def test_dual_stack_nft_restores_both_forwarding_values(self):
        values = {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
        commands = []
        ra_writes = []
        def run(cmd, **kwargs):
            commands.append((cmd, kwargs.get("input")))
            return subprocess.CompletedProcess(cmd, 0)
        with mock.patch.object(nat.sys, "platform", "linux"), \
             mock.patch.object(nat, "_nat_backend", return_value="nft"), \
             mock.patch.object(nat, "_read_sysctl", side_effect=lambda k: values[k]), \
             mock.patch.object(nat, "_write_sysctl", side_effect=lambda k, v: values.__setitem__(k, v)), \
             mock.patch.object(nat, "_read_accept_ra", return_value="1"), \
             mock.patch.object(nat, "_write_accept_ra", side_effect=lambda _e, v: ra_writes.append(v)), \
             mock.patch.object(nat.subprocess, "run", side_effect=run):
            gateway = nat.SubnetNat("100.64.0.0/10", "eth0", "fd12::/64").apply()
            self.assertEqual(list(values.values()), ["1", "1"])
            gateway.cleanup()
        self.assertEqual(list(values.values()), ["0", "0"])
        self.assertEqual(ra_writes, ["2", "1"])
        self.assertTrue(any(cmd[:4] == ["nft", "delete", "table", "ip6"] for cmd, _ in commands))
        self.assertTrue(any(inp and "table ip6 remotemac6" in inp for _, inp in commands))

    def test_ipv6_iptables_failure_removes_ipv4_rule(self):
        commands = []
        def run(cmd, **kwargs):
            commands.append(cmd)
            if cmd[0] == "ip6tables" and "-A" in cmd:
                raise OSError("ip6tables unavailable")
            return subprocess.CompletedProcess(cmd, 0 if "-A" in cmd else 1)
        with mock.patch.object(nat.sys, "platform", "linux"), \
             mock.patch.object(nat, "_nat_backend", return_value="iptables"), \
             mock.patch.object(nat.shutil, "which", return_value="/sbin/ip6tables"), \
             mock.patch.object(nat, "_read_sysctl", return_value="0"), \
             mock.patch.object(nat, "_write_sysctl"), \
             mock.patch.object(nat, "_read_accept_ra", return_value="2"), \
             mock.patch.object(nat.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(nat.NatError, "ip6tables unavailable"):
                nat.SubnetNat("100.64.0.0/10", "eth0", "fd12::/64").apply()
        self.assertTrue(any(cmd[0] == "iptables" and "-A" in cmd for cmd in commands))
        self.assertTrue(any(cmd[0] == "iptables" and "-D" in cmd
                            for cmd in commands[2:]))

    def test_cleanup_restores_forwarding_even_if_rule_delete_fails(self):
        gateway = nat.SubnetNat("100.64.0.0/10", "eth0", "fd12::/64")
        gateway._backend = "nft"
        gateway._applied = True
        gateway._prev_forward = gateway._prev_forward6 = "0"
        writes = []
        with mock.patch.object(nat.subprocess, "run", side_effect=OSError("nft missing")), \
             mock.patch.object(nat, "_write_sysctl", side_effect=lambda k, v: writes.append((k, v))):
            with self.assertRaisesRegex(nat.NatError, "cleanup incomplete"):
                gateway.cleanup()
        self.assertEqual(writes, [("net.ipv4.ip_forward", "0"),
                                  ("net.ipv6.conf.all.forwarding", "0")])
        self.assertTrue(gateway._applied)

    def test_invalid_egress_cannot_inject_nft_rules_or_sysctl_path(self):
        with mock.patch.object(nat.sys, "platform", "linux"), \
             mock.patch.object(nat, "_nat_backend", return_value="nft"):
            with self.assertRaisesRegex(nat.NatError, "invalid egress"):
                nat.SubnetNat("100.64.0.0/10", 'eth0"; delete table ip filter').apply()


if __name__ == "__main__":
    unittest.main()
