"""Root-free unit tests for the Linux subnet-NAT helpers (Phase 4).

Applying the rules needs root + nftables, so that path is manual-verified; here
we cover the pure ruleset generator and the egress-interface parser.
"""

import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
