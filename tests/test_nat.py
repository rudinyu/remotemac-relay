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
