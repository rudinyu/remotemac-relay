"""Root-free Windows NRPT lifecycle tests using a PowerShell stub."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import windns


class TestNrptConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "nrpt.json")
        self.rules = []
        self.calls = []
        self.ps_patch = mock.patch.object(windns, "_ps_run", side_effect=self._powershell)
        self.ps_patch.start()

    def tearDown(self):
        self.ps_patch.stop()
        self.tmp.cleanup()

    def _powershell(self, script):
        self.calls.append(script)
        if script.startswith("Get-DnsClientNrptRule"):
            return json.dumps(self.rules)
        if script.startswith("Add-DnsClientNrptRule"):
            with open(self.state) as f:
                state = json.load(f)
            self.rules.append({"Name": "{test-guid}", "Namespace": state["namespace"],
                               "NameServers": state["dns_ip"], "Comment": state["tag"],
                               "DisplayName": "RemoteMac mesh DNS"})
            return ""
        if script.startswith("Remove-DnsClientNrptRule"):
            self.rules.clear()
            return ""
        self.fail("unexpected PowerShell command: " + script)

    def _config(self):
        return windns.NrptConfig("mesh", state_path=self.state)

    def test_apply_and_restore_only_owned_rule(self):
        cfg = self._config().apply()
        self.assertEqual(len(self.rules), 1)
        self.assertEqual(self.rules[0]["Namespace"], ".mesh")
        self.assertTrue(os.path.exists(self.state))
        cfg.restore()
        self.assertEqual(self.rules, [])
        self.assertFalse(os.path.exists(self.state))

    def test_existing_rule_blocks_apply(self):
        self.rules = [{"Name": "other", "Namespace": ".mesh",
                       "NameServers": "1.1.1.1", "Comment": "someone-else"}]
        with self.assertRaisesRegex(windns.WindnsError, "already overlaps"):
            self._config().apply()
        self.assertEqual(len(self.rules), 1)
        self.assertFalse(os.path.exists(self.state))

    def test_more_specific_rule_blocks_apply(self):
        self.rules = [{"Name": "other", "Namespace": "GW.Mesh",
                       "NameServers": "1.1.1.1", "Comment": "someone-else"}]
        with self.assertRaisesRegex(windns.WindnsError, "already overlaps"):
            self._config().apply()
        self.assertEqual(len(self.rules), 1)

    def test_crash_recovery_replaces_only_previous_owned_rule(self):
        first = self._config().apply()
        first_tag = self.rules[0]["Comment"]
        first._release_lock()  # simulate process exit without restore()
        second = self._config().apply()
        self.assertEqual(len(self.rules), 1)
        self.assertNotEqual(self.rules[0]["Comment"], first_tag)
        second.restore()

    def test_changed_rule_is_not_removed(self):
        first = self._config().apply()
        first._release_lock()
        self.rules[0]["NameServers"] = "1.1.1.1"
        with self.assertRaisesRegex(windns.WindnsError, "changed"):
            self._config().apply()
        self.assertTrue(os.path.exists(self.state))
        self.assertEqual(self.rules[0]["NameServers"], "1.1.1.1")

    def test_invalid_saved_state_is_not_used(self):
        with open(self.state, "w") as f:
            json.dump({"tag": "attacker", "namespace": ".mesh",
                       "dns_ip": "127.0.0.1"}, f)
        with self.assertRaisesRegex(windns.WindnsError, "invalid saved"):
            self._config().apply()
        self.assertFalse(any(c.startswith("Remove-") for c in self.calls))

    def test_invalid_suffix_rejected_before_powershell(self):
        with self.assertRaisesRegex(windns.WindnsError, "invalid DNS suffix"):
            windns.NrptConfig("mesh'; Remove-DnsClientNrptRule", state_path=self.state)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
