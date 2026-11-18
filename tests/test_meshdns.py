"""Tests for the split-DNS resolver (Phase 8). Root-free — the server binds
127.0.0.1 on an ephemeral port and forwards to a stub upstream, so no privilege
and no changes to the system resolver are needed."""

import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import meshdns


def _query(name, qtype=meshdns.QTYPE_A, qid=b"\xab\xcd"):
    header = qid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)   # RD=1, 1 question
    return header + meshdns._encode_name(name) + struct.pack(">HH", qtype, 1)


def _answer_ip(resp):
    if struct.unpack(">H", resp[6:8])[0] == 0:      # ANCOUNT
        return None
    return socket.inet_ntoa(resp[-4:])


def _rcode(resp):
    return resp[3] & 0x0F


_LOOKUP = lambda h: {"gw": "100.64.0.9", "laptop": "100.64.0.2"}.get(h)
_LOOKUP_V6 = lambda h: {"gw": "fd12:3456:789a::9"}.get(h)


class TestParseQuery(unittest.TestCase):
    def test_parses_name_and_type(self):
        qid, qname, qtype = meshdns.parse_query(_query("gw.mesh"))
        self.assertEqual(qid, b"\xab\xcd")
        self.assertEqual(qname, "gw.mesh")
        self.assertEqual(qtype, meshdns.QTYPE_A)

    def test_lowercases(self):
        _, qname, _ = meshdns.parse_query(_query("GW.Mesh"))
        self.assertEqual(qname, "gw.mesh")

    def test_rejects_malformed(self):
        for bad in (b"", b"\x00" * 4, b"\xab\xcd" + struct.pack(">HHHHH", 0x0100, 0, 0, 0, 0)):
            with self.assertRaises(meshdns.DNSError):
                meshdns.parse_query(bad)


class TestAnswerFor(unittest.TestCase):
    def _ans(self, name, qtype=meshdns.QTYPE_A):
        qid, qname, qt = meshdns.parse_query(_query(name, qtype))
        return meshdns.answer_for(qid, qname, qt, "mesh", _LOOKUP, _LOOKUP_V6)

    def test_a_hit(self):
        self.assertEqual(_answer_ip(self._ans("gw.mesh")), "100.64.0.9")

    def test_aaaa_hit(self):
        resp = self._ans("gw.mesh", meshdns.QTYPE_AAAA)
        self.assertEqual(struct.unpack(">H", resp[6:8])[0], 1)
        self.assertEqual(struct.unpack(">H", resp[-26:-24])[0], meshdns.QTYPE_AAAA)
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, resp[-16:]), "fd12:3456:789a::9")

    def test_aaaa_is_nodata_when_only_ipv4_exists(self):
        resp = self._ans("laptop.mesh", meshdns.QTYPE_AAAA)
        self.assertIsNone(_answer_ip(resp))
        self.assertEqual(_rcode(resp), 0)            # NOERROR / NODATA

    def test_miss_is_nxdomain(self):
        self.assertEqual(_rcode(self._ans("nope.mesh")), 3)

    def test_other_suffix_forwards(self):
        self.assertIsNone(self._ans("example.com"))
        self.assertIsNone(self._ans("gw.example.com"))


class TestUpstreamParsers(unittest.TestCase):
    def test_resolvconf(self):
        text = "# comment\nsearch lan\nnameserver 192.168.0.1\nnameserver 8.8.8.8\n"
        self.assertEqual(meshdns._first_nameserver_resolvconf(text), "192.168.0.1")
        self.assertIsNone(meshdns._first_nameserver_resolvconf("search lan\n"))

    def test_scutil(self):
        text = ("resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\n"
                "  flags  : Request A records\n")
        self.assertEqual(meshdns._first_nameserver_scutil(text), "192.168.1.1")


class TestResolverConfigHelpers(unittest.TestCase):
    def test_linux_uses_route_only_domain_without_rewriting_resolv_conf(self):
        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run") as run:
            cfg = meshdns.ResolverConfig("mesh", "127.0.0.1", interface="remotemac0")
            cfg.apply()
            cfg.restore()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [
            ["resolvectl", "dns", "remotemac0", "127.0.0.1"],
            ["resolvectl", "domain", "remotemac0", "~mesh"],
            ["resolvectl", "default-route", "remotemac0", "no"],
            ["resolvectl", "revert", "remotemac0"],
        ])

    def test_suffix_validation(self):
        self.assertEqual(meshdns.validate_suffix("Mesh."), "mesh")
        for bad in ("", "-mesh", "mesh;exit", "mesh..local", "mesh\nfoo"):
            with self.assertRaises(ValueError):
                meshdns.validate_suffix(bad)

    def test_macos_resolver_path(self):
        self.assertEqual(meshdns.macos_resolver_file("mesh"), "/etc/resolver/mesh")

    def test_macos_restore_preserves_a_changed_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mesh")
            with mock.patch.object(meshdns.sys, "platform", "darwin"), \
                 mock.patch.object(meshdns.os, "makedirs"), \
                 mock.patch.object(meshdns, "macos_resolver_file", return_value=path):
                cfg = meshdns.ResolverConfig("mesh", "127.0.0.1").apply()
                with open(path, "w") as f:
                    f.write("nameserver 1.1.1.1\n")
                with self.assertRaisesRegex(meshdns.ResolverError, "changed"):
                    cfg.restore()
                with open(path) as f:
                    self.assertEqual(f.read(), "nameserver 1.1.1.1\n")
                with open(path, "w") as f:
                    f.write("nameserver 127.0.0.1\n")
                cfg.restore()
                self.assertFalse(os.path.exists(path))

    def test_windows_uses_nrpt_rule(self):
        with mock.patch.object(meshdns.sys, "platform", "win32"), \
             mock.patch("windns.NrptConfig") as nrpt:
            cfg = meshdns.ResolverConfig("mesh", "127.0.0.1")
            cfg.apply()
            self.assertFalse(cfg.uses_global_fallback)
            cfg.restore()
        nrpt.assert_called_once_with("mesh", "127.0.0.1")
        nrpt.return_value.apply.return_value.restore.assert_called_once_with()

    def test_restore_is_a_noop_when_never_applied(self):
        meshdns.ResolverConfig("mesh", "100.64.0.2", "1.1.1.1").restore()   # must not raise


class TestStaticResolverFallback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.resolv = os.path.join(self.tmp.name, "resolv.conf")
        self.state = os.path.join(self.tmp.name, "state.json")
        self.original = "search example.org\nnameserver 9.9.9.9\noptions timeout:2\n"
        with open(self.resolv, "w") as f:
            f.write(self.original)

    def tearDown(self):
        self.tmp.cleanup()

    def _config(self):
        return meshdns.ResolverConfig("mesh", "127.0.0.1", "9.9.9.9",
                                      interface="remotemac0", resolv_path=self.resolv,
                                      state_path=self.state, allow_global_fallback=True)

    def test_default_never_rewrites_global_resolver(self):
        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run", side_effect=FileNotFoundError):
            cfg = meshdns.ResolverConfig("mesh", "127.0.0.1", "9.9.9.9",
                                         interface="remotemac0", resolv_path=self.resolv,
                                         state_path=self.state)
            with self.assertRaisesRegex(meshdns.ResolverError, "system DNS unchanged"):
                cfg.apply()
        with open(self.resolv) as f:
            self.assertEqual(f.read(), self.original)
        self.assertFalse(os.path.exists(self.state))

    def test_failed_resolved_revert_blocks_global_fallback(self):
        def run(command, **_kwargs):
            if command[1] == "dns":
                return None
            raise meshdns.subprocess.CalledProcessError(1, command)

        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run", side_effect=run):
            cfg = self._config()
            with self.assertRaisesRegex(meshdns.ResolverError, "could not be reverted"):
                cfg.apply()
        with open(self.resolv) as f:
            self.assertEqual(f.read(), self.original)

    def test_fallback_rewrites_static_file_then_restores_it(self):
        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run", side_effect=FileNotFoundError):
            cfg = self._config().apply()
            with open(self.resolv) as f:
                installed = f.read()
            self.assertIn("nameserver 127.0.0.1", installed)
            self.assertIn("search example.org", installed)
            self.assertEqual(meshdns.detect_upstream(self.resolv, self.state), "9.9.9.9")
            cfg.restore()
        with open(self.resolv) as f:
            self.assertEqual(f.read(), self.original)
        self.assertFalse(os.path.exists(self.state))

    def test_previous_run_is_recovered_before_next_apply(self):
        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run", side_effect=FileNotFoundError):
            self._config().apply()  # simulate a process that exited without cleanup
            next_run = self._config().apply()
            next_run.restore()
        with open(self.resolv) as f:
            self.assertEqual(f.read(), self.original)

    def test_saved_state_before_replace_is_discarded_safely(self):
        cfg = self._config()
        with open(self.state, "w") as f:
            import json
            json.dump({"original": self.original, "installed": "nameserver 127.0.0.1\n"}, f)
        cfg._restore_file()
        self.assertFalse(os.path.exists(self.state))

    def test_changed_resolver_is_not_overwritten_on_restore(self):
        with mock.patch.object(meshdns.sys, "platform", "linux"), \
             mock.patch.object(meshdns.subprocess, "run", side_effect=FileNotFoundError):
            cfg = self._config().apply()
            with open(self.resolv, "w") as f:
                f.write("nameserver 1.1.1.1\n")
            with self.assertRaisesRegex(meshdns.ResolverError, "changed"):
                cfg.restore()
        self.assertTrue(os.path.exists(self.state))
        with open(self.resolv) as f:
            self.assertEqual(f.read(), "nameserver 1.1.1.1\n")

    def test_managed_symlink_is_not_overwritten(self):
        link = os.path.join(self.tmp.name, "linked.conf")
        os.symlink(self.resolv, link)
        cfg = meshdns.ResolverConfig("mesh", "127.0.0.1", "9.9.9.9",
                                     interface="remotemac0", resolv_path=link,
                                     state_path=self.state, allow_global_fallback=True)
        with self.assertRaisesRegex(meshdns.ResolverError, "symlink"):
            cfg._apply_file()
        with open(self.resolv) as f:
            self.assertEqual(f.read(), self.original)

    def test_upstream_cannot_point_at_mesh_resolver(self):
        cfg = meshdns.ResolverConfig("mesh", "127.0.0.1", "127.0.0.1",
                                     resolv_path=self.resolv, state_path=self.state,
                                     allow_global_fallback=True)
        with self.assertRaisesRegex(meshdns.ResolverError, "upstream DNS"):
            cfg._apply_file()


class TestServerIntegration(unittest.TestCase):
    def setUp(self):
        # Stub upstream: reply to any query with a fixed A (9.9.9.9) so we can tell
        # a forwarded answer apart from a locally-answered one.
        self.up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.up.bind(("127.0.0.1", 0))
        self.up_port = self.up.getsockname()[1]
        self._stop = threading.Event()

        def _serve():
            while not self._stop.is_set():
                try:
                    self.up.settimeout(0.2)
                    data, addr = self.up.recvfrom(4096)
                except OSError:
                    continue
                try:
                    qid, qname, qtype = meshdns.parse_query(data)
                    self.up.sendto(meshdns.build_response(qid, qname, qtype, ip="9.9.9.9"), addr)
                except meshdns.DNSError:
                    pass
        threading.Thread(target=_serve, daemon=True).start()

        self.server = meshdns.MeshDNSServer("127.0.0.1", 0, "mesh", _LOOKUP,
                                            upstream="127.0.0.1", upstream_port=self.up_port).start()
        time.sleep(0.1)

    def tearDown(self):
        self.server.stop()
        self._stop.set()
        self.up.close()

    def _ask(self, name, qtype=meshdns.QTYPE_A):
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.settimeout(3)
        c.sendto(_query(name, qtype), self.server.address)
        resp, _ = c.recvfrom(4096)
        c.close()
        return resp

    def test_mesh_name_answered_locally(self):
        self.assertEqual(_answer_ip(self._ask("gw.mesh")), "100.64.0.9")

    def test_mesh_aaaa_answered_locally(self):
        self.server.lookup_v6 = _LOOKUP_V6
        resp = self._ask("gw.mesh", meshdns.QTYPE_AAAA)
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, resp[-16:]),
                         "fd12:3456:789a::9")

    def test_other_name_forwarded_to_upstream(self):
        self.assertEqual(_answer_ip(self._ask("example.com")), "9.9.9.9")

    def test_other_name_refused_without_explicit_upstream(self):
        self.server.upstream = None
        self.assertEqual(_rcode(self._ask("example.com")), 5)

    def test_upstream_response_with_wrong_transaction_id_is_dropped(self):
        class FakeUDP:
            def __init__(self): self.sent = []
            def sendto(self, *args): self.sent.append(args)
        class FakeUpstream:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, _): pass
            def connect(self, _): pass
            def send(self, _): pass
            def recv(self, _):
                return meshdns.build_response(b"\x00\x00", "example.com", 1, "9.9.9.9")
        srv = meshdns.MeshDNSServer("127.0.0.1", 53, "mesh", _LOOKUP,
                                    upstream="9.9.9.9")
        srv.udp = FakeUDP()
        with mock.patch.object(meshdns.socket, "socket", return_value=FakeUpstream()):
            srv._forward(_query("example.com"), ("127.0.0.1", 5555))
        self.assertEqual(srv.udp.sent, [])

    def test_slow_query_does_not_block_other_queries(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.server._handle

        def delayed(data, addr):
            if meshdns.parse_query(data)[1] == "laptop.mesh":
                entered.set()
                release.wait(2)
            original(data, addr)

        self.server._handle = delayed
        slow = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            slow.sendto(_query("laptop.mesh"), self.server.address)
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            self.assertEqual(_answer_ip(self._ask("gw.mesh")), "100.64.0.9")
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            release.set()
            slow.close()

    def test_no_self_forward_loop(self):
        # An upstream equal to our own address (host+port) must NOT be forwarded
        # to (that would loop each query back in and leak a socket per hop).
        class _FakeSock:
            def __init__(self): self.sent = []
            def sendto(self, *a): self.sent.append(a)
        srv = meshdns.MeshDNSServer("127.0.0.1", 53, "mesh", _LOOKUP,
                                    upstream="127.0.0.1", upstream_port=53)
        srv.udp = _FakeSock()
        srv._forward(_query("example.com"), ("127.0.0.1", 5555))
        self.assertEqual(srv.udp.sent, [], "forwarded to self — loop guard failed")


if __name__ == "__main__":
    unittest.main()
