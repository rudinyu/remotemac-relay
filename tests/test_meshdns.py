"""Tests for the split-DNS resolver (Phase 8). Root-free — the server binds
127.0.0.1 on an ephemeral port and forwards to a stub upstream, so no privilege
and no changes to the system resolver are needed."""

import socket
import struct
import sys
import threading
import time
import unittest

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
        return meshdns.answer_for(qid, qname, qt, "mesh", _LOOKUP)

    def test_a_hit(self):
        self.assertEqual(_answer_ip(self._ans("gw.mesh")), "100.64.0.9")

    def test_aaaa_is_nodata_not_nxdomain(self):
        resp = self._ans("gw.mesh", meshdns.QTYPE_AAAA)
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
    def test_linux_resolvconf_keeps_upstream_as_fallback(self):
        body = meshdns.linux_resolvconf("100.64.0.2", "192.168.0.1")
        self.assertEqual(body, "nameserver 100.64.0.2\nnameserver 192.168.0.1\n")

    def test_linux_resolvconf_dedupes_and_handles_missing_upstream(self):
        self.assertEqual(meshdns.linux_resolvconf("100.64.0.2", None), "nameserver 100.64.0.2\n")
        # upstream == our IP would be a pointless (and looping) fallback → dropped
        self.assertEqual(meshdns.linux_resolvconf("100.64.0.2", "100.64.0.2"),
                         "nameserver 100.64.0.2\n")

    def test_macos_resolver_path(self):
        self.assertEqual(meshdns.macos_resolver_file("mesh"), "/etc/resolver/mesh")

    def test_restore_is_a_noop_when_never_applied(self):
        meshdns.ResolverConfig("mesh", "100.64.0.2", "1.1.1.1").restore()   # must not raise


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

    def test_other_name_forwarded_to_upstream(self):
        self.assertEqual(_answer_ip(self._ask("example.com")), "9.9.9.9")


if __name__ == "__main__":
    unittest.main()
