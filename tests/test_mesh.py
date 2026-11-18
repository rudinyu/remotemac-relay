"""Tests for the mesh control plane + node crypto (Phase 1)."""

import os
import ipaddress
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

try:
    import hashlib
    import hmac
    import mesh
    import coordinator
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestHandshake(unittest.TestCase):
    def test_derive_and_session_roundtrip(self):
        s_i = X25519PrivateKey.generate()
        s_r = X25519PrivateKey.generate()
        e_i = X25519PrivateKey.generate()
        e_r = X25519PrivateKey.generate()
        pi, pr = mesh.pub_bytes(s_i), mesh.pub_bytes(s_r)
        ei, er = mesh.pub_bytes(e_i), mesh.pub_bytes(e_r)

        tx_i, rx_i = mesh._derive(s_i, pi, pr, e_i, ei, er, initiator=True)
        tx_r, rx_r = mesh._derive(s_r, pr, pi, e_r, er, ei, initiator=False)

        # Keys cross-match between the two peers.
        self.assertEqual(tx_i, rx_r)
        self.assertEqual(rx_i, tx_r)

        a = mesh.Session(tx_i, rx_i)
        b = mesh.Session(tx_r, rx_r)
        ct = a.encrypt(b"secret payload")
        self.assertEqual(b.decrypt(ct), b"secret payload")
        ct2 = b.encrypt(b"reply")
        self.assertEqual(a.decrypt(ct2), b"reply")

    def test_wrong_static_key_fails_auth(self):
        s_i, s_r, imposter = (X25519PrivateKey.generate() for _ in range(3))
        e_i, e_r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        pi, pr = mesh.pub_bytes(s_i), mesh.pub_bytes(s_r)
        ei, er = mesh.pub_bytes(e_i), mesh.pub_bytes(e_r)

        tx_i, rx_i = mesh._derive(s_i, pi, pr, e_i, ei, er, initiator=True)
        # Responder is actually a different static key than the initiator expects.
        tx_r, rx_r = mesh._derive(imposter, mesh.pub_bytes(imposter), pi,
                                  e_r, er, ei, initiator=False)
        a = mesh.Session(tx_i, rx_i)
        b = mesh.Session(tx_r, rx_r)
        with self.assertRaises(Exception):
            b.decrypt(a.encrypt(b"x"))

    def test_session_rejects_replay(self):
        s_i, s_r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        e_i, e_r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        pi, pr = mesh.pub_bytes(s_i), mesh.pub_bytes(s_r)
        ei, er = mesh.pub_bytes(e_i), mesh.pub_bytes(e_r)
        tx_i, rx_i = mesh._derive(s_i, pi, pr, e_i, ei, er, initiator=True)
        tx_r, rx_r = mesh._derive(s_r, pr, pi, e_r, er, ei, initiator=False)
        a, b = mesh.Session(tx_i, rx_i), mesh.Session(tx_r, rx_r)
        ct = a.encrypt(b"once")
        self.assertEqual(b.decrypt(ct), b"once")
        with self.assertRaises(ValueError):
            b.decrypt(ct)   # replay of the same counter


    def test_init_key_matches_and_binds_initiator(self):
        s_i, s_r, imposter = (X25519PrivateKey.generate() for _ in range(3))
        e_i = X25519PrivateKey.generate()
        pi, pr, ei = mesh.pub_bytes(s_i), mesh.pub_bytes(s_r), mesh.pub_bytes(e_i)
        k_i = mesh._init_key(s_i, pi, pr, ei, 9, eph=e_i)
        self.assertEqual(k_i, mesh._init_key(s_r, pr, pi, ei, 9))
        # Someone without s_i (claiming pi) can't produce the responder's key.
        k_x = mesh._init_key(imposter, pi, pr, ei, 9, eph=e_i)
        self.assertNotEqual(k_x, mesh._init_key(s_r, pr, pi, ei, 9))
        # The sender index is bound in.
        self.assertNotEqual(k_i, mesh._init_key(s_r, pr, pi, ei, 10))

    def test_derive_keys_confirm_key_agrees(self):
        s_i, s_r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        e_i, e_r = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        pi, pr = mesh.pub_bytes(s_i), mesh.pub_bytes(s_r)
        ei, er = mesh.pub_bytes(e_i), mesh.pub_bytes(e_r)
        ki = mesh._derive_keys(s_i, pi, pr, e_i, ei, er, initiator=True)
        kr = mesh._derive_keys(s_r, pr, pi, e_r, er, ei, initiator=False)
        self.assertEqual(ki[2], kr[2])
        self.assertEqual(len({ki[0], ki[1], ki[2]}), 3)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestRegistrationProof(unittest.TestCase):
    """Proof-of-possession: a node must prove it holds the private key for the
    pubkey it registers, so a token holder can't claim another node's identity."""

    def _proof(self, node_priv, ce_pub, nonce, claimed_pub):
        dh = node_priv.exchange(X25519PublicKey.from_public_bytes(ce_pub))
        return hmac.new(dh, nonce + claimed_pub, hashlib.sha256).digest()

    def test_valid_proof_accepted(self):
        ce = X25519PrivateKey.generate()
        node = X25519PrivateKey.generate()
        npub = mesh.pub_bytes(node)
        nonce = os.urandom(32)
        proof = self._proof(node, mesh.pub_bytes(ce), nonce, npub)
        self.assertTrue(coordinator._verify_pop(ce, nonce, mesh._b64(npub), mesh._b64(proof)))

    def test_wrong_key_rejected(self):
        ce = X25519PrivateKey.generate()
        node = X25519PrivateKey.generate()
        imposter = X25519PrivateKey.generate()
        npub = mesh.pub_bytes(node)
        nonce = os.urandom(32)
        # Imposter signs a proof but claims the victim's pubkey → must be rejected.
        bad = self._proof(imposter, mesh.pub_bytes(ce), nonce, npub)
        self.assertFalse(coordinator._verify_pop(ce, nonce, mesh._b64(npub), mesh._b64(bad)))

    def test_malformed_rejected(self):
        ce = X25519PrivateKey.generate()
        nonce = os.urandom(32)
        self.assertFalse(coordinator._verify_pop(ce, nonce, "!!not-base64!!", "x"))
        self.assertFalse(coordinator._verify_pop(ce, nonce, mesh._b64(b"tooshort"), mesh._b64(b"x")))
        self.assertFalse(coordinator._verify_pop(ce, nonce, mesh._b64(os.urandom(32)), None))


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestSubnetRouteHelpers(unittest.TestCase):
    def test_ipv6_exit_flag_requires_exit_role(self):
        args = SimpleNamespace(advertise_routes=None, accept_routes=False,
                               accept_route=None, exit_node=None, lan_routes=None,
                               exit_ipv6=True, exit=False, dns=False, tun=False)
        with self.assertRaisesRegex(SystemExit, "requires --exit"):
            mesh._cmd_up(args)

    def test_windows_gateway_is_rejected_before_connecting(self):
        args = SimpleNamespace(advertise_routes=None, accept_routes=False,
                               accept_route=None, exit_node=None, lan_routes=None,
                               exit_ipv6=False, exit=True, dns=False, tun=True,
                               ping=None)
        with mock.patch.object(mesh.sys, "platform", "win32"), \
             mock.patch.object(mesh, "_has_tun_privilege", return_value=True):
            with self.assertRaisesRegex(SystemExit, "Windows currently supports"):
                mesh._cmd_up(args)

    def test_route_grants_require_a_full_key_and_cidr(self):
        key = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))
        self.assertEqual(mesh.parse_route_grants([key + ",10.20.1.5/16"]),
                         {key: {"10.20.0.0/16"}})
        self.assertEqual(mesh.parse_route_grants([key + ",2001:db8:2::1/64"]),
                         {key: {"2001:db8:2::/64"}})
        for bad in ("bad,10.20.0.0/16", key + ",not-a-cidr"):
            with self.assertRaises(ValueError):
                mesh.parse_route_grants([bad])

    def test_parse_cidrs_normalizes_and_skips_bad(self):
        self.assertEqual(mesh.parse_cidrs("192.168.1.0/24, 10.0.0.5/8"),
                         ["192.168.1.0/24", "10.0.0.0/8"])   # host bits masked off
        self.assertEqual(mesh.parse_cidrs("nonsense, 192.168.0.0/16"), ["192.168.0.0/16"])
        self.assertEqual(mesh.parse_cidrs("2001:db8:1::5/64"), ["2001:db8:1::/64"])
        self.assertEqual(mesh.parse_cidrs(""), [])

    def test_route_is_safe_guards(self):
        # overlaps the overlay net → unsafe
        self.assertFalse(mesh.route_is_safe("100.64.0.0/16", None, []))
        # contains the coordinator IP → unsafe (would loop mesh transport)
        self.assertFalse(mesh.route_is_safe("198.51.100.0/24", "198.51.100.9", []))
        # contains a peer endpoint IP → unsafe
        self.assertFalse(mesh.route_is_safe("203.0.113.0/24", None, ["203.0.113.7"]))
        # a private LAN unrelated to transport → safe
        self.assertTrue(mesh.route_is_safe("192.168.1.0/24", "198.51.100.9", ["203.0.113.7"]))
        ula = "fd12:3456:789a::/64"
        self.assertFalse(mesh.route_is_safe(ula, None, [], ula))
        self.assertFalse(mesh.route_is_safe("::/0", None, [], ula))
        self.assertFalse(mesh.route_is_safe("2001:db8:1::/64", None,
                                            ["2001:db8:1::7"], ula))
        self.assertTrue(mesh.route_is_safe("2001:db8:2::/64", None,
                                           ["2001:db8:1::7"], ula))

    def test_build_table_longest_prefix_and_match(self):
        peers = {
            "gw": {"ip": "100.64.0.2", "endpoints": ["203.0.113.5:41000"],
                   "routes": ["10.0.0.0/8", "10.1.2.0/24"]},
            "bad": {"ip": "100.64.0.3", "endpoints": [],
                    "routes": ["0.0.0.0/0", "100.64.0.0/12"]},   # both unsafe → dropped
        }
        table = mesh.build_route_table(peers, "198.51.100.9")
        self.assertEqual([str(n) for n, _ in table], ["10.1.2.0/24", "10.0.0.0/8"])
        self.assertEqual(mesh.match_route(table, "10.1.2.9"), "gw")   # longest prefix
        self.assertEqual(mesh.match_route(table, "10.9.9.9"), "gw")
        self.assertIsNone(mesh.match_route(table, "8.8.8.8"))
        self.assertIsNone(mesh.match_route(table, "not-an-ip"))


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestAllocator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        os.unlink(self.tmp.name)   # start with no file

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_stable_and_unique(self):
        a = coordinator.IPAllocator(self.tmp.name)
        ip1 = a.get("pkA")
        ip2 = a.get("pkB")
        self.assertNotEqual(ip1, ip2)
        self.assertEqual(a.get("pkA"), ip1)              # stable within instance
        self.assertTrue(ip1.startswith("100."))

        b = coordinator.IPAllocator(self.tmp.name)       # reload from disk
        self.assertEqual(b.get("pkA"), ip1)              # persisted across restarts
        self.assertEqual(b.get("pkB"), ip2)

    def test_ipv6_ula_is_stable_and_unique(self):
        a = coordinator.IPAllocator(self.tmp.name)
        ip6a = a.get6("pkA")
        ip6b = a.get6("pkB")
        prefix = a.network6
        self.assertNotEqual(ip6a, ip6b)
        self.assertTrue(ip6a.startswith("fd"))
        self.assertIn(ipaddress.IPv6Address(ip6a), ipaddress.IPv6Network(prefix))
        b = coordinator.IPAllocator(self.tmp.name)
        self.assertEqual(b.network6, prefix)
        self.assertEqual(b.get6("pkA"), ip6a)
        self.assertEqual(b.get6("pkB"), ip6b)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestMeshEndToEnd(unittest.TestCase):
    def setUp(self):
        self.token = b"mesh-test-token"
        self.port = _free_port()
        self.state = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.state.close()
        os.unlink(self.state.name)
        t = threading.Thread(
            target=coordinator.serve,
            args=("127.0.0.1", self.port, self.token, self.state.name),
            daemon=True)
        t.start()
        time.sleep(0.3)   # let the listener bind
        self.nodes = []

    def tearDown(self):
        for n in self.nodes:
            n.close()
        try:
            os.unlink(self.state.name)
        except OSError:
            pass

    def _node(self, name, advertise_routes=None, route_grants=None,
              is_exit=False, exit_node=None, identity=None, advertise_ready=True,
              exit_ipv6=False):
        n = mesh.MeshNode(identity or X25519PrivateKey.generate(), name, is_exit=is_exit,
                          advertise_routes=advertise_routes)
        n.is_exit_ipv6 = exit_ipv6
        n.advertise_ready = advertise_ready
        n.route_grants = route_grants or {}
        n.exit_node_key = exit_node
        n.connect(f"127.0.0.1:{self.port}", self.token)
        threading.Thread(target=n.run, daemon=True).start()
        self.nodes.append(n)
        return n

    def _wait(self, cond, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_two_nodes_get_ips_and_ping(self):
        a = self._node("alice")
        b = self._node("bob")

        # Both get overlay IPs and see each other in the map.
        self.assertTrue(self._wait(lambda: a.overlay_ip and b.overlay_ip))
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        self.assertNotEqual(a.overlay_ip, b.overlay_ip)

        # alice pings bob; on localhost this establishes a DIRECT UDP path.
        got = threading.Event()
        a.on_message = lambda src, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        dst = a.resolve("bob")
        self.assertIsNotNone(dst)
        a.send(dst, mesh.MESH_PING, b"hello")
        self.assertTrue(got.wait(5), "did not receive encrypted PONG")
        self.assertEqual(a._conns[dst].transport, "direct")
        self.assertIsNotNone(a._conns[dst].endpoint)

    def test_derp_fallback_when_no_direct_path(self):
        a = self._node("alice3")
        b = self._node("bob3")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        # Force DERP on BOTH sides: whichever node ends up the designated
        # initiator must also see no reachable UDP endpoints, so neither can
        # punch a direct path and both fall back to the coordinator relay.
        a._peer_endpoints = lambda pk: []
        b._peer_endpoints = lambda pk: []

        got = threading.Event()
        a.on_message = lambda src, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        dst = a.resolve("bob3")
        a.send(dst, mesh.MESH_PING, b"hi")
        self.assertTrue(got.wait(6), "did not receive PONG over DERP fallback")
        self.assertEqual(a._conns[dst].transport, "derp")

    def test_derp_to_direct_upgrade(self):
        # A session that first forms over DERP must transparently upgrade to a
        # direct UDP path once one is reachable — reusing the SAME session (not
        # rebuilding it). Unauthenticated handshake bytes over UDP must NOT move it.
        a = self._node("up-a")
        b = self._node("up-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        real_a_eps, real_b_eps = a._peer_endpoints, b._peer_endpoints
        a._peer_endpoints = lambda pk: []
        b._peer_endpoints = lambda pk: []

        got = threading.Event()
        a.on_message = lambda s, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        da = a.resolve("up-b")
        a.send(da, mesh.MESH_PING, b"x")
        self.assertTrue(got.wait(6), "DERP session did not form")
        self.assertEqual(a._conns[da].transport, "derp")
        db = b.resolve("up-a")
        self.assertTrue(self._wait(lambda: b._conns.get(db) and b._conns[db].session))
        pa, pb = a._conns[da], b._conns[db]
        sa, sb = pa.session, pb.session

        # Junk handshakes over UDP (both stages) are ignored on both sides.
        fake = ("127.0.0.1", 40000)
        for node, peer, pc, sess in ((a, da, pa, sa), (b, db, pb, sb)):
            for stage, n in ((mesh._HS_INIT, mesh._HS_INIT_LEN), (mesh._HS_RESP, mesh._HS_RESP_LEN)):
                node._handle_hs(peer, node._peer_static(peer),
                                bytes([stage]) + b"\x11" * (n - 1), "udp", fake)
            self.assertIs(pc.session, sess, "junk handshake replaced the session")
            self.assertEqual(pc.transport, "derp", "junk handshake moved the path")

        # Reachability returns → authenticated probes upgrade both sides to direct.
        a._peer_endpoints, b._peer_endpoints = real_a_eps, real_b_eps
        with pa.lock:
            pa.initiated = False
        a._ensure_connecting(pa)
        self.assertTrue(self._wait(lambda: pa.transport == "direct" and pb.transport == "direct", 8),
                        "DERP session did not upgrade to direct")
        self.assertIs(pa.session, sa, "session was rebuilt, not upgraded")
        self.assertIs(pb.session, sb, "session was rebuilt, not upgraded")

    def test_direct_failover_to_derp_on_silence(self):
        # A direct path that goes silent must fail over to the DERP relay so
        # traffic keeps flowing (reusing the same session).
        a = self._node("fo-a")
        b = self._node("fo-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))

        got = threading.Event()
        a.on_message = lambda s, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        da = a.resolve("fo-b")
        a.send(da, mesh.MESH_PING, b"x")
        self.assertTrue(got.wait(6), "direct path did not form")
        self.assertEqual(a._conns[da].transport, "direct")

        # Simulate a real outage of the direct path: UDP between the two is
        # dropped (authenticated UDP that still got through would rightly keep
        # the path direct) and there are no endpoints to re-punch, so failover
        # must stick on DERP. Mark the path silent on both ends and speed up the
        # liveness loop.
        db = b.resolve("fo-a")
        a._on_udp = lambda data, addr: None
        b._on_udp = lambda data, addr: None
        a._peer_endpoints = lambda pk: []
        b._peer_endpoints = lambda pk: []
        for n in (a, b):
            n._ka_tick = 0.05
            n.direct_timeout = 0.2
            n.keepalive_interval = 0.1
        a._conns[da].last_rx = time.monotonic() - 100
        b._conns[db].last_rx = time.monotonic() - 100
        self.assertTrue(self._wait(lambda: b._conns[db].transport == "derp", 5))

        self.assertTrue(self._wait(lambda: a._conns[da].transport == "derp", 5),
                        "did not fail over to DERP on silence")

        # Traffic still flows, now over the relay.
        got.clear()
        a.send(da, mesh.MESH_PING, b"again")
        self.assertTrue(got.wait(6), "no PONG after DERP failover")
        self.assertEqual(a._conns[da].transport, "derp")

    def test_direct_recovery_after_failover(self):
        # After failing over to DERP, a node must keep retrying hole punching and
        # transparently upgrade back to a direct path once it becomes reachable.
        a = self._node("rc-a")
        b = self._node("rc-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))

        got = threading.Event()
        a.on_message = lambda s, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        da = a.resolve("rc-b")
        a.send(da, mesh.MESH_PING, b"x")
        self.assertTrue(got.wait(6), "direct path did not form")
        self.assertEqual(a._conns[da].transport, "direct")

        # A real deployment runs identical keepalive config on every node, so
        # both ends detect the silence. Drive both fast so recovery is role-
        # independent (the designated initiator re-punches once it can reach us).
        db = b.resolve("rc-a")
        real_a_eps, real_b_eps = a._peer_endpoints, b._peer_endpoints
        real_a_udp, real_b_udp = a._on_udp, b._on_udp
        a._on_udp = lambda data, addr: None
        b._on_udp = lambda data, addr: None
        a._peer_endpoints = lambda pk: []
        b._peer_endpoints = lambda pk: []
        for n in (a, b):
            n._ka_tick = 0.05
            n.direct_timeout = 0.2
            n.keepalive_interval = 0.1
            n.direct_retry_interval = 0.2
        a._conns[da].last_rx = time.monotonic() - 100
        b._conns[db].last_rx = time.monotonic() - 100
        self.assertTrue(self._wait(lambda: a._conns[da].transport == "derp", 5),
                        "did not fail over to DERP")

        # Reachability returns → the periodic re-punch must restore a direct path.
        a._on_udp, b._on_udp = real_a_udp, real_b_udp
        a._peer_endpoints, b._peer_endpoints = real_a_eps, real_b_eps
        self.assertTrue(self._wait(lambda: a._conns[da].transport == "direct", 8),
                        "did not recover a direct path after reachability returned")

    def test_handshake_glare_both_initiate(self):
        # Both nodes try to open a session at the same instant. The deterministic
        # initiator tie-break must stop this from producing two mismatched
        # sessions — pings must succeed in BOTH directions.
        a = self._node("glare-a")
        b = self._node("glare-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))

        a_pong = threading.Event()
        b_pong = threading.Event()
        a.on_message = lambda s, mt, pl: a_pong.set() if mt == mesh.MESH_PONG else None
        b.on_message = lambda s, mt, pl: b_pong.set() if mt == mesh.MESH_PONG else None

        da, db = a.resolve("glare-b"), b.resolve("glare-a")
        # Fire simultaneously to provoke glare.
        threading.Thread(target=lambda: a.send(da, mesh.MESH_PING, b"a"), daemon=True).start()
        threading.Thread(target=lambda: b.send(db, mesh.MESH_PING, b"b"), daemon=True).start()

        self.assertTrue(a_pong.wait(6), "a did not get a PONG (glare broke keys?)")
        self.assertTrue(b_pong.wait(6), "b did not get a PONG (glare broke keys?)")

    # -- handshake authentication + session lifecycle ---------------------------

    def _pinger(self, node):
        ev = threading.Event()
        node.on_message = lambda s, mt, pl: ev.set() if mt == mesh.MESH_PONG else None
        return ev

    def _pair_ping(self, a, b, timeout=6):
        """Ping a→b and b→a, retrying like real traffic would (a packet sent on a
        stale session just before a rekey is lost); return (a_ok, b_ok)."""
        a_pong, b_pong = self._pinger(a), self._pinger(b)
        end = time.monotonic() + timeout
        while time.monotonic() < end and not (a_pong.is_set() and b_pong.is_set()):
            if not a_pong.is_set():
                a.send(b.pubkey_b64, mesh.MESH_PING, b"a")
            if not b_pong.is_set():
                b.send(a.pubkey_b64, mesh.MESH_PING, b"b")
            time.sleep(0.5)
        return a_pong.is_set(), b_pong.is_set()

    def _restart_and_ping(self, restart_initiator):
        a = self._node("rs-a")
        b = self._node("rs-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        self.assertEqual(self._pair_ping(a, b), (True, True), "initial session failed")

        a_is_init = a._am_initiator(b._pub)
        victim, survivor = (a, b) if a_is_init == restart_initiator else (b, a)
        # Restart the victim with the SAME identity (process restart): its new
        # instance has no session, while the survivor still holds the old one.
        key, name = victim._id, victim.hostname
        victim.close()
        self.nodes.remove(victim)
        self.assertTrue(self._wait(lambda: victim.pubkey_b64 not in survivor.peers))
        reborn = self._node(name, identity=key)
        self.assertTrue(self._wait(lambda: reborn.pubkey_b64 in survivor.peers
                                   and survivor.pubkey_b64 in reborn.peers))
        ok = self._pair_ping(reborn, survivor, timeout=8)
        self.assertEqual(ok, (True, True),
                         "peer pair did not recover after a restart (stale session)")

    def test_restart_of_responder_recovers(self):
        self._restart_and_ping(restart_initiator=False)

    def test_restart_of_initiator_recovers(self):
        self._restart_and_ping(restart_initiator=True)

    def test_periodic_rekey_replaces_session_and_traffic_flows(self):
        a = self._node("rk-a")
        b = self._node("rk-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        self.assertEqual(self._pair_ping(a, b), (True, True))
        init, resp = (a, b) if a._am_initiator(b._pub) else (b, a)
        pi = init._conns[resp.pubkey_b64]
        pr = resp._conns[init.pubkey_b64]
        old_i, old_r = pi.session, pr.session
        init._ka_tick = 0.05
        init.rekey_after = 0.3
        self.assertTrue(self._wait(lambda: pi.session is not old_i and pr.session is not old_r, 5),
                        "initiator did not rekey")
        init.rekey_after = 120.0
        self.assertEqual(self._pair_ping(a, b), (True, True), "traffic broke after rekey")
        self.assertEqual(pi.transport, "direct")

    def test_forged_init_cannot_squat_session(self):
        # Anyone who learns a peer's static pubkey (it travels in cleartext in UDP
        # handshake packets) must not be able to plant a session on the responder
        # that blocks the real handshake.
        a = self._node("sq-a")
        b = self._node("sq-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        init, resp = (a, b) if a._am_initiator(b._pub) else (b, a)

        forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forger.bind(("127.0.0.1", 0))
        fake_eph = mesh.pub_bytes(X25519PrivateKey.generate())
        body = bytes([mesh._HS_INIT]) + fake_eph + struct.pack(">I", 7) + os.urandom(24)
        forger.sendto(bytes([mesh._PKT_HS]) + init._pub + body,
                      ("127.0.0.1", resp.udp.getsockname()[1]))
        forger.close()
        time.sleep(0.3)
        pc = resp._conns.get(init.pubkey_b64)
        self.assertTrue(pc is None or pc.session is None,
                        "forged INIT installed a session")
        self.assertEqual(self._pair_ping(a, b), (True, True),
                         "real handshake blocked after a forged INIT")

    def test_replayed_init_does_not_move_endpoint(self):
        # Replaying a captured INIT from another address must not redirect the
        # responder's direct path to the attacker.
        a = self._node("rp-a")
        b = self._node("rp-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        init, resp = (a, b) if a._am_initiator(b._pub) else (b, a)

        captured = []
        real_sendto = init.udp.sendto

        class _Tap:
            def __getattr__(self, n):
                return getattr(init.udp_real, n)

            def sendto(self, data, addr):
                if data[:1] == bytes([mesh._PKT_HS]):
                    captured.append(data)
                return real_sendto(data, addr)
        init.udp_real = init.udp
        init.udp = _Tap()

        self.assertEqual(self._pair_ping(init, resp), (True, True))
        self.assertTrue(captured, "no INIT captured")
        pc = resp._conns[init.pubkey_b64]
        self.assertTrue(self._wait(lambda: pc.transport == "direct"))

        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        attacker.bind(("127.0.0.1", 0))
        evil = attacker.getsockname()
        for pkt in captured:
            attacker.sendto(pkt, ("127.0.0.1", resp.udp.getsockname()[1]))
        time.sleep(0.3)
        attacker.close()
        self.assertNotEqual(pc.endpoint, evil, "replayed INIT moved the direct endpoint")
        self.assertEqual(self._pair_ping(init, resp), (True, True))

    def test_initiator_tie_break_is_symmetric(self):
        a = self._node("tb-a")
        b = self._node("tb-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
        # Exactly one of the pair considers itself the initiator, and both agree.
        a_init = a._am_initiator(a._peer_static(b.pubkey_b64))
        b_init = b._am_initiator(b._peer_static(a.pubkey_b64))
        self.assertNotEqual(a_init, b_init)

    def test_stun_responder_echoes_source(self):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        myport = u.getsockname()[1]
        u.sendto(b"MSTU" + b"\x00" * 32, ("127.0.0.1", self.port))
        u.settimeout(3)
        data, _ = u.recvfrom(2048)
        u.close()
        self.assertEqual(data, b"MSTR" + f"127.0.0.1:{myport}".encode())

    def test_node_discovers_public_endpoint(self):
        a = self._node("stun-node")
        self.assertTrue(self._wait(lambda: a._stun_done.is_set(), 5))
        port = a.udp.getsockname()[1]
        self.assertIn(f"127.0.0.1:{port}", a.local_endpoints)

    def test_mesh_ip_dispatches_to_on_ip_packet(self):
        # A MESH_IP payload (a tunnelled IP packet) must be delivered to
        # on_ip_packet with the raw bytes intact, and must NOT leak to the
        # generic on_message path.
        a = self._node("ip-a")
        b = self._node("ip-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))

        got = threading.Event()
        seen = {}
        leaked = []
        b.on_ip_packet = lambda src, pkt: (seen.update(src=src, pkt=pkt), got.set())
        b.on_message = lambda src, mt, pl: leaked.append(mt)

        dst = a.resolve("ip-b")
        packet = b"\x45\x00\x00\x14rawining-packet"   # arbitrary raw bytes
        a.send(dst, mesh.MESH_IP, packet)
        self.assertTrue(got.wait(6), "MESH_IP was not delivered to on_ip_packet")
        self.assertEqual(seen["pkt"], packet)
        self.assertEqual(seen["src"], a.pubkey_b64)
        self.assertNotIn(mesh.MESH_IP, leaked, "MESH_IP leaked to on_message")

    def test_subnet_routes_advertise_accept_and_redirect(self):
        # A subnet router advertises a CIDR; a client that accepts routes learns
        # it (via the coordinator), routes matching packets to that peer, and
        # accepts LAN-sourced replies from it (anti-spoof widened for routers).
        gw = self._node("gw", advertise_routes=["192.168.1.0/24"])
        client = self._node("laptop", route_grants={gw.pubkey_b64: {"192.168.1.0/24"}})

        self.assertTrue(self._wait(
            lambda: gw.pubkey_b64 in client.peers
            and client.peers[gw.pubkey_b64].get("routes") == ["192.168.1.0/24"]),
            "client did not learn the advertised route via the coordinator")
        # The route table is rebuilt only from explicitly trusted claims.
        self.assertTrue(self._wait(lambda: client.route_for("192.168.1.50") == gw.pubkey_b64))
        # A non-advertised destination stays unroutable.
        self.assertIsNone(client.route_for("8.8.8.8"))
        # Anti-spoof: the subnet router may source its own overlay IP or a LAN IP
        # within the accepted route, but not an arbitrary address.
        self.assertTrue(client.src_permitted(gw.pubkey_b64, gw.overlay_ip))
        self.assertTrue(client.src_permitted(gw.pubkey_b64, "192.168.1.50"))
        self.assertFalse(client.src_permitted(gw.pubkey_b64, "203.0.113.1"))

    def test_routes_ignored_without_accept(self):
        gw = self._node("gw2", advertise_routes=["192.168.9.0/24"])
        client = self._node("laptop2")            # no route grants
        self.assertTrue(self._wait(lambda: gw.pubkey_b64 in client.peers))
        # Learned in the map, but not installed as a route (no opt-in).
        self.assertEqual(client.peers[gw.pubkey_b64].get("routes"), ["192.168.9.0/24"])
        self.assertIsNone(client.route_for("192.168.9.5"))

    def test_ipv6_subnet_route_requires_matching_grant(self):
        cidr = "2001:db8:42::/64"
        gw = self._node("v6-router", advertise_routes=[cidr])
        client = self._node("v6-client", route_grants={gw.pubkey_b64: {cidr}})
        self.assertTrue(self._wait(lambda: client.route_for("2001:db8:42::5")
                                  == gw.pubkey_b64))
        self.assertTrue(client.src_permitted(gw.pubkey_b64, "2001:db8:42::5"))
        self.assertFalse(client.src_permitted(gw.pubkey_b64, "2001:db8:43::5"))

        untrusted = self._node("v6-untrusted")
        self.assertTrue(self._wait(lambda: gw.pubkey_b64 in untrusted.peers))
        self.assertIsNone(untrusted.route_for("2001:db8:42::5"))

    def test_route_grant_cannot_be_claimed_by_another_peer(self):
        trusted = self._node("trusted-router", advertise_routes=["10.20.0.0/16"])
        rogue = self._node("rogue-router", advertise_routes=["10.20.0.0/16"])
        client = self._node("route-client",
                            route_grants={trusted.pubkey_b64: {"10.20.0.0/16"}})
        self.assertTrue(self._wait(lambda: rogue.pubkey_b64 in client.peers))
        self.assertTrue(self._wait(lambda: client.route_for("10.20.1.2") == trusted.pubkey_b64))
        self.assertFalse(client.src_permitted(rogue.pubkey_b64, "10.20.1.2"))

    def test_exit_node_full_tunnel_routing(self):
        # A client with --exit-node routes all non-overlay/non-subnet traffic to
        # the exit peer, and accepts replies from it sourced from any address.
        ex = self._node("exit", is_exit=True)
        client = self._node("laptop3", exit_node=ex.pubkey_b64)

        self.assertTrue(self._wait(lambda: client.exit_node_pk == ex.pubkey_b64),
                        "client did not resolve the exit node")
        # Internet-bound traffic goes to the exit; overlay still resolves to peers.
        self.assertEqual(client.route_for("8.8.8.8"), ex.pubkey_b64)
        self.assertEqual(client.route_for("1.1.1.1"), ex.pubkey_b64)
        self.assertEqual(client.route_for(ex.overlay_ip), ex.pubkey_b64)   # overlay wins
        # Anti-spoof: the exit may source anything; a non-exit peer may not.
        self.assertTrue(client.src_permitted(ex.pubkey_b64, "93.184.216.34"))
        self.assertFalse(client.src_permitted("some-other-pk", "93.184.216.34"))
        self.assertIsNone(client.route_for("2001:4860:4860::8888"))
        self.assertFalse(client.src_permitted(ex.pubkey_b64, "2001:4860:4860::8888"))

    def test_ipv6_exit_is_advertised_and_routes_public_ipv6(self):
        ex = self._node("dual-exit", is_exit=True, exit_ipv6=True,
                        advertise_ready=False)
        client = self._node("dual-client", exit_node=ex.pubkey_b64)
        self.assertTrue(self._wait(lambda: ex.pubkey_b64 in client.peers))
        self.assertFalse(client.peers[ex.pubkey_b64]["exit6"])
        ex.set_gateway_ready(True)
        self.assertTrue(self._wait(lambda: client.exit_node_pk == ex.pubkey_b64
                                  and client.peers[ex.pubkey_b64]["exit6"]))
        self.assertEqual(client.route_for("2001:4860:4860::8888"), ex.pubkey_b64)
        self.assertTrue(client.src_permitted(ex.pubkey_b64, "2001:4860:4860::8888"))
        ex.set_gateway_ready(False)
        self.assertTrue(self._wait(lambda: not client.peers[ex.pubkey_b64]["exit6"]))
        self.assertIsNone(client.route_for("2001:4860:4860::8888"))

    def test_gateway_is_advertised_only_after_it_is_ready(self):
        gateway = self._node("deferred-gateway", is_exit=True,
                             advertise_routes=["192.168.4.0/24"], advertise_ready=False)
        client = self._node("deferred-client")
        self.assertTrue(self._wait(lambda: gateway.pubkey_b64 in client.peers))
        self.assertFalse(client.peers[gateway.pubkey_b64]["exit"])
        self.assertEqual(client.peers[gateway.pubkey_b64]["routes"], [])

        gateway.set_gateway_ready(True)
        self.assertTrue(self._wait(lambda: client.peers[gateway.pubkey_b64]["exit"]
                                  and client.peers[gateway.pubkey_b64]["routes"]
                                  == ["192.168.4.0/24"]))

        gateway.set_gateway_ready(False)
        self.assertTrue(self._wait(lambda: not client.peers[gateway.pubkey_b64]["exit"]
                                  and client.peers[gateway.pubkey_b64]["routes"] == []))

    def test_no_exit_node_leaves_internet_unrouted(self):
        # Without --exit-node, internet destinations stay unroutable (dropped).
        a = self._node("plain-a")
        b = self._node("plain-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers))
        self.assertIsNone(a.route_for("8.8.8.8"))

    def test_exit_node_ignored_if_peer_not_advertising_exit(self):
        # Pinning a peer that isn't an exit must not enable full-tunnel: exit_node_pk
        # stays unresolved and internet traffic stays unrouted.
        plain = self._node("not-an-exit")
        client = self._node("laptop4", exit_node=plain.pubkey_b64)
        self.assertTrue(self._wait(lambda: plain.pubkey_b64 in client.peers))
        # Give the map a moment; the non-exit peer must never resolve as the exit.
        time.sleep(0.3)
        self.assertIsNone(client.exit_node_pk)
        self.assertIsNone(client.route_for("8.8.8.8"))

    def test_registration_rejects_claimed_pubkey_without_the_key(self):
        # A node that claims a pubkey it doesn't own (its proof is computed from
        # its real key) must be rejected — not admitted, not in the map.
        imp = mesh.MeshNode(X25519PrivateKey.generate(), "imp")
        imp.pubkey_b64 = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))  # claim a key we lack
        imp.connect(f"127.0.0.1:{self.port}", self.token)
        threading.Thread(target=imp.run, daemon=True).start()
        self.nodes.append(imp)

        good = self._node("good")
        self.assertTrue(self._wait(lambda: good.overlay_ip), "legit node was not admitted")
        time.sleep(0.4)
        self.assertIsNone(imp.overlay_ip, "imposter was admitted despite a bad proof")
        self.assertNotIn(imp.pubkey_b64, good.peers)

    def test_resolve_by_overlay_ip(self):
        a = self._node("alice2")
        b = self._node("bob2")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers))
        bob_ip = a.peers[b.pubkey_b64]["ip"]
        self.assertEqual(a.resolve(bob_ip), b.pubkey_b64)

    def test_ipv6_overlay_map_route_and_spoof_check(self):
        a = self._node("v6-alice")
        b = self._node("v6-bob")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and b.overlay_ip6))
        bob6 = a.peers[b.pubkey_b64]["ip6"]
        self.assertEqual(bob6, b.overlay_ip6)
        self.assertIn(ipaddress.IPv6Address(bob6),
                      ipaddress.IPv6Network(a.overlay_cidr6))
        self.assertEqual(a.resolve(bob6), b.pubkey_b64)
        self.assertEqual(a.route_for(bob6), b.pubkey_b64)
        self.assertTrue(a.src_permitted(b.pubkey_b64, bob6))
        self.assertFalse(a.src_permitted(b.pubkey_b64, a.overlay_ip6))
        self.assertIsNone(a.route_for("2001:db8::1234"))
        self.assertEqual(a.dns_lookup_v6(mesh.dns_key_label(b.pubkey_b64)), bob6)

    def test_dns_names_are_bound_to_peer_keys(self):
        client = mesh.MeshNode(X25519PrivateKey.generate(), "client")
        peer_key = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))
        other_key = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))
        client.peers = {peer_key: {"hostname": "gw", "ip": "100.64.0.2"}}
        label = mesh.dns_key_label(peer_key)
        self.assertEqual(mesh._key_for_dns_label(label), peer_key)
        self.assertEqual(client.dns_lookup(label), "100.64.0.2")
        self.assertIsNone(client.dns_lookup("gw"))
        client.dns_pins = {"gw": peer_key}
        self.assertEqual(client.dns_lookup("gw"), "100.64.0.2")
        client.peers = {other_key: {"hostname": "gw", "ip": "100.64.0.3"}}
        self.assertIsNone(client.dns_lookup("gw"))
        self.assertIsNone(client.dns_lookup(label))
        client.dns_allow_unpinned = True
        self.assertIsNone(client.dns_lookup("gw"))
        client.dns_pins = {}
        self.assertEqual(client.dns_lookup("gw"), "100.64.0.3")

    def test_dns_pins_reject_bad_keys_and_conflicts(self):
        key1 = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))
        key2 = mesh._b64(mesh.pub_bytes(X25519PrivateKey.generate()))
        self.assertEqual(mesh.parse_dns_pins(["GW=" + key1]), {"gw": key1})
        for pins in (["bad.name=" + key1], ["gw=short"],
                     ["gw=" + key1, "gw=" + key2],
                     [mesh.dns_key_label(key1) + "=" + key2]):
            with self.assertRaises(ValueError):
                mesh.parse_dns_pins(pins)

    def test_own_dns_name_with_remote_collision_fails_closed(self):
        client = mesh.MeshNode(X25519PrivateKey.generate(), "client")
        client.overlay_ip = "100.64.0.1"
        client.dns_allow_unpinned = True
        client.peers = {"other": {"hostname": "client", "ip": "100.64.0.2"}}
        self.assertIsNone(client.dns_lookup("client"))

    def test_duplicate_hostnames_fail_closed(self):
        n = mesh.MeshNode(X25519PrivateKey.generate(), "client")
        n.peers = {
            "first": {"hostname": "same", "ip": "100.64.0.2"},
            "second": {"hostname": "same", "ip": "100.64.0.3"},
        }
        self.assertIsNone(n.resolve("same"))
        self.assertIsNone(n.dns_lookup("same"))


if __name__ == "__main__":
    unittest.main()
