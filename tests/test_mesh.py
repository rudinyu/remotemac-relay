"""Tests for the mesh control plane + node crypto (Phase 1)."""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

try:
    import mesh
    import coordinator
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
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


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestSubnetRouteHelpers(unittest.TestCase):
    def test_parse_cidrs_normalizes_and_skips_bad(self):
        self.assertEqual(mesh.parse_cidrs("192.168.1.0/24, 10.0.0.5/8"),
                         ["192.168.1.0/24", "10.0.0.0/8"])   # host bits masked off
        self.assertEqual(mesh.parse_cidrs("nonsense, 192.168.0.0/16"), ["192.168.0.0/16"])
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

    def _node(self, name, advertise_routes=None, accept_routes=False,
              is_exit=False, exit_node=None):
        n = mesh.MeshNode(X25519PrivateKey.generate(), name, is_exit=is_exit,
                          advertise_routes=advertise_routes)
        n.accept_routes = accept_routes
        n.exit_node_name = exit_node
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
        # direct UDP endpoint when a handshake later arrives over UDP — reusing
        # the SAME session (not rebuilding it) and flipping transport to direct.
        a = self._node("up-a")
        b = self._node("up-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers and a.pubkey_b64 in b.peers))
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

        def _upgrade(node, peer, stage):
            pc = node._conns[peer]
            sess = pc.session
            fake = ("127.0.0.1", 40000)
            node._handle_hs(peer, node._peer_static(peer), stage,
                            b"\x11" * 32, 4242, "udp", fake)
            self.assertIs(pc.session, sess, "session was rebuilt, not upgraded")
            self.assertEqual(pc.transport, "direct")
            self.assertEqual(pc.endpoint, fake)

        # The initiator would receive a RESP over UDP; the responder, an INIT.
        a_is_init = a._am_initiator(a._peer_static(da))
        _upgrade(a, da, mesh._HS_RESP if a_is_init else mesh._HS_INIT)
        _upgrade(b, db, mesh._HS_INIT if a_is_init else mesh._HS_RESP)

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

        # No reachable endpoints to re-punch → failover must stick on DERP;
        # mark the path silent and speed up the liveness loop.
        a._peer_endpoints = lambda pk: []
        b._peer_endpoints = lambda pk: []
        a._ka_tick = 0.05
        a.direct_timeout = 0.2
        a.keepalive_interval = 0.1
        a._conns[da].last_rx = time.monotonic() - 100

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
        client = self._node("laptop", accept_routes=True)

        self.assertTrue(self._wait(
            lambda: gw.pubkey_b64 in client.peers
            and client.peers[gw.pubkey_b64].get("routes") == ["192.168.1.0/24"]),
            "client did not learn the advertised route via the coordinator")
        # The route table is rebuilt from the map when accept_routes is on.
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
        client = self._node("laptop2")            # accept_routes defaults off
        self.assertTrue(self._wait(lambda: gw.pubkey_b64 in client.peers))
        # Learned in the map, but not installed as a route (no opt-in).
        self.assertEqual(client.peers[gw.pubkey_b64].get("routes"), ["192.168.9.0/24"])
        self.assertIsNone(client.route_for("192.168.9.5"))

    def test_exit_node_full_tunnel_routing(self):
        # A client with --exit-node routes all non-overlay/non-subnet traffic to
        # the exit peer, and accepts replies from it sourced from any address.
        ex = self._node("exit", is_exit=True)
        client = self._node("laptop3", exit_node="exit")

        self.assertTrue(self._wait(lambda: client.exit_node_pk == ex.pubkey_b64),
                        "client did not resolve the exit node")
        # Internet-bound traffic goes to the exit; overlay still resolves to peers.
        self.assertEqual(client.route_for("8.8.8.8"), ex.pubkey_b64)
        self.assertEqual(client.route_for("1.1.1.1"), ex.pubkey_b64)
        self.assertEqual(client.route_for(ex.overlay_ip), ex.pubkey_b64)   # overlay wins
        # Anti-spoof: the exit may source anything; a non-exit peer may not.
        self.assertTrue(client.src_permitted(ex.pubkey_b64, "93.184.216.34"))
        self.assertFalse(client.src_permitted("some-other-pk", "93.184.216.34"))

    def test_no_exit_node_leaves_internet_unrouted(self):
        # Without --exit-node, internet destinations stay unroutable (dropped).
        a = self._node("plain-a")
        b = self._node("plain-b")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers))
        self.assertIsNone(a.route_for("8.8.8.8"))

    def test_exit_node_ignored_if_peer_not_advertising_exit(self):
        # Naming a peer that isn't an exit must not enable full-tunnel: exit_node_pk
        # stays unresolved and internet traffic stays unrouted.
        plain = self._node("not-an-exit")
        client = self._node("laptop4", exit_node="not-an-exit")
        self.assertTrue(self._wait(lambda: plain.pubkey_b64 in client.peers))
        # Give the map a moment; the non-exit peer must never resolve as the exit.
        time.sleep(0.3)
        self.assertIsNone(client.exit_node_pk)
        self.assertIsNone(client.route_for("8.8.8.8"))

    def test_resolve_by_overlay_ip(self):
        a = self._node("alice2")
        b = self._node("bob2")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers))
        bob_ip = a.peers[b.pubkey_b64]["ip"]
        self.assertEqual(a.resolve(bob_ip), b.pubkey_b64)


if __name__ == "__main__":
    unittest.main()
