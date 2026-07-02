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

    def _node(self, name):
        n = mesh.MeshNode(X25519PrivateKey.generate(), name)
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
        # Force DERP: pretend we know no UDP endpoints for the peer.
        a._peer_endpoints = lambda pk: []

        got = threading.Event()
        a.on_message = lambda src, mt, pl: got.set() if mt == mesh.MESH_PONG else None
        dst = a.resolve("bob3")
        a.send(dst, mesh.MESH_PING, b"hi")
        self.assertTrue(got.wait(5), "did not receive PONG over DERP fallback")
        self.assertEqual(a._conns[dst].transport, "derp")

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

    def test_resolve_by_overlay_ip(self):
        a = self._node("alice2")
        b = self._node("bob2")
        self.assertTrue(self._wait(lambda: b.pubkey_b64 in a.peers))
        bob_ip = a.peers[b.pubkey_b64]["ip"]
        self.assertEqual(a.resolve(bob_ip), b.pubkey_b64)


if __name__ == "__main__":
    unittest.main()
