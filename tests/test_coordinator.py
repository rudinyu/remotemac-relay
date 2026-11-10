"""Tests for coordinator resource limits: admission control, bounded scrypt,
per-node outboxes, and control-channel keepalive."""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

try:
    import coordinator
    import mesh
    import remote_desktop
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


def _wait(cond, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def _is_dropped(sock, timeout=2):
    """True if the server closed this connection without sending anything."""
    sock.settimeout(timeout)
    try:
        return sock.recv(64) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def _got_nonce(sock, timeout=2):
    """True if the server started a handshake (sent its 32-byte nonce)."""
    sock.settimeout(timeout)
    try:
        return len(remote_desktop._read_exactly(sock, 32)) == 32
    except Exception:
        return False


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestKdfSlots(unittest.TestCase):
    def test_auth_bounds_concurrent_scrypt(self):
        # With one KDF slot, concurrent handshakes run scrypt strictly one at a time.
        active, peak, lock = [0], [0], threading.Lock()
        real_scrypt = remote_desktop.hashlib.scrypt

        def slow_scrypt(*a, **kw):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.2)
            with lock:
                active[0] -= 1
            return real_scrypt(*a, **kw)

        slots = threading.BoundedSemaphore(1)
        results = []

        def host(sock):
            try:
                remote_desktop._auth(sock, b"psk", True, kdf_slots=slots)
                results.append(True)
            except Exception as exc:
                results.append(exc)

        def client(sock):
            try:
                remote_desktop._auth(sock, b"psk", False)
            except Exception:
                pass

        with mock.patch.object(remote_desktop.hashlib, "scrypt", slow_scrypt):
            threads = []
            for _ in range(3):
                h, c = socket.socketpair()
                threads += [threading.Thread(target=host, args=(h,)),
                            threading.Thread(target=client, args=(c,))]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(results, [True, True, True])
        # Clients are unbounded (3 at once at most); host-side runs are gated
        # by the single slot, so total concurrency never exceeds 1 + 3.
        self.assertLessEqual(peak[0], 4)

    def test_slots_gate_host_side_only(self):
        # Direct check: a held slot blocks the host's derivation.
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        h, c = socket.socketpair()
        done = threading.Event()

        def host():
            try:
                remote_desktop._auth(h, b"psk", True, kdf_slots=slots)
            except Exception:
                pass
            done.set()
        threading.Thread(target=host, daemon=True).start()
        threading.Thread(target=lambda: remote_desktop._auth(c, b"psk", False),
                         daemon=True).start()
        self.assertFalse(done.wait(0.5), "host derived keys without a free KDF slot")
        slots.release()
        self.assertTrue(done.wait(5), "host did not proceed once a slot freed up")


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestOutbox(unittest.TestCase):
    def test_relay_queue_is_bounded(self):
        gate = threading.Event()

        class _BlockedCh:
            def send(self, data):
                gate.wait(5)

        ob = coordinator._Outbox(_BlockedCh(), socket.socket(), lambda: {})
        try:
            for i in range(ob.MAX_QUEUED + 50):
                ob.put({"t": "from", "i": i})
            # One message may already be in flight; the rest are capped.
            self.assertGreaterEqual(ob.dropped, 49)
        finally:
            ob.close()
            gate.set()


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestCoordinatorLimits(unittest.TestCase):
    def setUp(self):
        self.token = b"coord-test-token"
        state = os.path.join(tempfile.mkdtemp(), "state.json")
        self.coord = coordinator.Coordinator(self.token, coordinator.IPAllocator(state))
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(128)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self.socks, self.nodes = [], []

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self.srv.accept()
            except OSError:
                return
            self.coord.accept(conn, addr)

    def tearDown(self):
        for n in self.nodes:
            n.close()
        for s in self.socks:
            s.close()
        self.srv.close()

    def _raw(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        self.socks.append(s)
        return s

    def _node(self, name, **attrs):
        n = mesh.MeshNode(X25519PrivateKey.generate(), name)
        for k, v in attrs.items():
            setattr(n, k, v)
        n.connect(f"127.0.0.1:{self.port}", self.token)
        threading.Thread(target=n.run, daemon=True).start()
        self.nodes.append(n)
        return n

    def test_pending_connections_capped_per_ip(self):
        # Connections that never authenticate hold a pending slot; past the
        # per-IP cap, new ones are closed at once without a handshake.
        idle = [self._raw() for _ in range(coordinator.MAX_PENDING_PER_IP)]
        for s in idle:
            self.assertTrue(_got_nonce(s), "an in-limit connection was not served")
        self.assertTrue(_is_dropped(self._raw()), "connection past the per-IP cap was served")
        # Freeing the slots lets a real node in.
        for s in idle:
            s.close()
        self.assertTrue(_wait(lambda: self.coord._pending_total == 0))
        n = self._node("after-flood")
        self.assertTrue(_wait(lambda: n.overlay_ip), "node not admitted after slots freed")

    def test_pending_connections_capped_globally(self):
        with mock.patch.object(coordinator, "MAX_PENDING", 3), \
             mock.patch.object(coordinator, "MAX_PENDING_PER_IP", 100):
            idle = [self._raw() for _ in range(3)]
            for s in idle:
                self.assertTrue(_got_nonce(s))
            self.assertTrue(_is_dropped(self._raw()), "connection past the global cap was served")

    def test_registered_nodes_do_not_count_as_pending(self):
        nodes = [self._node(f"n{i}") for i in range(coordinator.MAX_PENDING_PER_IP + 1)]
        self.assertTrue(_wait(lambda: all(n.overlay_ip for n in nodes)),
                        "registered nodes kept holding pending slots")
        self.assertEqual(self.coord._pending_total, 0)

    def test_unregistered_connection_is_dropped_after_deadline(self):
        with mock.patch.object(coordinator, "REGISTER_TIMEOUT", 0.5):
            s = self._raw()
            self.assertTrue(_got_nonce(s))
            self.assertTrue(_is_dropped(s, timeout=3), "stalled handshake was not reaped")
        self.assertTrue(_wait(lambda: self.coord._pending_total == 0))

    def test_slow_node_does_not_stall_map_pushes(self):
        a = self._node("slow")
        b = self._node("fast")
        self.assertTrue(_wait(lambda: a.pubkey_b64 in b.peers))
        # Wedge the slow node's channel: every send to it blocks for seconds.
        with self.coord._lock:
            rec = self.coord._nodes[a.pubkey_b64]
        real_send = rec["ch"].send
        rec["ch"].send = lambda data: (time.sleep(5), real_send(data))
        c = self._node("newcomer")
        self.assertTrue(_wait(lambda: c.pubkey_b64 in b.peers, 1.5),
                        "map push to a healthy node was blocked by a slow one")

    def test_idle_node_stays_connected_with_keepalive(self):
        with mock.patch.object(remote_desktop, "_IDLE_TIMEOUT", 1):
            a = self._node("idle-a", control_keepalive=0.3)
            b = self._node("idle-b", control_keepalive=0.3)
            self.assertTrue(_wait(lambda: a.pubkey_b64 in b.peers and b.pubkey_b64 in a.peers))
            time.sleep(3)
            self.assertFalse(a._done.is_set() or b._done.is_set(),
                             "idle node's control channel was dropped")
            self.assertIn(a.pubkey_b64, b.peers)

    def test_silent_node_is_reaped(self):
        # Without keepalives, the coordinator's idle timeout still reaps a dead
        # control channel (that's the liveness mechanism the keepalive feeds).
        with mock.patch.object(remote_desktop, "_IDLE_TIMEOUT", 1):
            a = self._node("silent", control_keepalive=60)
            b = self._node("watcher", control_keepalive=0.3)
            self.assertTrue(_wait(lambda: a.pubkey_b64 in b.peers))
            self.assertTrue(_wait(lambda: a.pubkey_b64 not in b.peers, 5),
                            "silent node was never reaped")


if __name__ == "__main__":
    unittest.main()
