"""Unit tests for the crypto and protocol layer in remote_desktop.py."""

import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from remote_desktop import (
    SecureChannel,
    _auth,
    _hmac,
    _read_exactly,
    _str_to_key,
    _tk_key_str,
    _xor,
    _XofCipher,
    _MAX_FRAME,
    MSG_FRAME,
    MSG_MOUSE_MOVE,
    MSG_MOUSE_BTN,
    MSG_MOUSE_SCROLL,
    MSG_KEY,
    COORD,
)

PSK = b"test-passphrase-for-unit-tests"


def _make_pair_and_auth(psk=PSK):
    """Return (host_channel, client_channel) after a successful auth handshake."""
    hs, cs = socket.socketpair()
    errors = []

    def run_host():
        try:
            return _auth(hs, psk, is_host=True)
        except Exception as e:
            errors.append(f"host: {e}")

    def run_client():
        try:
            return _auth(cs, psk, is_host=False)
        except Exception as e:
            errors.append(f"client: {e}")

    results = [None, None]

    def th():
        results[0] = run_host()

    def tc():
        results[1] = run_client()

    t1 = threading.Thread(target=th)
    t2 = threading.Thread(target=tc)
    t1.start(); t2.start()
    t1.join(); t2.join()
    if errors:
        raise AssertionError(errors)
    return results[0], results[1]


class TestXor(unittest.TestCase):
    def test_roundtrip(self):
        a = b"\xde\xad\xbe\xef" * 8
        b = b"\x12\x34\x56\x78" * 8
        self.assertEqual(_xor(_xor(a, b), b), a)

    def test_zeros(self):
        data = b"\xff" * 32
        key  = b"\xff" * 32
        self.assertEqual(_xor(data, key), b"\x00" * 32)


class TestXofCipher(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = b"k" * 32
        c1  = _XofCipher(key)
        c2  = _XofCipher(key)
        plaintext = b"hello world" * 100
        self.assertEqual(c2.crypt(c1.crypt(plaintext)), plaintext)

    def test_counter_advances(self):
        key = b"k" * 32
        c   = _XofCipher(key)
        ct1 = c.crypt(b"A" * 32)
        ct2 = c.crypt(b"A" * 32)
        self.assertNotEqual(ct1, ct2)

    def test_empty(self):
        self.assertEqual(_XofCipher(b"k" * 32).crypt(b""), b"")


class TestReadExactly(unittest.TestCase):
    def test_basic(self):
        hs, cs = socket.socketpair()
        cs.sendall(b"hello")
        self.assertEqual(_read_exactly(hs, 5), b"hello")
        hs.close(); cs.close()

    def test_eof_raises(self):
        hs, cs = socket.socketpair()
        cs.close()
        with self.assertRaises(ConnectionError):
            _read_exactly(hs, 1)
        hs.close()


class TestAuth(unittest.TestCase):
    def test_success(self):
        hc, cc = _make_pair_and_auth()
        self.assertIsInstance(hc, SecureChannel)
        self.assertIsInstance(cc, SecureChannel)
        hc.close(); cc.close()

    def test_wrong_psk_rejected(self):
        hs, cs = socket.socketpair()
        errors = []

        def run_h():
            try:
                _auth(hs, b"correct", is_host=True)
                errors.append("host: should have raised")
            except (PermissionError, ConnectionError):
                pass
            except Exception as e:
                errors.append(f"host unexpected: {e}")

        def run_c():
            try:
                _auth(cs, b"wrong", is_host=False)
                errors.append("client: should have raised")
            except (PermissionError, ConnectionError):
                pass
            except Exception as e:
                errors.append(f"client unexpected: {e}")

        t1 = threading.Thread(target=run_h)
        t2 = threading.Thread(target=run_c)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])

    def test_sock_closed_on_wrong_psk(self):
        """Socket must be closed by _auth on auth failure (no leak)."""
        hs, cs = socket.socketpair()
        # We only need to check one side; use a flag checked after join.
        closed = threading.Event()

        def run_h():
            try:
                _auth(hs, b"correct", is_host=True)
            except (PermissionError, ConnectionError):
                pass
            # After _auth raises, fileno() should be -1 (closed)
            if hs.fileno() == -1:
                closed.set()

        def run_c():
            try:
                _auth(cs, b"wrong", is_host=False)
            except (PermissionError, ConnectionError):
                pass

        t1 = threading.Thread(target=run_h)
        t2 = threading.Thread(target=run_c)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertTrue(closed.is_set(), "socket not closed after auth failure")


class TestSecureChannel(unittest.TestCase):
    def setUp(self):
        self.hc, self.cc = _make_pair_and_auth()

    def tearDown(self):
        self.hc.close(); self.cc.close()

    def test_send_recv(self):
        self.hc.send(b"ping")
        self.assertEqual(self.cc.recv(), b"ping")

    def test_bidirectional(self):
        self.hc.send(b"host->client")
        self.cc.send(b"client->host")
        self.assertEqual(self.cc.recv(), b"host->client")
        self.assertEqual(self.hc.recv(), b"client->host")

    def test_large_payload(self):
        import os
        data = os.urandom(512 * 1024)
        received = []
        errors = []

        def recv_side():
            try:
                received.append(self.cc.recv())
            except Exception as e:
                errors.append(str(e))

        t = threading.Thread(target=recv_side)
        t.start()
        self.hc.send(data)
        t.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(received, [data])

    def test_tampered_mac_rejected(self):
        """Flip one bit in the MAC; recv() must raise PermissionError."""
        hs, cs = socket.socketpair()
        errors = []
        result = []

        def sender():
            try:
                ch = _auth(hs, PSK, is_host=True)
                plaintext = b"legitimate payload"
                with ch._wlock:
                    ct      = ch._enc.crypt(plaintext)
                    mac     = _hmac(ch._ms, struct.pack(">Q", ch._sseq) + ct)
                    ch._sseq += 1
                    bad_mac = bytes([mac[0] ^ 0xFF]) + mac[1:]   # flip first byte
                    ch._send_raw(struct.pack(">I", len(ct)) + bad_mac + ct)
            except Exception as e:
                errors.append(f"sender: {e}")

        def recver():
            try:
                ch = _auth(cs, PSK, is_host=False)
                ch.recv()
                errors.append("recv should have raised PermissionError")
            except PermissionError:
                result.append("ok")
            except Exception as e:
                errors.append(f"recver unexpected: {e}")

        t1 = threading.Thread(target=sender)
        t2 = threading.Thread(target=recver)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])
        self.assertEqual(result, ["ok"])

    def test_send_multi(self):
        self.hc.send_multi(b"frame-1", b"frame-2", b"frame-3")
        self.assertEqual(self.cc.recv(), b"frame-1")
        self.assertEqual(self.cc.recv(), b"frame-2")
        self.assertEqual(self.cc.recv(), b"frame-3")

    def test_frame_too_large_rejected(self):
        """recv() must raise ValueError when length field exceeds _MAX_FRAME."""
        hs, cs = socket.socketpair()
        errors = []
        result = []

        def sender():
            try:
                _auth(hs, PSK, is_host=True)
                # Inject a raw 4-byte length field that exceeds _MAX_FRAME,
                # bypassing SecureChannel so we can test the guard directly.
                hs.sendall(struct.pack(">I", _MAX_FRAME + 1))
            except Exception as e:
                errors.append(f"sender: {e}")

        def recver():
            try:
                ch = _auth(cs, PSK, is_host=False)
                ch.recv()
                errors.append("recv should have raised ValueError")
            except ValueError:
                result.append("ok")
            except Exception as e:
                errors.append(f"recver unexpected: {e}")

        t1 = threading.Thread(target=sender)
        t2 = threading.Thread(target=recver)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])
        self.assertEqual(result, ["ok"])


class TestProtocolEncoding(unittest.TestCase):
    def test_frame_header(self):
        w, h = 1920, 1080
        jpeg = b"\xff\xd8" + b"\x00" * 50
        msg = struct.pack(">B HH", MSG_FRAME, w, h) + jpeg
        self.assertEqual(msg[0], MSG_FRAME)
        fw, fh = struct.unpack(">HH", msg[1:5])
        self.assertEqual((fw, fh), (w, h))
        self.assertEqual(msg[5:], jpeg)

    def test_mouse_move(self):
        xn, yn = 32767, 16383
        msg = struct.pack(">B HH", MSG_MOUSE_MOVE, xn, yn)
        self.assertEqual(struct.unpack(">HH", msg[1:]), (xn, yn))

    def test_mouse_btn(self):
        msg = struct.pack(">B BB", MSG_MOUSE_BTN, 1, 1)
        self.assertEqual(msg[1], 1)
        self.assertEqual(msg[2], 1)

    def test_scroll_negative(self):
        msg = struct.pack(">B hh", MSG_MOUSE_SCROLL, 0, -3)
        self.assertEqual(struct.unpack(">hh", msg[1:]), (0, -3))

    def test_key_event(self):
        key_str = "Key.enter"
        msg = bytes([MSG_KEY, 1]) + key_str.encode()
        self.assertEqual(msg[0], MSG_KEY)
        self.assertEqual(msg[1], 1)
        self.assertEqual(msg[2:].decode(), key_str)

    def test_coord_clamp(self):
        self.assertEqual(max(0, min(COORD, -1)), 0)
        self.assertEqual(max(0, min(COORD, COORD + 1)), COORD)


class TestKeyMapping(unittest.TestCase):
    def setUp(self):
        try:
            from pynput import keyboard as kb
            self.kb = kb
        except Exception:
            self.skipTest("pynput unavailable in this environment")

    def test_special_key(self):
        self.assertEqual(_str_to_key("Key.enter", self.kb), self.kb.Key.enter)
        self.assertEqual(_str_to_key("Key.ctrl_l", self.kb), self.kb.Key.ctrl_l)

    def test_char_key(self):
        self.assertEqual(_str_to_key("a", self.kb), self.kb.KeyCode.from_char("a"))

    def test_unknown_key(self):
        self.assertIsNone(_str_to_key("Key.nonexistent", self.kb))
        self.assertIsNone(_str_to_key("multi", self.kb))

    def test_tk_special_keys(self):
        class E:
            keysym = "Return"; char = ""
        self.assertEqual(_tk_key_str(E()), "Key.enter")
        E.keysym = "Meta_L"
        self.assertEqual(_tk_key_str(E()), "Key.cmd")
        E.keysym = "F5"
        self.assertEqual(_tk_key_str(E()), "Key.f5")
        E.keysym = "Control_L"
        self.assertEqual(_tk_key_str(E()), "Key.ctrl_l")

    def test_tk_printable_char(self):
        class E:
            keysym = "z"; char = "z"
        self.assertEqual(_tk_key_str(E()), "z")

    def test_tk_unrecognised(self):
        class E:
            keysym = "XF86AudioPlay"; char = ""
        self.assertEqual(_tk_key_str(E()), "")


if __name__ == "__main__":
    unittest.main()
