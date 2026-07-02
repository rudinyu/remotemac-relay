"""Unit + integration tests for the SOCKS5 proxy (mux) layer in remote_desktop.py."""

import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from remote_desktop import (
    _auth,
    _encode_addr,
    _decode_addr,
    _parse_udp_req,
    _build_udp_reply,
    _make_allow,
    _mux_frame,
    _GatewayMux,
    _SocksMux,
    _keepalive_loop,
    MUX_OPEN,
    MUX_DATA,
    MUX_KEEPALIVE,
)

PSK = b"proxy-test-passphrase"


def _auth_pair():
    """Return (host_channel, client_channel) after a successful handshake."""
    hs, cs = socket.socketpair()
    out = [None, None]

    def run_h():
        out[0] = _auth(hs, PSK, is_host=True)

    def run_c():
        out[1] = _auth(cs, PSK, is_host=False)

    t1 = threading.Thread(target=run_h)
    t2 = threading.Thread(target=run_c)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert out[0] is not None and out[1] is not None, "auth failed"
    return out[0], out[1]


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAddrCodec(unittest.TestCase):
    def test_ipv4_roundtrip(self):
        enc = _encode_addr("93.184.216.34", 443)
        self.assertEqual(enc[0], 0x01)
        self.assertEqual(_decode_addr(enc), ("93.184.216.34", 443, len(enc)))

    def test_ipv6_roundtrip(self):
        enc = _encode_addr("2606:2800:220:1:248:1893:25c8:1946", 80)
        self.assertEqual(enc[0], 0x04)
        host, port, off = _decode_addr(enc)
        self.assertEqual(port, 80)
        self.assertEqual(off, len(enc))

    def test_domain_roundtrip(self):
        enc = _encode_addr("example.com", 8080)
        self.assertEqual(enc[0], 0x03)
        self.assertEqual(_decode_addr(enc), ("example.com", 8080, len(enc)))

    def test_mux_frame_layout(self):
        f = _mux_frame(MUX_DATA, 0x01020304, b"hi")
        self.assertEqual(f[0], MUX_DATA)
        self.assertEqual(struct.unpack(">I", f[1:5])[0], 0x01020304)
        self.assertEqual(f[5:], b"hi")


class TestUdpCodec(unittest.TestCase):
    def test_parse_and_build(self):
        pkt = b"\x00\x00\x00" + _encode_addr("1.2.3.4", 53) + b"payload"
        self.assertEqual(_parse_udp_req(pkt), ("1.2.3.4", 53, b"payload"))
        reply = _build_udp_reply("1.2.3.4", 53, b"payload")
        self.assertEqual(reply[:3], b"\x00\x00\x00")

    def test_fragment_rejected(self):
        pkt = b"\x00\x00\x01" + _encode_addr("1.2.3.4", 53) + b"x"
        self.assertIsNone(_parse_udp_req(pkt))


class TestAllowFilter(unittest.TestCase):
    def test_allow_all_when_empty(self):
        ok = _make_allow([])
        self.assertTrue(ok("anything.com", 80))

    def test_domain_suffix(self):
        ok = _make_allow(["example.com"])
        self.assertTrue(ok("example.com", 80))
        self.assertTrue(ok("www.example.com", 443))
        self.assertFalse(ok("evil.com", 80))
        self.assertFalse(ok("notexample.com", 80))

    def test_cidr(self):
        ok = _make_allow(["10.0.0.0/8"])
        self.assertTrue(ok("10.1.2.3", 22))
        self.assertFalse(ok("192.168.1.1", 22))


class _MuxHarness:
    """Wire a gateway mux and a socks mux together over an authed channel pair,
    and expose a bound local SOCKS5 listener that speaks to the socks mux."""

    def __init__(self, allow=None, bind="127.0.0.1"):
        self.hc, self.cc = _auth_pair()
        self.gw   = _GatewayMux(self.hc, _make_allow(allow or []))
        self.smux = _SocksMux(self.cc, bind)
        self.bind = bind
        self._threads = [
            threading.Thread(target=self.gw.run, daemon=True),
            threading.Thread(target=self.smux.run, daemon=True),
            threading.Thread(target=_keepalive_loop, args=(self.smux,), daemon=True),
        ]
        # Local SOCKS5 listener feeding the socks mux.
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind((bind, 0))
        self.lsock.listen(16)
        self.port = self.lsock.getsockname()[1]
        self._threads.append(threading.Thread(target=self._accept, daemon=True))

    def _accept(self):
        while True:
            try:
                cs, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self.smux.handle, args=(cs,), daemon=True).start()

    def start(self):
        for t in self._threads:
            t.start()

    def stop(self):
        self.gw.stop(); self.smux.stop()
        try: self.lsock.close()
        except Exception: pass

    def socks_connect(self, host, port):
        """Open a SOCKS5 CONNECT through the local listener; return the socket
        and the SOCKS reply code (0 = success)."""
        s = socket.create_connection((self.bind, self.port), timeout=5)
        s.sendall(b"\x05\x01\x00")
        self.assertEqual2(s.recv(2), b"\x05\x00")
        s.sendall(b"\x05\x01\x00" + _encode_addr(host, port))
        rep = s.recv(10)
        return s, rep[1]

    # tiny assert shim so harness can be used outside a TestCase too
    def assertEqual2(self, a, b):
        assert a == b, f"{a!r} != {b!r}"


def _echo_server():
    """Start a local TCP echo server; return (host, port, stop_fn)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    host, port = srv.getsockname()

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            def handle(c=c):
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        c.sendall(d)
                except Exception:
                    pass
                finally:
                    c.close()
            threading.Thread(target=handle, daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return host, port, srv.close


def _udp_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    host, port = srv.getsockname()

    def serve():
        try:
            while True:
                data, addr = srv.recvfrom(65535)
                srv.sendto(data, addr)
        except Exception:
            return

    threading.Thread(target=serve, daemon=True).start()
    return host, port, srv.close


class TestSocksTcp(unittest.TestCase):
    def setUp(self):
        self.h = _MuxHarness()
        self.h.assertEqual2 = lambda a, b: self.assertEqual(a, b)
        self.h.start()
        self.ehost, self.eport, self.estop = _echo_server()

    def tearDown(self):
        self.estop()
        self.h.stop()

    def test_connect_and_echo(self):
        s, rep = self.h.socks_connect(self.ehost, self.eport)
        self.assertEqual(rep, 0x00)
        s.sendall(b"hello proxy")
        self.assertEqual(s.recv(64), b"hello proxy")
        s.sendall(b"second")
        self.assertEqual(s.recv(64), b"second")
        s.close()

    def test_connect_refused_maps_error(self):
        dead = _free_port()
        s, rep = self.h.socks_connect("127.0.0.1", dead)
        self.assertNotEqual(rep, 0x00)   # some SOCKS failure code
        s.close()

    def test_allowlist_blocks(self):
        h = _MuxHarness(allow=["example.com"])
        h.assertEqual2 = lambda a, b: self.assertEqual(a, b)
        h.start()
        try:
            s, rep = h.socks_connect(self.ehost, self.eport)   # 127.0.0.1 not allowed
            self.assertEqual(rep, 0x02)   # connection not allowed by ruleset
            s.close()
        finally:
            h.stop()


class TestSocksUdp(unittest.TestCase):
    def setUp(self):
        self.h = _MuxHarness()
        self.h.assertEqual2 = lambda a, b: self.assertEqual(a, b)
        self.h.start()
        self.uhost, self.uport, self.ustop = _udp_echo_server()

    def tearDown(self):
        self.ustop()
        self.h.stop()

    def test_udp_associate_echo(self):
        ctrl = socket.create_connection((self.h.bind, self.h.port), timeout=5)
        ctrl.sendall(b"\x05\x01\x00")
        self.assertEqual(ctrl.recv(2), b"\x05\x00")
        ctrl.sendall(b"\x05\x03\x00" + _encode_addr("0.0.0.0", 0))
        reply = ctrl.recv(64)
        self.assertEqual(reply[1], 0x00)
        relay_host, relay_port, _ = _decode_addr(reply, 3)

        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(5)
        pkt = b"\x00\x00\x00" + _encode_addr(self.uhost, self.uport) + b"ping-udp"
        u.sendto(pkt, (relay_host, relay_port))
        data, _ = u.recvfrom(65535)
        parsed = _parse_udp_req(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[2], b"ping-udp")
        u.close()
        ctrl.close()


if __name__ == "__main__":
    unittest.main()
