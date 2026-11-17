"""Unit tests for the relay pairing/bridging logic in relay.py."""

import asyncio
import hashlib
import hmac
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import relay
import remote_desktop

DEVICE_ID = b"testdev1"


class RelayTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        relay.hosts.clear()
        relay.conns_per_ip.clear()
        self._host_token = relay.HOST_TOKEN
        relay.HOST_TOKEN = None
        self._tasks = []
        self._writers = []

    async def asyncTearDown(self):
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for w in self._writers:
            try:
                w.close()
            except Exception:
                pass
        relay.hosts.clear()
        relay.conns_per_ip.clear()
        relay.HOST_TOKEN = self._host_token

    async def _connect(self, ip, entry=relay._dispatch, **kwargs):
        """Simulate one inbound connection; returns the test-side (reader, writer)."""
        a, b = socket.socketpair()
        cr, cw = await asyncio.open_connection(sock=a)
        sr, sw = await asyncio.open_connection(sock=b)
        if entry is relay._dispatch:
            task = asyncio.create_task(relay._dispatch(sr, sw, ip))
        else:
            task = asyncio.create_task(entry(sr, sw))
        self._tasks.append(task)
        self._writers.extend((cw, sw))
        return cr, cw

    async def _read(self, reader, n=1):
        return await asyncio.wait_for(reader.readexactly(n), timeout=5)

    async def _read_eof(self, reader):
        # A refused connection may close cleanly (EOF → b"") or, when the server
        # closes with the client's bytes still unread, reset (RST). Linux surfaces
        # the RST as ConnectionResetError where macOS gives a clean EOF; treat both
        # as "the peer closed".
        try:
            return await asyncio.wait_for(reader.read(1), timeout=5)
        except (ConnectionResetError, BrokenPipeError):
            return b""

    async def _register_host(self, ip="10.0.0.1", rid=DEVICE_ID, token=None):
        r, w = await self._connect(ip)
        w.write(b"H" + rid)
        await w.drain()
        response = await self._read(r)
        if token is not None:
            self.assertEqual(response, b"A")
            nonce = await self._read(r, 32)
            w.write(hmac.new(token, b"host-register" + rid + nonce, hashlib.sha256).digest())
            await w.drain()
            response = await self._read(r)
        self.assertEqual(response, b"R")
        return r, w

    async def test_host_registers(self):
        await self._register_host()
        self.assertIn(DEVICE_ID, relay.hosts)

    async def test_client_without_host_gets_n(self):
        r, w = await self._connect("10.0.0.9")
        w.write(b"C" + b"nosuchid")
        await w.drain()
        self.assertEqual(await self._read(r), b"N")
        self.assertEqual(await self._read_eof(r), b"")

    async def test_pairing_bridges_both_directions(self):
        hr, hw = await self._register_host()
        cr, cw = await self._connect("10.0.0.2")
        cw.write(b"C" + DEVICE_ID)
        await cw.drain()
        self.assertEqual(await self._read(cr), b"P")
        self.assertEqual(await self._read(hr), b"P")

        cw.write(b"from-client")
        await cw.drain()
        self.assertEqual(await self._read(hr, 11), b"from-client")

        hw.write(b"from-host")
        await hw.drain()
        self.assertEqual(await self._read(cr, 9), b"from-host")

        # Host slot was consumed by the pairing.
        self.assertNotIn(DEVICE_ID, relay.hosts)

    async def test_slot_occupied_by_other_ip_rejected(self):
        await self._register_host(ip="10.0.0.1")
        r2, w2 = await self._connect("10.0.0.2")
        w2.write(b"H" + DEVICE_ID)
        await w2.drain()
        self.assertEqual(await self._read(r2), b"D")
        self.assertEqual(await self._read_eof(r2), b"")

    async def test_protected_registration_rejects_unproved_host(self):
        token = b"relay-host-secret"
        relay.HOST_TOKEN = token
        r, w = await self._connect("10.0.0.9")
        w.write(b"H" + DEVICE_ID)
        await w.drain()
        self.assertEqual(await self._read(r), b"A")
        await self._read(r, 32)
        w.write(b"\0" * 32)
        await w.drain()
        self.assertEqual(await self._read_eof(r), b"")
        self.assertNotIn(DEVICE_ID, relay.hosts)
        await self._register_host(token=token)
        self.assertIn(DEVICE_ID, relay.hosts)

    async def test_python_host_interoperates_with_protected_relay(self):
        relay.HOST_TOKEN = b"relay-host-secret"
        server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with mock.patch.dict(os.environ, {"REMOTEMAC_RELAY_HOST_TOKEN": "relay-host-secret"}):
                loop = asyncio.get_running_loop()
                host = loop.run_in_executor(None, remote_desktop._relay_connect,
                                            f"127.0.0.1:{port}", "testdev1", True)
                for _ in range(100):
                    if DEVICE_ID in relay.hosts:
                        break
                    await asyncio.sleep(0.01)
                self.assertIn(DEVICE_ID, relay.hosts)
                cr, cw = await asyncio.open_connection("127.0.0.1", port)
                try:
                    cw.write(b"C" + DEVICE_ID)
                    await cw.drain()
                    self.assertEqual(await asyncio.wait_for(cr.readexactly(1), 2), b"P")
                    hs = await asyncio.wait_for(host, 2)
                    hs.close()
                finally:
                    cw.close()
                    await cw.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_same_ip_reconnect_evicts_old(self):
        r1, w1 = await self._register_host(ip="10.0.0.1")
        r2, w2 = await self._register_host(ip="10.0.0.1")
        # Old connection is closed; new one holds the slot.
        self.assertEqual(await self._read_eof(r1), b"")
        self.assertIn(DEVICE_ID, relay.hosts)

    async def test_bad_role_byte_closes(self):
        r, w = await self._connect("10.0.0.3")
        w.write(b"X" + DEVICE_ID)
        await w.drain()
        self.assertEqual(await self._read_eof(r), b"")

    async def test_per_ip_connection_limit(self):
        # socketpair connections have no peername, so handle() sees ip="unknown".
        relay.conns_per_ip["unknown"] = relay.MAX_CONNS_PER_IP
        r, w = await self._connect(None, entry=relay.handle)
        w.write(b"H" + DEVICE_ID)
        await w.drain()
        self.assertEqual(await self._read_eof(r), b"")
        self.assertNotIn(DEVICE_ID, relay.hosts)


if __name__ == "__main__":
    unittest.main()
