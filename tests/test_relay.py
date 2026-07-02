"""Unit tests for the relay pairing/bridging logic in relay.py."""

import asyncio
import socket
import sys
import unittest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import relay

DEVICE_ID = b"testdev1"


class RelayTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        relay.hosts.clear()
        relay.conns_per_ip.clear()
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
        return await asyncio.wait_for(reader.read(1), timeout=5)

    async def _register_host(self, ip="10.0.0.1", rid=DEVICE_ID):
        r, w = await self._connect(ip)
        w.write(b"H" + rid)
        await w.drain()
        self.assertEqual(await self._read(r), b"R")
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
