#!/usr/bin/env python3
"""
RemoteMac rendezvous relay — run this on a host that is reachable from the internet
(a VPS, or your own box with its port forwarded). Python 3.8+, NO dependencies.

What it does
------------
Lets the iPad reach the Mac from ANY network with no port-forwarding ON THE MAC: both
the Mac host and the iPad connect *outbound* to this relay, which bridges them by an
8-character Device ID. It is a BLIND byte-pipe — the Mac<->iPad traffic stays TLS-PSK
encrypted end-to-end, so this relay never sees your screen, input, files, or password.

Run
---
    python3 relay.py            # listens on 0.0.0.0:21118
    python3 relay.py 9000       # custom port
Open that TCP port in the firewall / security group.

Protocol (plaintext control bytes, before the end-to-end TLS the Mac/iPad speak):
each connection first sends  [1 byte role 'H'|'C'][8 byte device-id]
  'H' (host)   -> registered; gets 'R', then 'P' when a client pairs, then bytes bridge.
  'C' (client) -> host online: both get 'P' and bytes bridge; else gets 'N' and closes.
"""
import asyncio
import hashlib
import socket
import sys
from collections import defaultdict

__version__ = "1.5.0"

HOST = "0.0.0.0"
DEFAULT_PORT = 21118

# Safety limits — prevent resource exhaustion from abusive clients.
MAX_CONNS_PER_IP = 5   # simultaneous connections from one IP
MAX_HOSTS = 10_000     # total registered hosts in memory at once

hosts = {}          # device-id (bytes) -> (reader, writer, ip)
conns_per_ip = defaultdict(int)


def _log_id(rid):
    """Return a short, non-reversible token for logging — never log the raw device ID."""
    return hashlib.sha256(rid).hexdigest()[:12]


def _keepalive(writer):
    # Detect a host whose link died silently (e.g. home Wi-Fi dropped) so a later client
    # isn't bridged to a dead socket.
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
    except Exception:
        pass


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _dispatch(reader, writer, ip):
    _keepalive(writer)
    try:
        header = await asyncio.wait_for(reader.readexactly(9), timeout=15)
    except Exception:
        writer.close()
        return
    role, rid = header[0:1], header[1:9]
    lid = _log_id(rid)

    if role == b"H":
        # Refuse if the hosts table is full and this is a brand-new ID.
        if len(hosts) >= MAX_HOSTS and rid not in hosts:
            writer.close()
            return

        old = hosts.get(rid)
        if old:
            old_reader, old_writer, old_ip = old
            if old_writer is not writer:
                if not old_writer.is_closing() and old_ip != ip:
                    # A live host from a different IP already holds this slot — reject
                    # the newcomer to prevent host-displacement attacks.
                    print(f"[relay] host registration rejected (id={lid}, slot occupied)", flush=True)
                    try:
                        writer.write(b"D")
                        await writer.drain()
                    except Exception:
                        pass
                    writer.close()
                    return
                # Same IP reconnecting, or old writer already closing — evict the stale entry.
                try:
                    old_writer.close()
                except Exception:
                    pass

        entry = (reader, writer, ip)
        hosts[rid] = entry
        print(f"[relay] host registered id={lid} from {ip}", flush=True)
        try:
            writer.write(b"R")
            await writer.drain()
        except Exception:
            hosts.pop(rid, None)
            writer.close()
            return

        try:
            # Hold the connection open until a client consumes it or it closes.
            while not writer.is_closing() and hosts.get(rid) is entry:
                await asyncio.sleep(15)
        finally:
            # Always clean up so stale entries never linger.
            if hosts.get(rid) is entry:
                hosts.pop(rid, None)
        return

    if role == b"C":
        peer = hosts.pop(rid, None)
        if not peer:
            print(f"[relay] client: no host for id={lid} from {ip}", flush=True)
            try:
                writer.write(b"N")
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return
        hr, hw, _ = peer
        print(f"[relay] bridging client {ip} <-> host id={lid}", flush=True)
        try:
            hw.write(b"P"); await hw.drain()
            writer.write(b"P"); await writer.drain()
        except Exception:
            try:
                hw.close()
            except Exception:
                pass
            writer.close()
            return
        await asyncio.gather(_pipe(reader, hw), _pipe(hr, writer))
        print(f"[relay] session ended id={lid}", flush=True)
        return

    writer.close()


async def handle(reader, writer):
    peername = writer.get_extra_info("peername")
    ip = peername[0] if peername else "unknown"

    if conns_per_ip[ip] >= MAX_CONNS_PER_IP:
        writer.close()
        return

    conns_per_ip[ip] += 1
    try:
        await _dispatch(reader, writer, ip)
    finally:
        conns_per_ip[ip] -= 1
        if conns_per_ip[ip] == 0:
            del conns_per_ip[ip]


async def main(port: int):
    server = await asyncio.start_server(handle, HOST, port)
    print(f"RemoteMac relay listening on {HOST}:{port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print(f"relay.py {__version__}")
        sys.exit(0)
    try:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        sys.exit("usage: relay.py [port]   (port must be 1–65535)")
    try:
        asyncio.run(main(port))
    except KeyboardInterrupt:
        pass
