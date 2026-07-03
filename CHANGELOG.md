# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.8.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 8) — split-DNS (opt-in).** With `--dns`, a node runs a
  tiny stdlib resolver that answers `<name>.mesh` with the peer's overlay IP and
  forwards everything else to the existing upstream, so `ssh laptop.mesh` works.
  - New `meshdns.py`: DNS query parse + answer/forward (`answer_for`: A hit →
    overlay IP; host hit but non-A → NOERROR/NODATA; miss → NXDOMAIN; other
    suffix → forward). Binds `127.0.0.1:53` (local-only, so a peer can't use it as
    an open forwarder), with a self-forward loop guard.
  - `ResolverConfig` auto-points the OS resolver at it and restores on exit:
    macOS via a per-domain `/etc/resolver/<suffix>` (global DNS untouched); Linux
    by rewriting `/etc/resolv.conf` (our server first, the real upstream kept as a
    fallback), backing up + restoring the original.
  - `mesh.py`: `--dns` / `--dns-suffix` (default `mesh`) / `--dns-upstream`, all
    requiring `--tun`; names resolve from the peer map (hostname → overlay IP).
  - Tests: query parse, answer_for branches, resolvconf body, self-forward guard,
    localhost server integration (stub upstream). Real resolver config needs
    root → manual-verified.
- Deferred to a later phase: IPv6, macOS exit (pf), reverse (PTR) DNS.

## [1.7.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 7) — iptables fallback for NAT egress.** A subnet router /
  exit node no longer requires nftables: `nat.py` now prefers `nft` but falls back
  to `iptables` (masquerade rule in the `nat`/`POSTROUTING` chain, tagged with a
  `remotemac` comment for clean teardown) when `nft` is absent, and errors clearly
  only if neither is available. The chosen backend is tracked so cleanup uses the
  matching tool; IP-forwarding save/restore is unchanged.
  - Tests: iptables argv generation (add/delete), backend selection (nft →
    iptables → none). Real NAT needs root → manual-verified.

## [1.6.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 6) — `--lan-routes` for full-tunnel.** Keep extra local
  subnets (ones reached via your LAN router, not directly connected) on the
  physical gateway while full-tunneling: `--exit-node exit --lan-routes
  10.0.0.0/8,172.16.0.0/12`. `netroute.FullTunnelRoutes` installs them via the
  physical gateway (more specific than the `0.0.0.0/1`+`128.0.0.0/1` split, so
  they win) and removes them on teardown.

### Fixed
- **Docs: full-tunnel LAN reachability.** The Phase 5 note that the local LAN is
  unreachable under full-tunnel was inaccurate. The directly-connected subnet's
  route is more specific than the `/1` split, so it stays on the physical
  interface and remains reachable; only traffic that would have used the default
  gateway is tunneled. README (en/zh) corrected.

## [1.5.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 5) — full-tunnel exit node (opt-in).** A client can route
  **all** outbound traffic through a chosen exit node, so its public IP becomes the
  exit's. Off by default; the default route is only touched with `--exit-node`.
  - `mesh.py`: `--exit-node NAME` selects a full-tunnel exit (validated to be
    advertising `exit=true`; re-validated on every map so routing pauses if it
    leaves); `--exit` advertises a node as an exit (reuses the Phase 4 nftables
    masquerade — its overlay-source rule already covers any destination).
    `route_for()` falls back to the exit as an internet catch-all; `src_permitted()`
    lets the exit source any address. Both require `--tun`; `--exit-node` is
    mutually exclusive with `--advertise-routes`.
  - `netroute.py` (new, **macOS + Linux**): detect the physical default route, pin
    mesh transport (coordinator + peer UDP endpoints + the exit's live endpoint) as
    /32 host routes via the physical gateway, then add `0.0.0.0/1`+`128.0.0.0/1` via
    the TUN to override the default without deleting it. Pins are kept in sync as
    endpoints change; teardown restores the default route and unpins.
  - Resilience: transport is pinned before the redirect and torn down in reverse;
    the `/1` routes vanish with the TUN so a crash self-heals the default route.
  - Tests: default-route parsers, incremental pin diff, exit selection / catch-all
    routing / widened anti-spoof / rejection of a non-exit peer. Real routing needs
    root + two hosts → manual-verified.
- Deferred to a later phase: a LAN exception (keep the local LAN reachable while
  full-tunneling), split-DNS, macOS exit (pf), iptables fallback, IPv6.

## [1.4.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 4) — subnet routing.** A node can act as a **subnet
  router**: advertise LAN CIDRs it can reach and let other nodes route matching
  traffic to it through the mesh (subnet-router style — the default route is
  untouched).
  - `mesh.py`: `--advertise-routes CIDR,…` announces routes (distributed by the
    coordinator, mirroring `endpoints`); `--accept-routes` opts a client in.
    Accepted CIDRs get OS routes into the TUN; `_from_tun` sends matching packets
    to the advertising peer via a longest-prefix route table.
  - Safety: advertised CIDRs that overlap `100.64.0.0/10` or contain the
    coordinator / a peer endpoint IP are refused, so mesh transport can't loop.
    Anti-spoof is widened just enough that a subnet router may source replies from
    within the routes you accepted from it — otherwise unchanged.
  - `nat.py` (new, **Linux**): a subnet router enables `net.ipv4.ip_forward` and
    installs an nftables masquerade rule in a dedicated `remotemac` table (clean
    teardown; forwarding/state restored on exit). `--egress` overrides the egress
    interface. macOS exit (pf) and an iptables fallback are deferred.
  - `coordinator.py`: carries a `routes` field on the node record + peer map.
  - Tests: route parse/safety-guard/longest-prefix match, advertise→accept
    redirect + widened anti-spoof, nftables ruleset + egress parsing. Real
    NAT/forwarding needs root → manual-verified.
- Deferred to a later phase: full-tunnel (route *all* internet traffic through an
  exit node), macOS exit (pf), iptables fallback, IPv6 subnets, split-DNS.

## [1.3.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 3) — TUN overlay device.** Real apps can now use the mesh
  as a network: with `--tun` (needs root), a node brings up a virtual interface,
  assigns its overlay IP, and routes `100.64.0.0/10` to it, so `ping 100.64.0.x`,
  `ssh`, http, etc. reach peers by overlay IP — not just the built-in `--ping`.
  - New `tun.py`: a `TunDevice` presenting raw IPv4 over read()/write(). macOS
    `utun` via the stdlib `AF_SYSTEM`/`SYSPROTO_CONTROL` socket (no kext); Linux
    `/dev/net/tun` with `TUNSETIFF`. `configure()` assigns the IP and installs the
    overlay route; MTU defaults to 1280.
  - `mesh.py`: `MeshNode.on_ip_packet` + `MESH_IP` dispatch in `_recv_data`; the
    `--tun` / `--tun-mtu` / `--tun-name` CLI opens the device and pumps packets
    both ways, reusing the Phase 2 P2P/DERP data path (first packet lazily
    handshakes). Root is checked up front; `--tun` and `--ping` are exclusive.
  - Anti-spoof: a peer may only inject packets whose IPv4 source is its own
    assigned overlay IP; mismatches are dropped.
  - Tests: `MESH_IP`→`on_ip_packet` dispatch (non-leak to `on_message`), IPv4
    src/dst parsing, `src_allowed` matrix, macOS AF-header framing. Device I/O and
    OS routing need root → manual-verified.
- Deferred to a later phase: exit-node NAT + default route (route all internet
  traffic through an `--exit` node), IPv6 overlay, split-DNS, Windows.

## [1.2.0] - 2026-07-03

### Added
- **Mesh overlay (Phase 2) — UDP P2P + NAT hole punching.** Node↔node traffic now
  goes **peer-to-peer over UDP** wherever the network allows, instead of always
  relaying through the coordinator.
  - UDP data plane in `mesh.py`: one data-plane socket per node with a WireGuard-
    style index (SPI) to demux many peers; the existing forward-secret handshake
    and ChaCha20-Poly1305 session are carried over UDP (`--bind`, `--udp-port`).
  - **STUN-lite endpoint discovery**: `coordinator.py` runs a UDP responder on its
    control port; each node learns its public (post-NAT) endpoint and advertises
    its candidates, which the coordinator distributes in the peer map.
  - **Hole punching + signaling**: a `connect` nudge relayed through the
    coordinator makes both peers punch simultaneously; a deterministic pubkey
    tie-break picks the initiator so glare can't derive two mismatched sessions.
  - **Transparent path selection**: direct-first, with automatic **DERP fallback**
    when no direct path forms (e.g. symmetric NAT). A keepalive holds the NAT
    mapping open; a silent direct path fails over to the relay (reusing the
    session) and is periodically re-punched to upgrade back to direct.
  - The coordinator still only ever sees **ciphertext** on the data path.
  - Tests: hole-punch handshake glare tie-break, localhost direct-session
    end-to-end, DERP fallback, DERP→direct upgrade, direct→DERP failover on
    silence, and recovery once reachability returns — all root-free.
- Deferred to a later phase: TUN overlay device + exit-node NAT (Phase 3).

## [1.1.0] - 2026-07-02

### Added
- **Mesh overlay (Phase 1)** — a Tailscale-lite control plane, evolving the
  1:1 host↔client model toward a peer group.
  - `coordinator.py`: nodes connect over a token-authenticated encrypted control
    channel; assigns stable overlay IPs from `100.64.0.0/10` (persisted),
    distributes the peer map, and relays end-to-end-encrypted node↔node traffic
    (DERP fallback — the coordinator only sees ciphertext).
  - `mesh.py`: per-node X25519 identity (persisted, `$REMOTEMAC_MESH_KEY`
    overridable), joins a network, learns peers, and has an encrypted data path
    with a mutually authenticated, forward-secret handshake (X25519 triple-DH →
    HKDF-SHA256 → ChaCha20-Poly1305) plus a built-in `--ping`.
  - New dependency `cryptography` (mesh only; relay / pipe / gateway / socks stay
    pure stdlib). See `requirements.txt`.
  - Tests: `tests/test_mesh.py` (handshake roundtrip, wrong-key/replay rejection,
    overlay-IP allocator persistence, end-to-end encrypted ping) — all root-free.
- Deferred to later phases: UDP P2P + NAT hole punching (Phase 2), TUN overlay +
  exit-node NAT (Phase 3).

## [1.0.0] - 2026-07-02

### Added
- **Encrypted SOCKS5 proxy** (`gateway` / `socks` modes) in `remote_desktop.py`:
  route other apps' traffic out through a remote host over the existing encrypted
  channel, like a self-hosted `ssh -D`. Many connections are multiplexed over one
  relay bridge; supports TCP (SOCKS5 CONNECT) and UDP associate, with domain names
  resolved on the gateway side. `--allow HOST/CIDR` allowlist, `--bind`, `--port`.
- **Bidirectional clipboard sync** for `host`/`viewer` modes (`--no-clip` to disable).
- **Persistent `host`/`gateway`** modes: re-register with the relay after each
  session with exponential-backoff reconnect; `--once` restores single-session.
- `--version` for `remote_desktop.py`; `--version`/`-V` for `relay.py`.
- Tests: `tests/test_relay.py` (relay pairing/bridging) and `tests/test_proxy.py`
  (mux/SOCKS5 codecs, allowlist, TCP echo, UDP associate).
- `.codex/ci.sh` so the pre-commit hook runs the suite via stdlib `unittest`.
- Bilingual README: English (`README.md`) + Traditional Chinese (`README.zh-TW.md`).

### Fixed
- Viewer mouse wheel on macOS (Tk `delta` is not a multiple of 120).
- Viewer now letterboxes frames to preserve aspect ratio, with pointer mapping
  aligned to the displayed image area.
- Proxy reader thread could stall the whole tunnel waiting on a stream that never
  became ready; the wait is now bounded.
- Gateway UDP sends to domain targets are resolved off the reader thread so a DNS
  lookup cannot stall other streams.

### Changed
- `relay.py` parses `sys.argv` inside `__main__` so the module imports cleanly
  (enables unit testing); CLI behavior is unchanged.
