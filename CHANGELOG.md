# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
