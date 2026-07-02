# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
