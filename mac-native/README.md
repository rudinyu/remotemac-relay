# RemoteMac Viewer — pure-native (Swift)

A **pure Swift** reimplementation of the client — no Python, no bundled runtime.
A verified, byte-compatible port of the encrypted transport (`SecureChannel`) plus
the relay + auth handshake, and a native **AppKit GUI** on top: a connection form, a
window that renders the host's screen, and mouse + keyboard forwarded back to the
host. A headless CLI is also included and is what the interop test drives.

## Why a port (and what was the hard part)

The wire protocol uses **scrypt** (KDF) + **SHAKE-256 XOF counter-mode** (cipher) +
HMAC-SHA256 framing. Apple's CryptoKit provides only HMAC-SHA256, so scrypt and
SHAKE-256 are implemented from scratch here (`Scrypt.swift`, `SHAKE256.swift`) and
**verified byte-for-byte against Python** — see below.

## Build & test

```bash
cd mac-native
swift build -c release            # builds the CLI + the GUI executable
swift test                        # crypto vectors: SHAKE-256, HMAC, scrypt, XOF cipher
./interop-test.sh                 # live end-to-end auth + frames vs a real Python host
./build-app.sh                    # assemble "dist/RemoteMac Viewer.app" (add --run to launch)
```

`swift test` checks the primitives against known/Python-computed vectors.
`interop-test.sh` stands up a Python `remote_desktop._auth` host and has the Swift
client authenticate and exchange encrypted frames both ways — proving interop.

## GUI app

`./build-app.sh` produces `dist/RemoteMac Viewer.app` (ad-hoc signed for local
use). Double-click it, then fill in the connection form:

- **Relay host / Port** — the relay the host is registered with.
- **Device ID** — the host's device id (the relay pairing key).
- **Passphrase** — the shared secret; optionally remembered in the login Keychain.

On connect a window renders the host's screen (letterboxed, aspect-preserving).
Mouse move/drag/click/scroll and keyboard (including modifiers) are forwarded to
the host as the same `MSG_*` events the Python viewer sends. Closing the window
ends the session and returns to the form.

Not code-signed for distribution — for sharing outside your machine, sign with a
Developer ID and notarize.

## CLI (headless client)

```bash
# raw auth + one frame each way against a host (no relay) — used by interop-test.sh
.build/release/remotemac-viewer authtest <host> <port> <passphrase>

# the real path: via the relay, then print incoming screen frames
.build/release/remotemac-viewer connect <relay-host> <port> <device-id> <passphrase>
```

## Layout

| File | What |
|---|---|
| `Sources/RemoteMacCore/SHAKE256.swift` | Keccak-f[1600] / SHAKE-256 XOF |
| `Sources/RemoteMacCore/Scrypt.swift` | scrypt (Salsa20/8 + BlockMix + ROMix) |
| `Sources/RemoteMacCore/Crypto.swift` | HMAC-SHA256 (CryptoKit), helpers |
| `Sources/RemoteMacCore/SecureChannel.swift` | XOF cipher + framed encrypted channel |
| `Sources/RemoteMacCore/RelayClient.swift` | relay pairing + scrypt auth handshake |
| `Sources/remotemac-viewer/` | CLI (`authtest`, `connect`) |
| `Sources/RemoteMacViewerApp/` | AppKit GUI (form, `Session`, `RemoteView`, Keychain) |
| `build-app.sh` | assemble the `.app` bundle |
| `Tests/…` | crypto vectors |

## Interop caveat

The client uses **scrypt** (what a modern host derives). A host on an ancient
OpenSSL where Python silently falls back to PBKDF2 (`hashlib.scrypt` missing) would
derive a different key and fail to authenticate — run such a host with the
`cryptography` package's scrypt, or a current OpenSSL.

## Status & limitations

The transport core is verified byte-compatible with Python (unit + live interop).
The GUI compiles and is wired to that core; runtime interaction (rendering + input)
is best confirmed against a live host on a real desktop session. Known rough edges:

- Keyboard maps macOS keycodes → the same `Key.<name>` / character strings the
  Python viewer sends; exotic keys and `⌘`-equivalents may need tuning.
- Scroll direction follows `scrollingDeltaY` sign — flip in `RemoteView.scrollWheel`
  if it feels inverted for your setup.
- No clipboard sync yet (`MSG_CLIP` is received but ignored).
