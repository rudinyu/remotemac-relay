# RemoteMac Viewer — pure-native (Swift)

A **pure Swift** reimplementation of the client — no Python, no bundled runtime.
This is the foundation: a verified, byte-compatible port of the encrypted transport
(`SecureChannel`) plus the relay + auth handshake, with a CLI to prove it works
end-to-end against a real Python host. The SwiftUI window (frame display + input) is
the next step on top of this core.

## Why a port (and what was the hard part)

The wire protocol uses **scrypt** (KDF) + **SHAKE-256 XOF counter-mode** (cipher) +
HMAC-SHA256 framing. Apple's CryptoKit provides only HMAC-SHA256, so scrypt and
SHAKE-256 are implemented from scratch here (`Scrypt.swift`, `SHAKE256.swift`) and
**verified byte-for-byte against Python** — see below.

## Build & test

```bash
cd mac-native
swift build -c release            # builds .build/release/remotemac-viewer
swift test                        # crypto vectors: SHAKE-256, HMAC, scrypt, XOF cipher
./interop-test.sh                 # live end-to-end auth + frames vs a real Python host
```

`swift test` checks the primitives against known/Python-computed vectors.
`interop-test.sh` stands up a Python `remote_desktop._auth` host and has the Swift
client authenticate and exchange encrypted frames both ways — proving interop.

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
| `Tests/…` | crypto vectors |

## Interop caveat

The client uses **scrypt** (what a modern host derives). A host on an ancient
OpenSSL where Python silently falls back to PBKDF2 (`hashlib.scrypt` missing) would
derive a different key and fail to authenticate — run such a host with the
`cryptography` package's scrypt, or a current OpenSSL.

## Next

A SwiftUI app target on top of `RemoteMacCore`: a connection form, a window that
renders the received JPEG frames (`MSG_FRAME`), and mouse/keyboard → `MSG_*` events.
The transport core it needs is done and verified.

(There is also a py2app-packaged variant in [`../mac/`](../mac/) that bundles the
existing Python viewer — quicker to ship, but not pure-native.)
