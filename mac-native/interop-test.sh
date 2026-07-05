#!/usr/bin/env bash
# Verify the Swift SecureChannel interoperates with the Python implementation
# end-to-end: a Python "host" runs the real remote_desktop._auth (with scrypt) and
# exchanges an encrypted frame; the Swift client connects, authenticates, and
# round-trips a frame back. Run on macOS from anywhere:  ./mac-native/interop-test.sh
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

echo "==> building the swift client (release)"
swift build -c release >/dev/null

PSK="swift-interop-psk"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/host.py" <<PY
import socket, sys
sys.path.insert(0, "$REPO")
import remote_desktop as rd
try:
    import hashlib; hashlib.scrypt   # modern OpenSSL: use it
except AttributeError:               # else fall back to the cryptography package's scrypt
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    rd.hashlib.scrypt = lambda password, salt, n, r, p, dklen, maxmem=0: \
        Scrypt(salt=salt, length=dklen, n=n, r=r, p=p).derive(password)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(1)
print("PORT", srv.getsockname()[1], flush=True)
conn, _ = srv.accept()
ch = rd._auth(conn, b"$PSK", is_host=True)
ch.send(b"ping-from-host")
print("HOST-RECEIVED", ch.recv().decode(errors="replace"), flush=True)
PY

python3 "$TMP/host.py" > "$TMP/host.out" 2>/dev/null &
HPID=$!
PORT=""
for _ in $(seq 1 50); do PORT="$(awk '/^PORT/{print $2}' "$TMP/host.out" 2>/dev/null)"; [ -n "$PORT" ] && break; sleep 0.1; done
[ -n "$PORT" ] || { echo "FAIL: python host did not start (is 'cryptography' installed?)"; exit 1; }

OUT="$(.build/release/remotemac-viewer authtest 127.0.0.1 "$PORT" "$PSK")"
wait "$HPID" 2>/dev/null || true
echo "$OUT"
grep -q "auth: succeeded"          <<<"$OUT"        || { echo "FAIL: swift auth";  exit 1; }
grep -q "recv: ping-from-host"     <<<"$OUT"        || { echo "FAIL: swift recv";  exit 1; }
grep -q "HOST-RECEIVED hi-from-swift" "$TMP/host.out" || { echo "FAIL: host recv"; exit 1; }
echo "PASS: Swift ↔ Python interop (scrypt auth + encrypted frames both directions)"
