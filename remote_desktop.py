#!/usr/bin/env python3
"""
remote_desktop.py — authenticated remote desktop over remotemac-relay.

Modes
-----
  host   Register as the machine to be controlled (screen capture + input injection):
    python3 remote_desktop.py host   <relay:port> <device_id> --psk <psk> [--fps 15] [--quality 75]

  viewer Control a waiting host (display + keyboard/mouse):
    python3 remote_desktop.py viewer <relay:port> <device_id> --psk <psk>

  pipe   Raw stdin/stdout bridge (no GUI, no extra deps — useful for scripting):
    python3 remote_desktop.py pipe   <relay:port> <device_id> host|client --psk <psk>

  PSK can also be set via REMOTEMAC_PSK env var, or omitted for interactive prompt.

Requirements
------------
  host / viewer modes:  pip install mss Pillow pynput
  pipe  mode:           Python 3.8+ stdlib only

macOS permissions
-----------------
  host:   System Preferences > Privacy & Security > Screen Recording   (mss)
          System Preferences > Privacy & Security > Accessibility       (pynput inject)
  viewer: System Preferences > Privacy & Security > Accessibility       (pynput capture)

Security model
--------------
After the relay bridges both TCP connections, a mutual challenge-response
handshake runs before any application data flows:

  1. Nonce exchange  — each side contributes 32 random bytes.
  2. scrypt stretch  — scrypt(psk, nonce_h‖nonce_c, N=16384) makes offline
                       dictionary attacks ~16 384× more expensive per guess.
                       Falls back to PBKDF2-HMAC-SHA256/200 000 if unavailable.
  3. Key derivation  — five independent 32-byte subkeys via HMAC-expand.
  4. Token exchange  — HMAC(auth_key, role‖nonces) verified with compare_digest.

All subsequent frames are:
  • encrypted   — SHAKE-256 XOF counter-mode (one Keccak call per frame)
  • integrity   — HMAC-SHA256 MAC over (seq_num ‖ ciphertext)
  • replay-safe — monotone 64-bit sequence number per direction

Wire frame layout:
  ┌──────────┬──────────────────────┬────────────────────┐
  │ 4 B len  │ 32 B HMAC-SHA256 MAC │ N B ciphertext     │
  └──────────┴──────────────────────┴────────────────────┘
"""

import argparse
import hashlib
import hmac as _hmac_lib
import io
import os
import socket
import struct
import sys
import threading
import time

# ─── tunables ────────────────────────────────────────────────────────────────

_SCRYPT_N     = 16_384
_SCRYPT_R     = 8
_SCRYPT_P     = 1
_AUTH_TIMEOUT = 30          # seconds for auth handshake
_IDLE_TIMEOUT = 120         # seconds before idle connection is dropped
_MAX_FRAME    = 4 * 1024 * 1024   # 4 MiB per SecureChannel frame
_MAX_FPS      = 5_000       # max received frames/s (DoS guard)

# ─── logging ─────────────────────────────────────────────────────────────────

def _log(msg: str):
    print(f"[remotemac] {msg}", file=sys.stderr, flush=True)

# ─── crypto ──────────────────────────────────────────────────────────────────

def _hmac(key: bytes, msg: bytes) -> bytes:
    return _hmac_lib.new(key, msg, hashlib.sha256).digest()


def _expand(master: bytes, label: str) -> bytes:
    return _hmac(master, label.encode() + b"\x01")


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"_xor: length mismatch {len(a)} vs {len(b)}")
    n = len(a)
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(n, "big")


class _XofCipher:
    """SHAKE-256 XOF counter-mode stream cipher (one Keccak call per frame)."""

    def __init__(self, key: bytes):
        self._key = key
        self._ctr = 0

    def crypt(self, data: bytes) -> bytes:
        if not data:
            return b""
        ks = hashlib.shake_256(self._key + struct.pack(">Q", self._ctr)).digest(len(data))
        self._ctr += 1
        return _xor(data, ks)


class _RateLimiter:
    def __init__(self, max_fps: int):
        self._max   = max_fps
        self._count = 0
        self._start = time.monotonic()

    def check(self):
        now = time.monotonic()
        if now - self._start >= 1.0:
            self._count = 0
            self._start = now
        self._count += 1
        if self._count > self._max:
            raise PermissionError(f"frame rate limit exceeded ({self._count}/s)")

# ─── secure channel ───────────────────────────────────────────────────────────

class SecureChannel:
    """
    Framed, encrypted, integrity-checked, rate-limited duplex channel.

    send() is thread-safe (internal lock). recv() is single-consumer.
    """

    def __init__(self, sock: socket.socket,
                 enc: bytes, dec: bytes,
                 mac_send: bytes, mac_recv: bytes):
        self._sock  = sock
        self._enc   = _XofCipher(enc)
        self._dec   = _XofCipher(dec)
        self._ms    = mac_send
        self._mr    = mac_recv
        self._sseq  = 0
        self._rseq  = 0
        self._wlock = threading.Lock()
        self._rlim  = _RateLimiter(_MAX_FPS)

    def _send_raw(self, data: bytes):
        mv, sent = memoryview(data), 0
        while sent < len(data):
            n = self._sock.send(mv[sent:])
            if n == 0:
                raise ConnectionError("connection closed")
            sent += n

    def _recv_raw(self, n: int) -> bytes:
        return _read_exactly(self._sock, n)

    def send(self, plaintext: bytes):
        with self._wlock:
            ct  = self._enc.crypt(plaintext)
            mac = _hmac(self._ms, struct.pack(">Q", self._sseq) + ct)
            self._sseq += 1
            self._send_raw(struct.pack(">I", len(ct)) + mac + ct)

    def send_multi(self, *plaintexts: bytes):
        """Send multiple frames under one lock — no interleave from other threads."""
        with self._wlock:
            for plaintext in plaintexts:
                ct  = self._enc.crypt(plaintext)
                mac = _hmac(self._ms, struct.pack(">Q", self._sseq) + ct)
                self._sseq += 1
                self._send_raw(struct.pack(">I", len(ct)) + mac + ct)

    def recv(self) -> bytes:
        self._rlim.check()
        length = struct.unpack(">I", self._recv_raw(4))[0]
        if length > _MAX_FRAME:
            raise ValueError(f"frame too large: {length} B (max {_MAX_FRAME} B)")
        mac = self._recv_raw(32)
        ct  = self._recv_raw(length)
        expected = _hmac(self._mr, struct.pack(">Q", self._rseq) + ct)
        if not _hmac_lib.compare_digest(mac, expected):
            raise PermissionError("MAC verification failed — wrong PSK or tampered frame")
        self._rseq += 1
        return self._dec.crypt(ct)

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

# ─── relay handshake ─────────────────────────────────────────────────────────

def _read_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock; raises ConnectionError on EOF."""
    chunks, got = [], 0
    while got < n:
        chunk = sock.recv(n - got)
        if not chunk:
            raise ConnectionError("connection closed")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _relay_connect(relay_addr: str, device_id: str, is_host: bool) -> socket.socket:
    host, _, port_s = relay_addr.rpartition(":")
    sock = socket.create_connection((host, int(port_s)), timeout=15)
    sock.settimeout(30)

    rid = device_id.encode("ascii")[:8].ljust(8, b"\x00")
    sock.sendall((b"H" if is_host else b"C") + rid)

    resp = _read_exactly(sock, 1)
    if is_host:
        if resp != b"R":
            sock.close()
            raise ConnectionError(f"relay rejected host registration: {resp!r}")
        _log("relay: registered — waiting for peer…")
        resp = _read_exactly(sock, 1)

    errors = {b"N": "no host for that device id",
              b"D": "host slot occupied by another IP"}
    if resp in errors:
        sock.close()
        raise ConnectionError(f"relay: {errors[resp]}")
    if resp != b"P":
        sock.close()
        raise ConnectionError(f"relay: unexpected response {resp!r}")

    _log("relay: bridge established")
    sock.settimeout(None)
    return sock

# ─── auth handshake ───────────────────────────────────────────────────────────

def _auth(sock: socket.socket, psk: bytes, is_host: bool) -> SecureChannel:
    """
    Mutual challenge-response with scrypt key stretching.

    Wire sequence (H = host side, C = client side):
        H → nonce_h  (32 B random)
        C → nonce_c  (32 B random)
        — both derive master = scrypt(psk, nonce_h‖nonce_c) —
        H → HMAC(auth_key, "host"   ‖ nonce_h ‖ nonce_c)
        C → HMAC(auth_key, "client" ‖ nonce_h ‖ nonce_c)
    """
    _done = False
    try:
        sock.settimeout(_AUTH_TIMEOUT)
        my_nonce = os.urandom(32)

        if is_host:
            sock.sendall(my_nonce)
            peer_nonce = _read_exactly(sock, 32)
            nonce_h, nonce_c = my_nonce, peer_nonce
        else:
            peer_nonce = _read_exactly(sock, 32)
            sock.sendall(my_nonce)
            nonce_h, nonce_c = peer_nonce, my_nonce

        _log("auth: deriving keys…")
        salt = nonce_h + nonce_c
        try:
            master = hashlib.scrypt(psk, salt=salt,
                                    n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        except (AttributeError, OSError):
            _log("[WARNING] scrypt unavailable — falling back to PBKDF2-HMAC-SHA256/200000. "
                 "This is weaker than scrypt. Upgrade your OpenSSL to enable scrypt.")
            master = hashlib.pbkdf2_hmac("sha256", psk, salt, 200_000, dklen=32)

        enc_h2c = _expand(master, "enc-h2c")
        enc_c2h = _expand(master, "enc-c2h")
        mac_h2c = _expand(master, "mac-h2c")
        mac_c2h = _expand(master, "mac-c2h")
        auth_k  = _expand(master, "auth")

        my_label   = b"host"   if is_host else b"client"
        peer_label = b"client" if is_host else b"host"
        my_token       = _hmac(auth_k, my_label   + nonce_h + nonce_c)
        expected_token = _hmac(auth_k, peer_label + nonce_h + nonce_c)

        if is_host:
            sock.sendall(my_token)
            peer_token = _read_exactly(sock, 32)
        else:
            peer_token = _read_exactly(sock, 32)
            sock.sendall(my_token)

        if not _hmac_lib.compare_digest(peer_token, expected_token):
            raise PermissionError("auth failed: peer does not know the PSK")

        _log("auth: mutual authentication succeeded ✓")
        sock.settimeout(_IDLE_TIMEOUT)

        if is_host:
            ch = SecureChannel(sock, enc=enc_h2c, dec=enc_c2h,
                                mac_send=mac_h2c, mac_recv=mac_c2h)
        else:
            ch = SecureChannel(sock, enc=enc_c2h, dec=enc_h2c,
                                mac_send=mac_c2h, mac_recv=mac_h2c)
        _done = True
        return ch
    finally:
        if not _done:
            sock.close()

# ─── pipe mode (stdin ↔ stdout bridge) ───────────────────────────────────────

def _run_pipe(ch: SecureChannel):
    done = threading.Event()

    def recv_loop():
        try:
            while not done.is_set():
                sys.stdout.buffer.write(ch.recv())
                sys.stdout.buffer.flush()
        except Exception as exc:
            if not done.is_set():
                _log(f"pipe recv: {exc}")
        finally:
            done.set()
            ch.close()

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()
    try:
        while not done.is_set():
            data = sys.stdin.buffer.read1(65536)
            if not data:
                break
            ch.send(data)
    except Exception as exc:
        if not done.is_set():
            _log(f"pipe send: {exc}")
    finally:
        done.set()
        ch.close()
    t.join()

# ─── remote desktop protocol ──────────────────────────────────────────────────

MSG_FRAME        = 0x01   # host→viewer  [2B w][2B h][jpeg...]
MSG_MOUSE_MOVE   = 0x02   # viewer→host  [2B xn][2B yn]   uint16 0-65535
MSG_MOUSE_BTN    = 0x03   # viewer→host  [1B btn][1B down] 0=L 1=R 2=M
MSG_MOUSE_SCROLL = 0x04   # viewer→host  [2B dx][2B dy]   int16 notches
MSG_KEY          = 0x05   # viewer→host  [1B down][utf-8 key_str]
MSG_CLIP         = 0x06   # both dirs    [4B len][utf-8 text]
MSG_PING         = 0x07
MSG_PONG         = 0x08

COORD = 65535

# ─── host session ─────────────────────────────────────────────────────────────

def _run_host(ch: SecureChannel, fps: int = 15, quality: int = 75):
    try:
        import mss
        from PIL import Image
        from pynput import keyboard as kb, mouse as ms
    except ImportError as e:
        sys.exit(f"Missing dependency for host mode: {e}\n  pip install mss Pillow pynput")

    fps     = max(1, min(fps, 60))
    quality = max(20, min(quality, 95))
    done    = threading.Event()

    # ── capture → send ────────────────────────────────────────────────────────

    def capture_loop():
        interval = 1.0 / fps
        buf = io.BytesIO()          # reused across frames — avoids per-frame allocation
        with mss.mss() as sct:
            if len(sct.monitors) < 2:
                _log("error: no display monitor detected (mss found no index-1 monitor)")
                done.set()
                return
            mon = sct.monitors[1]
            while not done.is_set():
                t0  = time.monotonic()
                raw = sct.grab(mon)
                img = Image.frombytes("RGB", (raw.width, raw.height),
                                      raw.bgra, "raw", "BGRX")
                buf.seek(0)
                buf.truncate()
                img.save(buf, format="JPEG", quality=quality,
                         optimize=False, progressive=False)
                frame = struct.pack(">B HH", MSG_FRAME, raw.width, raw.height) + buf.getvalue()
                try:
                    ch.send(frame)
                except Exception as exc:
                    _log(f"host capture: {exc}")
                    done.set()
                    return
                wait = interval - (time.monotonic() - t0)
                if wait > 0:
                    time.sleep(wait)

    # ── receive events → inject ───────────────────────────────────────────────

    def event_loop():
        mouse_ctrl = ms.Controller()
        kbd_ctrl   = kb.Controller()
        # Keep mss context alive so monitor dimensions can be re-queried on each
        # MSG_MOUSE_MOVE — picks up resolution/arrangement changes mid-session.
        with mss.mss() as sct:
            while not done.is_set():
                try:
                    msg = ch.recv()
                except socket.timeout:
                    continue
                except Exception as exc:
                    _log(f"host event: {exc}")
                    done.set()
                    return

                mtype, payload = msg[0], msg[1:]

                if mtype == MSG_MOUSE_MOVE:
                    if len(sct.monitors) < 2:
                        continue
                    mon = sct.monitors[1]   # re-read — picks up resolution changes
                    xn, yn = struct.unpack(">HH", payload)
                    mouse_ctrl.position = (round(xn / COORD * mon["width"]),
                                           round(yn / COORD * mon["height"]))

                elif mtype == MSG_MOUSE_BTN:
                    btn_id, down = payload[0], payload[1]
                    _buttons = (ms.Button.left, ms.Button.right, ms.Button.middle)
                    if btn_id >= len(_buttons):
                        continue
                    btn = _buttons[btn_id]
                    try:
                        (mouse_ctrl.press if down else mouse_ctrl.release)(btn)
                    except Exception:
                        pass

                elif mtype == MSG_MOUSE_SCROLL:
                    dx, dy = struct.unpack(">hh", payload)
                    mouse_ctrl.scroll(dx, dy)

                elif mtype == MSG_KEY:
                    down, key_str = payload[0], payload[1:].decode("utf-8", errors="replace")
                    key = _str_to_key(key_str, kb)
                    if key is not None:
                        try:
                            (kbd_ctrl.press if down else kbd_ctrl.release)(key)
                        except Exception:
                            pass

                elif mtype == MSG_CLIP:
                    length = struct.unpack(">I", payload[:4])[0]
                    _set_clipboard(payload[4:4 + length].decode("utf-8", errors="replace"))

                elif mtype == MSG_PING:
                    try:
                        ch.send(bytes([MSG_PONG]))
                    except Exception:
                        pass

    t = threading.Thread(target=capture_loop, daemon=True)
    t.start()
    try:
        event_loop()
    finally:
        done.set()
        t.join(timeout=2.0)   # wait for capture_loop to finish current send before closing
        ch.close()


def _str_to_key(s: str, kb):
    if s.startswith("Key."):
        return getattr(kb.Key, s[4:], None)
    if len(s) == 1:
        return kb.KeyCode.from_char(s)
    return None


def _set_clipboard(text: str):
    import subprocess
    for cmd in (["pbcopy"], ["xclip", "-selection", "clipboard"]):
        try:
            subprocess.run(cmd, input=text.encode(), check=True,
                           capture_output=True, timeout=2)
            return
        except (FileNotFoundError, subprocess.SubprocessError):
            continue

# ─── viewer session ───────────────────────────────────────────────────────────

_TK_TO_PYNPUT = {
    "Return": "Key.enter",   "KP_Enter": "Key.enter",
    "BackSpace": "Key.backspace", "Tab": "Key.tab",
    "Escape": "Key.esc",     "Delete": "Key.delete",
    "Insert": "Key.insert",  "Home": "Key.home",  "End": "Key.end",
    "Prior": "Key.page_up",  "Next": "Key.page_down",
    "Up": "Key.up", "Down": "Key.down", "Left": "Key.left", "Right": "Key.right",
    **{f"F{i}": f"Key.f{i}" for i in range(1, 13)},
    "Control_L": "Key.ctrl_l",  "Control_R": "Key.ctrl_r",
    "Alt_L":     "Key.alt_l",   "Alt_R":     "Key.alt_r",
    "Shift_L":   "Key.shift_l", "Shift_R":   "Key.shift_r",
    "Super_L":   "Key.cmd",     "Super_R":   "Key.cmd_r",
    "Meta_L":    "Key.cmd",     "Meta_R":    "Key.cmd_r",
    "Caps_Lock": "Key.caps_lock",
    "space": " ",
}


def _tk_key_str(event) -> str:
    if event.keysym in _TK_TO_PYNPUT:
        return _TK_TO_PYNPUT[event.keysym]
    if event.char and len(event.char) == 1 and event.char.isprintable():
        return event.char
    return ""


def _run_viewer(ch: SecureChannel):
    try:
        from PIL import Image, ImageTk
        import tkinter as tk
    except ImportError as e:
        sys.exit(f"Missing dependency for viewer mode: {e}\n  pip install Pillow")

    done   = threading.Event()
    root   = tk.Tk()
    root.title("Remote Desktop")
    root.configure(bg="black")
    root.protocol("WM_DELETE_WINDOW", lambda: _quit())

    canvas = tk.Canvas(root, bg="black", highlightthickness=0, cursor="none")
    canvas.pack(fill=tk.BOTH, expand=True)
    root.geometry("1280x720")

    state = {"photo": None}   # mutable ref to keep ImageTk alive
    _img_id = canvas.create_image(0, 0, anchor=tk.CENTER)   # persistent item, updated per frame

    def _quit():
        done.set()
        try:
            root.destroy()
        except Exception:
            pass

    # ── frame reception ───────────────────────────────────────────────────────

    def recv_loop():
        while not done.is_set():
            try:
                msg = ch.recv()
            except Exception as exc:
                if not done.is_set():
                    _log(f"viewer recv: {exc}")
                    root.after(0, _quit)
                return
            mtype, payload = msg[0], msg[1:]
            if mtype == MSG_FRAME:
                w, h = struct.unpack(">HH", payload[:4])
                try:
                    img = Image.open(io.BytesIO(payload[4:]))
                    cw  = canvas.winfo_width()  or w
                    ch_ = canvas.winfo_height() or h
                    if (cw, ch_) != img.size:
                        img = img.resize((cw, ch_), Image.Resampling.BILINEAR)
                    photo = ImageTk.PhotoImage(img)
                    root.after(0, _show, photo)
                except Exception:
                    pass
            elif mtype == MSG_PONG:
                pass

    def _show(photo):
        if not root.winfo_exists():
            return
        state["photo"] = photo
        cw, ch_ = canvas.winfo_width(), canvas.winfo_height()
        canvas.coords(_img_id, cw // 2, ch_ // 2)
        canvas.itemconfig(_img_id, image=photo)

    # ── keepalive ping ────────────────────────────────────────────────────────

    def ping_loop():
        while not done.is_set():
            done.wait(timeout=30)
            if not done.is_set():
                try:
                    ch.send(bytes([MSG_PING]))
                except Exception:
                    done.set()

    # ── input helpers ─────────────────────────────────────────────────────────

    def norm(event):
        cw  = canvas.winfo_width()  or 1
        ch_ = canvas.winfo_height() or 1
        return (max(0, min(COORD, round(event.x / cw  * COORD))),
                max(0, min(COORD, round(event.y / ch_ * COORD))))

    def send(data: bytes):
        try:
            ch.send(data)
        except Exception as exc:
            if not done.is_set():
                _log(f"viewer send: {exc}")
            done.set()
            ch.close()

    # ── input bindings ────────────────────────────────────────────────────────

    canvas.bind("<Motion>",
                lambda e: send(struct.pack(">B HH", MSG_MOUSE_MOVE, *norm(e))))

    def on_press(e):
        xn, yn = norm(e)
        btn = {1: 0, 3: 1, 2: 2}.get(e.num, 0)
        # Combine move + button-down into one send — one lock, atomic ordering
        try:
            ch.send_multi(
                struct.pack(">B HH", MSG_MOUSE_MOVE, xn, yn),
                struct.pack(">B BB", MSG_MOUSE_BTN, btn, 1),
            )
        except Exception as exc:
            if not done.is_set():
                _log(f"viewer send: {exc}")
            done.set()
            ch.close()

    def on_release(e):
        btn = {1: 0, 3: 1, 2: 2}.get(e.num, 0)
        send(struct.pack(">B BB", MSG_MOUSE_BTN, btn, 0))

    def scroll(dx, dy):
        send(struct.pack(">B hh", MSG_MOUSE_SCROLL, dx, dy))

    canvas.bind("<ButtonPress>",   on_press)
    canvas.bind("<ButtonRelease>", on_release)
    canvas.bind("<MouseWheel>",    lambda e: scroll(0, -e.delta // 120))
    canvas.bind("<Button-4>",      lambda e: scroll(0, -1))
    canvas.bind("<Button-5>",      lambda e: scroll(0,  1))

    root.bind("<KeyPress>",
              lambda e: send(bytes([MSG_KEY, 1]) + s.encode()) if (s := _tk_key_str(e)) else None)
    root.bind("<KeyRelease>",
              lambda e: send(bytes([MSG_KEY, 0]) + s.encode()) if (s := _tk_key_str(e)) else None)

    canvas.focus_set()

    threading.Thread(target=recv_loop, daemon=True).start()
    threading.Thread(target=ping_loop, daemon=True).start()

    root.mainloop()
    done.set()
    ch.close()

# ─── entry point ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="remote_desktop.py",
        description="Authenticated remote desktop over remotemac-relay.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 remote_desktop.py host   relay.example.com:21118 myid --psk 'passphrase'\n"
            "  python3 remote_desktop.py viewer relay.example.com:21118 myid --psk 'passphrase'\n"
            "  echo hi | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk 'pw'"
        ),
    )
    p.add_argument("mode", choices=["host", "viewer", "pipe"])
    p.add_argument("relay_addr", metavar="relay:port")
    p.add_argument("device_id")
    p.add_argument("pipe_role", nargs="?", choices=["host", "client"],
                   help="required for pipe mode: which relay role this side takes")
    p.add_argument("--fps",     type=int, default=15,
                   help="capture frame rate, host mode only (default: 15)")
    p.add_argument("--quality", type=int, default=75,
                   help="JPEG quality 20-95, host mode only (default: 75)")
    p.add_argument("--psk", metavar="PASSPHRASE",
                   help="shared passphrase; if omitted reads REMOTEMAC_PSK env var, "
                        "then prompts interactively (avoids exposure in `ps aux`)")
    args = p.parse_args()

    if args.mode == "pipe" and not args.pipe_role:
        p.error("pipe mode requires pipe_role: host or client")

    # Resolve PSK: flag → env var → interactive prompt (never require it on the command
    # line so it is not visible to other users via `ps aux` / /proc/<pid>/cmdline).
    if args.psk:
        psk_str = args.psk
    elif "REMOTEMAC_PSK" in os.environ:
        psk_str = os.environ["REMOTEMAC_PSK"]
    else:
        import getpass
        psk_str = getpass.getpass("PSK: ")

    # Only the remote desktop host and pipe-host register as relay 'H'; viewer is 'C'
    is_relay_host = args.mode == "host" or (args.mode == "pipe" and args.pipe_role == "host")

    try:
        sock = _relay_connect(args.relay_addr, args.device_id, is_relay_host)
        ch   = _auth(sock, psk_str.encode(), is_relay_host)
    except (ConnectionError, PermissionError) as exc:
        sys.exit(f"error: {exc}")

    try:
        if args.mode == "host":
            _run_host(ch, fps=args.fps, quality=args.quality)
        elif args.mode == "viewer":
            _run_viewer(ch)
        else:
            _run_pipe(ch)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
