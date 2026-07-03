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

  gateway Exit node for the SOCKS5 proxy (opens real outbound TCP/UDP):
    python3 remote_desktop.py gateway <relay:port> <device_id> --psk <psk> [--allow HOST/CIDR ...]

  socks  Local SOCKS5 proxy that tunnels app traffic through a gateway (like ssh -D):
    python3 remote_desktop.py socks  <relay:port> <device_id> --psk <psk> [--port 1080]

  PSK can also be set via REMOTEMAC_PSK env var, or omitted for interactive prompt.

Requirements
------------
  host / viewer modes:      pip install mss Pillow pynput
  pipe / gateway / socks:   Python 3.8+ stdlib only

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
import ipaddress
import os
import socket
import struct
import sys
import threading
import time

__version__ = "1.3.0"

# ─── tunables ────────────────────────────────────────────────────────────────

_SCRYPT_N     = 16_384
_SCRYPT_R     = 8
_SCRYPT_P     = 1
_AUTH_TIMEOUT = 30          # seconds for auth handshake
_IDLE_TIMEOUT = 120         # seconds before idle connection is dropped
_MAX_FRAME    = 4 * 1024 * 1024   # 4 MiB per SecureChannel frame
_MAX_FPS      = 5_000       # max received frames/s (DoS guard)
_MAX_CLIP     = 1024 * 1024       # 1 MiB max clipboard payload
_CLIP_POLL    = 1.0         # seconds between local clipboard polls

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

def _run_host(ch: SecureChannel, fps: int = 15, quality: int = 75, clipboard: bool = True):
    try:
        import mss
        from PIL import Image
        from pynput import keyboard as kb, mouse as ms
    except ImportError as e:
        sys.exit(f"Missing dependency for host mode: {e}\n  pip install mss Pillow pynput")

    fps     = max(1, min(fps, 60))
    quality = max(20, min(quality, 95))
    done    = threading.Event()
    clip    = _ClipSync(ch, done) if clipboard else None

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
                    if clip is not None:
                        clip.on_received(payload)

                elif mtype == MSG_PING:
                    try:
                        ch.send(bytes([MSG_PONG]))
                    except Exception:
                        pass

    t = threading.Thread(target=capture_loop, daemon=True)
    t.start()
    if clip is not None:
        clip.start()
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


def _get_clipboard():
    import subprocess
    for cmd in (["pbpaste"], ["xclip", "-selection", "clipboard", "-o"]):
        try:
            out = subprocess.run(cmd, check=True, capture_output=True, timeout=2)
            return out.stdout.decode("utf-8", errors="replace")
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
    return None


class _ClipSync:
    """Bidirectional clipboard sync over MSG_CLIP frames.

    Polls the local clipboard and sends changes to the peer; applies received
    text to the local clipboard. Tracks the last text seen in either direction
    so an applied remote update is not echoed straight back.
    """

    def __init__(self, ch: SecureChannel, done: threading.Event):
        self._ch   = ch
        self._done = done
        self._lock = threading.Lock()
        self._last = None

    def on_received(self, payload: bytes):
        """Handle an incoming MSG_CLIP payload ([4B len][utf-8 text])."""
        if len(payload) < 4:
            return
        length = struct.unpack(">I", payload[:4])[0]
        text = payload[4:4 + length].decode("utf-8", errors="replace")
        with self._lock:
            self._last = text
        _set_clipboard(text)

    def start(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _poll_loop(self):
        # Seed with the current clipboard so pre-existing content is not
        # broadcast the moment the session starts.
        with self._lock:
            self._last = _get_clipboard()
        while not self._done.wait(_CLIP_POLL):
            text = _get_clipboard()
            if text is None or not text:
                continue
            data = text.encode("utf-8")
            if len(data) > _MAX_CLIP:
                continue
            with self._lock:
                if text == self._last:
                    continue
                self._last = text
            try:
                self._ch.send(struct.pack(">BI", MSG_CLIP, len(data)) + data)
            except Exception:
                return

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


def _run_viewer(ch: SecureChannel, clipboard: bool = True):
    try:
        from PIL import Image, ImageTk
        import tkinter as tk
    except ImportError as e:
        sys.exit(f"Missing dependency for viewer mode: {e}\n  pip install Pillow")

    done   = threading.Event()
    clip   = _ClipSync(ch, done) if clipboard else None
    root   = tk.Tk()
    root.title("Remote Desktop")
    root.configure(bg="black")
    root.protocol("WM_DELETE_WINDOW", lambda: _quit())

    canvas = tk.Canvas(root, bg="black", highlightthickness=0, cursor="none")
    canvas.pack(fill=tk.BOTH, expand=True)
    root.geometry("1280x720")

    # "photo" keeps the ImageTk alive; "rect" is the on-canvas image area
    # (x0, y0, w, h) used to map viewer pixels onto host screen coordinates.
    state = {"photo": None, "rect": None}
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
                    # Letterbox: scale to fit while preserving aspect ratio.
                    scale = min(cw / img.width, ch_ / img.height)
                    dw = max(1, round(img.width  * scale))
                    dh = max(1, round(img.height * scale))
                    if (dw, dh) != img.size:
                        img = img.resize((dw, dh), Image.Resampling.BILINEAR)
                    photo = ImageTk.PhotoImage(img)
                    root.after(0, _show, photo, dw, dh)
                except Exception:
                    pass
            elif mtype == MSG_CLIP:
                if clip is not None:
                    clip.on_received(payload)
            elif mtype == MSG_PONG:
                pass

    def _show(photo, dw, dh):
        if not root.winfo_exists():
            return
        state["photo"] = photo
        cw, ch_ = canvas.winfo_width(), canvas.winfo_height()
        state["rect"] = ((cw - dw) // 2, (ch_ - dh) // 2, dw, dh)
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
        rect = state["rect"]
        if rect:
            x0, y0, dw, dh = rect
        else:
            x0, y0 = 0, 0
            dw = canvas.winfo_width()  or 1
            dh = canvas.winfo_height() or 1
        return (max(0, min(COORD, round((event.x - x0) / dw * COORD))),
                max(0, min(COORD, round((event.y - y0) / dh * COORD))))

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

    def on_wheel(e):
        # macOS Tk reports small notch values in e.delta; Windows reports
        # multiples of 120 per notch.
        delta = e.delta if sys.platform == "darwin" else e.delta // 120
        delta = max(-32768, min(32767, delta))
        if delta:
            scroll(0, -delta)

    canvas.bind("<ButtonPress>",   on_press)
    canvas.bind("<ButtonRelease>", on_release)
    canvas.bind("<MouseWheel>",    on_wheel)
    canvas.bind("<Button-4>",      lambda e: scroll(0, -1))
    canvas.bind("<Button-5>",      lambda e: scroll(0,  1))

    root.bind("<KeyPress>",
              lambda e: send(bytes([MSG_KEY, 1]) + s.encode()) if (s := _tk_key_str(e)) else None)
    root.bind("<KeyRelease>",
              lambda e: send(bytes([MSG_KEY, 0]) + s.encode()) if (s := _tk_key_str(e)) else None)

    canvas.focus_set()

    threading.Thread(target=recv_loop, daemon=True).start()
    threading.Thread(target=ping_loop, daemon=True).start()
    if clip is not None:
        clip.start()

    root.mainloop()
    done.set()
    ch.close()

# ─── SOCKS5 proxy: encrypted mux over the relay (VPN-like) ─────────────────────
#
# The `socks` mode runs a local SOCKS5 server; the `gateway` mode is the exit
# node. Many app connections are multiplexed over a single SecureChannel, each
# tagged with a 32-bit stream id. Every SecureChannel frame carries one mux
# message:  [1B MUX_TYPE][4B stream_id][payload].

MUX_OPEN      = 0x01   # socks→gw   payload = SOCKS5 addr        open a TCP stream
MUX_OK        = 0x02   # gw→socks   payload = bound SOCKS5 addr  connected
MUX_ERR       = 0x03   # gw→socks   payload = [1B SOCKS5 reply]  connect failed
MUX_DATA      = 0x04   # both dirs  payload = raw bytes
MUX_CLOSE     = 0x05   # both dirs  stream closed
MUX_UDP_ASSOC = 0x06   # socks→gw   open a UDP associate (stream_id = assoc id)
MUX_UDP       = 0x07   # both dirs  payload = SOCKS5 addr + datagram
MUX_UDP_CLOSE = 0x08   # both dirs  tear down UDP associate
MUX_KEEPALIVE = 0x09   # socks→gw   idle keepalive (stream_id = 0)

_MUX_CHUNK          = 60 * 1024   # max app bytes per MUX_DATA frame
_MAX_STREAMS        = 256         # concurrent streams per tunnel
_KEEPALIVE_INTERVAL = 30          # seconds between socks→gw keepalives
_CONNECT_TIMEOUT    = 10          # gateway outbound connect timeout

# SOCKS5 canned replies (BND.ADDR/PORT = 0.0.0.0:0 — clients tolerate this).
_SOCKS_OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def _socks_fail(rep: int) -> bytes:
    return b"\x05" + bytes([rep]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"


def _mux_frame(mtype: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BI", mtype, sid) + payload


def _encode_addr(host: str, port: int) -> bytes:
    """Encode host:port in SOCKS5 address form (IPv4 / IPv6 / domain)."""
    try:
        ip = ipaddress.ip_address(host)
        atyp = b"\x01" if ip.version == 4 else b"\x04"
        return atyp + ip.packed + struct.pack(">H", port)
    except ValueError:
        b = host.encode("utf-8")[:255]
        return bytes([0x03, len(b)]) + b + struct.pack(">H", port)


def _decode_addr(buf: bytes, off: int = 0):
    """Decode a SOCKS5 address; return (host, port, next_offset)."""
    atyp = buf[off]; off += 1
    if atyp == 0x01:
        host = socket.inet_ntoa(buf[off:off + 4]); off += 4
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, buf[off:off + 16]); off += 16
    elif atyp == 0x03:
        ln = buf[off]; off += 1
        host = buf[off:off + ln].decode("utf-8", "replace"); off += ln
    else:
        raise ValueError(f"bad SOCKS5 atyp {atyp}")
    port = struct.unpack(">H", buf[off:off + 2])[0]; off += 2
    return host, port, off


def _parse_udp_req(pkt: bytes):
    """Parse a SOCKS5 UDP request datagram → (host, port, data), or None."""
    if len(pkt) < 4 or pkt[2] != 0:   # RSV(2) FRAG(1); we don't support fragments
        return None
    try:
        host, port, off = _decode_addr(pkt, 3)
    except Exception:
        return None
    return host, port, pkt[off:]


def _build_udp_reply(host: str, port: int, data: bytes) -> bytes:
    return b"\x00\x00\x00" + _encode_addr(host, port) + data


def _make_allow(allow_list):
    """Build an allow(host, port) predicate from --allow HOST/CIDR entries."""
    if not allow_list:
        return lambda host, port: True
    nets, suffixes = [], []
    for a in allow_list:
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            suffixes.append(a.lower().lstrip("."))

    def ok(host, port):
        hl = host.lower()
        try:
            ip = ipaddress.ip_address(host)
            if any(ip in n for n in nets):
                return True
        except ValueError:
            pass
        return any(hl == s or hl.endswith("." + s) for s in suffixes)

    return ok


class _Stream:
    __slots__ = ("sid", "sock", "connected", "ready", "err", "bound")

    def __init__(self, sid, sock):
        self.sid       = sid
        self.sock      = sock
        self.connected = threading.Event()   # set when MUX_OK/MUX_ERR arrives
        self.ready     = threading.Event()   # set once SOCKS reply is written
        self.err       = None
        self.bound     = None


class _UdpAssoc:
    __slots__ = ("sid", "usock", "ctrl", "client_addr")

    def __init__(self, sid, usock, ctrl=None):
        self.sid         = sid
        self.usock       = usock
        self.ctrl        = ctrl
        self.client_addr = None


class _MuxBase:
    """Shared mux plumbing: single reader thread, thread-safe sends, cleanup."""

    def __init__(self, ch: SecureChannel):
        self.ch      = ch
        self.streams = {}          # sid -> _Stream
        self.udp     = {}          # sid -> _UdpAssoc
        self.lock    = threading.Lock()
        self.done    = threading.Event()

    def send(self, mtype, sid, payload=b""):
        try:
            self.ch.send(_mux_frame(mtype, sid, payload))
        except Exception:
            self.stop()

    def _remove(self, sid):
        with self.lock:
            st = self.streams.pop(sid, None)
        if st:
            try:
                st.sock.close()
            except Exception:
                pass

    def _remove_udp(self, sid):
        with self.lock:
            a = self.udp.pop(sid, None)
        if a:
            try:
                a.usock.close()
            except Exception:
                pass

    def stop(self):
        if self.done.is_set():
            return
        self.done.set()
        with self.lock:
            socks = [s.sock for s in self.streams.values()]
            socks += [a.usock for a in self.udp.values()]
            self.streams.clear()
            self.udp.clear()
        for s in socks:
            try:
                s.close()
            except Exception:
                pass
        self.ch.close()

    def _pump(self, st):
        """Read a local socket and forward its bytes as MUX_DATA frames."""
        try:
            while not self.done.is_set():
                data = st.sock.recv(_MUX_CHUNK)
                if not data:
                    break
                self.send(MUX_DATA, st.sid, data)
        except Exception:
            pass
        finally:
            self.send(MUX_CLOSE, st.sid)
            self._remove(st.sid)

    def run(self):
        """Sole consumer of ch.recv(); dispatch frames until the channel dies."""
        try:
            while not self.done.is_set():
                try:
                    msg = self.ch.recv()
                except socket.timeout:
                    continue
                except Exception:
                    break
                if len(msg) < 5:
                    continue
                mtype = msg[0]
                sid   = struct.unpack(">I", msg[1:5])[0]
                try:
                    self.dispatch(mtype, sid, msg[5:])
                except Exception as exc:
                    _log(f"mux dispatch: {exc}")
        finally:
            self.stop()

    def dispatch(self, mtype, sid, payload):   # pragma: no cover - overridden
        raise NotImplementedError


class _SocksMux(_MuxBase):
    """Client side: local SOCKS5 server multiplexed over the channel."""

    def __init__(self, ch, bind_host):
        super().__init__(ch)
        self.bind_host = bind_host
        self._next     = 1
        self._nlock    = threading.Lock()

    def _alloc(self):
        with self._nlock:
            sid = self._next
            self._next = (self._next + 1) & 0xFFFFFFFF or 1
            return sid

    def dispatch(self, mtype, sid, payload):
        if mtype == MUX_OK:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                try:
                    st.bound = _decode_addr(payload)[:2]
                except Exception:
                    st.bound = ("0.0.0.0", 0)
                st.connected.set()
        elif mtype == MUX_ERR:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                st.err = payload[0] if payload else 0x01
                st.connected.set()
        elif mtype == MUX_DATA:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                # Wait (bounded) for the SOCKS reply to be written before we
                # forward data. A bare wait() here would let a misbehaving peer
                # stall the single reader thread — and thus every stream.
                if not st.ready.wait(_CONNECT_TIMEOUT + 5):
                    self._remove(sid)
                    self.send(MUX_CLOSE, sid)
                    return
                try:
                    st.sock.sendall(payload)
                except Exception:
                    self._remove(sid)
                    self.send(MUX_CLOSE, sid)
        elif mtype == MUX_CLOSE:
            self._remove(sid)
        elif mtype == MUX_UDP:
            self._udp_to_app(sid, payload)
        # MUX_KEEPALIVE / unknown: ignore

    def handle(self, csock):
        """Run the SOCKS5 handshake for one accepted local connection."""
        try:
            if not _socks_negotiate(csock):
                csock.close(); return
            req = _socks_read_request(csock)
            if req is None:
                csock.sendall(_socks_fail(0x07)); csock.close(); return
            cmd, host, port = req
            if cmd == 0x01:
                self._connect(csock, host, port)
            elif cmd == 0x03:
                self._udp_associate(csock)
            else:
                csock.sendall(_socks_fail(0x07)); csock.close()
        except Exception:
            try:
                csock.close()
            except Exception:
                pass

    def _connect(self, csock, host, port):
        if self.done.is_set():
            csock.close(); return
        with self.lock:
            if len(self.streams) >= _MAX_STREAMS:
                csock.sendall(_socks_fail(0x01)); csock.close(); return
            sid = self._alloc()
            st  = _Stream(sid, csock)
            self.streams[sid] = st
        self.send(MUX_OPEN, sid, _encode_addr(host, port))
        if not st.connected.wait(_CONNECT_TIMEOUT + 5):
            try: csock.sendall(_socks_fail(0x04))
            except Exception: pass
            self._remove(sid); return
        if st.err is not None:
            try: csock.sendall(_socks_fail(st.err))
            except Exception: pass
            self._remove(sid); return
        try:
            csock.sendall(_SOCKS_OK)
        except Exception:
            self._remove(sid); self.send(MUX_CLOSE, sid); return
        st.ready.set()
        self._pump(st)   # this handler thread now pumps app→gateway

    def _udp_associate(self, csock):
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            usock.bind((self.bind_host, 0))
        except Exception:
            csock.sendall(_socks_fail(0x01)); csock.close(); return
        uport = usock.getsockname()[1]
        with self.lock:
            sid = self._alloc()
            self.udp[sid] = _UdpAssoc(sid, usock, csock)
        self.send(MUX_UDP_ASSOC, sid)
        try:
            csock.sendall(b"\x05\x00\x00" + _encode_addr(self.bind_host, uport))
        except Exception:
            self._remove_udp(sid); csock.close(); return
        threading.Thread(target=self._udp_from_app, args=(sid, usock), daemon=True).start()
        # Hold the associate open until the control connection closes.
        try:
            while not self.done.is_set():
                if not csock.recv(1):
                    break
        except Exception:
            pass
        finally:
            self.send(MUX_UDP_CLOSE, sid)
            self._remove_udp(sid)
            try: csock.close()
            except Exception: pass

    def _udp_from_app(self, sid, usock):
        try:
            while not self.done.is_set():
                data, addr = usock.recvfrom(65535)
                with self.lock:
                    a = self.udp.get(sid)
                if not a:
                    break
                a.client_addr = addr
                parsed = _parse_udp_req(data)
                if parsed is None:
                    continue
                host, port, body = parsed
                self.send(MUX_UDP, sid, _encode_addr(host, port) + body)
        except Exception:
            pass

    def _udp_to_app(self, sid, payload):
        with self.lock:
            a = self.udp.get(sid)
        if not a or a.client_addr is None:
            return
        try:
            host, port, off = _decode_addr(payload)
            a.usock.sendto(_build_udp_reply(host, port, payload[off:]), a.client_addr)
        except Exception:
            pass


class _GatewayMux(_MuxBase):
    """Exit side: open real outbound TCP/UDP on behalf of the socks client."""

    def __init__(self, ch, allow):
        super().__init__(ch)
        self.allow = allow

    def dispatch(self, mtype, sid, payload):
        if mtype == MUX_OPEN:
            try:
                host, port, _ = _decode_addr(payload)
            except Exception:
                self.send(MUX_ERR, sid, bytes([0x01])); return
            threading.Thread(target=self._open, args=(sid, host, port), daemon=True).start()
        elif mtype == MUX_DATA:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                try:
                    st.sock.sendall(payload)
                except Exception:
                    self._remove(sid); self.send(MUX_CLOSE, sid)
        elif mtype == MUX_CLOSE:
            self._remove(sid)
        elif mtype == MUX_UDP_ASSOC:
            self._udp_open(sid)
        elif mtype == MUX_UDP:
            self._udp_send(sid, payload)
        elif mtype == MUX_UDP_CLOSE:
            self._remove_udp(sid)
        # MUX_KEEPALIVE / unknown: ignore

    def _open(self, sid, host, port):
        if not self.allow(host, port):
            _log(f"gateway: DENY tcp {host}:{port}")
            self.send(MUX_ERR, sid, bytes([0x02])); return
        try:
            rsock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT)
        except ConnectionRefusedError:
            self.send(MUX_ERR, sid, bytes([0x05])); return
        except socket.gaierror:
            self.send(MUX_ERR, sid, bytes([0x04])); return
        except Exception:
            self.send(MUX_ERR, sid, bytes([0x01])); return
        rsock.settimeout(None)
        with self.lock:
            if self.done.is_set() or len(self.streams) >= _MAX_STREAMS:
                rsock.close(); self.send(MUX_ERR, sid, bytes([0x01])); return
            st = _Stream(sid, rsock)
            self.streams[sid] = st
        bound = rsock.getsockname()
        self.send(MUX_OK, sid, _encode_addr(bound[0], bound[1]))
        _log(f"gateway: open {host}:{port}")
        self._pump(st)

    def _udp_open(self, sid):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with self.lock:
            self.udp[sid] = _UdpAssoc(sid, u)
        threading.Thread(target=self._udp_recv, args=(sid, u), daemon=True).start()
        _log(f"gateway: udp associate {sid}")

    def _udp_recv(self, sid, u):
        try:
            while not self.done.is_set():
                data, addr = u.recvfrom(65535)
                self.send(MUX_UDP, sid, _encode_addr(addr[0], addr[1]) + data)
        except Exception:
            pass

    def _udp_send(self, sid, payload):
        with self.lock:
            a = self.udp.get(sid)
        if not a:
            return
        try:
            host, port, off = _decode_addr(payload)
        except Exception:
            return
        if not self.allow(host, port):
            _log(f"gateway: DENY udp {host}:{port}")
            return
        data = payload[off:]
        try:
            ipaddress.ip_address(host)   # already a literal IP → send inline
            a.usock.sendto(data, (host, port))
        except ValueError:
            # Domain target: resolve+send off the reader thread so a DNS lookup
            # cannot stall the single mux reader (and thus every stream).
            threading.Thread(target=self._udp_send_domain,
                             args=(a, host, port, data), daemon=True).start()
        except Exception:
            pass

    def _udp_send_domain(self, a, host, port, data):
        try:
            a.usock.sendto(data, (host, port))
        except Exception:
            pass


def _socks_negotiate(csock) -> bool:
    hdr = _read_exactly(csock, 2)
    if hdr[0] != 0x05:
        return False
    methods = _read_exactly(csock, hdr[1]) if hdr[1] else b""
    if 0x00 not in methods:      # we only offer "no authentication"
        try: csock.sendall(b"\x05\xff")
        except Exception: pass
        return False
    csock.sendall(b"\x05\x00")
    return True


def _socks_read_request(csock):
    hdr = _read_exactly(csock, 4)
    if hdr[0] != 0x05:
        return None
    cmd, atyp = hdr[1], hdr[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(_read_exactly(csock, 4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, _read_exactly(csock, 16))
    elif atyp == 0x03:
        ln = _read_exactly(csock, 1)[0]
        host = _read_exactly(csock, ln).decode("utf-8", "replace")
    else:
        return None
    port = struct.unpack(">H", _read_exactly(csock, 2))[0]
    return cmd, host, port


def _keepalive_loop(mux):
    while not mux.done.wait(_KEEPALIVE_INTERVAL):
        mux.send(MUX_KEEPALIVE, 0)


def _run_gateway(ch: SecureChannel, allow):
    _GatewayMux(ch, allow).run()


def _run_socks(relay_addr, device_id, psk, port, bind):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.bind((bind, port))
    except OSError as exc:
        sys.exit(f"error: cannot bind {bind}:{port}: {exc}")
    lsock.listen(128)
    _log(f"socks: listening on {bind}:{port} (SOCKS5)")
    state = {"mux": None}
    slock = threading.Lock()

    def accept_loop():
        while True:
            try:
                csock, _ = lsock.accept()
            except OSError:
                return
            with slock:
                mux = state["mux"]
            if mux is None:
                csock.close()
                continue
            threading.Thread(target=mux.handle, args=(csock,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()

    retry_delay = 2
    try:
        while True:
            try:
                sock = _relay_connect(relay_addr, device_id, False)
                ch   = _auth(sock, psk, False)
            except (ConnectionError, PermissionError, OSError) as exc:
                _log(f"socks: {exc} — retrying in {retry_delay}s")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
                continue
            retry_delay = 2
            mux = _SocksMux(ch, bind)
            with slock:
                state["mux"] = mux
            threading.Thread(target=_keepalive_loop, args=(mux,), daemon=True).start()
            mux.run()   # blocks until the tunnel drops
            with slock:
                state["mux"] = None
            _log("socks: tunnel lost — reconnecting…")
    except KeyboardInterrupt:
        return

# ─── entry point ─────────────────────────────────────────────────────────────

def _serve_persistent(relay_addr, device_id, psk, once, label, run_fn):
    """Register as relay 'H', run run_fn(ch) per session, and (unless --once)
    re-register after each session; reconnect with exponential backoff."""
    retry_delay = 2
    try:
        while True:
            try:
                sock = _relay_connect(relay_addr, device_id, True)
                ch   = _auth(sock, psk, True)
            except (ConnectionError, PermissionError, OSError) as exc:
                if once:
                    sys.exit(f"error: {exc}")
                _log(f"{label}: {exc} — retrying in {retry_delay}s")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
                continue
            retry_delay = 2
            try:
                run_fn(ch)
            finally:
                ch.close()
            if once:
                return
            _log(f"{label}: session ended — re-registering…")
    except KeyboardInterrupt:
        return


def main():
    p = argparse.ArgumentParser(
        prog="remote_desktop.py",
        description="Authenticated remote desktop and encrypted SOCKS5 proxy over remotemac-relay.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 remote_desktop.py host    relay.example.com:21118 myid --psk 'passphrase'\n"
            "  python3 remote_desktop.py viewer  relay.example.com:21118 myid --psk 'passphrase'\n"
            "  echo hi | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk 'pw'\n"
            "  python3 remote_desktop.py gateway relay.example.com:21118 vpn  --psk 'pw'\n"
            "  python3 remote_desktop.py socks   relay.example.com:21118 vpn  --psk 'pw' --port 1080\n"
            "  curl -x socks5h://127.0.0.1:1080 https://api.ipify.org"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("mode", choices=["host", "viewer", "pipe", "gateway", "socks"])
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
    p.add_argument("--no-clip", action="store_true",
                   help="disable bidirectional clipboard sync (host/viewer modes)")
    p.add_argument("--once", action="store_true",
                   help="host/gateway: exit after one session instead of re-registering")
    p.add_argument("--port", type=int, default=1080,
                   help="socks mode: local SOCKS5 listen port (default: 1080)")
    p.add_argument("--bind", default="127.0.0.1",
                   help="socks mode: local bind address (default: 127.0.0.1; "
                        "change to expose the proxy to other machines — do so with care)")
    p.add_argument("--allow", action="append", metavar="HOST/CIDR", default=[],
                   help="gateway mode: allow only these targets (domain suffix or IP/CIDR); "
                        "repeatable. Omit to allow all (PSK is the gate).")
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
    psk = psk_str.encode()

    if args.mode == "host":
        _serve_persistent(args.relay_addr, args.device_id, psk, args.once, "host",
                          lambda ch: _run_host(ch, fps=args.fps, quality=args.quality,
                                               clipboard=not args.no_clip))
        return

    if args.mode == "gateway":
        allow = _make_allow(args.allow)
        if args.allow:
            _log(f"gateway: allowlist active ({', '.join(args.allow)})")
        _serve_persistent(args.relay_addr, args.device_id, psk, args.once, "gateway",
                          lambda ch: _run_gateway(ch, allow))
        return

    if args.mode == "socks":
        _run_socks(args.relay_addr, args.device_id, psk, args.port, args.bind)
        return

    # viewer / pipe: single relay session, client- or host-role depending on mode.
    is_relay_host = args.mode == "pipe" and args.pipe_role == "host"
    try:
        sock = _relay_connect(args.relay_addr, args.device_id, is_relay_host)
        ch   = _auth(sock, psk, is_relay_host)
    except (ConnectionError, PermissionError) as exc:
        sys.exit(f"error: {exc}")

    try:
        if args.mode == "viewer":
            _run_viewer(ch, clipboard=not args.no_clip)
        else:
            _run_pipe(ch)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
