#!/usr/bin/env python3
"""
RemoteMac Viewer — a small macOS front-end for remote_desktop.py's viewer.

Shows a connection form (relay address, device id, PSK), then opens the remote
screen. Packaged as a double-clickable .app with py2app (see build.sh / setup.py),
or run from source:  python3 mac/viewer_app.py

The heavy lifting is reused from remote_desktop.py: _relay_connect + _auth open
the encrypted channel; _run_viewer draws the remote screen and sends input.
"""
import json
import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk

# Make remote_desktop importable whether we run from source (mac/ is a sibling of
# the repo root) or from inside the .app bundle (it's copied alongside us).
_HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (_HERE, os.path.dirname(_HERE)):
    if os.path.exists(os.path.join(_cand, "remote_desktop.py")) and _cand not in sys.path:
        sys.path.insert(0, _cand)
import remote_desktop as rd  # noqa: E402

CONFIG_PATH = os.path.expanduser("~/.config/remotemac/viewer.json")
KEYCHAIN_SERVICE = "remotemac-viewer"


# ─── small persistence: profile in a json file, PSK in the login Keychain ──────

def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


def _account(relay: str, device: str) -> str:
    return f"{relay}|{device}"


def keychain_get(relay: str, device: str):
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE,
             "-a", _account(relay, device), "-w"],
            capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def keychain_set(relay: str, device: str, secret: str):
    # -U updates if present. The secret is passed as an argument — acceptable on a
    # local single-user machine; brief `ps` exposure only.
    try:
        subprocess.run(
            ["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE,
             "-a", _account(relay, device), "-w", secret],
            capture_output=True, text=True, timeout=5)
    except Exception:
        pass


def keychain_delete(relay: str, device: str):
    try:
        subprocess.run(
            ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE,
             "-a", _account(relay, device)],
            capture_output=True, text=True, timeout=5)
    except Exception:
        pass


# ─── connection form ───────────────────────────────────────────────────────────

def main():
    cfg = load_config()
    result = {}

    root = tk.Tk()
    root.title("RemoteMac Viewer")
    root.resizable(False, False)
    frm = ttk.Frame(root, padding=16)
    frm.grid(sticky="nsew")

    relay_var = tk.StringVar(value=cfg.get("relay", ""))
    device_var = tk.StringVar(value=cfg.get("device", ""))
    psk_var = tk.StringVar()
    remember_var = tk.BooleanVar(value=bool(cfg.get("remember", False)))
    clip_var = tk.BooleanVar(value=bool(cfg.get("clipboard", True)))
    status_var = tk.StringVar(value="")

    def _row(r, label, widget):
        ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", padx=(0, 10), pady=4)
        widget.grid(row=r, column=1, sticky="ew", pady=4)

    frm.columnconfigure(1, weight=1)
    _row(0, "Relay (host:port)", ttk.Entry(frm, textvariable=relay_var, width=32))
    _row(1, "Device id", ttk.Entry(frm, textvariable=device_var, width=32))
    psk_entry = ttk.Entry(frm, textvariable=psk_var, width=32, show="•")
    _row(2, "Passphrase", psk_entry)
    ttk.Checkbutton(frm, text="Remember passphrase (Keychain)", variable=remember_var)\
        .grid(row=3, column=1, sticky="w", pady=(0, 2))
    ttk.Checkbutton(frm, text="Sync clipboard", variable=clip_var)\
        .grid(row=4, column=1, sticky="w")

    # Pre-fill a remembered passphrase for the saved relay/device.
    if remember_var.get() and relay_var.get() and device_var.get():
        saved = keychain_get(relay_var.get(), device_var.get())
        if saved:
            psk_var.set(saved)

    status = ttk.Label(frm, textvariable=status_var, foreground="#a33")
    status.grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))
    connect_btn = ttk.Button(frm, text="Connect")
    connect_btn.grid(row=7, column=1, sticky="e", pady=(10, 0))

    def set_busy(busy, msg=""):
        status_var.set(msg)
        status.configure(foreground="#666" if busy else "#a33")
        connect_btn.configure(state="disabled" if busy else "normal", text="Connecting…" if busy else "Connect")

    def on_connect(*_):
        relay = relay_var.get().strip()
        device = device_var.get().strip()
        psk = psk_var.get()
        if not relay or ":" not in relay:
            set_busy(False, "Enter the relay as host:port"); return
        if not device:
            set_busy(False, "Enter a device id"); return
        if not psk:
            set_busy(False, "Enter the passphrase"); return
        set_busy(True, "Connecting to the relay…")

        def work():
            try:
                sock = rd._relay_connect(relay, device, False)
                ch = rd._auth(sock, psk.encode(), False)
            except Exception as exc:
                root.after(0, lambda: set_busy(False, f"{exc}"))
                return
            result["ch"] = ch
            result["clip"] = clip_var.get()
            save_config({"relay": relay, "device": device,
                         "remember": remember_var.get(), "clipboard": clip_var.get()})
            if remember_var.get():
                keychain_set(relay, device, psk)
            else:
                keychain_delete(relay, device)
            root.after(0, root.destroy)

        threading.Thread(target=work, daemon=True).start()

    connect_btn.configure(command=on_connect)
    root.bind("<Return>", on_connect)
    psk_entry.focus_set()    # relay/device are usually remembered; the passphrase isn't

    root.mainloop()

    # Form closed: if we connected, hand off to the viewer (it makes its own window).
    if result.get("ch"):
        rd._run_viewer(result["ch"], clipboard=result.get("clip", True))


if __name__ == "__main__":
    main()
