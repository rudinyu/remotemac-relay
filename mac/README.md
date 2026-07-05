# RemoteMac Viewer — native macOS app

A double-clickable `.app` for the remote-desktop **viewer** (the controlling
side): fill in a small connection form, then see and control the remote Mac. It
reuses `remote_desktop.py`'s encrypted transport — this is just a friendly
front-end packaged as a native app.

## Run from source (no build)

```bash
pip install Pillow            # tkinter ships with python.org / Homebrew python-tk
python3 mac/viewer_app.py
```

## Build the .app

On macOS, with a Python that has a working Tk (the python.org installer, or
Homebrew `python3` + `python-tk`):

```bash
./mac/build.sh
# → mac/dist/RemoteMac Viewer.app
open "mac/dist/RemoteMac Viewer.app"
cp -R "mac/dist/RemoteMac Viewer.app" /Applications/     # optional
```

`build.sh` creates a throwaway venv, installs `py2app` + `Pillow`, and runs
`python setup.py py2app`. Edit `setup.py` for the bundle name / id / icon.

## First launch (unsigned app)

The build is **not code-signed**, so Gatekeeper blocks it the first time:

- Right-click the app → **Open** → **Open** (only needed once), or
- `xattr -dr com.apple.quarantine "mac/dist/RemoteMac Viewer.app"`

To distribute it to others without the warning you'd sign + notarize it with an
Apple Developer ID (`codesign --deep --sign …` then `notarytool submit`) — out of
scope here.

## What it does

1. Shows a form: relay `host:port`, device id, passphrase (masked), "remember
   passphrase" (login Keychain), and a clipboard-sync toggle.
2. On **Connect** it opens the encrypted channel (`_relay_connect` + `_auth`) on a
   background thread, then hands off to `_run_viewer` which draws the remote
   screen and forwards your keyboard/mouse.
3. The relay + device id (and the *choice* to remember) are saved to
   `~/.config/remotemac/viewer.json`; the passphrase, if remembered, lives in the
   login Keychain (service `remotemac-viewer`), never in the JSON.

Viewer-only dependencies are `Pillow` + `tkinter` — the `mss`/`pynput` packages
are host-side and are not needed here.
