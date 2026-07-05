#!/usr/bin/env bash
# Build "RemoteMac Viewer.app" with py2app.  Run on macOS:  ./mac/build.sh
# Requires a Python with a working Tk (python.org installer, or Homebrew
# `python3` + `python-tk`). The result is mac/dist/RemoteMac Viewer.app.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
"$PY" -c 'import tkinter' 2>/dev/null || {
  echo "error: this Python has no tkinter — install python.org Python or 'brew install python-tk', or set PYTHON=..." >&2
  exit 1
}

echo "==> creating build venv"
"$PY" -m venv .build-venv
# shellcheck disable=SC1091
source .build-venv/bin/activate
pip install --quiet --upgrade pip py2app Pillow

echo "==> building"
rm -rf build dist
python setup.py py2app

APP="dist/RemoteMac Viewer.app"
echo "==> done: $(pwd)/$APP"
echo "    run it:            open \"$APP\""
echo "    install it:        cp -R \"$APP\" /Applications/"
echo "    unsigned Gatekeeper: right-click → Open the first time, or"
echo "                         xattr -dr com.apple.quarantine \"$APP\""
