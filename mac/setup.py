"""py2app build for the RemoteMac Viewer .app.

    cd mac && ./build.sh        # or: python3 setup.py py2app

Produces mac/dist/RemoteMac Viewer.app. Build with a Python that has a working
Tk (python.org, or Homebrew `python-tk`) — plain `python3 setup.py py2app` uses
whatever python runs it.
"""
import os
import sys

# Make the sibling remote_desktop.py importable so py2app bundles it.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from setuptools import setup  # noqa: E402

APP = ["viewer_app.py"]
OPTIONS = {
    "argv_emulation": False,
    "includes": ["remote_desktop", "tkinter"],
    "packages": ["PIL"],           # imported lazily inside the viewer — force it in
    "plist": {
        "CFBundleName": "RemoteMac Viewer",
        "CFBundleDisplayName": "RemoteMac Viewer",
        "CFBundleIdentifier": "com.remotemac.viewer",
        "CFBundleShortVersionString": "2.0.0",
        "CFBundleVersion": "2.0.0",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
    },
}

setup(
    name="RemoteMac Viewer",
    app=APP,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
