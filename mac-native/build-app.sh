#!/usr/bin/env bash
# Build a double-clickable "RemoteMac Viewer.app" bundle from the SwiftPM
# executable target RemoteMacViewerApp. Output: ./dist/RemoteMac Viewer.app
# Run on macOS:  ./mac-native/build-app.sh   (add --run to launch it after)
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="RemoteMac Viewer"
BUNDLE_ID="com.remotemac.viewer"
EXE="RemoteMacViewerApp"

echo "==> building release binary"
swift build -c release --product "$EXE" >/dev/null
BIN="$(swift build -c release --product "$EXE" --show-bin-path)/$EXE"

APP="dist/$APP_NAME.app"
echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/$EXE"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>              <string>$APP_NAME</string>
    <key>CFBundleDisplayName</key>       <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>        <string>$BUNDLE_ID</string>
    <key>CFBundleVersion</key>           <string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleExecutable</key>        <string>$EXE</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>LSMinimumSystemVersion</key>    <string>12.0</string>
    <key>NSPrincipalClass</key>          <string>NSApplication</string>
    <key>NSHighResolutionCapable</key>   <true/>
</dict>
</plist>
PLIST

echo "PkgInfo APPL????" > /dev/null; printf 'APPL????' > "$APP/Contents/PkgInfo"

# Ad-hoc sign so Gatekeeper lets the local build run (no notarization).
codesign --force --deep --sign - "$APP" 2>/dev/null || echo "   (codesign skipped)"

echo "==> built $APP"
if [ "${1:-}" = "--run" ]; then open "$APP"; fi
