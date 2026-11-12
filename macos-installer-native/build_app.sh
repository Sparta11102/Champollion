#!/bin/sh
# Builds build/ChampollionInstaller.app (macOS 11+), with the Python backend bundled inside.
# Requires the Xcode Command Line Tools (Swift 5.4+) and Python 3.8+ on the Mac that runs it.
# Set UNIVERSAL=1 for a universal (arm64 + x86_64) binary; needs Xcode 13 or later.
set -eu
cd "$(dirname "$0")"
ROOT=".."

ARCH_FLAGS=""
if [ "${UNIVERSAL:-0}" = "1" ]; then
    ARCH_FLAGS="--arch arm64 --arch x86_64"
fi
# shellcheck disable=SC2086
swift build -c release $ARCH_FLAGS
# shellcheck disable=SC2086
BIN="$(swift build -c release $ARCH_FLAGS --show-bin-path)/ChampollionInstaller"

APP="build/ChampollionInstaller.app"
BACKEND="$APP/Contents/Resources/backend"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$BACKEND"
cp "$BIN" "$APP/Contents/MacOS/ChampollionInstaller"
cp Resources/Info.plist "$APP/Contents/Info.plist"

cp "$ROOT/champollion_cli.py" "$ROOT/installer_app.py" "$ROOT/installer_ui.html" "$BACKEND/"
mkdir -p "$BACKEND/proto"
for f in __init__ macho arm64_decode aot_translator ipa; do cp "$ROOT/proto/$f.py" "$BACKEND/proto/"; done
# Sources for the optional JIT build (built into ~/.champollion/build, never inside the app).
cp "$ROOT/CMakeLists.txt" "$BACKEND/"
cp -R "$ROOT/include" "$ROOT/src" "$BACKEND/"
find "$BACKEND" -name __pycache__ -prune -exec rm -rf {} +

codesign --force --deep -s - "$APP"
echo "Built $APP"
