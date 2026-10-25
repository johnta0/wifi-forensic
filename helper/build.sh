#!/usr/bin/env bash
# Builds WfxHelper.app. Output: helper/build/WfxHelper.app
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$DIR/build/WfxHelper.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$DIR/Info.plist" "$APP/Contents/Info.plist"

swiftc -O -o "$APP/Contents/MacOS/WfxHelper" "$DIR/Sources/main.swift" \
  -framework AppKit -framework CoreLocation -framework CoreWLAN

# Note: ad-hoc signing ("-") changes the code identity on every build, so the
# TCC (location) permission must be granted again after a rebuild.
# Set WFX_SIGN_IDENTITY to a stable certificate name to avoid re-granting.
codesign --force --sign "${WFX_SIGN_IDENTITY:--}" --identifier dev.wifi-forensic.helper "$APP"
codesign --verify --verbose "$APP"
echo "built: $APP"
