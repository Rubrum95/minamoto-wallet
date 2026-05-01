#!/usr/bin/env bash
# Build a distributable .dmg containing Minamoto Wallet.app and a
# convenience symlink to /Applications, so a user only has to drag the
# icon across the window to install.
#
# Layout inside the .dmg (mounted as /Volumes/Minamoto Wallet):
#
#   Minamoto Wallet.app    ← the bundle (full copy)
#   Applications -> /Applications  ← symlink for drag-target
#
# Distribution caveat: this is **adhoc-signed**, NOT notarized. Anyone
# downloading the .dmg from the internet will see Gatekeeper say:
#   "<App Name> can't be opened because Apple cannot check it for malicious software."
# They can right-click → Open the first time to bypass. Or run:
#   xattr -dr com.apple.quarantine "/Applications/Minamoto Wallet.app"
# Real notarization requires an Apple Developer ID ($99/yr) and a
# `xcrun notarytool submit`. Out of scope for this script.
#
# Requirements:
#   - hdiutil (built into macOS)
#   - Minamoto Wallet.app already built next to this script (run
#     make-app.sh first; --install is not required).
#
# Usage:
#   dist/make-dmg.sh
#   dist/make-dmg.sh --version 0.1.0   # tags the filename

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="Minamoto Wallet.app"
APP_PATH="$SCRIPT_DIR/$APP_NAME"
VOL_NAME="Minamoto Wallet"
VERSION="0.1.0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        -h|--help) sed -n '1,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

DMG_NAME="Minamoto-Wallet-${VERSION}.dmg"
DMG_PATH="$SCRIPT_DIR/$DMG_NAME"

if [[ ! -d "$APP_PATH" ]]; then
    echo "missing bundle: $APP_PATH"
    echo "run: dist/make-app.sh"
    exit 1
fi

echo "==> Staging contents in temp directory"
STAGE="$(mktemp -d)/dmg"
mkdir -p "$STAGE"
# Bundle (cp -R preserves codesign).
cp -R "$APP_PATH" "$STAGE/"
# Drag-target symlink → users just slide the bundle across.
ln -s /Applications "$STAGE/Applications"

# Optional .DS_Store could go here to lay out icon positions; we keep
# the default Finder presentation for simplicity (it shows two icons
# side by side with normal sort, which is good enough).

echo "==> Cleaning previous DMG"
rm -f "$DMG_PATH"

echo "==> Creating $DMG_NAME"
# UDZO = compressed read-only. ULFO compresses better but needs a
# slightly newer macOS; UDZO is universally readable.
hdiutil create \
    -volname "$VOL_NAME" \
    -srcfolder "$STAGE" \
    -ov \
    -format UDZO \
    "$DMG_PATH" >/dev/null

# Codesign the DMG itself adhoc, so distribution metadata is signed
# even if the contents are also adhoc.
codesign --force --sign - "$DMG_PATH"

# Strip our own quarantine flag — we built this locally, it shouldn't
# carry the "downloaded from internet" mark inside this dev environment.
# Recipients who download via Safari/Chrome WILL get the flag set by
# the browser at download time; that's expected.
xattr -dr com.apple.quarantine "$DMG_PATH" 2>/dev/null || true

SIZE=$(du -h "$DMG_PATH" | cut -f1)
echo "==> $DMG_PATH ($SIZE)"
echo
echo "Distribute by sharing the .dmg file. Recipients:"
echo "  1. Double-click the .dmg, drag 'Minamoto Wallet' to Applications."
echo "  2. First launch: right-click 'Minamoto Wallet' → Open (Gatekeeper bypass)."
echo "  3. (Optional) tighter security: 'xattr -dr com.apple.quarantine' to skip the warning entirely."
