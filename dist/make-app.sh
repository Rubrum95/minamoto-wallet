#!/usr/bin/env bash
# Build a self-contained `Minamoto Wallet.app` bundle that launches the
# local UI on double-click, with a proper Dock icon entry, Spotlight
# coverage, etc. The bundle wraps the same binary the CLI uses; nothing
# new is built or duplicated functionality-wise.
#
# Layout we produce:
#
#   Minamoto Wallet.app/
#   └── Contents/
#       ├── Info.plist            # bundle metadata (id, version, exec name)
#       ├── MacOS/
#       │   ├── Minamoto Wallet   # tiny wrapper script (runs `… ui`)
#       │   └── minamoto-wallet   # the actual signed binary, copied from target/release
#       └── Resources/
#           └── AppIcon.icns      # optional — drop your own here later
#
# Usage:
#   dist/make-app.sh                   # builds the bundle in dist/
#   dist/make-app.sh --install         # also moves it to /Applications/
#
# Requirements:
#   - cargo + the binary already built at target/release/minamoto-wallet
#   - codesign present (Xcode CLT is enough — no Developer ID needed,
#     we use ad-hoc signing).
#
# Re-signing implications:
#   The Keychain ACL is bound to the binary's cdhash. The copy inside the
#   .app gets a NEW cdhash when re-signed here, so macOS will pop the
#   "allow access" dialog the first time the .app touches the keychain.
#   Click "Permitir siempre" once and subsequent launches are silent.
#   The CLI binary at target/release/minamoto-wallet keeps its own auth
#   independently — the two are separate identities to the keychain.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_SRC="$ROOT/target/release/minamoto-wallet"
APP_NAME="Minamoto Wallet.app"
APP_DST="$SCRIPT_DIR/$APP_NAME"
INSTALL=0

for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        -h|--help)
            sed -n '1,30p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ ! -x "$BIN_SRC" ]]; then
    echo "binary missing: $BIN_SRC"
    echo "run: cargo build --release"
    exit 1
fi

echo "==> Cleaning old bundle"
rm -rf "$APP_DST"

echo "==> Building $APP_DST"
mkdir -p "$APP_DST/Contents/MacOS" "$APP_DST/Contents/Resources"

# --- Info.plist ---------------------------------------------------------
cat > "$APP_DST/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Minamoto Wallet</string>
    <key>CFBundleExecutable</key>
    <string>Minamoto Wallet</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>org.minamoto.wallet</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Minamoto Wallet</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.finance</string>
    <!-- LSUIElement=true: we are a localhost-only background server with
         no AppKit window of our own; the user-facing UI lives in a real
         browser window opened by `open <url>`. Without this, the Dock
         icon bounces forever because LaunchServices never receives the
         "finished launching" signal that AppKit normally sends. With
         this set, no Dock icon appears at all — the browser is the only
         visible affordance, which matches the actual flow.
         Quit the server via the in-UI button (POST /api/quit) or:
            lsof -nP -iTCP:7825 -sTCP:LISTEN -t | xargs kill -->
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <!-- We talk to localhost only (the Rust process serves on
             127.0.0.1:7825). ATS would block plain HTTP otherwise. -->
        <key>NSAllowsLocalNetworking</key>
        <true/>
    </dict>
</dict>
</plist>
PLIST

# --- Wrapper script -----------------------------------------------------
cat > "$APP_DST/Contents/MacOS/Minamoto Wallet" <<'WRAP'
#!/bin/bash
# Launcher: invoke the bundled binary with the `ui` subcommand. We chain
# stdout/stderr to a per-day log so the user can inspect failures
# without having to relaunch from Terminal.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$HOME/Library/Logs/minamoto-wallet"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ui-$(date +%Y%m%d).log"
exec "$DIR/minamoto-wallet" ui >>"$LOG_FILE" 2>&1
WRAP
chmod +x "$APP_DST/Contents/MacOS/Minamoto Wallet"

# --- Bundled binary -----------------------------------------------------
cp "$BIN_SRC" "$APP_DST/Contents/MacOS/minamoto-wallet"

# --- Optional icon ------------------------------------------------------
# Look for a logo at dist/logo.{png,jpg,jpeg}. If the source isn't already
# a square PNG, normalize it via Pillow (transparent-padded square)
# before passing to sips/iconutil — non-square sources squash badly with
# sips -z alone.
LOGO_SRC=""
for ext in png jpg jpeg PNG JPG JPEG; do
    if [[ -f "$SCRIPT_DIR/logo.$ext" ]]; then
        LOGO_SRC="$SCRIPT_DIR/logo.$ext"
        break
    fi
done
LOGO_PNG="$SCRIPT_DIR/logo.png"
if [[ -n "$LOGO_SRC" ]]; then
    # Normalize to a square transparent-padded PNG via Pillow.
    # We always overwrite logo.png with the normalized version; that way
    # the running app's `/assets/logo.png` endpoint serves the same
    # square image and the Resources copy stays in sync.
    echo "==> Normalizing $(basename "$LOGO_SRC") → square logo.png"
    python3 - "$LOGO_SRC" "$LOGO_PNG" <<'PY'
import sys
from PIL import Image
src, dst = sys.argv[1], sys.argv[2]
img = Image.open(src).convert("RGBA")
w, h = img.size
side = max(w, h)
canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
canvas.paste(img, ((side - w) // 2, (side - h) // 2), img)
canvas.save(dst, format="PNG", optimize=True)
print(f"  {w}x{h} → {side}x{side} (transparent square)")
PY
fi

# --- Optional XOR token glyph ----------------------------------------
# If `dist/xor_logo.png` exists, ship it inside Contents/Resources
# alongside the app icon. The running binary serves it on
# `/assets/xor-logo.png` and the JS `tokenGlyph()` helper renders it
# in the Balance card. Square sources work best (32×32 final render);
# we don't normalize this one — drop in whatever shape you want and
# CSS `object-fit: cover` handles it.
XOR_LOGO_SRC="$SCRIPT_DIR/xor_logo.png"
if [[ -f "$XOR_LOGO_SRC" ]]; then
    cp "$XOR_LOGO_SRC" "$APP_DST/Contents/Resources/xor_logo.png"
    echo "==> XOR token glyph embedded ($(stat -f%z "$XOR_LOGO_SRC") bytes)"
fi
if [[ -f "$LOGO_PNG" ]]; then
    # Copy as-is into Resources so the running app can serve it on
    # /assets/logo.png for the in-UI header. The binary uses
    # `find_logo_bytes()` to locate it relative to the executable.
    cp "$LOGO_PNG" "$APP_DST/Contents/Resources/logo.png"
    echo "==> Building AppIcon.icns from logo.png"
    ICONSET_DIR="$(mktemp -d)/AppIcon.iconset"
    mkdir -p "$ICONSET_DIR"
    # Apple HIG sizes (Big Sur+): 16, 32, 64, 128, 256, 512, 1024 with @2x.
    # `sips` ships with macOS, no Homebrew needed.
    for SIZE in 16 32 64 128 256 512; do
        DOUBLE=$((SIZE * 2))
        sips -z "$SIZE"   "$SIZE"   "$LOGO_PNG" --out "$ICONSET_DIR/icon_${SIZE}x${SIZE}.png"     >/dev/null
        sips -z "$DOUBLE" "$DOUBLE" "$LOGO_PNG" --out "$ICONSET_DIR/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
    done
    # Final 1024 (= 512@2x); iconutil also wants 512x512@2x literally.
    sips -z 1024 1024 "$LOGO_PNG" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null
    iconutil -c icns "$ICONSET_DIR" -o "$APP_DST/Contents/Resources/AppIcon.icns"
    rm -rf "$ICONSET_DIR"
    echo "    AppIcon.icns embedded"
else
    echo "==> No dist/logo.png — bundle uses generic icon"
fi

# --- Codesign the whole bundle -----------------------------------------
# Adhoc-sign without entitlements (Sequoia kills the binary if we ship
# `keychain-access-groups`; we tested this empirically — see STATUS.md).
echo "==> Codesigning bundle (adhoc)"
codesign --force --deep --sign - "$APP_DST"

# Strip the quarantine xattr from our just-built bundle so the user does
# not get the Gatekeeper "downloaded from internet" prompt the first time
# they double-click. We're not pulling this from a download — we're
# building it locally — so the flag would be misleading.
xattr -dr com.apple.quarantine "$APP_DST" 2>/dev/null || true

echo "==> Verifying signature"
codesign -dv --verbose=2 "$APP_DST" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature)' || true

# --- Icon cache hint ---------------------------------------------------
# macOS aggressively caches Finder/Dock/Spotlight icons keyed by the
# bundle's path + cdhash. After re-codesigning we touch the bundle so
# LaunchServices re-reads the metadata; if that's not enough, the user
# can `killall Dock Finder` to force a refresh — we do that below when
# --install is passed (the user has already approved an install action,
# bouncing Dock once is acceptable).
touch "$APP_DST"

# --- Install ------------------------------------------------------------
if [[ $INSTALL -eq 1 ]]; then
    DEST_DIR="/Applications"
    if [[ ! -w "$DEST_DIR" ]]; then
        DEST_DIR="$HOME/Applications"
        mkdir -p "$DEST_DIR"
    fi
    echo "==> Installing to $DEST_DIR"
    rm -rf "$DEST_DIR/$APP_NAME"
    cp -R "$APP_DST" "$DEST_DIR/"
    # Force LaunchServices to forget any cached metadata for the old
    # path (same path, but stale entries can pin the generic icon).
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -f "$DEST_DIR/$APP_NAME" >/dev/null 2>&1 || true
    # Bounce Dock + Finder to wipe the icon cache. This is intrusive
    # (~1s flicker) but guarantees the user sees the new icon without
    # having to reboot or wait for the cache TTL.
    killall Dock 2>/dev/null || true
    killall Finder 2>/dev/null || true
    echo "Installed: $DEST_DIR/$APP_NAME (Dock + Finder restarted)"
fi

echo
echo "Bundle ready at:"
echo "  $APP_DST"
echo
echo "To install manually: drag the bundle into /Applications in Finder."
echo "To run the (re)installed version, double-click it or open via Spotlight."
echo "Stop the running instance first if needed:"
echo "  lsof -nP -iTCP:7825 -sTCP:LISTEN -t | xargs kill 2>/dev/null"
