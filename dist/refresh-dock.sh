#!/usr/bin/env bash
# Force macOS to re-read the application icon from disk and drop any
# cached versions in the Dock / Spotlight / Finder.
#
# Why this is needed: `make-app.sh --install` already calls `lsregister
# -f` and `killall Dock Finder`, but on macOS Sequoia the per-user
# IconServices snapshot store can survive that flush — especially when
# the app is pinned to the Dock (the Dock keeps a private cache keyed
# by bundle path). This script does the aggressive nuke.
#
# Usage:
#   dist/refresh-dock.sh
#
# Safe — only touches macOS UI caches; user data is untouched.

set -euo pipefail

APP="/Applications/Minamoto Wallet.app"

if [[ ! -d "$APP" ]]; then
    echo "App not installed at $APP — run dist/make-app.sh --install first."
    exit 1
fi

echo "==> Re-registering bundle with LaunchServices"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f "$APP" >/dev/null 2>&1 || true

echo "==> Removing per-user IconServices cache"
rm -rf "$HOME/Library/Caches/com.apple.iconservices."* 2>/dev/null || true
# `getconf DARWIN_USER_CACHE_DIR` returns the per-user temp cache root
USER_CACHE="$(getconf DARWIN_USER_CACHE_DIR 2>/dev/null || true)"
if [[ -n "$USER_CACHE" && -d "${USER_CACHE}com.apple.dock.iconcache" ]]; then
    rm -rf "${USER_CACHE}com.apple.dock.iconcache" 2>/dev/null || true
fi

echo "==> Removing system IconServices store (needs sudo)"
echo "    If you don't want sudo, you can also reboot — same effect."
sudo rm -rf /Library/Caches/com.apple.iconservices.store 2>/dev/null || \
    echo "    (skipped — run with sudo if the icon still doesn't refresh)"

echo "==> Restarting Dock + Finder"
killall Dock 2>/dev/null || true
killall Finder 2>/dev/null || true

echo
echo "Done. The icon may flash to a generic placeholder for a second"
echo "while macOS re-renders. If the icon STILL shows the old version:"
echo
echo "  1. Drag 'Minamoto Wallet' off your Dock and add it back."
echo "  2. If that doesn't work, log out + log back in."
echo "  3. As a last resort, reboot."
