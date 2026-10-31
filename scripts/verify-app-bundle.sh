#!/bin/sh
# Checks the built PacketMind.app: contains the packaged backend and the capture-permission script, the backend is executable,
# no source-tree paths or secrets were embedded, and reports signing status honestly.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP="${1:-$ROOT/desktop/src-tauri/target/release/bundle/macos/PacketMind.app}"
[ -d "$APP" ] || { echo "App not found: $APP" >&2; exit 1; }
RES="$APP/Contents/Resources"
[ -x "$RES/backend/packetmind-backend" ] && echo "ok   packaged backend present and executable" || { echo "FAIL: backend missing from the app"; exit 1; }
[ -f "$RES/scripts/macos-bpf-access.sh" ] && echo "ok   capture-permission script bundled" || { echo "FAIL: permission script missing"; exit 1; }
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist" | grep -qx com.packetmind.desktop && echo "ok   bundle identifier com.packetmind.desktop" || { echo "FAIL: bundle identifier"; exit 1; }
if grep -rIl "$ROOT" "$APP/Contents/MacOS" "$RES/backend/packetmind-backend" 2>/dev/null | grep -q .; then echo "WARN: the build machine's project path appears in the app executable (check it is not needed at runtime)"; fi
if grep -rIlE 'AIza[0-9A-Za-z_-]{30,}' "$APP" 2>/dev/null | grep -q .; then echo "FAIL: something that looks like a Google API key is inside the app"; exit 1; fi; echo "ok   no API key pattern inside the app"
if codesign --verify --deep --strict "$APP" 2>/dev/null && ! codesign -dv "$APP" 2>&1 | grep -q 'Signature=adhoc'; then echo "info signed with a real identity (notarization is separate: check with 'spctl -a -vv')"; else echo "info NOT signed with a Developer ID (unsigned/ad-hoc): fine on this Mac, other Macs show a Gatekeeper warning"; fi
