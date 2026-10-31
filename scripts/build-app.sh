#!/bin/sh
# Builds the installable macOS app and DMG.
#   scripts/build-app.sh            unsigned build (works on this Mac; other Macs need right-click > Open the first time)
# Signing/notarization (optional, needs your Apple Developer account; nothing is embedded in the repo):
#   APPLE_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)" \
#   APPLE_ID=you@example.com APPLE_PASSWORD=<app-specific-password> APPLE_TEAM_ID=TEAMID scripts/build-app.sh
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
"$ROOT/scripts/build-backend.sh"
"$ROOT/scripts/verify-backend-bundle.sh"
cd "$ROOT/desktop"
[ -d node_modules ] || npm ci
npm test
# The DMG step styles its Finder window with AppleScript, which macOS blocks until Finder automation is allowed for your terminal
# (error "AppleEvent timed out -1712"). If that happens, retry without the cosmetic styling: the DMG is just as installable.
if ! npx tauri build; then
  echo "DMG styling failed; retrying without Finder styling (CI=true)..." >&2
  CI=true npx tauri build --bundles dmg
fi
"$ROOT/scripts/verify-app-bundle.sh"
echo "Artifacts:"; ls -d "$ROOT"/desktop/src-tauri/target/release/bundle/macos/PacketMind.app "$ROOT"/desktop/src-tauri/target/release/bundle/dmg/*.dmg
