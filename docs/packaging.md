# Packaging PacketMind as a macOS app

PacketMind ships as `PacketMind.app` (and a `.dmg`). The installed app starts its own Python backend; no terminal, Python or
virtual environment is needed to use it.

## Installing and opening (end users)
1. Open `PacketMind_<version>_aarch64.dmg`, drag **PacketMind** onto **Applications**.
2. Open it from Applications, Launchpad or Spotlight (and keep it in the Dock if you like).
3. **Unsigned builds** (anything not signed with an Apple Developer ID, e.g. built on your own Mac): on *this* Mac it opens
   normally. On another Mac, macOS says it cannot verify the app: right-click the app > **Open** > **Open** once, or allow it in
   System Settings > Privacy & Security.
4. Quit with **PacketMind > Quit** (Cmd-Q). Closing the window also quits PacketMind - a deliberate choice, so no hidden backend or
   capture keeps running. Reopening starts a fresh backend; there is never more than one.

## Where things live
| What | Location |
|---|---|
| Database, captures, reports, uploads, backend app log | `~/Library/Application Support/com.packetmind.desktop/` |
| Backend process output (startup problems) | `~/Library/Logs/com.packetmind.desktop/backend.log` (rotated at 5 MB) |
| Gemini API key | macOS Keychain (Settings > AI / Gemini); never in the app, a file or the logs |

Upgrading the app replaces only the app bundle; the data folder is untouched. Data from a development checkout
(`captures/`, `reports/`, `backend/data/`) is **not** migrated automatically: import old captures with *PCAP Analysis*, or copy the
folders into the Application Support folder while PacketMind is closed.

## How the app starts its backend
`desktop/src-tauri/src/backend.rs` (lifecycle) and `lib.rs` (wiring):
1. On launch the app picks a **free loopback port** and a random **per-launch token**, and starts the bundled backend
   (`Contents/Resources/backend/packetmind-backend`) with `PACKETMIND_DATA_DIR`, `PACKETMIND_PORT`, `PACKETMIND_API_TOKEN`, ...
2. It waits for a **real readiness answer** (`GET /api/health` returns `status: ok`), not a timer. Timeout: 60 s
   (`PACKETMIND_STARTUP_TIMEOUT_SECS`, 1-600). Early exit or timeout shows a startup screen with the reason, the log path and *Try again*.
3. The frontend asks the shell for the address and token (`backend_info`) and sends the token as `X-PacketMind-Token` on every API
   call. The backend rejects anything else with 401 (the readiness probe and CORS preflight are open). Other programs and web
   pages on the Mac cannot call the API without the token.
4. If the backend dies, the shell restarts it (up to 3 times, same port and token), then reports the failure.
5. On Quit the shell sends SIGTERM (the backend closes an active capture and its database), then force-kills after 8 s.
   If the app itself is killed, the backend notices (`PACKETMIND_PARENT_PID`) and exits on its own.

`npm run tauri dev` is unchanged: no backend is bundled in debug builds, you run `python main.py` yourself on port 8765 and the
frontend uses its default address without a token.

## Live capture (needs a one-time permission) vs offline analysis (needs nothing)
Offline PCAP/PCAPNG analysis is pure Python (Scapy parser) and needs no special permission. **TShark/pyshark are not used** and are not
bundled. Live capture uses Scapy on libpcap/BPF, which needs read/write access to `/dev/bpf*`:

```
sudo "/Applications/PacketMind.app/Contents/Resources/scripts/macos-bpf-access.sh" install   # one-time, survives reboot
scripts/macos-bpf-access.sh status                                                           # (from a checkout) check
sudo ".../macos-bpf-access.sh" uninstall                                                     # undo
```
Read the script first: it only changes the group of `/dev/bpf*` to `admin` with group read/write and installs a LaunchDaemon that
repeats that at boot. Security trade-off: any admin user on the Mac can then sniff its interfaces; uninstall when not needed. The app
itself never runs as root. If permission is missing, *Start capture* shows this exact command; the app never falls back to fake traffic.

## Building (developers)
Requirements: macOS, Xcode command-line tools, Rust (`rustup`), Node 20+, Python 3.12+ with the backend venv:
```
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cd ../desktop && npm ci
cd .. && scripts/build-app.sh
```
`scripts/build-app.sh` = `build-backend.sh` (PyInstaller, one-folder, output `build/backend-dist/`) > `verify-backend-bundle.sh`
(starts the packaged backend alone: readiness, token enforcement, PCAP analysis, data dir, clean stop) > frontend tests > `tauri build`
> `verify-app-bundle.sh` (backend + permission script present, bundle id, no API-key pattern, signing status).
Outputs: `desktop/src-tauri/target/release/bundle/macos/PacketMind.app` and `.../bundle/dmg/PacketMind_<version>_<arch>.dmg`.
The build is for the architecture of the machine that builds it (Apple Silicon here); build on an Intel Mac, or add a universal
backend build, to support the other. Python, Node and Rust are build-time only.

The DMG step styles its window through Finder (AppleScript). If macOS blocks that ("AppleEvent timed out"), `build-app.sh` retries with
`CI=true`, which skips only the cosmetic styling.

Tests: `cd backend && .venv/bin/pytest` (includes `tests/test_packaging.py`), `cd desktop && npm test`, `cd desktop/src-tauri && cargo test`.

## Signing and notarization (not done by default)
Without an Apple Developer ID the build is **unsigned** (Tauri ad-hoc signs it for local use). To distribute: join the Apple Developer
Program, create a *Developer ID Application* certificate in your keychain, then
```
APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
APPLE_ID=you@example.com APPLE_PASSWORD=<app-specific-password> APPLE_TEAM_ID=TEAMID scripts/build-app.sh
```
Tauri then signs and notarizes. The bundled backend contains many native libraries; they must be signed too (the Tauri bundler signs
resources it copies, but verify with `codesign --verify --deep --strict` and `spctl -a -vv PacketMind.app`). No credential is stored in
the repository. Until this is verified on a signed build, do not describe a release as signed or notarized.
