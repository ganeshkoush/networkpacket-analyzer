# PacketMind

A local desktop tool for analyzing network traffic. It imports PCAP/PCAPNG files (or captures live from one interface), aggregates the traffic locally, runs explainable threat detectors, and can optionally ask an LLM (Google Gemini) to write up an investigation of the *aggregated evidence*. Findings are hedged, confidence-scored indicators for a human analyst, not verdicts.

## Architecture
```
desktop/ (Tauri 2 + React + TS + Tailwind 4)  -- UI only, talks to the backend through src/api/client.ts
        │ HTTP, loopback only (127.0.0.1:8765)
backend/ (FastAPI + SQLite)
  app/analysis   streaming PCAP parser + analyzers -> bounded aggregates (never raw packets in results)
  app/detection  pure-function detectors over the aggregates; each Finding has evidence, reasoning, caveats, confidence
  app/ai         Gemini investigator behind a provider interface; read-only tool allowlist; output grounded against evidence
  app/capture    live capture (Scapy, listen-only) with a rolling analysis window; recorder.py writes the standard PCAP/PCAPNG file
  app/services   background analysis jobs, capture library (capture_store.py, capture_library.py), report builder/store/export
  app/api        HTTP routes: analyses, captures, live, reports, system
```
Packets are parsed and aggregated on your machine. Only structured evidence (counts, IPs, ports, detector output) can ever reach the LLM, and only when you opt in.

## Features
- **PCAP import and analysis**: PCAP/PCAPNG upload, streamed to disk with progress; protocol, IP, port, TCP, DNS, ARP and timeline statistics.
- **Domain activity**: DNS answers are matched to the connections that follow them, giving per-domain connections, bytes sent/received and first/last seen (PCAP Analysis → Domains; `GET /api/analyses/{id}/domains`). Domains are inferred hostnames, not visited URLs.
- **Threat detection**: port scan, SYN flood, ARP spoofing, DNS anomalies (NXDOMAIN rate, DGA-like names), TCP anomalies, connection-behavior detectors. Thresholds live in `backend/app/detection/config.py`.
- **Findings**: severity-sorted list and detail view with confidence breakdown, evidence, reasoning, benign explanations and a non-destructive recommendation.
- **AI investigation (optional)**: Gemini summarizes findings from aggregated evidence. Output is validated: unknown IPs rejected, uncited numbers dropped, overclaims rejected, command/blocking suggestions removed, severity capped at the highest local finding.
- **Live capture (optional)**: pick an interface, start explicitly, see throughput, protocols, top talkers and live findings. The packets are recorded to a standard `.pcap`/`.pcapng` file; when you stop, a *Capture completed* screen shows the saved file, a protocol/domain/finding summary and buttons to download it, analyze it or delete it. See [docs/live-capture.md](docs/live-capture.md).
- **Capture library** (Captures page): every live recording and imported PCAP is kept in a private local folder with its status (Ready / Analyzing / Analyzed / Failed). Open, *Analyze Again* with the current detectors, export to anywhere you can write (native save dialog), or delete (with confirmation). Imports use the same analysis pipeline as live recordings, so the same traffic gives the same results.
- **Reports**: save an investigation as a self-contained JSON snapshot in SQLite; export to HTML, Markdown or JSON; delete with confirmation.
- **Settings** (17 categories): capture defaults and limits, analysis switches, detector thresholds and sensitivity, performance and baseline options, domain and privacy controls, Gemini model/key/usage limits, notifications, storage cleanup, database backup/restore, diagnostics and an About page. Everything is validated, saved explicitly (Save Changes), and consumed by the backend; controls PacketMind cannot honour are shown disabled with the reason.

## Installation
Requirements: macOS, Linux or Windows; Node 20+; Python 3.11+ (developed on 3.14); Rust/Cargo (desktop shell only).
```bash
# Backend
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# Desktop
cd desktop && npm install
```
macOS: `brew install rust`. Native open/save dialogs come from the Tauri dialog plugin (`tauri-plugin-dialog` / `@tauri-apps/plugin-dialog`). Wireshark/TShark is **not** required by the app (`pyshark` is listed in `requirements.txt` but is not used by the current code).

## Dependencies
- Backend: FastAPI, Uvicorn, SQLAlchemy, pydantic / pydantic-settings, Scapy, google-genai (see `backend/requirements.txt`).
- Desktop: React, React Router, Tailwind CSS 4, Vite, Vitest, Tauri 2.

## Configuration
Environment variables or `backend/.env` (git-ignored; template in `backend/.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | unset | Enables AI investigation |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Model name |
| `GEMINI_TIMEOUT_SECONDS` / `GEMINI_MAX_OUTPUT_TOKENS` | 60 / 4096 | Request limits |
| `PACKETMIND_LOG_LEVEL` | `INFO` | Backend log level |
| `PACKETMIND_PORT` | 8765 | Backend port (host stays `127.0.0.1`) |
| `PACKETMIND_MAX_UPLOAD_BYTES` | 4 GiB | Upload size limit |
| `PACKETMIND_MAX_RETAINED_ANALYSES` | 10 | Analyses kept in memory |
| `PACKETMIND_ANALYSIS_WORKERS` | 2 | Overridden by Settings → Advanced → Maximum concurrent analyses |
| `PACKETMIND_CAPTURES_DIR` | `captures/` | Where recorded and imported captures are kept (owner-only files; git-ignored) |
| `VITE_BACKEND_URL` | `http://127.0.0.1:8765` | Backend URL used by the UI (build time) |

Logs go to the console and `backend/data/logs/packetmind.log` (rotating). They contain request method/path/status and errors, never packet data, request bodies or keys.

## AI provider setup
**The AI layer uses Google Gemini, not Claude.** All Gemini-specific code is in `backend/app/ai/gemini_client.py` behind `AIProvider`, so another provider could be added, but none other is implemented.
1. Create a Gemini API key.
2. Put `GEMINI_API_KEY=...` in `backend/.env` and restart the backend.
3. Settings → AI investigation should read "Configured". AI summaries are then available when saving a report ("Include AI summary") and, if ticked at start, for live findings.

Without a key everything else works; AI steps report "unavailable" and never block saving.

## PCAP analysis
1. Start the backend and the desktop app (below).
2. **PCAP Analysis** → choose a `.pcap`/`.pcapng` file. Results appear in tabs; **Findings** lists detections.
3. **Save report** to persist it; open it later under **Reports**.

CLI: `cd backend && .venv/bin/python -m app.analysis tests/fixtures/attack_demo.pcap --detect` (`--json -o out.json` for the full result). `attack_demo.pcap` is a synthetic capture that triggers a scan, SYN flood, ARP spoofing and DGA-like DNS.

## Live capture requirements
Needs Scapy plus OS capture privileges: on macOS read access to `/dev/bpf*` (`brew install --cask wireshark-chmodbpf` or `scripts/macos-bpf-access.sh`), on Linux root or `CAP_NET_RAW` for the Python binary, on Windows Npcap (untested). Capture is listen-only, starts only on explicit confirmation, and raw packets are neither stored nor sent anywhere. Details: [docs/live-capture.md](docs/live-capture.md).

## Development commands
```bash
cd backend && .venv/bin/python main.py        # API on 127.0.0.1:8765 (docs at /docs)
cd desktop && npm run tauri dev               # native window (first run compiles Rust)
cd desktop && npm run dev                     # UI in a browser at http://localhost:1420
cd desktop && npm run build                   # type-check + production bundle
cd desktop && npm run tauri build             # packaged app
```

### Install as a normal Mac app (no terminal needed afterwards)
`scripts/build-app.sh` builds `PacketMind.app` and a `.dmg` with the backend bundled; the app starts and stops it by itself.
See [docs/packaging.md](docs/packaging.md) for installing, where data lives, the one-time live-capture permission, and signing.

Regenerate fixtures: `backend/tests/fixtures/build_fixtures.py`. Project conventions and safety rules: [CLAUDE.md](CLAUDE.md).

## Testing
```bash
cd backend && .venv/bin/pytest     # backend unit/API tests plus ../tests; no network or API key needed (AI is mocked)
cd desktop && npm test             # Vitest (components, pages, API client)
```
`cd desktop && npm run test:e2e` runs the API client against a real, already-running backend (not part of `npm test`).

## Security considerations
- Backend binds to loopback only; CORS is limited to the app origins; uploads need a non-simple content type plus a custom header so other web pages cannot post captures.
- No packet injection, blocking or other network-modifying action. AI output is never executed; AI tools are a fixed read-only allowlist.
- Live capture and file access are user-initiated. Report deletion and capture start require explicit confirmation.
- Report exports escape dynamic text and are written only to the reports folder with generated names.
- Captures, reports, the database, logs and `.env` are git-ignored. Captures can contain sensitive traffic; treat saved reports (which include IPs, domains and capture hashes) accordingly.
- When AI is enabled, aggregated evidence (IPs, ports, domains, counts) is sent to Google's API. Do not enable it for traffic you are not permitted to share that metadata about.

## Known limitations
- Detection is heuristic: expect false positives (scanners, CDNs, NAT, DHCP/ARP quirks) and false negatives (low-and-slow activity, encrypted payloads, anything the aggregates do not capture). Findings are leads, not verdicts.
- Domain attribution depends on DNS being visible in the capture. HTTPS URLs/paths are encrypted and never shown; lookups served from a host cache, made before the capture, or sent over DoH/DoT are missed; CDN addresses shared by several domains are attributed to the most recent lookup and flagged as less certain. Not shown for live capture.
- Analysis caps (top-N lists, bounded aggregates) mean very large captures are summarized, not exhaustively indexed. No payload inspection or TLS decryption.
- Analysis jobs are kept in memory (last 10); restarting the backend discards un-saved analyses. Only saved reports persist.
- Live capture: one interface at a time, rolling 60 s window; macOS verified, Linux/Windows untested. Capture privileges can't be reliably detected in advance.
- AI: Gemini only; quality depends on the model, and output is constrained to the supplied evidence.
- Single-user local app: no authentication, no multi-user support. Settings are read-only in the UI.
- The desktop shell (Tauri) was built and tested via the web bundle and unit tests in this pass; packaged installers were not produced or signed.


## Capture files and privacy
Captured and imported traffic can contain passwords, cookies, personal data and anything else that crossed the network. PacketMind keeps these files only in its private `captures/` folder (owner read/write, git-ignored), never uploads them, and never sends them to Gemini: the AI only receives the structured summaries its local analysis produces. Imported files are treated as untrusted input: they are validated by signature, parsed read-only, malformed packets are skipped, nothing in a capture is ever executed, and stored names are generated (the name you see is sanitised display text). Exporting copies a file to a place you choose; deleting a capture removes its managed copy only after you confirm. If a capture shows a **Failed** status, the reason is shown and no file is claimed as saved.


## Settings and secrets
Settings live in one validated document in the local SQLite database (`app_settings`); the UI edits a draft and saves it as one change, and the backend rejects the whole change if any value is invalid. Export/Import uses a versioned JSON file that contains **no secrets and no paths** and is rejected completely if it names an unknown setting. Folders are fixed by `PACKETMIND_*` environment variables, so a settings file cannot redirect them.

The Gemini API key can be saved in Settings → AI / Gemini. It is stored in your operating system's keychain (macOS Keychain, Windows Credential Locker, Secret Service), is write-only (no endpoint returns it, not even a fragment), is never logged and is never written to the database or a settings file. If no secure storage exists the app refuses to save it and `GEMINI_API_KEY` in the environment still works (a saved key takes precedence). AI permissions (read-only analysis, no commands, firewall, routing, network changes or file deletion) are fixed in code, not settings. Request counts, a daily limit and result caching are in Settings → AI Usage; PacketMind shows request counts, never a price.
