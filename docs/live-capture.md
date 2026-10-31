# Live capture

Passive capture from one network interface, with a rolling local analysis window.

```
packets -> PacketRecord (bounded rolling window, in memory only)
        -> every 5 s: local analysis + detectors
        -> suspicious events (findings, tracked across windows)
        -> [opt-in] AI investigation of an event that crosses the thresholds (aggregated evidence only)
```

## Guarantees
- Capture starts only on `POST /api/live/start` with `confirm: true` (the **Start capture** button). Nothing starts at launch.
- Passive only: a listen-only socket, no packet injection, no traffic modification, no blocking. A test asserts the capture code contains no send/firewall calls.
- Non-promiscuous by default (traffic to/from this machine plus broadcast/multicast).
- Packets are never sent anywhere. The rolling analysis window is bounded in memory (`max_window_packets`, default 50,000). Unless the user turns it off, the capture is also *recorded* to a standard `.pcap` (or `.pcapng`) file in PacketMind's private capture folder (`captures/`, owner-only permissions, git-ignored) so it can be exported and analysed again. See "Recording and export" below.
- AI investigation is **off unless ticked** at start. Even then, only aggregated evidence for one finding is sent (via the Gemini investigator), never individual packets, and only when severity >= MEDIUM and confidence >= 0.6, with a 5-minute per-event cooldown and at most 6 investigations/hour. Failures (e.g. no `GEMINI_API_KEY`) are shown on the finding; capture keeps running.

## Tunables (`LiveConfig`, `backend/app/capture/live_capture.py`)
`window_seconds` 60, `max_window_packets` 50000, `refresh_seconds` 5, `rate_window_seconds` 5,
`investigate_min_severity` MEDIUM, `investigate_min_confidence` 0.6, `investigation_cooldown_seconds` 300,
`max_investigations_per_hour` 6, `max_events` 100.

## API
| Method | Path | Notes |
|---|---|---|
| GET | `/api/live/interfaces` | name, description, kind (`wifi`/`ethernet`/`vpn`/`loopback`/`other`), addresses. No privileges needed |
| POST | `/api/live/start` | `{interface, confirm: true, auto_investigate?: false}`. 400 unknown interface / no confirm, 403 permission, 409 already running |
| GET | `/api/live/status` | state (`capturing`/`stopped`/`permission_error`/`error`), packet count, pkt/s, bit/s, protocols, top talkers, top ports, findings + investigations |
| POST | `/api/live/stop` | Idempotent; also clears a permission/error state |

UI indicators: `● Capturing`, `○ Stopped`, `⚠ Permission error` (also `⚠ Capture error`).

## OS requirements
Packet capture needs OS privileges. **Start the backend with them**; the desktop UI just talks to it. Without them the UI shows `⚠ Permission error` with the hint for your OS.

**macOS**: capture opens `/dev/bpf*` read/write, which are root-only by default. Pick one:
- **Recommended (no Wireshark, no sudo for the backend):** `sudo scripts/macos-bpf-access.sh install`. It gives the `admin` group access to `/dev/bpf*` via a small LaunchDaemon so it survives reboots. No restart needed: click **Start capture** again. Check with `scripts/macos-bpf-access.sh status`; undo with `sudo scripts/macos-bpf-access.sh uninstall`. Trade-off: any admin user on the Mac can then sniff traffic.
- **Temporary:** `sudo scripts/macos-bpf-access.sh now` (until reboot).
- **Run as root:** `cd backend && sudo -E .venv/bin/python main.py`. Not preferred: files the backend creates (e.g. `backend/data/packetmind.db`) become root-owned and later non-sudo runs fail.
- Wi-Fi/Ethernet labels come from `networksetup -listallhardwareports`. VPNs appear as `utunN`.

**Linux**: needs `CAP_NET_RAW` (+ `CAP_NET_ADMIN` for some drivers).
- Quick: `sudo .venv/bin/python main.py` (note: root's environment, so keep the venv path and `GEMINI_API_KEY` available: `sudo -E`).
- Better: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f backend/.venv/bin/python)`.
- Loopback is `lo`; Wi-Fi is detected via `/sys/class/net/<if>/wireless`; VPNs via `tun*`/`wg*`.

**Windows**: needs **Npcap** (https://npcap.com; install with "WinPcap API-compatible mode") and an Administrator terminal for the backend. Loopback capture requires Npcap's loopback adapter ("Npcap Loopback Adapter"). Adapter names/descriptions are used to label Wi-Fi/Ethernet/VPN.

Notes: libpcap/BPF/AF_PACKET do not see traffic on interfaces that are down; on macOS `lo0` shows only local traffic; Wi-Fi in monitor mode is not supported (we capture normal frames).

## Manual test
1. `cd backend && sudo .venv/bin/python main.py` (or the OS-specific setup above) and `cd desktop && npm run tauri dev`.
2. Open **Live Capture**, choose an interface, click **Start capture** (`● Capturing`). Browse some sites: packet count, rate, protocols, talkers and ports update about once a second (window stats every ~5 s).
3. Generate a detectable pattern against a host you own, e.g. `nmap -sS -p 1-1000 <your-own-test-host>`; a "Possible TCP port scan" finding should appear.
4. Tick the AI option (with `GEMINI_API_KEY` set) before starting to see the investigation attach to the finding.
5. Click **Stop capture** (`○ Stopped`). Run without privileges to see `⚠ Permission error`.

curl equivalent: `curl -XPOST localhost:8765/api/live/start -H 'content-type: application/json' -d '{"interface":"lo0","confirm":true}'`.

## Tests
`cd backend && .venv/bin/pytest tests/capture` (no privileges: a fake packet source drives the real manager; one test runs Scapy's real `AsyncSniffer` against a pcap-backed socket and one exercises the real OS permission path). `cd desktop && npm test` covers the UI states.


## Recording and export
- **Start**: `POST /api/live/start` records by default (`save: true`, `format: "pcap" | "pcapng"`). A capture-library row (`CAPTURING`) and an empty owner-only file named `packetmind_capture_<date>_<time>_<id>.pcap` are created in the managed folder; names are generated, never taken from user input. If the interface cannot be opened the empty file and row are removed.
- **While capturing**: `GET /api/live/status` reports `capture` (file name, format, packets and bytes written). No filesystem path is exposed.
- **Stop** (also on shutdown, interface loss or a write failure): the source is stopped first, the writer is flushed and closed, the file is verified (exists, valid PCAP header, first packet readable), the row is finalised (`COMPLETED`, packets, bytes, duration, size) and the saved file is analysed automatically with the standard pipeline (`ANALYZING` -> `ANALYZED` with a protocol/domain/finding summary).
- **Failures are never reported as saved**: a disk-full/permission error while writing stops the capture (`capture_write_failed`), marks the row `FAILED` with the reason, and the UI says the file is incomplete. If the interface disappears, what was captured is still saved and the error is shown.
- **Export**: `POST /api/captures/{id}/export {destination}` copies the file to a path chosen in the native save dialog (absolute path, no `..`, existing folder, not PacketMind's own folder, not a symlink, never overwrites without `overwrite: true`; written to a temp name and renamed). The managed copy is kept. `GET /api/captures/{id}/download` streams it for browser use.
- **Privacy**: the capture file is the raw traffic and may contain sensitive data. It stays on this machine and is never sent to Gemini; only PacketMind's local summaries are.
