# Local application / process mapping

PacketMind can show which **local application** held a connection (for example "Visual Studio Code — 12 connections" on the
github.com page). This is **operating-system information, not packet information**: a packet capture never says which
program sent a packet. Where the OS can say, PacketMind reads it; where it cannot, the UI shows
**"Process information unavailable"** and never guesses a name.

## What the OS gives us (macOS)
- `/usr/sbin/lsof -nP +c 0 -iTCP -iUDP -F pcPn` lists internet sockets with the owning process (pid, name, local/remote address).
- `/bin/ps -o pid=,comm= -p …` gives each process's executable path. The **outermost `.app` bundle** in that path is the
  application name (so "Google Chrome Helper" and "Code Helper (Plugin)" group under "Google Chrome" and "Visual Studio Code").
  Executables that are not in an app bundle (for example `curl`) are shown by their process name, labelled as a process.

Both are read-only. PacketMind never uses a shell, never changes firewall rules, network configuration or processes, and
never asks for elevation.

## Permissions
- **No administrator rights, no Full Disk Access, no entitlements.**
- Without administrator rights macOS only reveals sockets of processes owned by **your own user account**. Connections made by
  system services or other users show as "Process information unavailable". PacketMind deliberately does not escalate to see them.

## When a mapping is valid
A snapshot describes sockets open **at the moment it was taken**. Therefore:
- Snapshots are taken only when you ask (Web Activity → *Local applications*: **Take a snapshot now**, or **Watch while capturing**,
  which samples every few seconds for at most an hour). Nothing is read automatically.
- A connection is matched only against snapshots taken while it was active (a few seconds of slack). A capture analysed later,
  from another machine, or for which no snapshot was taken, has **no** usable mapping and says so.
- Matching uses the full local and remote address and port plus protocol. A socket bound only to a local port is a LOW-confidence
  match; several processes claiming the same endpoints at different times is marked ambiguous and LOW.
- Snapshots are kept in memory only (never in SQLite or on disk), bounded, and can be cleared at any time.

## Adding Windows or Linux
Add a module next to `backend/app/platform/macos.py` with a `ProcessConnectionSource` subclass (for example `/proc` + `ss` on Linux,
`GetExtendedTcpTable` on Windows) and register it in `get_process_source()`. Until then those platforms report themselves as unsupported.
