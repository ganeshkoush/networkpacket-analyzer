"""macOS process <-> connection mapping, using two read-only system tools that need no special privileges.

* ``/usr/sbin/lsof -nP +c 0 -iTCP -iUDP -F ...`` lists internet sockets with their owning process.
* ``/bin/ps -o pid=,comm= -p ...`` gives each process's executable path, from which the application bundle is read.

Permissions: no administrator rights, no Full Disk Access, no entitlements. Without root, ``lsof`` only reports sockets of
processes owned by the *current user*; sockets of system services and other users simply do not appear, and PacketMind
never asks for elevation to see them. Nothing is modified: the commands only read.
"""
from __future__ import annotations

import ipaddress
import os
import subprocess
from collections.abc import Callable

from app.models.process import ProcessConnectionMapping, ProcessSnapshot
from app.platform.base import ProcessConnectionSource, ProcessSourceError

LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
TIMEOUT_SECONDS = 15.0
MAX_MAPPINGS = 20_000
_PS_CHUNK = 200

PERMISSION_NOTE = (
    "macOS: uses the built-in read-only tools lsof and ps. No administrator rights, Full Disk Access or other permission is "
    "requested. Without administrator rights macOS only lets these tools see sockets owned by your own user account, so "
    "connections made by system services or other users' processes are not visible and show as "
    "'Process information unavailable'."
)

Runner = Callable[[list[str]], str]


def run_command(args: list[str]) -> str:
    """Run one fixed, read-only command (never through a shell) and return its stdout."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False, shell=False)  # noqa: S603
    except FileNotFoundError:
        raise ProcessSourceError(f"{args[0]} is not available on this system.") from None
    except subprocess.TimeoutExpired:
        raise ProcessSourceError(f"{os.path.basename(args[0])} did not answer within {TIMEOUT_SECONDS:.0f} seconds.") from None
    if done.returncode not in (0, 1):  # lsof exits 1 when it simply finds nothing
        raise ProcessSourceError(f"{os.path.basename(args[0])} failed: {(done.stderr or '').strip()[:200] or 'unknown error'}")
    return done.stdout


def _endpoint(text: str) -> tuple[str | None, int | None]:
    """'192.168.1.5:443', '[2001:db8::1]:443', '*:5353' -> (ip | None for wildcard, port)."""
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    if not port.isdigit():
        return None, None
    if host in ("*", ""):
        return None, int(port)
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return None, int(port)
    ip = getattr(ip, "ipv4_mapped", None) or ip  # dual-stack sockets show ::ffff:a.b.c.d
    return str(ip), int(port)


def parse_lsof(output: str, now: float) -> tuple[list[ProcessConnectionMapping], int, bool]:
    """Parse ``lsof -F pcPn`` field output into mappings (without ``application``; that comes from ``ps``).

    Returns ``(mappings, process count, truncated)``. Unknown or malformed records are skipped, never guessed.
    """
    mappings: list[ProcessConnectionMapping] = []
    pids: set[int] = set()
    pid: int | None = None
    name: str | None = None
    proto: str | None = None
    truncated = False
    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid = int(value) if value.isdigit() else None
            name, proto = None, None
        elif tag == "c":
            name = value or None
        elif tag == "f":
            proto = None  # a new file record begins
        elif tag == "P":
            proto = value if value in ("TCP", "UDP") else None
        elif tag == "n" and pid is not None and name and proto:
            local, _, remote = value.partition("->")
            lip, lport = _endpoint(local)
            if lport is None:
                continue
            rip, rport = _endpoint(remote) if remote else (None, None)
            if remote and rport is None:
                continue
            if len(mappings) >= MAX_MAPPINGS:
                truncated = True
                continue
            pids.add(pid)
            connected = rip is not None and rport is not None
            mappings.append(ProcessConnectionMapping(
                process_name=name, pid=pid, local_ip=lip, local_port=lport, remote_ip=rip, remote_port=rport,
                protocol=proto, timestamp=now, confidence=("HIGH" if proto == "TCP" else "MEDIUM") if connected else "LOW"))  # type: ignore[arg-type]
    return mappings, len(pids), truncated


def application_from_path(path: str) -> str | None:
    """The outermost ``.app`` bundle name in an executable path ("…/Google Chrome.app/…/Helper.app/…" -> "Google Chrome")."""
    for part in path.split("/"):
        if part.endswith(".app") and len(part) > 4:
            return part[:-4]
    return None


def parse_ps(output: str) -> dict[int, str]:
    """``ps -o pid=,comm=`` lines -> {pid: executable path}."""
    paths: dict[int, str] = {}
    for line in output.splitlines():
        head, _, rest = line.strip().partition(" ")
        if head.isdigit() and rest.strip():
            paths[int(head)] = rest.strip()
    return paths


class MacOSProcessSource(ProcessConnectionSource):
    platform = "macOS"
    mechanism = "lsof + ps (read-only)"
    permission_note = PERMISSION_NOTE

    def __init__(self, runner: Runner = run_command) -> None:
        self._run = runner  # injectable so tests never execute real commands

    def snapshot(self, now: float) -> ProcessSnapshot:
        out = self._run([LSOF, "-nP", "+c", "0", "-iTCP", "-iUDP", "-F", "pcPn"])
        mappings, processes, truncated = parse_lsof(out, now)
        notes = []
        paths: dict[int, str] = {}
        pids = sorted({m.pid for m in mappings})
        try:
            for i in range(0, len(pids), _PS_CHUNK):
                chunk = pids[i:i + _PS_CHUNK]
                paths.update(parse_ps(self._run([PS, "-o", "pid=,comm=", "-p", ",".join(map(str, chunk))])))
        except ProcessSourceError as exc:
            notes.append(f"Application names could not be read ({exc}); process names are shown instead.")
        for m in mappings:
            m.application = application_from_path(paths.get(m.pid, ""))
        if truncated:
            notes.append(f"Only the first {MAX_MAPPINGS:,} sockets were kept.")
        return ProcessSnapshot(timestamp=now, platform=self.platform, mappings=mappings, processes=processes, truncated=truncated, notes=notes)
