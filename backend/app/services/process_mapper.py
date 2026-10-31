"""Local process mapping: explicit OS snapshots, kept in memory, matched to observed connections.

Principles (see ``app/platform``):

* A packet capture does not identify the sending application. Process information comes only from OS snapshots, which
  describe sockets open *at the moment the snapshot was taken*. A connection is therefore matched only against snapshots
  taken while it was active (a few seconds of slack); a capture analysed long after the fact simply has no usable snapshots.
* Matching is by the full endpoint pair (local ip:port + remote ip:port + protocol). Anything weaker is LOW confidence, and
  a connection without a match is reported as "Process information unavailable": names are never guessed.
* Snapshots are taken only on an explicit user action (one-off or a bounded watch), are never written to disk or the
  database, and can be cleared at any time. Nothing here changes firewall rules, processes or network configuration.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass

from app.models.analysis import AnalysisResult, Connection
from app.models.process import (
    UNAVAILABLE, ApplicationUsage, ConnectionProcessMatch, DomainApplications, MappingConfidence, ProcessConnectionMapping,
    ProcessSnapshot, ProcessSourceStatus,
)
from app.platform import ProcessConnectionSource, ProcessSourceError, get_process_source

logger = logging.getLogger(__name__)

SLACK_SECONDS = 2.0          # a snapshot counts for a connection that started/ended this close to it
MIN_INTERVAL_SECONDS = 2.0   # a watch never samples faster than this
MAX_WATCH_SECONDS = 3600.0   # a watch stops by itself
MAX_SNAPSHOTS = 720          # ring buffer (one hour at 5 s)


def _norm(ip: str | None) -> str | None:
    if ip is None:
        return None
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ip
    return str(getattr(a, "ipv4_mapped", None) or a)


@dataclass
class _Claim:
    process_name: str
    pid: int
    application: str | None
    confidence: MappingConfidence
    timestamps: list[float]


class ProcessMapper:
    def __init__(self, source: ProcessConnectionSource | None = None, clock: Callable[[], float] = time.time,
                 max_snapshots: int = MAX_SNAPSHOTS) -> None:
        self._source = source or get_process_source()
        self._clock = clock
        self._snapshots: deque[ProcessSnapshot] = deque(maxlen=max_snapshots)
        self._lock = threading.RLock()
        self._watcher: threading.Thread | None = None
        self._stop = threading.Event()
        self._interval: float | None = None
        self._last_error: str | None = None

    # ------------------------------------------------------------------ status / snapshots (all user-initiated)
    def status(self) -> ProcessSourceStatus:
        with self._lock:
            snaps = list(self._snapshots)
            watching = self._watcher is not None and self._watcher.is_alive()
            return ProcessSourceStatus(
                platform=self._source.platform, supported=self._source.supported, mechanism=self._source.mechanism,
                permission_note=self._source.permission_note, snapshots=len(snaps),
                first_snapshot_at=snaps[0].timestamp if snaps else None, last_snapshot_at=snaps[-1].timestamp if snaps else None,
                watching=watching, watch_interval_seconds=self._interval if watching else None, last_error=self._last_error,
                notes=["Snapshots are kept in memory only and are lost when the backend stops.",
                       "A snapshot describes sockets open at the moment it was taken, so it can only identify the application of "
                       "connections that were active then: take snapshots while the traffic is being captured."])

    def snapshot(self) -> ProcessSnapshot:
        """Ask the OS once and remember the answer. Raises ``ProcessSourceError`` if the OS cannot be queried."""
        snap = self._source.snapshot(self._clock())
        with self._lock:
            self._snapshots.append(snap)
            self._last_error = None
        return snap

    def start_watch(self, interval_seconds: float = 5.0, max_seconds: float = MAX_WATCH_SECONDS) -> None:
        if not self._source.supported:
            raise ProcessSourceError(f"Process mapping is not supported on {self._source.platform}.")
        interval = max(interval_seconds, MIN_INTERVAL_SECONDS)
        with self._lock:
            if self._watcher is not None and self._watcher.is_alive():
                return
            self._stop.clear()
            self._interval = interval
            self._watcher = threading.Thread(target=self._watch, args=(interval, min(max_seconds, MAX_WATCH_SECONDS)),
                                             name="packetmind-process-watch", daemon=True)
            self._watcher.start()

    def _watch(self, interval: float, max_seconds: float) -> None:
        deadline = self._clock() + max_seconds
        while not self._stop.is_set() and self._clock() < deadline:
            try:
                self.snapshot()
            except ProcessSourceError as exc:
                with self._lock:
                    self._last_error = str(exc)
            except Exception:  # a watcher must never die noisily
                logger.exception("Process snapshot failed")
            self._stop.wait(interval)

    def stop_watch(self) -> None:
        self._stop.set()
        t = self._watcher
        if t is not None and t is not threading.current_thread():
            t.join(timeout=5)
        with self._lock:
            self._watcher, self._interval = None, None

    def clear(self) -> int:
        with self._lock:
            n = len(self._snapshots)
            self._snapshots.clear()
            return n

    def snapshots_between(self, start: float, end: float, slack: float = SLACK_SECONDS) -> list[ProcessSnapshot]:
        with self._lock:
            return [s for s in self._snapshots if start - slack <= s.timestamp <= end + slack]

    def shutdown(self) -> None:
        self.stop_watch()

    # ------------------------------------------------------------------ matching
    def match(self, connections: list[Connection]) -> dict[str, ConnectionProcessMatch]:
        """Match connections to the OS-reported process of the same endpoints, using only snapshots taken while they were active."""
        with self._lock:
            snaps = list(self._snapshots)
        return match_connections(connections, snaps)

    def _prepare(self, result: AnalysisResult, domain: str, conns: list[Connection]) -> tuple[DomainApplications | None, list[ProcessSnapshot]]:
        """Either an "unavailable" answer (with the reason) or the snapshots that overlap the capture."""
        status = self._source
        base = dict(domain=domain, permission_note=status.permission_note, connections_considered=len(conns), connections_unmatched=len(conns))
        if not status.supported:
            return DomainApplications(status="unsupported", message=f"{UNAVAILABLE}: process mapping is not supported on {status.platform} yet.", **base), []
        meta = result.metadata
        with self._lock:
            have = len(self._snapshots)
        if have == 0:
            return DomainApplications(status="no_snapshots", message=f"{UNAVAILABLE}: no local process snapshot has been taken. Take snapshots while the traffic is being captured "
                                      "(they can't be taken retroactively for a saved capture).", **base), []
        if meta.first_packet_time is None or meta.last_packet_time is None:
            return DomainApplications(status="no_overlap", message=f"{UNAVAILABLE}: the capture has no timestamps to compare with the snapshots.", **base), []
        overlapping = self.snapshots_between(meta.first_packet_time, meta.last_packet_time)
        if not overlapping:
            return DomainApplications(status="no_overlap", message=f"{UNAVAILABLE}: none of the {have} snapshot(s) were taken while this capture was recorded, so the OS "
                                      "cannot say which application owned its connections.", **base), []
        return None, overlapping

    def capture_matches(self, result: AnalysisResult, conns: list[Connection]) -> tuple[dict[str, ConnectionProcessMatch], str | None]:
        """Process matches for connections of a whole capture, or ({}, the reason process information is unavailable)."""
        early, overlapping = self._prepare(result, "", conns)
        if early is not None:
            return {}, early.message
        matches = match_connections(conns, overlapping)
        if not matches:
            return {}, (f"{UNAVAILABLE}: no open local socket matched these connections. They may come from another computer, or belong to "
                        "processes this user account cannot see (system services).")
        return matches, None

    def applications_for_domain(self, result: AnalysisResult, domain: str) -> DomainApplications:
        """Applications that held this domain's connections (as far as OS snapshots can tell)."""
        conns = [c for c in result.connections if c.domain == domain and c.protocol in ("TCP", "UDP")]
        base = dict(domain=domain, permission_note=self._source.permission_note)
        early, overlapping = self._prepare(result, domain, conns)
        if early is not None:
            return early
        matches = match_connections(conns, overlapping)
        usage: dict[str, dict] = {}
        for c in conns:
            m = matches.get(c.id)
            if m is None:
                continue
            key = m.application or m.process_name
            u = usage.setdefault(key, {"kind": "application" if m.application else "process", "names": set(), "pids": set(), "n": 0, "conf": Counter()})
            u["names"].add(m.process_name)
            u["pids"].add(m.pid)
            u["n"] += 1
            u["conf"][m.confidence] += 1
        apps = [ApplicationUsage(name=k, kind=u["kind"], process_names=sorted(u["names"]), pids=sorted(u["pids"]), connections=u["n"],
                                 confidence_counts=dict(u["conf"])) for k, u in usage.items()]
        apps.sort(key=lambda a: (-a.connections, a.name.lower()))
        matched = sum(a.connections for a in apps)
        if matched == 0:
            return DomainApplications(
                status="no_matches", connections_considered=len(conns), connections_unmatched=len(conns), snapshots_used=len(overlapping),
                message=f"{UNAVAILABLE}: no open local socket matched these connections. They may come from another computer, or belong to "
                        "processes this user account cannot see (system services).", **base)
        partial = matched < len(conns)
        return DomainApplications(
            status="partial" if partial else "available", applications=apps, connections_considered=len(conns), connections_matched=matched,
            connections_unmatched=len(conns) - matched, snapshots_used=len(overlapping),
            message=(f"{len(conns) - matched} of {len(conns)} connection(s) could not be matched: {UNAVAILABLE.lower()} for them." if partial
                     else f"All {len(conns)} connection(s) matched an OS-reported process."), **base)


# --------------------------------------------------------------------- pure matching (no OS access)
def _key(proto: str, lip: str | None, lport: int | None, rip: str | None, rport: int | None):
    return (proto, _norm(lip), lport, _norm(rip), rport)


def match_connections(connections: list[Connection], snapshots: list[ProcessSnapshot], slack: float = SLACK_SECONDS) -> dict[str, ConnectionProcessMatch]:
    """{connection id: match} for connections whose endpoints an OS snapshot attributes to a process.

    A snapshot only counts for a connection if it was taken while the connection was active (``start - slack`` to
    ``end + slack``). The full endpoint pair matches either way round (the capture may call the local side "client" or
    "server"). A socket bound to a local port only (e.g. unconnected UDP) is a LOW-confidence match.
    """
    by_full: dict[tuple, list[tuple[float, ProcessConnectionMapping]]] = {}
    by_local: dict[tuple, list[tuple[float, ProcessConnectionMapping]]] = {}
    for s in snapshots:
        for m in s.mappings:
            if m.remote_ip is not None and m.remote_port is not None:
                by_full.setdefault(_key(m.protocol, m.local_ip, m.local_port, m.remote_ip, m.remote_port), []).append((s.timestamp, m))
            else:
                by_local.setdefault((m.protocol, m.local_port), []).append((s.timestamp, m))

    out: dict[str, ConnectionProcessMatch] = {}
    for c in connections:
        if c.protocol not in ("TCP", "UDP") or c.client_port is None or c.server_port is None:
            continue
        lo, hi = c.start_time - slack, c.end_time + slack
        claims: dict[tuple[int, str], _Claim] = {}
        inside = False
        for lip, lport, rip, rport in ((c.client_ip, c.client_port, c.server_ip, c.server_port), (c.server_ip, c.server_port, c.client_ip, c.client_port)):
            for ts, m in by_full.get(_key(c.protocol, lip, lport, rip, rport), []):
                if lo <= ts <= hi:
                    claim = claims.setdefault((m.pid, m.process_name), _Claim(m.process_name, m.pid, m.application, m.confidence, []))
                    claim.timestamps.append(ts)
                    inside = inside or c.start_time <= ts <= c.end_time
        confidence: MappingConfidence
        reason: str
        if claims:
            reason = "The OS reported a socket with exactly these local and remote addresses and ports for this process."
        else:  # weaker: a socket bound to a local port that equals one end of this connection
            for lip, lport in ((c.client_ip, c.client_port), (c.server_ip, c.server_port)):
                for ts, m in by_local.get((c.protocol, lport), []):
                    if lo <= ts <= hi and (m.local_ip is None or _norm(m.local_ip) == _norm(lip)):
                        claim = claims.setdefault((m.pid, m.process_name), _Claim(m.process_name, m.pid, m.application, "LOW", []))
                        claim.timestamps.append(ts)
            reason = "The OS reported a socket bound to this local port but without a remote address, so it does not prove it owns this flow."
        if not claims:
            continue
        best = max(claims.values(), key=lambda k: (len(k.timestamps), k.pid))
        ambiguous = len(claims) > 1
        if best.confidence == "LOW":
            confidence = "LOW"
        elif ambiguous:
            confidence, reason = "LOW", "Several processes claimed these endpoints in different snapshots; the most frequent is shown."
        else:
            confidence = best.confidence if inside else "MEDIUM" if best.confidence == "HIGH" else "LOW"  # only seen just outside the connection's lifetime
        out[c.id] = ConnectionProcessMatch(
            connection_id=c.id, process_name=best.process_name, pid=best.pid, application=best.application, confidence=confidence,
            snapshots_matched=len(best.timestamps), reason=reason, ambiguous=ambiguous)
    return out


_mapper: ProcessMapper | None = None


def get_process_mapper() -> ProcessMapper:
    """The app-wide mapper (tests replace ``_mapper``)."""
    global _mapper
    if _mapper is None:
        _mapper = ProcessMapper()
    return _mapper
