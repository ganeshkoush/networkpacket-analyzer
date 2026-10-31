"""Tiny forward-only SQLite migration runner using `PRAGMA user_version`.

Add a function to MIGRATIONS with the next version number; it runs once, inside a transaction,
on startup. Never edit a released migration - append a new one.
"""
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import Connection, Engine, text


def _v1_reports(conn: Connection) -> None:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,            -- ISO-8601 UTC
            source_kind TEXT NOT NULL,           -- 'pcap' | 'live'
            capture_name TEXT NOT NULL,
            highest_severity TEXT,
            finding_count INTEGER NOT NULL,
            total_packets INTEGER NOT NULL,
            ai_status TEXT NOT NULL,             -- 'completed' | 'failed' | 'not_run'
            schema_version INTEGER NOT NULL,
            content TEXT NOT NULL                -- ReportContent as JSON
        )"""))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_reports_created_at ON reports (created_at DESC)"))


def _v2_performance_history(conn: Connection) -> None:
    """Local history of per-domain performance aggregates (no packets, no IP addresses)."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS perf_sources (
            source_id TEXT PRIMARY KEY,          -- capture SHA-256 (pcap) or a live-session id
            source_kind TEXT NOT NULL,           -- 'pcap' | 'live'
            name TEXT NOT NULL,                  -- file name / interface label
            captured_at REAL NOT NULL,           -- epoch seconds of the capture's traffic
            recorded_at TEXT NOT NULL            -- ISO-8601 UTC
        )"""))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS perf_observations (
            source_id TEXT NOT NULL REFERENCES perf_sources (source_id) ON DELETE CASCADE,
            domain TEXT NOT NULL,
            captured_at REAL NOT NULL,
            connections INTEGER NOT NULL,
            handshake_ms REAL, handshake_samples INTEGER NOT NULL DEFAULT 0,
            rtt_avg_ms REAL, rtt_p95_ms REAL, rtt_samples INTEGER NOT NULL DEFAULT 0,
            dns_ms REAL, dns_lookups INTEGER NOT NULL DEFAULT 0,
            response_ms REAL, response_samples INTEGER NOT NULL DEFAULT 0,
            tcp_packets INTEGER NOT NULL DEFAULT 0, retransmissions INTEGER NOT NULL DEFAULT 0,
            tcp_attempted INTEGER NOT NULL DEFAULT 0, tcp_failed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (source_id, domain)
        )"""))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_perf_obs_domain_time ON perf_observations (domain, captured_at)"))


def _v3_captures(conn: Connection) -> None:
    """The capture library: one row per saved capture file (live recordings and imports). The PCAP bytes live in
    ``captures_dir`` under a generated name (``filename``); the database never holds packets."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS captures (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL UNIQUE,       -- generated name inside captures_dir (never user supplied)
            original_filename TEXT NOT NULL,     -- display only: sanitised name the user knows it by
            source_type TEXT NOT NULL,           -- 'LIVE_CAPTURE' | 'UPLOADED_PCAP'
            capture_format TEXT NOT NULL,        -- 'pcap' | 'pcapng'
            interface TEXT,
            start_time REAL, end_time REAL, duration_seconds REAL,
            packet_count INTEGER NOT NULL DEFAULT 0,
            byte_count INTEGER NOT NULL DEFAULT 0,
            file_size INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,                -- CAPTURING | COMPLETED | ANALYZING | ANALYZED | FAILED
            error_message TEXT,
            created_at TEXT NOT NULL,            -- ISO-8601 UTC
            analyzed_at TEXT,
            summary TEXT                         -- CaptureSummary as JSON (protocol shares, counts), set after analysis
        )"""))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_captures_created_at ON captures (created_at DESC)"))


def _v4_settings(conn: Connection) -> None:
    """User settings (one JSON document, validated on every read and write) and the daily AI request counters."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            content TEXT NOT NULL,               -- AppSettings as JSON (never secrets, never paths)
            updated_at TEXT NOT NULL
        )"""))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ai_usage (
            day TEXT NOT NULL,                   -- UTC date, YYYY-MM-DD
            kind TEXT NOT NULL,                  -- 'request' | 'cached' | 'auto' | 'blocked'
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (day, kind)
        )"""))


MIGRATIONS: list[tuple[int, Callable[[Connection], None]]] = [
    (1, _v1_reports),
    (2, _v2_performance_history),
    (3, _v3_captures),
    (4, _v4_settings),
]


def current_version(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("PRAGMA user_version")).scalar() or 0)


def migrate(engine: Engine) -> int:
    """Apply pending migrations; returns the resulting schema version."""
    version = current_version(engine)
    for number, fn in sorted(MIGRATIONS, key=lambda m: m[0]):
        if number <= version:
            continue
        with engine.begin() as conn:
            fn(conn)
            conn.execute(text(f"PRAGMA user_version = {int(number)}"))  # int-cast: PRAGMA cannot be parameterised
        version = number
    return version
