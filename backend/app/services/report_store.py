"""SQLite persistence for reports (parameterised SQL; schema from app/migrations.py)."""
from __future__ import annotations

import uuid
from datetime import timezone

from sqlalchemy import Engine, text

from app.models.report import ReportContent, ReportListItem, SavedReport


def _iso(dt) -> str:
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


class ReportStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def save(self, content: ReportContent) -> SavedReport:
        report_id = uuid.uuid4().hex
        with self._engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO reports (id, title, created_at, source_kind, capture_name, highest_severity,
                                     finding_count, total_packets, ai_status, schema_version, content)
                VALUES (:id, :title, :created_at, :source_kind, :capture_name, :sev, :fc, :tp, :ai, :sv, :content)"""),
                {"id": report_id, "title": content.title, "created_at": _iso(content.investigation_timestamp),
                 "source_kind": content.capture.source_kind, "capture_name": content.capture.name,
                 "sev": content.summary.highest_severity.value if content.summary.highest_severity else None,
                 "fc": content.summary.finding_count, "tp": content.summary.total_packets,
                 "ai": content.ai_investigation.status, "sv": content.schema_version,
                 "content": content.model_dump_json()})
        return SavedReport(id=report_id, content=content)

    def list(self, limit: int = 200, offset: int = 0) -> list[ReportListItem]:
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT id, title, created_at, source_kind, capture_name, highest_severity, finding_count,
                       total_packets, ai_status FROM reports ORDER BY created_at DESC, rowid DESC
                LIMIT :limit OFFSET :offset"""), {"limit": limit, "offset": offset}).mappings().all()
        return [ReportListItem(id=r["id"], title=r["title"], created_at=r["created_at"], source_kind=r["source_kind"],
                               capture_name=r["capture_name"], highest_severity=r["highest_severity"],
                               finding_count=r["finding_count"], total_packets=r["total_packets"],
                               ai_status=r["ai_status"]) for r in rows]

    def get(self, report_id: str) -> SavedReport | None:
        with self._engine.connect() as conn:
            row = conn.execute(text("SELECT id, content FROM reports WHERE id = :id"), {"id": report_id}).mappings().first()
        if row is None:
            return None
        return SavedReport(id=row["id"], content=ReportContent.model_validate_json(row["content"]))

    def delete(self, report_id: str) -> bool:
        with self._engine.begin() as conn:
            return conn.execute(text("DELETE FROM reports WHERE id = :id"), {"id": report_id}).rowcount > 0
