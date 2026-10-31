import json
import time

import pcap_factory as pf
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import app.api.reports as reports_api
from app.ai.provider import InvalidApiKeyError
from app.ai.schemas import InvestigationReport, InvestigationResult
from app.analysis import analyze_pcap
from app.api import analyses
from app.config import settings
from app.database import make_engine
from app.detection import Severity, detect_threats
from app.main import create_app
from app.migrations import MIGRATIONS, current_version, migrate

LATEST = max(n for n, _ in MIGRATIONS)
from app.models.report import ReportAi
from app.services.analysis_jobs import AnalysisJobManager, Job
from app.services.report_builder import ai_from_report, build_report
from app.services.report_export import export_filename, render, to_html, to_markdown
from app.services.report_store import ReportStore

SCANNER, TARGET = "10.0.0.99", "10.0.0.9"


@pytest.fixture
def analysis_and_findings(tmp_path):
    path = pf.write_pcap(tmp_path / "scan.pcap", sorted(pf.scan_packets(SCANNER, TARGET, range(1, 121)), key=lambda p: p.time))
    result = analyze_pcap(path)
    return result, detect_threats(result)


def ai_result(**kw):
    base = dict(investigation_summary="Possible port scanning.", finding_type="PORT_SCAN", severity=Severity.HIGH,
                confidence=0.85, evidence=["120 SYN packets were observed."], interpretation="Consistent with TCP SYN scanning.",
                possible_explanations=["Security scanning"], recommended_next_steps=["Confirm the scan was authorized.", "Review host logs."],
                additional_evidence_needed=["Host logs"], limitations=["A PCAP cannot establish intent."])
    base.update(kw)
    return InvestigationResult(**base)


def ai_ok():
    return ai_from_report(InvestigationReport(result=ai_result(), model="gemini-x", provider="gemini", notes=["Confidence capped"]))


# ---------------------------------------------------------------- migrations
def test_migration_creates_schema_and_is_idempotent(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'm.db'}")
    assert current_version(eng) == 0
    assert migrate(eng) == LATEST and migrate(eng) == LATEST
    with eng.connect() as c:
        cols = {r[1] for r in c.execute(text("PRAGMA table_info(reports)"))}
        assert {"id", "title", "created_at", "highest_severity", "content", "schema_version"} <= cols
        assert c.execute(text("PRAGMA index_list(reports)")).fetchall()


# ---------------------------------------------------------------- builder
def test_report_contains_all_required_sections(analysis_and_findings):
    analysis, findings = analysis_and_findings
    c = build_report(analysis, findings, source_kind="pcap", ai=ai_ok(), title="  My case ")
    assert c.title == "My case"
    assert c.capture.name == "scan.pcap" and c.capture.sha256 and c.capture.packets == analysis.metadata.packets_read
    assert c.summary.total_packets > 0 and c.summary.finding_count == len(findings) >= 1
    assert c.summary.highest_severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
    assert "possible" in c.summary.headline and "not confirmed incidents" in c.summary.headline
    assert c.protocols and c.top_talkers and c.top_ports
    f = c.findings[0]
    assert f.evidence and f.investigation_steps and f.caveats and f.recommendation and 0 < f.confidence <= 0.95
    assert c.ai_investigation.status == "completed" and c.ai_investigation.result.investigation_summary
    assert c.investigation_timestamp.tzinfo is not None
    # detector recommendation first, then AI steps; no duplicates
    acts = [a.action for a in c.recommended_actions]
    assert "Confirm the scan was authorized." in acts and len(acts) == len(set(a.lower() for a in acts))
    assert {a.source for a in c.recommended_actions} == {"detector", "ai"}
    assert "A PCAP cannot establish intent." in c.limitations


def test_no_findings_report_is_not_overconfident():
    from detection_helpers import blank_result
    c = build_report(blank_result(), [], source_kind="live", interface="en0")
    assert c.summary.finding_count == 0 and c.summary.highest_severity is None
    assert "not proof" in c.summary.headline and c.capture.interface == "en0"
    assert c.ai_investigation.status == "not_run"


def test_report_has_no_chain_of_thought_fields(analysis_and_findings):
    analysis, findings = analysis_and_findings
    dump = build_report(analysis, findings, source_kind="pcap", ai=ai_ok()).model_dump_json()
    for forbidden in ("chain_of_thought", "thinking", "scratchpad", "reasoning_trace", "thought"):
        assert forbidden not in dump.lower()


def test_untrusted_strings_are_cleaned(analysis_and_findings):
    analysis, findings = analysis_and_findings
    findings[0].evidence["note"] = "evil\x00‮" + "A" * 1000
    c = build_report(analysis, findings, source_kind="pcap", notes="n\x07ote")
    note = c.findings[0].evidence["note"]
    assert "\x00" not in note and "‮" not in note and len(note) < 400 and c.analyst_notes == "note"


# ---------------------------------------------------------------- store / persistence
def test_store_crud_and_ordering(tmp_path, analysis_and_findings):
    eng = make_engine(f"sqlite:///{tmp_path / 's.db'}")
    migrate(eng)
    store = ReportStore(eng)
    analysis, findings = analysis_and_findings
    a = store.save(build_report(analysis, findings, source_kind="pcap", title="first"))
    time.sleep(0.01)
    b = store.save(build_report(analysis, [], source_kind="live", title="second"))
    items = store.list()
    assert [i.title for i in items] == ["second", "first"]
    assert items[1].finding_count == len(findings) and items[1].highest_severity is not None and items[0].highest_severity is None
    assert store.get(a.id).content.findings[0].evidence == a.content.findings[0].evidence
    assert store.delete(a.id) is True and store.delete(a.id) is False and store.get(a.id) is None
    assert [i.id for i in store.list()] == [b.id]


def test_reports_persist_across_engine_restart(tmp_path, analysis_and_findings):
    url = f"sqlite:///{tmp_path / 'persist.db'}"
    eng1 = make_engine(url)
    migrate(eng1)
    analysis, findings = analysis_and_findings
    saved = ReportStore(eng1).save(build_report(analysis, findings, source_kind="pcap", ai=ai_ok(), title="durable"))
    eng1.dispose()  # simulate the app exiting
    eng2 = make_engine(url)
    assert migrate(eng2) == LATEST  # re-running migrations must not wipe data
    again = ReportStore(eng2).get(saved.id)
    assert again is not None and again.content == saved.content
    assert again.content.ai_investigation.result.confidence == 0.85


def test_store_is_safe_against_sql_injection_ids(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'i.db'}")
    migrate(eng)
    assert ReportStore(eng).get("x' OR '1'='1") is None


# ---------------------------------------------------------------- export
def hostile(analysis, findings):
    findings[0].evidence["qname"] = "<script>alert(1)</script>.evil.example"
    findings[0].title = "Scan <img src=x onerror=alert(1)> | `tick`"
    return build_report(analysis, findings, source_kind="pcap", title="<b>T</b>", notes="<script>x</script>", ai=ai_ok())


def test_html_export_is_escaped_complete_and_inert(analysis_and_findings):
    from app.models.report import SavedReport
    c = hostile(*analysis_and_findings)
    page = to_html(c)
    assert "<script>" not in page and "<img src=x" not in page and "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page
    for heading in ("Capture information", "Analysis summary", "Protocol statistics", "Top talkers", "Findings",
                    "AI investigation summary", "Recommended actions", "Limitations", "Investigation timestamp"):
        assert heading in page
    assert "Confirm the scan was authorized." in page and "UTC" in page


def test_markdown_export_escapes_and_json_roundtrips(analysis_and_findings):
    from app.models.report import SavedReport
    c = hostile(*analysis_and_findings)
    md = to_markdown(c)
    import re
    prose = re.sub(r"```.*?```", "", md, flags=re.S)  # evidence lives in fenced code blocks
    assert not re.search(r"(?<!\\)<", prose)  # every '<' outside code fences is backslash-escaped
    assert "\\<b\\>T\\</b\\>" in md.splitlines()[0]
    assert "## 6. AI investigation summary" in md and "```json" in md
    saved = SavedReport(id="a" * 32, content=c)
    data = json.loads(render(saved, "json"))
    assert data["id"] == "a" * 32 and data["findings"][0]["severity"]


def test_export_filename_is_safe(analysis_and_findings):
    from app.models.report import SavedReport
    c = build_report(*analysis_and_findings, source_kind="pcap", title="../../etc/passwd \"x\"; rm -rf /")
    name = export_filename(SavedReport(id="b" * 32, content=c), "html")
    assert "/" not in name and '"' not in name and " " not in name and name.endswith(".html") and name.startswith("packetmind-")


# ---------------------------------------------------------------- API
class FakeInv:
    def __init__(self, error=None):
        self.error, self.calls = error, []

    def investigate_analysis(self, analysis, findings, question=None, finding_id=None):
        self.calls.append(findings)
        if self.error:
            raise self.error
        return InvestigationReport(result=ai_result(), model="m", provider="fake")


@pytest.fixture
def api(tmp_path, monkeypatch, analysis_and_findings):
    eng = make_engine(f"sqlite:///{tmp_path / 'api.db'}")
    migrate(eng)
    monkeypatch.setattr(reports_api, "_store", ReportStore(eng))
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "exports")
    inv = FakeInv()
    monkeypatch.setattr(reports_api, "investigator_factory", lambda: inv)
    mgr = AnalysisJobManager()
    analysis, findings = analysis_and_findings
    mgr._jobs["done"] = Job(id="done", filename="scan.pcap", size_bytes=1, status="completed", result=analysis, findings=findings)
    mgr._jobs["busy"] = Job(id="busy", filename="b.pcap", size_bytes=1, status="running")
    monkeypatch.setattr(analyses, "_manager", mgr)
    return TestClient(create_app()), inv, tmp_path


def test_api_create_list_get(api):
    c, inv, _ = api
    r = c.post("/api/reports", json={"analysis_id": "done", "title": "Case 1", "notes": "seen on VLAN 5"})
    assert r.status_code == 201
    body = r.json()
    assert body["content"]["title"] == "Case 1" and body["content"]["analyst_notes"] == "seen on VLAN 5"
    assert body["content"]["ai_investigation"]["status"] == "not_run" and inv.calls == []  # AI is opt-in
    assert [i["title"] for i in c.get("/api/reports").json()] == ["Case 1"]
    assert c.get(f"/api/reports/{body['id']}").json()["content"]["findings"]


def test_api_create_with_ai_and_ai_failure_still_saves(api, monkeypatch):
    c, inv, _ = api
    ok = c.post("/api/reports", json={"analysis_id": "done", "run_ai": True}).json()
    assert ok["content"]["ai_investigation"]["status"] == "completed" and len(inv.calls) == 1
    assert ok["content"]["ai_investigation"]["result"]["investigation_summary"]
    bad_inv = FakeInv(error=InvalidApiKeyError())
    monkeypatch.setattr(reports_api, "investigator_factory", lambda: bad_inv)
    failed = c.post("/api/reports", json={"analysis_id": "done", "run_ai": True})
    assert failed.status_code == 201
    ai = failed.json()["content"]["ai_investigation"]
    assert ai["status"] == "failed" and "rejected" in ai["message"] and ai["result"] is None
    assert len(c.get("/api/reports").json()) == 2


def test_api_create_errors(api):
    c, *_ = api
    assert c.post("/api/reports", json={"analysis_id": "nope"}).status_code == 404
    assert c.post("/api/reports", json={"analysis_id": "busy"}).status_code == 409
    assert c.post("/api/reports", json={}).status_code == 404
    assert c.post("/api/reports", json={"analysis_id": "done", "title": "x" * 500}).status_code == 422


def test_api_report_from_live_capture(api, monkeypatch, analysis_and_findings):
    import app.api.live as live_api
    c, *_ = api
    analysis, findings = analysis_and_findings

    class Live:
        def __init__(self, snap): self.snap = snap
        def snapshot(self): return self.snap

    monkeypatch.setattr(live_api, "_manager", Live((None, [], None, {})))
    assert c.post("/api/reports", json={"source": "live"}).json()["detail"]["code"] == "no_live_data"
    monkeypatch.setattr(live_api, "_manager", Live((analysis, findings, "en0", {findings[0].id: ai_result()})))
    body = c.post("/api/reports", json={"source": "live"}).json()["content"]
    assert body["capture"]["source_kind"] == "live" and body["capture"]["interface"] == "en0"
    assert body["findings"][0]["ai_assessment"]["finding_type"] == "PORT_SCAN"


def test_api_get_and_download_exports(api):
    c, *_ = api
    rid = c.post("/api/reports", json={"analysis_id": "done", "run_ai": True}).json()["id"]
    for fmt, mime in (("html", "text/html"), ("md", "text/markdown"), ("json", "application/json")):
        r = c.get(f"/api/reports/{rid}/export", params={"format": fmt})
        assert r.status_code == 200 and r.headers["content-type"].startswith(mime)
        assert f".{fmt}" in r.headers["content-disposition"] and r.content
    assert c.get(f"/api/reports/{rid}/export", params={"format": "exe"}).status_code == 400
    assert c.get("/api/reports/%27%20OR%201%3D1/export").status_code == 404
    assert c.get("/api/reports/" + "0" * 32).status_code == 404


def test_api_export_writes_into_reports_folder_only(api):
    c, _, tmp = api
    rid = c.post("/api/reports", json={"analysis_id": "done", "title": "../../evil"}).json()["id"]
    r = c.post(f"/api/reports/{rid}/export", params={"format": "md"}).json()
    from pathlib import Path
    p = Path(r["path"])
    assert p.parent == tmp / "exports" and p.read_text().startswith("# ") and p.name == r["filename"]
    assert list((tmp / "exports").iterdir()) == [p]


def test_api_delete_requires_confirmation(api):
    c, *_ = api
    rid = c.post("/api/reports", json={"analysis_id": "done"}).json()["id"]
    r = c.delete(f"/api/reports/{rid}")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "confirmation_required"
    assert c.get(f"/api/reports/{rid}").status_code == 200  # still there
    assert c.delete(f"/api/reports/{rid}", params={"confirm": "true"}).status_code == 204
    assert c.get(f"/api/reports/{rid}").status_code == 404
    assert c.delete(f"/api/reports/{rid}", params={"confirm": "true"}).status_code == 404
    assert c.get("/api/reports").json() == []


def test_report_includes_escaped_top_domains(tmp_path):
    c, s, ip = "192.168.1.10", "8.8.8.8", "140.82.112.3"
    name = "<script>x</script>.example"
    pk = [pf.dns_query(c, s, name, ts=pf.T0), pf.dns_response(c, s, name, answers=[ip], ts=pf.T0 + 0.01),
          pf.tcp(c, ip, 50000, 443, "PA", payload=b"x" * 50, ts=pf.T0 + 1)]
    analysis = analyze_pcap(pf.write_pcap(tmp_path / "d.pcap", pk))
    report = build_report(analysis, [], source_kind="pcap")
    content = getattr(report, "content", report)
    assert [d.connections for d in content.domains] == [1]
    page, md = to_html(content), to_markdown(content)
    assert "<script>x</script>" not in page and "not exact URLs" in page and "not exact URLs" in md
