import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from pcap_factory import T0
from app.api import analyses
from app.config import settings
from app.main import app
from app.models.process import ProcessConnectionMapping, ProcessSnapshot
from app.platform.base import ProcessConnectionSource
from app.services import process_mapper as pm
from app.services.analysis_jobs import AnalysisJobManager
from correlation import scenarios as sc

C, GH, YT = "192.168.1.10", "140.82.112.3", "142.250.80.46"


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(app) as c:
        yield c


def analyze(client, tmp_path, packets):
    data = pf.write_pcap(tmp_path / "m.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "m.pcap"}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            return job_id
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def browsing_capture():
    """github.com (TCP, with RTT samples) and youtube.com (UDP/QUIC) from one local host, with DNS lookups for both."""
    pk = []
    for name, ip, t in (("github.com", GH, 0), ("youtube.com", YT, 1)):
        pk += [pf.dns_query(C, "8.8.8.8", name, txid=int(t) + 1, sport=30000 + int(t), ts=T0 + t), pf.dns_response(C, "8.8.8.8", name, txid=int(t) + 1, dport=30000 + int(t), answers=[ip], ts=T0 + t + 0.02)]
    for i in range(3):
        sp, t = 50000 + i, T0 + 2 + i
        pk += [pf.tcp(C, GH, sp, 443, "S", seq=100, ts=t), pf.tcp(GH, C, 443, sp, "SA", seq=500, ack=101, ts=t + 0.02), pf.tcp(C, GH, sp, 443, "A", seq=101, ack=501, ts=t + 0.03)]
        for k in range(4):
            pk += [pf.tcp(GH, C, 443, sp, "PA", seq=501 + k * 100, ack=101, payload=b"d" * 100, ts=t + 1 + k), pf.tcp(C, GH, sp, 443, "A", seq=101, ack=601 + k * 100, ts=t + 1 + k + 0.04)]
    pk += [pf.udp(C, YT, 55000, 443, b"q" * 1200, ts=T0 + 20), pf.udp(YT, C, 443, 55000, b"r" * 1200, ts=T0 + 20.05)]
    return pk


def get(client, job, **params):
    r = client.get(f"/api/analyses/{job}/network-map", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_network_map_of_a_real_capture(client, tmp_path):
    job = analyze(client, tmp_path, browsing_capture())
    m = get(client, job)
    by_kind = {k: sorted(n["label"] for n in m["nodes"] if n["kind"] == k) for k in ("local", "domain", "group", "ip", "port")}
    # every address here has a single port, so the port is part of the address label (no separate port nodes)
    assert by_kind == {"local": [C], "domain": ["github.com", "youtube.com"], "group": ["No DNS name"],
                       "ip": [f"{GH}:443", f"{YT}:443", "8.8.8.8:53"], "port": []}
    gh = next(n for n in m["nodes"] if n["id"] == "domain:github.com")
    assert gh["connections"] == 3 and gh["latency_kind"] == "rtt" and gh["latency_ms"] == pytest.approx(40, abs=1) and gh["state"] in ("healthy", "degraded")
    e = next(e for e in m["edges"] if e["id"] == f"domain:github.com>ip:{GH}")
    assert e["protocol"] == "TCP" and e["ports"] == [443] and e["connections"] == 3 and e["bytes"] > 0
    assert m["total_connections"] == 6 and m["shown_connections"] == 6 and len(m["connections"]) == 6 and m["local"] == C
    ids = {e["id"] for e in m["edges"]}
    assert {"local>group:no-dns", "group:no-dns>ip:8.8.8.8"} <= ids                                    # no DNS name: grouped in the domain row, not a line skipping a row
    assert any("inferred from DNS" in n for n in m["notes"])
    ids = {n["id"] for n in m["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in m["edges"])


def test_filters_are_applied_by_the_backend(client, tmp_path):
    job = analyze(client, tmp_path, browsing_capture())
    assert [n["label"] for n in get(client, job, protocol="UDP")["nodes"] if n["kind"] == "domain"] == ["youtube.com"]
    assert [n["label"] for n in get(client, job, search="github")["nodes"] if n["kind"] == "domain"] == ["github.com"]
    assert get(client, job, search="nothing-matches")["nodes"] == []
    late = get(client, job, start=T0 + 19)
    assert [n["label"] for n in late["nodes"] if n["kind"] == "domain"] == ["youtube.com"] and late["applied_start"] == T0 + 19
    assert {c["id"] for c in get(client, job, health="suspicious")["connections"]} == set()
    small = get(client, job, max_nodes=10)
    assert len(small["nodes"]) <= 10 or small["hidden"]["destinations"] > 0


def test_invalid_parameters_are_rejected(client, tmp_path):
    job = analyze(client, tmp_path, browsing_capture())
    for params, code in (({"start": 10, "end": 5}, "invalid_range"), ({"local": "not-an-ip"}, "invalid_ip")):
        r = client.get(f"/api/analyses/{job}/network-map", params=params)
        assert r.status_code == 422 and r.json()["detail"]["code"] == code
    for params in ({"protocol": "ICMP"}, {"health": "bogus"}, {"max_nodes": 5}, {"max_nodes": 500}, {"search": "x" * 300}):
        assert client.get(f"/api/analyses/{job}/network-map", params=params).status_code == 422
    assert client.get("/api/analyses/nope/network-map").status_code == 404


def test_findings_appear_on_the_map(client, tmp_path):
    job = analyze(client, tmp_path, sc.port_scan_scenario())
    findings = client.get(f"/api/analyses/{job}/result").json()["findings"]
    scan = next(f for f in findings if f["type"] == "PORT_SCAN")
    m = get(client, job)
    assert scan["id"] in {f["id"] for f in m["findings"]}
    scanner = next(n for n in m["nodes"] if n["id"] == "ip:45.33.32.156")
    assert scanner["state"] == "suspicious" and scan["id"] in scanner["finding_ids"]
    assert any(n["state"] == "suspicious" for n in m["nodes"] if n["kind"] == "port")
    assert get(client, job, health="suspicious")["shown_connections"] > 0


def test_a_large_capture_stays_within_the_node_budget(client, tmp_path):
    job = analyze(client, tmp_path, sc.syn_flood_scenario(total=60.0, flood_start=20.0))
    m = get(client, job, max_nodes=40)
    assert len(m["nodes"]) <= 40 and m["total_connections"] >= 100 and m["hidden"]["destinations"] > 0
    assert any(n["kind"] == "other" for n in m["nodes"]) and any("folded into one node" in n for n in m["notes"])


# ------------------------------------------------------------------ applications (OS information, mocked)
class FakeSource(ProcessConnectionSource):
    platform, mechanism, permission_note = "macOS", "lsof + ps (read-only)", "No administrator rights needed."

    def __init__(self, mappings):
        self.mappings = mappings

    def snapshot(self, now):
        return ProcessSnapshot(timestamp=now, platform="macOS", mappings=[m.model_copy(update={"timestamp": now}) for m in self.mappings], processes=2)


def test_applications_are_included_only_on_request_and_only_from_os_snapshots(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, browsing_capture())
    assert not any(n["kind"] == "application" for n in get(client, job)["nodes"])           # off by default

    unavailable = get(client, job, include_applications="true")
    assert not any(n["kind"] == "application" for n in unavailable["nodes"])
    assert unavailable["applications_status"].startswith("Process information unavailable")

    maps = [ProcessConnectionMapping(process_name="Code Helper", pid=1, application="Visual Studio Code", local_ip=C, local_port=50000 + i, remote_ip=GH, remote_port=443,
                                     protocol="TCP", timestamp=0, confidence="HIGH") for i in range(3)]
    mapper = pm.ProcessMapper(FakeSource(maps), clock=lambda: T0 + 4)
    monkeypatch.setattr(pm, "_mapper", mapper)
    mapper.snapshot()
    m = get(client, job, include_applications="true")
    apps = [n for n in m["nodes"] if n["kind"] == "application"]
    assert [(n["label"], n["tier"], n["connections"]) for n in apps] == [("Visual Studio Code", 1, 3)] and m["applications_status"] is None
    assert any(e["id"] == "app:Visual Studio Code>domain:github.com" for e in m["edges"])
    assert [c["application"] for c in m["connections"] if c["domain"] == "github.com"] == ["Visual Studio Code"] * 3
    assert all(c["application"] is None for c in m["connections"] if c["domain"] == "youtube.com")      # never invented for unmatched connections


def test_application_names_never_leak_into_the_default_map(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, browsing_capture())
    maps = [ProcessConnectionMapping(process_name="Code Helper", pid=1, application="Visual Studio Code", local_ip=C, local_port=50000, remote_ip=GH, remote_port=443,
                                     protocol="TCP", timestamp=0, confidence="HIGH")]
    mapper = pm.ProcessMapper(FakeSource(maps), clock=lambda: T0 + 4)
    monkeypatch.setattr(pm, "_mapper", mapper)
    mapper.snapshot()
    assert b"Visual Studio Code" not in client.get(f"/api/analyses/{job}/network-map").content
