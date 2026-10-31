"""Domain / Web Activity dashboard: rows, details, time series, health, paging and incomplete data."""
import pytest

import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis import web_activity as wa
from app.models.analysis import AnalysisOptions, DomainPerformance

C = "192.168.1.10"
GH, GOOG, QUIC = "140.82.112.3", "142.250.80.46", "151.101.1.69"


def lookup(name, ip, t, ms=20, txid=1, client=C):
    return [pf.dns_query(client, "8.8.8.8", name, txid=txid, ts=t),
            pf.dns_response(client, "8.8.8.8", name, txid=txid, answers=[ip], ts=t + ms / 1000)]


def web_conn(server, sport, t, rtts_ms=(40, 42, 44, 46, 48), dport=443, retransmit=False, reset=False):
    """Handshake (20 + 10 ms) then 100-byte server segments, each acknowledged by a pure ACK after rtts_ms[i]."""
    pk = [pf.tcp(C, server, sport, dport, "S", seq=100, ts=t), pf.tcp(server, C, dport, sport, "SA", seq=500, ack=101, ts=t + 0.020),
          pf.tcp(C, server, sport, dport, "A", seq=101, ack=501, ts=t + 0.030)]
    for i, rtt in enumerate(rtts_ms):
        s = t + 1 + i
        pk += [pf.tcp(server, C, dport, sport, "PA", seq=501 + i * 100, ack=101, payload=b"d" * 100, ts=s),
               pf.tcp(C, server, sport, dport, "A", seq=101, ack=601 + i * 100, ts=s + rtt / 1000)]
    if retransmit:
        pk += [pf.tcp(server, C, dport, sport, "PA", seq=501, ack=101, payload=b"d" * 100, ts=t + 20)]
    if reset:
        pk += [pf.tcp(server, C, dport, sport, "R", seq=999, ts=t + 21)]
    return pk


def analyze(make_pcap, packets, **opts):
    return analyze_pcap(make_pcap(packets), AnalysisOptions(**opts) if opts else None)


def perf_domain(name, **kw) -> DomainPerformance:
    return DomainPerformance(domain=name, connections=kw.pop("connections", 4), **kw)


# ------------------------------------------------------------------ rows
def test_table_row_combines_existing_measurements(make_pcap):
    result = analyze(make_pcap, lookup("github.com", GH, T0, ms=19) + web_conn(GH, 50001, T0 + 1))
    page = wa.query(result)
    assert page.total_matching == 1
    r = page.domains[0]
    assert r.domain == "github.com" and r.connections == 1
    assert r.dns_latency_ms == pytest.approx(19, abs=0.01) and r.tcp_handshake_ms == pytest.approx(30, abs=0.01)
    assert r.avg_rtt_ms == pytest.approx(44, abs=0.01) and r.p95_rtt_ms == pytest.approx(48, abs=0.01)
    activity = result.domain_statistics.domains[0]
    assert r.total_bytes == activity.total_bytes_sent + activity.total_bytes_received == r.bytes_sent + r.bytes_received
    assert r.health == "good" and r.health_reasons == []


def test_values_match_the_underlying_analysis_not_a_recomputation(make_pcap):
    result = analyze(make_pcap, lookup("github.com", GH, T0) + web_conn(GH, 50001, T0 + 1))
    perf = result.performance_statistics.domains[0]
    row = wa.build_rows(result)[0]
    assert (row.tcp_handshake_ms, row.avg_rtt_ms, row.p95_rtt_ms, row.dns_latency_ms) == \
           (perf.tcp_handshake_ms, perf.avg_rtt_ms, perf.p95_rtt_ms, perf.dns_latency_ms)


# ------------------------------------------------------------------ detail
def test_domain_detail_sections(make_pcap):
    pk = lookup("github.com", GH, T0, ms=19) + web_conn(GH, 50001, T0 + 1, retransmit=True) + web_conn(GH, 50002, T0 + 40, reset=True)
    result = analyze(make_pcap, pk)
    d = wa.build_detail(result, "GitHub.com.")  # case and trailing dot are normalised
    assert d is not None and d.domain == "github.com"
    # overview
    assert d.overview.connection_count == d.connections_total == 2
    assert d.overview.first_seen == pytest.approx(T0) and d.overview.last_seen >= T0 + 40
    # performance
    p = d.performance
    assert p is not None and p.dns_latency_ms == pytest.approx(19, abs=0.01) and p.tcp_handshake_ms == pytest.approx(30, abs=0.01)
    assert p.avg_rtt_ms == pytest.approx(44, abs=0.01) and p.max_rtt_ms == pytest.approx(48, abs=0.01)
    assert p.retransmissions == 1 and p.resets == 1 and p.connections_reset == 1
    # traffic
    sent = sum(1 for x in pk if x.haslayer("TCP") and x["IP"].src == C and x["IP"].dst == GH)
    recv = sum(1 for x in pk if x.haslayer("TCP") and x["IP"].src == GH)
    assert (d.overview.packets_sent, d.overview.packets_received) == (sent, recv)
    assert d.overview.total_bytes_sent > 0 and d.overview.total_bytes_received > 500
    # connections joined with their measurements
    assert len(d.connections) == 2
    first = next(c for c in d.connections if c.client_port == 50001)
    assert first.handshake_ms == pytest.approx(30, abs=0.01) and first.avg_rtt_ms == pytest.approx(44, abs=0.01)
    assert first.retransmissions == 1 and first.measurement_confidence == "LOW"  # 1 of 6 segments retransmitted: lowered and first.application_response_ms is None
    assert next(c for c in d.connections if c.client_port == 50002).resets == 1


def test_unknown_domain_has_no_detail(make_pcap):
    assert wa.build_detail(analyze(make_pcap, lookup("github.com", GH, T0)), "nope.example") is None


# ------------------------------------------------------------------ time series
def test_series_are_built_from_the_connections(make_pcap):
    pk = lookup("github.com", GH, T0) + web_conn(GH, 50001, T0 + 1) + web_conn(GH, 50002, T0 + 60, rtts_ms=(80, 90, 100, 110, 120))
    d = wa.build_detail(analyze(make_pcap, pk), "github.com")
    s = d.series
    assert [round(p.t) for p in s.handshake] == [round(T0 + 1), round(T0 + 60)] and all(p.handshake_ms == pytest.approx(30, abs=0.01) for p in s.handshake)
    assert [p.avg_rtt_ms for p in s.rtt] == pytest.approx([44, 100], abs=0.01)
    assert s.rtt[0].t < s.rtt[1].t and all(p.response_ms is None for p in s.rtt)


def test_traffic_series_is_exact_and_ordered(make_pcap):
    pk = lookup("github.com", GH, T0) + web_conn(GH, 50001, T0 + 1)
    result = analyze(make_pcap, pk)
    d = wa.build_detail(result, "github.com")
    assert d.series.bin_seconds == 1
    assert [p.t for p in d.series.traffic] == sorted(p.t for p in d.series.traffic)
    assert sum(p.bytes_sent for p in d.series.traffic) == d.overview.total_bytes_sent
    assert sum(p.bytes_received for p in d.series.traffic) == d.overview.total_bytes_received


def test_traffic_bins_merge_to_stay_bounded_without_losing_bytes(make_pcap):
    pk = lookup("long.example.org", GH, T0)
    for i in range(40):  # 40 separate seconds of traffic -> far more bins than the cap of 6
        pk += [pf.udp(C, GH, 40000, 4443, b"x" * 100, ts=T0 + 1 + i * 5)]
    result = analyze(make_pcap, pk, timeline_max_points=6)
    d = wa.build_detail(result, "long.example.org")
    assert 0 < len(d.series.traffic) <= 6 and d.series.bin_seconds >= 8 and d.series.bin_seconds in (8, 16, 32, 64)
    assert sum(p.bytes_sent for p in d.series.traffic) == d.overview.total_bytes_sent


# ------------------------------------------------------------------ not serialised into the analysis bundle
def test_series_stay_out_of_the_serialised_result(make_pcap):
    result = analyze(make_pcap, lookup("github.com", GH, T0) + web_conn(GH, 50001, T0 + 1))
    assert result.performance_statistics.series  # held in memory for the dashboard
    assert "series" not in result.model_dump()["performance_statistics"]
    assert '"series"' not in result.model_dump_json()


# ------------------------------------------------------------------ incomplete data
def test_udp_only_domain_has_traffic_but_no_tcp_measurements(make_pcap):
    pk = lookup("quic.example.org", QUIC, T0) + [pf.udp(C, QUIC, 41000, 443, b"q" * 200, ts=T0 + 1), pf.udp(QUIC, C, 443, 41000, b"r" * 900, ts=T0 + 1.05)]
    result = analyze(make_pcap, pk)
    row = wa.query(result).domains[0]
    assert row.domain == "quic.example.org" and row.connections == 1 and row.total_bytes > 1000
    assert row.tcp_handshake_ms is None and row.avg_rtt_ms is None and row.p95_rtt_ms is None
    assert row.dns_latency_ms is None  # DNS latency is only reported for domains with a TCP connection
    assert row.health == "unknown" and row.health_reasons == []
    d = wa.build_detail(result, "quic.example.org")
    assert d.performance is None and d.series.rtt == [] and d.series.handshake == [] and d.series.traffic


def test_connection_without_measurable_rtt_has_unknown_or_partial_health(make_pcap):
    pk = lookup("syn.example.org", GH, T0) + [pf.tcp(C, GH, 50001, 443, "S", seq=1, ts=T0 + 1)]
    result = analyze(make_pcap, pk)
    row = wa.query(result).domains[0]
    assert row.tcp_handshake_ms is None and row.avg_rtt_ms is None
    assert row.dns_latency_ms == pytest.approx(20, abs=0.01) and row.health == "good"  # only DNS was measurable


def test_dns_only_domains_are_hidden_unless_requested(make_pcap):
    result = analyze(make_pcap, lookup("lonely.example.org", GH, T0))
    assert wa.query(result).domains == [] and wa.query(result).summary.total_domains == 1
    page = wa.query(result, include_dns_only=True)
    assert [r.domain for r in page.domains] == ["lonely.example.org"] and page.domains[0].connections == 0 and page.domains[0].health == "unknown"


def test_empty_capture(tmp_path):
    result = analyze_pcap(pf.write_pcap(tmp_path / "empty.pcap", []))
    page = wa.query(result)
    assert page.total_matching == 0 and page.domains == [] and page.summary.total_domains == 0
    assert wa.build_detail(result, "anything.example") is None


# ------------------------------------------------------------------ query: search, sort, filter, paging
def many_domains(make_pcap):
    pk = []
    plan = [("fast.example.com", GH, 50001, (20, 22, 24, 26, 28), 10), ("slow.example.com", GOOG, 50002, (400, 420, 440, 460, 480), 20),
            ("mid.example.com", QUIC, 50003, (120, 130, 140, 150, 160), 30)]
    for i, (name, ip, sport, rtts, dns) in enumerate(plan):
        pk += lookup(name, ip, T0 + i * 100, ms=dns, txid=i + 1) + web_conn(ip, sport, T0 + i * 100 + 1, rtts_ms=rtts)
    return analyze(make_pcap, pk)


def test_sort_orders(make_pcap):
    r = many_domains(make_pcap)
    names = lambda **kw: [d.domain for d in wa.query(r, **kw).domains]  # noqa: E731
    assert names(sort="rtt") == ["slow.example.com", "mid.example.com", "fast.example.com"]
    assert names(sort="p95")[0] == "slow.example.com"
    assert names(sort="dns")[0] == "mid.example.com" and names(sort="name") == ["fast.example.com", "mid.example.com", "slow.example.com"]
    assert names(sort="recent")[0] == "mid.example.com"
    assert names(sort="health")[0] == "slow.example.com"
    assert names(sort="handshake")  # all equal: ties break alphabetically
    assert names(sort="handshake") == ["fast.example.com", "mid.example.com", "slow.example.com"]


def test_search_health_filter_and_paging(make_pcap):
    r = many_domains(make_pcap)
    assert [d.domain for d in wa.query(r, search=" SLOW").domains] == ["slow.example.com"]
    assert wa.query(r, search="nothing").total_matching == 0
    health = {d.domain: d.health for d in wa.query(r).domains}
    assert health == {"fast.example.com": "good", "mid.example.com": "fair", "slow.example.com": "poor"}
    assert [d.domain for d in wa.query(r, health="poor").domains] == ["slow.example.com"]
    assert wa.query(r).summary.health_counts == {"good": 1, "fair": 1, "poor": 1}
    p1 = wa.query(r, sort="name", limit=2, offset=0)
    p2 = wa.query(r, sort="name", limit=2, offset=2)
    assert p1.total_matching == p2.total_matching == 3 and len(p1.domains) == 2 and [d.domain for d in p2.domains] == ["slow.example.com"]
    assert wa.query(r, offset=10).domains == []


# ------------------------------------------------------------------ health rules
def test_health_good_fair_poor_and_reasons():
    assert wa.assess_health(perf_domain("a", tcp_handshake_ms=40, avg_rtt_ms=50, p95_rtt_ms=90), 20) == ("good", [])
    health, reasons = wa.assess_health(perf_domain("a", tcp_handshake_ms=150, avg_rtt_ms=50), 20)
    assert health == "fair" and reasons == ["TCP handshake (average) 150 ms is elevated (threshold 100 ms)"]
    health, reasons = wa.assess_health(perf_domain("a", tcp_handshake_ms=40, avg_rtt_ms=400, p95_rtt_ms=700), 600)
    assert health == "poor" and len(reasons) == 3 and "Average RTT 400 ms is high (threshold 300 ms)" in reasons


def test_health_is_unknown_without_measurements_rather_than_good():
    assert wa.assess_health(None, None) == ("unknown", [])
    assert wa.assess_health(perf_domain("a"), None) == ("unknown", [])


def test_loss_indicators_need_enough_data():
    few = perf_domain("a", tcp_handshake_ms=30, tcp_packets=10, retransmissions=5, connections=2, connections_reset=2)
    assert wa.assess_health(few, None) == ("good", [])  # too little data to call a rate or a share
    many = perf_domain("a", tcp_handshake_ms=30, tcp_packets=200, retransmissions=20, connections=10, connections_reset=3)
    health, reasons = wa.assess_health(many, None)
    assert health == "poor" and any("Retransmission indicators 10.0%" in r for r in reasons) and any("Connections with resets 30.0%" in r for r in reasons)
