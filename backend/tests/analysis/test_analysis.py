import json

import pcap_factory as pf
from app.analysis import analyze_pcap
from app.models.analysis import AnalysisOptions


# ----------------------------------------------------------------- basics / metadata
def test_small_valid_pcap_metadata_and_stats(sample_pcap):
    r = analyze_pcap(sample_pcap)
    m, ps = r.metadata, r.packet_statistics
    assert m.capture_format == "pcap" and len(m.sha256) == 64
    assert m.packets_read == ps.total_packets == 30
    assert m.duration_seconds == 8.6
    assert m.first_packet_time == pf.T0 - 1
    assert ps.min_packet_size == 42 and ps.max_packet_size >= ps.min_packet_size
    assert ps.mean_packet_size == round(ps.total_bytes / 30, 2)
    assert sum(b.packets for b in ps.size_distribution) == 30
    assert ps.avg_packets_per_second == round(30 / 8.6, 3)


def test_result_is_json_serialisable_and_has_expected_sections(sample_pcap):
    data = json.loads(analyze_pcap(sample_pcap).model_dump_json())
    for key in ("metadata", "protocol_statistics", "ip_statistics", "port_statistics",
                "tcp_statistics", "dns_statistics", "connections", "timeline"):
        assert key in data


def test_single_packet_capture_has_no_rate(make_pcap):
    r = analyze_pcap(make_pcap([pf.arp()]))
    assert r.metadata.duration_seconds == 0
    assert r.packet_statistics.avg_packets_per_second is None


# ----------------------------------------------------------------- protocols
def test_protocol_distribution(sample_pcap):
    dist = {p.protocol: p for p in analyze_pcap(sample_pcap).protocol_statistics.distribution}
    assert dist["TCP"].packets == 23
    assert dist["DNS"].packets == 4
    assert dist["UDP"].packets == dist["ICMP"].packets == dist["ARP"].packets == 1
    assert round(sum(p.percent_of_packets for p in dist.values())) == 100


def test_ipv6_is_recognised(make_pcap):
    r = analyze_pcap(make_pcap([pf.ipv6_tcp("fe80::1", "fe80::2", 1234, 22)]))
    assert r.ip_statistics.ip_version_packets == {"IPv6": 1}
    assert r.protocol_statistics.layer_packet_counts["IPv6"] == 1


# ----------------------------------------------------------------- TCP
def test_tcp_packets_and_flags(make_pcap):
    r = analyze_pcap(make_pcap(pf.tcp_session()))
    t = r.tcp_statistics
    assert t.total_packets == 7
    assert (t.syn_packets, t.syn_ack_packets, t.ack_only_packets, t.fin_packets, t.rst_packets) == (1, 1, 1, 2, 0)
    assert t.flag_counts["SYN"] == 2 and t.flag_counts["ACK"] == 6 and t.flag_counts["PSH"] == 2
    combos = {c.flags: c.packets for c in t.flag_combinations}
    assert combos == {"SYN": 1, "SYN,ACK": 1, "ACK": 1, "PSH,ACK": 2, "FIN,ACK": 2}
    assert t.syn_to_syn_ack_ratio == 1.0


def test_rst_and_null_flags(make_pcap):
    r = analyze_pcap(make_pcap([pf.tcp("1.1.1.1", "2.2.2.2", 1, 2, "R", ts=pf.T0),
                                pf.tcp("1.1.1.1", "2.2.2.2", 1, 3, "", ts=pf.T0 + 1)]))
    combos = {c.flags: c.packets for c in r.tcp_statistics.flag_combinations}
    assert combos == {"RST": 1, "NONE": 1}
    assert r.tcp_statistics.rst_packets == 1


def test_syn_sources_unanswered_ratio(sample_pcap):
    sources = {s.ip: s for s in analyze_pcap(sample_pcap).tcp_statistics.top_syn_sources}
    assert sources["10.0.0.99"].syn_sent == 7 and sources["10.0.0.99"].unanswered_ratio == 1.0
    assert sources["10.0.0.5"].unanswered_ratio == 0.0


def test_retransmission_detected(sample_pcap):
    r = analyze_pcap(sample_pcap).tcp_statistics.retransmissions
    assert r.retransmitted_segments == 1
    assert r.top_flows[0].dst_port == 8080 and r.top_flows[0].retransmissions == 1
    assert 0 < r.retransmission_rate < 1


def test_no_false_retransmissions_in_clean_session(make_pcap):
    assert analyze_pcap(make_pcap(pf.tcp_session())).tcp_statistics.retransmissions.retransmitted_segments == 0


def test_syn_retransmission_and_duplicate_acks(make_pcap):
    pk = [pf.tcp("1.1.1.1", "2.2.2.2", 5, 80, "S", seq=7, ts=pf.T0),
          pf.tcp("1.1.1.1", "2.2.2.2", 5, 80, "S", seq=7, ts=pf.T0 + 1),
          pf.tcp("1.1.1.1", "2.2.2.2", 5, 80, "A", seq=8, ack=50, ts=pf.T0 + 2),
          pf.tcp("1.1.1.1", "2.2.2.2", 5, 80, "A", seq=8, ack=50, ts=pf.T0 + 3)]
    r = analyze_pcap(make_pcap(pk)).tcp_statistics.retransmissions
    assert r.syn_retransmissions == 1 and r.duplicate_acks == 1


# ----------------------------------------------------------------- UDP / IPs / ports
def test_udp_packets(make_pcap):
    r = analyze_pcap(make_pcap([pf.udp("10.1.1.1", "10.1.1.2", 1111, 2222, b"hi", ts=pf.T0)]))
    assert r.protocol_statistics.distribution[0].protocol == "UDP"
    assert r.port_statistics.top_destination_ports[0].port == 2222
    assert r.port_statistics.top_destination_ports[0].protocol == "UDP"
    assert r.connections[0].protocol == "UDP" and r.connections[0].handshake_complete is None
    assert r.tcp_statistics.total_packets == 0


def test_multiple_ips_sources_destinations_and_talkers(sample_pcap):
    ip = analyze_pcap(sample_pcap).ip_statistics
    assert ip.unique_source_ips == 6 and ip.unique_destination_ips == 7
    assert ip.top_talkers[0].ip == "93.184.216.34" and not ip.top_talkers[0].is_private
    talkers = {t.ip: t for t in ip.top_talkers}
    assert talkers["10.0.0.99"].packets_received == 0 and talkers["10.0.0.99"].packets_sent == 7
    assert all(t.total_packets == t.packets_sent + t.packets_received for t in talkers.values())
    assert ip.top_sources[0].bytes >= ip.top_sources[-1].bytes


def test_conversations_are_bidirectional(make_pcap):
    r = analyze_pcap(make_pcap(pf.tcp_session(client="10.0.0.5", server="10.0.0.80")))
    assert r.ip_statistics.total_conversations == 1
    c = r.ip_statistics.conversations[0]
    assert c.packets == 7 and c.packets_a_to_b + c.packets_b_to_a == 7
    assert c.packets_a_to_b > 0 and c.packets_b_to_a > 0


def test_multiple_ports_and_fanout(sample_pcap):
    p = analyze_pcap(sample_pcap).port_statistics
    fan = {f.source_ip: f for f in p.destination_ports_per_source}
    assert p.destination_ports_per_source[0].source_ip == "10.0.0.99"
    assert fan["10.0.0.99"].unique_destination_ports == 7
    assert fan["10.0.0.99"].sample_ports == [21, 22, 23, 25, 80, 443, 3389]
    dst = {(x.protocol, x.port): x for x in p.top_destination_ports}
    assert dst[("TCP", 80)].service_hint == "http" and dst[("TCP", 443)].service_hint == "https"
    assert p.unique_destination_ports >= 8
    assert any(x.port == 50000 for x in p.top_source_ports)


# ----------------------------------------------------------------- DNS
def test_dns_queries_and_responses(sample_pcap):
    d = analyze_pcap(sample_pcap).dns_statistics
    assert (d.total_queries, d.total_responses) == (2, 2)
    assert d.unique_domains == 2
    assert d.query_types == {"A": 2}
    assert d.response_codes == {"NOERROR": 1, "NXDOMAIN": 1}
    assert d.nxdomain_responses == 1 and d.empty_responses == 1
    assert d.answered_queries == 2 and d.unanswered_queries == 0
    assert d.avg_response_ms is not None and 40 <= d.avg_response_ms <= 50
    assert {x.name for x in d.top_domains} == {"example.com", "no-such-host.invalid"}
    assert d.top_servers[0].name == "8.8.8.8"
    assert [q.qname for q in d.query_log] == ["example.com", "no-such-host.invalid"]


def test_dns_unanswered_and_orphan(make_pcap):
    pk = [pf.dns_query("10.0.0.5", "8.8.8.8", "Lonely.Example.", txid=9, ts=pf.T0),
          pf.dns_response("10.0.0.5", "8.8.8.8", "other.example", txid=77, ts=pf.T0 + 1)]
    d = analyze_pcap(make_pcap(pk)).dns_statistics
    assert d.unanswered_queries == 1 and d.responses_without_query == 1
    assert d.top_domains[0].name == "lonely.example"  # normalised: lower-case, no trailing dot


def test_dns_log_is_capped(make_pcap):
    pk = [pf.dns_query("10.0.0.5", "8.8.8.8", f"h{i}.example", txid=i, ts=pf.T0 + i) for i in range(5)]
    d = analyze_pcap(make_pcap(pk), AnalysisOptions(max_dns_log=2)).dns_statistics
    assert len(d.query_log) == 2 and d.query_log_truncated and d.total_queries == 5


def test_non_dns_udp_not_counted_as_dns(make_pcap):
    d = analyze_pcap(make_pcap([pf.udp("1.1.1.1", "2.2.2.2", 1000, 2000, b"zzzz")])).dns_statistics
    assert d.total_queries == 0 and d.total_responses == 0


# ----------------------------------------------------------------- connections
def test_connection_tracking(sample_pcap):
    r = analyze_pcap(sample_pcap)
    s = r.connection_summary
    assert s.by_protocol == {"TCP": 10, "UDP": 3, "ICMP": 1}
    assert s.tcp_handshakes_complete == 2 and s.total_connections == 14
    web = next(c for c in r.connections if c.server_port == 80)
    assert (web.client_ip, web.client_port) == ("10.0.0.5", 50000)
    assert web.packets == 7 and web.packets_client_to_server == 4 and web.packets_server_to_client == 3
    assert web.handshake_complete and web.syn_seen and web.fin_seen and not web.rst_seen
    assert web.duration_seconds == 0.07
    assert {"SYN", "ACK", "FIN", "PSH"} <= set(web.tcp_flags_seen)
    scan = next(c for c in r.connections if c.server_port == 21)
    assert scan.syn_seen and not scan.handshake_complete


def test_connection_limit(sample_pcap):
    r = analyze_pcap(sample_pcap, AnalysisOptions(max_connections=3))
    assert len(r.connections) == 3 and r.connection_summary.total_connections == 14
    assert r.connections == sorted(r.connections, key=lambda c: c.bytes, reverse=True)


# ----------------------------------------------------------------- timeline
def test_timeline_buckets_and_peak(sample_pcap):
    r = analyze_pcap(sample_pcap)
    assert sum(p.packets for p in r.timeline) == 30
    assert r.packet_statistics.peak_packets_per_second == max(p.packets for p in r.timeline) == 7
    assert r.timeline[0].offset_seconds == 0 and r.timeline[0].interval_seconds == 1


def test_timeline_downsamples_and_keeps_gaps(make_pcap):
    pk = [pf.arp(ts=pf.T0), pf.arp(ts=pf.T0 + 999)]
    r = analyze_pcap(make_pcap(pk), AnalysisOptions(timeline_max_points=100))
    assert len(r.timeline) <= 100 and r.timeline[0].interval_seconds == 10
    assert sum(p.packets for p in r.timeline) == 2
    assert any(p.packets == 0 for p in r.timeline)


# ----------------------------------------------------------------- CLI
def test_cli_summary_and_json(sample_pcap, capsys):
    from app.analysis.cli import main
    assert main([str(sample_pcap)]) == 0
    out = capsys.readouterr().out
    assert "Protocols" in out and "10.0.0.99" in out
    assert main([str(sample_pcap), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["metadata"]["packets_read"] == 30


def test_cli_errors(tmp_path, capsys):
    from app.analysis.cli import main
    assert main([str(tmp_path / "missing.pcap")]) == 2
    bad = tmp_path / "bad.pcap"
    bad.write_text("nope nope nope")
    assert main([str(bad)]) == 2
    assert "error:" in capsys.readouterr().err
