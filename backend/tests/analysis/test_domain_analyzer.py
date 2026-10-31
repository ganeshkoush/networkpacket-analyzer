"""Domain activity: DNS answers correlated with later connections."""
import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap

C, DNS_SRV = "192.168.1.10", "8.8.8.8"
GH, GOOG = "140.82.112.3", "142.250.80.46"


def domains(make_pcap, packets):
    stats = analyze_pcap(make_pcap(packets)).domain_statistics
    return {d.domain: d for d in stats.domains}, stats.summary


def lookup(name, ips, t, client=C, txid=1, **kw):
    return [pf.dns_query(client, DNS_SRV, name, txid=txid, ts=t),
            pf.dns_response(client, DNS_SRV, name, txid=txid, answers=ips, ts=t + 0.02, **kw)]


def https(dst, t, sport=50000, client=C, up=200, down=1200):
    return [pf.tcp(client, dst, sport, 443, "S", ts=t), pf.tcp(dst, client, 443, sport, "SA", ts=t + 0.01),
            pf.tcp(client, dst, sport, 443, "PA", payload=b"x" * up, ts=t + 0.02),
            pf.tcp(dst, client, 443, sport, "PA", payload=b"y" * down, ts=t + 0.03)]


def test_dns_answer_is_correlated_with_following_connection(make_pcap):
    doms, summary = domains(make_pcap, lookup("github.com", [GH], T0) + https(GH, T0 + 1))
    d = doms["github.com"]
    assert d.resolved_ips == [GH] and d.clients == [C]
    assert (d.dns_queries, d.dns_responses) == (1, 1)
    assert (d.connection_count, d.tcp_connection_count, d.udp_connection_count) == (1, 1, 0)
    assert d.total_bytes_sent > 200 and d.total_bytes_received > 1200
    assert d.server_ports == [443]
    assert d.first_seen == T0 and d.last_seen >= T0 + 1.03
    assert (d.min_ttl, d.max_ttl) == (60, 60)
    assert summary.attributed_connections == 1 and summary.unattributed_connections == 0


def test_one_domain_with_multiple_ips(make_pcap):
    other = "140.82.112.4"
    pk = lookup("github.com", [GH, other], T0) + https(GH, T0 + 1, 50001) + https(other, T0 + 2, 50002)
    doms, _ = domains(make_pcap, pk)
    d = doms["github.com"]
    assert set(d.resolved_ips) == {GH, other} and d.connection_count == 2


def test_multiple_domains_for_one_ip_use_latest_lookup_and_are_flagged(make_pcap):
    pk = lookup("a.example.com", [GOOG], T0) + lookup("b.example.com", [GOOG], T0 + 1, txid=2)
    pk += https(GOOG, T0 + 2)
    doms, summary = domains(make_pcap, pk)
    assert doms["b.example.com"].connection_count == 1 and doms["a.example.com"].connection_count == 0
    assert doms["b.example.com"].ambiguous_connection_count == 1
    assert GOOG in doms["a.example.com"].shared_ips and GOOG in doms["b.example.com"].shared_ips
    assert summary.ambiguous_connections == 1 and any("shared" in n for n in summary.notes)


def test_connection_before_lookup_is_not_attributed(make_pcap):
    doms, summary = domains(make_pcap, https(GH, T0) + lookup("github.com", [GH], T0 + 5))
    assert doms["github.com"].connection_count == 0
    assert summary.unattributed_connections == 1


def test_connection_without_dns_is_unattributed_with_note(make_pcap):
    doms, summary = domains(make_pcap, https("151.101.1.69", T0))
    assert doms == {} and summary.unattributed_connections == 1
    assert any("No DNS queries were captured" in n for n in summary.notes)


def test_query_without_response_is_listed_as_dns_only(make_pcap):
    doms, summary = domains(make_pcap, [pf.dns_query(C, DNS_SRV, "lonely.example", ts=T0)])
    d = doms["lonely.example"]
    assert (d.dns_queries, d.dns_responses, d.resolved_ips, d.connection_count) == (1, 0, [], 0)
    assert summary.dns_only_domains == 1


def test_nxdomain_creates_no_mapping(make_pcap):
    pk = [pf.dns_query(C, DNS_SRV, "nope.example", ts=T0), pf.dns_response(C, DNS_SRV, "nope.example", rcode=3, ts=T0 + 0.02)]
    doms, _ = domains(make_pcap, pk)
    assert doms["nope.example"].resolved_ips == [] and doms["nope.example"].dns_responses == 1


def test_mappings_are_per_client(make_pcap):
    other = "192.168.1.11"
    pk = lookup("github.com", [GH], T0) + https(GH, T0 + 1) + https(GH, T0 + 2, client=other)
    doms, summary = domains(make_pcap, pk)
    assert doms["github.com"].connection_count == 1 and summary.unattributed_connections == 1


def test_udp_connection_counted_separately(make_pcap):
    pk = lookup("quic.example", [GOOG], T0) + [pf.udp(C, GOOG, 51000, 443, b"q" * 100, ts=T0 + 1),
                                               pf.udp(GOOG, C, 443, 51000, b"r" * 300, ts=T0 + 1.1)]
    d = domains(make_pcap, pk)[0]["quic.example"]
    assert (d.udp_connection_count, d.tcp_connection_count) == (1, 0)
    assert d.total_bytes_received > d.total_bytes_sent


def test_ipv6_lookup_and_connection(make_pcap):
    c6, s6, ip6 = "2001:db8:1::10", "2001:4860:4860::8888", "2606:4700:4700::1111"
    pk = lookup("v6.example", [ip6], T0, client=c6)
    pk[0] = pf.dns_query(c6, s6, "v6.example", ts=T0)
    pk[1] = pf.dns_response(c6, s6, "v6.example", answers=[ip6], ts=T0 + 0.02)
    pk += [pf.ipv6_tcp(c6, ip6, 50000, 443, "S", ts=T0 + 1), pf.ipv6_tcp(ip6, c6, 443, 50000, "SA", ts=T0 + 1.01)]
    doms, _ = domains(make_pcap, pk)
    d = doms["v6.example"]
    assert d.resolved_ips == [ip6] and d.connection_count == 1 and d.clients == [c6]


def test_capture_starting_mid_flow_attributes_via_server_side_packet(make_pcap):
    pk = lookup("github.com", [GH], T0) + [pf.tcp(GH, C, 443, 50000, "PA", payload=b"z" * 500, ts=T0 + 1),
                                           pf.tcp(C, GH, 50000, 443, "A", ts=T0 + 1.01)]
    d = domains(make_pcap, pk)[0]["github.com"]
    assert d.connection_count == 1 and d.total_bytes_received > 500 and d.total_bytes_sent < 100


def test_dns_and_dot_flows_are_not_website_activity(make_pcap):
    pk = lookup("github.com", [GH], T0) + [pf.tcp(C, "1.1.1.1", 52000, 853, "S", ts=T0 + 1)]
    doms, summary = domains(make_pcap, pk)
    assert summary.unattributed_connections == 0 and summary.encrypted_dns_flows == 1
    assert any("DNS-over-TLS" in n for n in summary.notes)


def test_reverse_lookups_are_ignored(make_pcap):
    pk = [pf.dns_query(C, DNS_SRV, "1.1.168.192.in-addr.arpa", qtype="PTR", ts=T0)]
    assert domains(make_pcap, pk)[0] == {}


def test_malformed_packets_do_not_break_domain_analysis(tmp_path):
    from scapy.utils import wrpcap
    from scapy.layers.l2 import Ether
    good = lookup("github.com", [GH], T0) + https(GH, T0 + 1)
    bad = pf.stamp(Ether(**pf.ETH) / pf.IP(src=C, dst=GH) / pf.UDP(sport=40000, dport=53) / b"\xff\x01garbage", T0 + 0.5)
    path = tmp_path / "m.pcap"
    wrpcap(str(path), sorted(good + [bad], key=lambda p: p.time))
    result = analyze_pcap(path)
    assert not any("domains" in w for w in result.metadata.warnings)
    assert result.domain_statistics.domains[0].domain == "github.com"


def test_ranking_and_cap(make_pcap):
    pk = lookup("small.example", ["1.2.3.4"], T0) + https("1.2.3.4", T0 + 1, up=10, down=10)
    pk += lookup("big.example", ["5.6.7.8"], T0, txid=2) + https("5.6.7.8", T0 + 1, 50001, up=5000, down=9000)
    from app.models.analysis import AnalysisOptions
    result = analyze_pcap(make_pcap(pk), AnalysisOptions(max_domains=1))
    assert [d.domain for d in result.domain_statistics.domains] == ["big.example"]
    assert result.domain_statistics.summary.total_domains == 2 and result.domain_statistics.summary.reported_domains == 1


def test_attack_demo_fixture_still_analyzes(sample_pcap):
    assert analyze_pcap(sample_pcap).domain_statistics.summary.total_domains >= 0
