"""Analysis aggregates added for the detection layer."""
import pcap_factory as pf
from app.analysis import analyze_pcap


def test_syn_pairs_sources_and_targets(make_pcap):
    r = analyze_pcap(make_pcap(pf.scan_packets("10.0.0.99", "10.0.0.9", range(1, 21), open_ports={20})))
    t = r.tcp_statistics
    (pair,) = t.syn_pairs
    assert (pair.src_ip, pair.dst_ip, pair.syn_packets, pair.unique_destination_ports) == ("10.0.0.99", "10.0.0.9", 20, 20)
    assert pair.syn_ack_received == 1 and pair.rst_received == 19 and pair.sample_ports[:3] == [1, 2, 3]
    (src,) = t.top_syn_sources
    assert src.unique_destination_hosts == 1 and src.unique_destination_ports == 20 and src.rst_received == 19
    assert src.first_syn_time < src.last_syn_time
    assert len(t.syn_targets) == 20 and all(x.syn_packets == 1 for x in t.syn_targets)
    open_t = next(x for x in t.syn_targets if x.dst_port == 20)
    assert open_t.syn_ack_sent == 1


def test_syn_target_peak_rate_and_completion_counts(make_pcap):
    r = analyze_pcap(make_pcap(pf.syn_flood_packets("10.0.0.9", 80, 300, per_second=100)))
    (t,) = r.tcp_statistics.syn_targets
    assert t.syn_packets == 300 and t.peak_syn_per_second in (100, 101, 99) and t.unique_sources == 300
    assert t.ack_packets_in == 0
    r = analyze_pcap(make_pcap(pf.tcp_session(server="10.0.0.9")))
    (t,) = r.tcp_statistics.syn_targets
    assert t.ack_packets_in >= 3  # final handshake ACK + data + FIN-ACK from the client


def test_flag_anomaly_aggregates(make_pcap):
    pk = [pf.tcp("1.1.1.1", "2.2.2.2", 5, 80 + i % 3, "", seq=i, ts=pf.T0 + i) for i in range(4)]
    pk.append(pf.tcp("1.1.1.1", "2.2.2.2", 5, 80, "SF", ts=pf.T0 + 9))
    (a, b) = sorted(analyze_pcap(make_pcap(pk)).tcp_statistics.flag_anomalies, key=lambda x: -x.packets)
    assert (a.anomaly, a.packets, a.flags) == ("NULL", 4, "NONE") and (b.anomaly, b.packets) == ("SYN+FIN", 1)


def test_arp_statistics(make_pcap):
    pk = [pf.arp_pkt(1, "bb:bb:bb:bb:bb:05", "10.0.0.5", "10.0.0.1", ts=pf.T0),
          pf.arp_pkt(2, "aa:aa:aa:aa:aa:01", "10.0.0.1", "10.0.0.5", target_mac="bb:bb:bb:bb:bb:05", ts=pf.T0 + 1),
          pf.arp_pkt(2, "aa:aa:aa:aa:aa:01", "10.0.0.1", "10.0.0.5", target_mac="bb:bb:bb:bb:bb:05", ts=pf.T0 + 2),  # 2nd reply, one request
          pf.arp_pkt(2, "cc:cc:cc:cc:cc:09", "10.0.0.1", "10.0.0.5", target_mac="bb:bb:bb:bb:bb:05", eth_src="dd:dd:dd:dd:dd:dd", ts=pf.T0 + 3)]
    a = analyze_pcap(make_pcap(pk)).arp_statistics
    assert (a.total_packets, a.requests, a.replies, a.unsolicited_replies) == (4, 1, 3, 2)
    (b,) = a.multi_mac_ips
    assert b.ip == "10.0.0.1" and len(b.macs) == 2 and b.binding_changes == 1
    assert b.unsolicited_replies == 2 and b.eth_mismatch_packets == 1


def test_arp_ignored_in_non_arp_capture(sample_pcap):
    a = analyze_pcap(sample_pcap).arp_statistics
    assert a.total_packets == 1 and a.multi_mac_ips == []  # sample has one request from 10.0.0.1


def test_dns_client_and_group_profiles(make_pcap):
    pk = [pf.dns_query("10.0.0.5", "8.8.8.8", f"{'x' * 30}{i}.t.example.com", txid=i, sport=2000 + i, qtype="TXT", ts=pf.T0 + i)
          for i in range(5)]
    pk += [pf.dns_response("10.0.0.5", "8.8.8.8", "x.t.example.com", txid=i, dport=2000 + i, rcode=3, ts=pf.T0 + i + 0.1)
           for i in range(3)]
    d = analyze_pcap(make_pcap(pk)).dns_statistics
    (c,) = d.clients
    assert (c.queries, c.responses, c.nxdomain, c.unique_domains) == (5, 3, 3, 5)
    (g,) = d.domain_groups
    assert g.base_domain == "example.com" and g.unique_names == 5 and g.txt_null_queries == 5
    assert g.mean_subdomain_label_length >= 30 and g.top_client == "10.0.0.5"


def test_base_domain_helper():
    from app.analysis.dns_analyzer import base_domain
    assert base_domain("a.b.example.com") == "example.com"
    assert base_domain("www.example.co.uk") == "example.co.uk"
    assert base_domain("example.com") == "example.com" and base_domain("localhost") == "localhost"
