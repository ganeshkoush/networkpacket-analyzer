"""TCP three-way handshake timing: only packets matched by seq/ack numbers are timed."""
import pytest

import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis.connection_tracker import resolve_handshake

C, S = "192.168.1.10", "142.250.80.46"
C6, S6 = "2001:db8::10", "2606:4700:4700::1111"
SEQ_C, SEQ_S = 1000, 5000


def syn(c=C, s=S, sport=52341, dport=443, t=T0, seq=SEQ_C, v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return f(c, s, sport, dport, "S", seq=seq, ts=t)


def synack(c=C, s=S, sport=52341, dport=443, t=T0 + 0.045, seq=SEQ_S, ack=SEQ_C + 1, v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return f(s, c, dport, sport, "SA", seq=seq, ack=ack, ts=t)


def ack(c=C, s=S, sport=52341, dport=443, t=T0 + 0.052, seq=SEQ_C + 1, ackn=SEQ_S + 1, flags="A", payload=b"", v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return f(c, s, sport, dport, flags, seq=seq, ack=ackn, payload=payload, ts=t)


def handshake(**kw):
    return [syn(**kw), synack(**kw), ack(**kw)]


def analyze(make_pcap, packets, sort=True):
    return analyze_pcap(make_pcap(packets, sort=sort))


def only(make_pcap, packets, sort=True):
    result = analyze(make_pcap, packets, sort)
    assert len(result.connections) == 1
    return result.connections[0]


# ------------------------------------------------------------------ successful
def test_successful_handshake_matches_the_documented_example(make_pcap):
    t = 1_700_000_010.0
    c = only(make_pcap, [syn(t=t), synack(t=t + 0.045), ack(t=t + 0.052)])
    assert c.handshake_status == "completed" and c.handshake_incomplete_reason is None
    assert (c.tcp_syn_timestamp, c.tcp_syn_ack_timestamp, c.tcp_ack_timestamp) == pytest.approx((t, t + 0.045, t + 0.052))
    assert c.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01)
    assert c.tcp_ack_latency_ms == pytest.approx(7, abs=0.01)
    assert c.tcp_handshake_time_ms == pytest.approx(52, abs=0.01)
    assert c.tcp_syn_retransmissions == 0 and c.tcp_syn_ack_retransmissions == 0


def test_total_is_the_sum_of_both_legs(make_pcap):
    c = only(make_pcap, handshake())
    assert c.tcp_handshake_time_ms == pytest.approx(c.tcp_syn_ack_latency_ms + c.tcp_ack_latency_ms, abs=0.01)


def test_final_ack_may_carry_data(make_pcap):
    c = only(make_pcap, [syn(), synack(), ack(flags="PA", payload=b"GET /")])
    assert c.handshake_status == "completed" and c.tcp_ack_latency_ms == pytest.approx(7, abs=0.01)


def test_sequence_number_wraparound(make_pcap):
    last = 0xFFFFFFFF
    pk = [syn(seq=last), synack(seq=0xFFFFFFFE, ack=0), ack(seq=0, ackn=0xFFFFFFFF)]
    c = only(make_pcap, pk)
    assert c.handshake_status == "completed" and c.tcp_handshake_time_ms == pytest.approx(52, abs=0.01)


def test_later_data_is_not_mistaken_for_the_handshake_ack(make_pcap):
    data = ack(t=T0 + 0.5, seq=SEQ_C + 1, ackn=SEQ_S + 1, flags="PA", payload=b"x" * 10)
    c = only(make_pcap, [syn(), synack(), data])  # no pure final ACK, but this data packet acks the SYN-ACK
    assert c.handshake_status == "completed" and c.tcp_ack_timestamp == pytest.approx(T0 + 0.5)
    # ...whereas an ACK with unrelated numbers is not used at all
    c = only(make_pcap, [syn(), synack(), ack(t=T0 + 0.5, seq=SEQ_C + 77, ackn=SEQ_S + 1)])
    assert c.handshake_status == "incomplete" and c.tcp_ack_latency_ms is None and c.tcp_handshake_time_ms is None


# ------------------------------------------------------------------ incomplete
def test_syn_without_synack_is_incomplete(make_pcap):
    c = only(make_pcap, [syn()])
    assert (c.handshake_status, c.handshake_incomplete_reason) == ("incomplete", "no_synack")
    assert c.tcp_syn_timestamp == pytest.approx(T0)
    assert c.tcp_syn_ack_timestamp is None and c.tcp_ack_timestamp is None
    assert c.tcp_syn_ack_latency_ms is None and c.tcp_ack_latency_ms is None and c.tcp_handshake_time_ms is None


def test_synack_without_final_ack_keeps_only_the_proven_latency(make_pcap):
    c = only(make_pcap, [syn(), synack()])
    assert (c.handshake_status, c.handshake_incomplete_reason) == ("incomplete", "no_final_ack")
    assert c.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01)
    assert c.tcp_ack_latency_ms is None and c.tcp_handshake_time_ms is None and c.tcp_ack_timestamp is None


def test_synack_that_does_not_acknowledge_the_syn_is_not_paired(make_pcap):
    c = only(make_pcap, [syn(), synack(ack=SEQ_C + 999), ack()])
    assert (c.handshake_status, c.handshake_incomplete_reason) == ("incomplete", "no_synack")
    assert c.tcp_syn_ack_latency_ms is None and c.tcp_handshake_time_ms is None


def test_capture_started_mid_connection(make_pcap):
    c = only(make_pcap, [ack(t=T0 + 1), pf.tcp(S, C, 443, 52341, "PA", seq=SEQ_S + 1, ack=SEQ_C + 1, payload=b"hi", ts=T0 + 1.1)])
    assert (c.handshake_status, c.handshake_incomplete_reason) == ("incomplete", "no_syn_seen")
    assert c.tcp_syn_timestamp is None and c.tcp_handshake_time_ms is None


def test_reset_during_handshake(make_pcap):
    refused = only(make_pcap, [syn(), pf.tcp(S, C, 443, 52341, "RA", seq=0, ack=SEQ_C + 1, ts=T0 + 0.03)])
    assert (refused.handshake_status, refused.handshake_incomplete_reason) == ("incomplete", "reset")
    assert refused.tcp_handshake_time_ms is None and refused.tcp_syn_ack_latency_ms is None

    midway = only(make_pcap, [syn(), synack(), pf.tcp(C, S, 52341, 443, "R", seq=SEQ_C + 1, ts=T0 + 0.05)])
    assert (midway.handshake_status, midway.handshake_incomplete_reason) == ("incomplete", "reset")
    assert midway.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01) and midway.tcp_handshake_time_ms is None


def test_reset_after_a_completed_handshake_does_not_undo_it(make_pcap):
    c = only(make_pcap, handshake() + [pf.tcp(S, C, 443, 52341, "R", seq=SEQ_S + 1, ts=T0 + 5)])
    assert c.handshake_status == "completed" and c.rst_seen and c.tcp_handshake_time_ms == pytest.approx(52, abs=0.01)


def test_simultaneous_open_is_not_timed(make_pcap):
    pk = [syn(), pf.tcp(S, C, 443, 52341, "S", seq=SEQ_S, ts=T0 + 0.001), synack(), ack()]
    c = only(make_pcap, pk)
    assert (c.handshake_status, c.handshake_incomplete_reason) == ("incomplete", "simultaneous_open")
    assert c.tcp_syn_ack_latency_ms is None and c.tcp_handshake_time_ms is None


def test_ack_that_precedes_the_synack_is_not_used(make_pcap):
    c = only(make_pcap, [syn(), synack(), ack(t=T0 + 0.01)])  # claims to answer a SYN-ACK that came later
    assert c.handshake_status == "incomplete" and c.tcp_ack_latency_ms is None


# ------------------------------------------------------------------ retransmissions
def test_retransmitted_syn(make_pcap):
    pk = [syn(t=T0), syn(t=T0 + 1.0), synack(t=T0 + 1.05), ack(t=T0 + 1.06)]
    c = only(make_pcap, pk)
    assert c.handshake_status == "completed" and c.tcp_syn_retransmissions == 1
    assert c.tcp_syn_timestamp == pytest.approx(T0)  # first SYN: time includes the retransmission delay
    assert c.tcp_syn_ack_latency_ms == pytest.approx(1050, abs=0.01) and c.tcp_handshake_time_ms == pytest.approx(1060, abs=0.01)


def test_retransmitted_synack(make_pcap):
    pk = [syn(), synack(t=T0 + 0.05), synack(t=T0 + 1.05), ack(t=T0 + 1.06)]
    c = only(make_pcap, pk)
    assert c.handshake_status == "completed" and c.tcp_syn_ack_retransmissions == 1 and c.tcp_syn_retransmissions == 0
    assert c.tcp_syn_ack_latency_ms == pytest.approx(50, abs=0.01)
    assert c.tcp_ack_latency_ms == pytest.approx(1010, abs=0.01)


def test_retransmitted_syn_without_any_reply_stays_incomplete(make_pcap):
    c = only(make_pcap, [syn(t=T0), syn(t=T0 + 1), syn(t=T0 + 3)])
    assert c.handshake_status == "incomplete" and c.tcp_syn_retransmissions == 2
    assert c.tcp_syn_timestamp == pytest.approx(T0) and c.tcp_handshake_time_ms is None


# ------------------------------------------------------------------ ordering / multiple connections
def test_out_of_order_packets_in_the_file(make_pcap):
    shuffled = [ack(), synack(), syn()]  # file order is the reverse of time order
    assert [p.time for p in shuffled] == sorted([p.time for p in shuffled], reverse=True)
    c = only(make_pcap, shuffled, sort=False)
    assert c.handshake_status == "completed"
    assert c.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01) and c.tcp_handshake_time_ms == pytest.approx(52, abs=0.01)
    assert c.handshake_complete and c.state == "ESTABLISHED"  # consistent with the timed handshake


def test_multiple_concurrent_connections_are_timed_independently(make_pcap):
    pk = []
    for sport, (d1, d2) in zip((50001, 50002, 50003), ((0.040, 0.005), (0.100, 0.020), (0.010, 0.001))):
        pk += [syn(sport=sport), synack(sport=sport, t=T0 + d1), ack(sport=sport, t=T0 + d1 + d2)]
    pk.append(syn(sport=50004, t=T0 + 0.001))  # a fourth one that never completes
    result = analyze(make_pcap, pk)
    by_port = {c.client_port: c for c in result.connections}
    assert by_port[50001].tcp_handshake_time_ms == pytest.approx(45, abs=0.01)
    assert by_port[50002].tcp_handshake_time_ms == pytest.approx(120, abs=0.01)
    assert by_port[50003].tcp_handshake_time_ms == pytest.approx(11, abs=0.01)
    assert by_port[50004].handshake_status == "incomplete" and by_port[50004].tcp_handshake_time_ms is None
    assert result.connection_summary.handshakes_timed == 3 and result.connection_summary.handshakes_incomplete == 1
    assert result.connection_summary.avg_handshake_ms == pytest.approx((45 + 120 + 11) / 3, abs=0.01)


def test_two_servers_with_the_same_client_port_do_not_mix(make_pcap):
    other = "151.101.1.69"
    pk = handshake() + [syn(s=other), synack(s=other, t=T0 + 0.2), ack(s=other, t=T0 + 0.21)]
    by_server = {c.server_ip: c for c in analyze(make_pcap, pk).connections}
    assert by_server[S].tcp_handshake_time_ms == pytest.approx(52, abs=0.01)
    assert by_server[other].tcp_handshake_time_ms == pytest.approx(210, abs=0.01)


# ------------------------------------------------------------------ IPv4 / IPv6 / non-TCP
def test_ipv6_handshake(make_pcap):
    c = only(make_pcap, handshake(c=C6, s=S6, v6=True))
    assert c.client_ip == C6 and c.handshake_status == "completed"
    assert c.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01) and c.tcp_handshake_time_ms == pytest.approx(52, abs=0.01)


def test_ipv6_incomplete_handshake(make_pcap):
    c = only(make_pcap, [syn(c=C6, s=S6, v6=True), synack(c=C6, s=S6, v6=True)])
    assert c.handshake_incomplete_reason == "no_final_ack" and c.tcp_syn_ack_latency_ms == pytest.approx(45, abs=0.01)


def test_udp_has_no_handshake_fields(make_pcap):
    c = only(make_pcap, [pf.udp(C, "8.8.4.4", 41000, 5000, b"q", ts=T0), pf.udp("8.8.4.4", C, 5000, 41000, b"r", ts=T0 + 0.1)])
    assert c.handshake_status is None and c.tcp_handshake_time_ms is None and c.tcp_syn_timestamp is None


# ------------------------------------------------------------------ aggregation by domain
def lookup(name, ip, t):
    return [pf.dns_query(C, "8.8.8.8", name, ts=t), pf.dns_response(C, "8.8.8.8", name, answers=[ip], ts=t + 0.02)]


def test_average_handshake_time_by_domain(make_pcap):
    g1, g2, gh, yt, bare = "142.250.80.46", "142.250.80.47", "140.82.112.3", "172.217.1.1", "198.18.5.5"
    pk = lookup("google.com", g1, T0) + lookup("google.com", g2, T0 + 0.1) + lookup("github.com", gh, T0 + 0.2) + lookup("youtube.com", yt, T0 + 0.3)
    legs = [(g1, 50001, 0.040, 0.002), (g2, 50002, 0.044, 0.002), (gh, 50003, 0.050, 0.001),
            (yt, 50004, 0.070, 0.003), (yt, 50005, 0.0, 0.0)]  # last one is incomplete: excluded from averages
    for i, (srv, sport, d1, d2) in enumerate(legs):
        t = T0 + 1 + i
        pk.append(syn(s=srv, sport=sport, t=t))
        if sport != 50005:
            pk += [synack(s=srv, sport=sport, t=t + d1), ack(s=srv, sport=sport, t=t + d1 + d2)]
    pk += handshake(s=bare, sport=50006, t=T0 + 9)  # completed, but no DNS: counts overall, not per domain
    summary = analyze(make_pcap, pk).connection_summary
    by = {d.domain: d for d in summary.handshake_by_domain}
    assert set(by) == {"google.com", "github.com", "youtube.com"}
    assert by["google.com"].avg_handshake_ms == pytest.approx(44, abs=0.01) and by["google.com"].samples == 2
    assert (by["google.com"].min_handshake_ms, by["google.com"].max_handshake_ms) == pytest.approx((42, 46), abs=0.01)
    assert by["github.com"].avg_handshake_ms == pytest.approx(51, abs=0.01)
    assert by["youtube.com"].avg_handshake_ms == pytest.approx(73, abs=0.01) and by["youtube.com"].samples == 1
    assert [d.domain for d in summary.handshake_by_domain] == ["youtube.com", "github.com", "google.com"]  # slowest first
    assert summary.handshakes_timed == 5 and summary.handshakes_incomplete == 1


def test_no_dns_means_no_domain_aggregates_but_still_timed(make_pcap):
    summary = analyze(make_pcap, handshake()).connection_summary
    assert summary.handshake_by_domain == [] and summary.handshakes_timed == 1 and summary.avg_handshake_ms == pytest.approx(52, abs=0.01)


# ------------------------------------------------------------------ pure resolver
def test_resolver_ignores_a_synack_older_than_its_syn():
    h = resolve_handshake([(10.0, 1, 0)], [(9.0, 7, 2, 1)], [(10.5, 2, 8, 0)], rst=False)
    assert h.status == "incomplete" and h.syn_ack_latency_ms is None


def test_resolver_uses_the_first_attempt_that_completes():
    syns = [(1.0, 100, 0), (5.0, 200, 0)]  # port reuse: second attempt is the one that gets answered
    synacks = [(5.05, 900, 201, 1)]
    acks = [(5.06, 201, 901, 0)]
    h = resolve_handshake(syns, synacks, acks, rst=False)
    assert h.status == "completed" and h.syn_timestamp == 5.0 and h.handshake_time_ms == pytest.approx(60, abs=0.01)


def test_resolver_with_no_packets():
    assert resolve_handshake([], [], [], rst=False).incomplete_reason == "no_syn_seen"
