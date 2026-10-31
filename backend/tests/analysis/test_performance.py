"""Latency analysis: DNS lookup time, TCP RTT, cleartext HTTP response time, HTTPS (what is and is not visible)."""
import pytest

import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis.pcap_parser import classify_tcp_payload

C, S, S2 = "192.168.1.10", "142.250.80.46", "140.82.112.3"
C6, S6 = "2001:db8::10", "2606:4700:4700::1111"
SPORT, DPORT = 52341, 443
REQ = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def tls_record(kind: int, body_len: int = 40) -> bytes:
    body = b"\x03\x03" + b"\x00" * (body_len - 2)
    return b"\x16\x03\x01" + (len(body) + 4).to_bytes(2, "big") + bytes([kind]) + len(body).to_bytes(3, "big") + body


CLIENT_HELLO, SERVER_HELLO = tls_record(1), tls_record(2)


def analyze(make_pcap, packets, sort=True):
    return analyze_pcap(make_pcap(packets, sort=sort))


def perf(make_pcap, packets, sort=True):
    """(rows keyed by (protocol, server port), full result)."""
    result = analyze(make_pcap, packets, sort)
    ids = {c.id: c for c in result.connections}
    rows = {(m.protocol, ids[m.connection_id].server_port): m for m in result.performance_statistics.metrics}
    return rows, result


def tcp_row(make_pcap, packets, sort=True, port=DPORT):
    rows, _ = perf(make_pcap, packets, sort)
    return rows[("TCP", port)]


def handshake(c=C, s=S, sport=SPORT, dport=DPORT, t=T0, v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return [f(c, s, sport, dport, "S", seq=1000, ts=t), f(s, c, dport, sport, "SA", seq=5000, ack=1001, ts=t + 0.020),
            f(c, s, sport, dport, "A", seq=1001, ack=5001, ts=t + 0.030)]


def server_data(seq, n, t, c=C, s=S, sport=SPORT, dport=DPORT, v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return f(s, c, dport, sport, "PA", seq=seq, ack=1001, payload=b"d" * n, ts=t)


def client_ack(ack, t, c=C, s=S, sport=SPORT, dport=DPORT, v6=False):
    f = pf.ipv6_tcp if v6 else pf.tcp
    return f(c, s, sport, dport, "A", seq=1001, ack=ack, ts=t)


def rtt_flow(delays_ms, base=T0 + 1, seq0=5001, **kw):
    """Server sends 100-byte segments; the client's pure ACK for segment i arrives delays_ms[i] later."""
    pk = []
    for i, d in enumerate(delays_ms):
        t = base + i * 0.5
        pk += [server_data(seq0 + i * 100, 100, t, **kw), client_ack(seq0 + 100 + i * 100, t + d / 1000, **kw)]
    return pk


# ------------------------------------------------------------------ DNS timing
def lookup(name, ip, t, ms=21, txid=1, sport=40000, client=C):
    return [pf.dns_query(client, "8.8.8.8", name, txid=txid, sport=sport, ts=t),
            pf.dns_response(client, "8.8.8.8", name, txid=txid, dport=sport, answers=[ip], ts=t + ms / 1000)]


def test_dns_response_time(make_pcap):
    rows, result = perf(make_pcap, lookup("github.com", S, 1_700_000_010.000, ms=21))
    dns = rows[("UDP", 53)]
    assert dns.application_protocol == "DNS" and dns.dns_latency_ms == pytest.approx(21, abs=0.01) and dns.dns_lookups == 1
    assert dns.measurement_confidence == "HIGH" and dns.tcp_handshake_ms is None and dns.rtt_samples == 0


def test_dns_latency_is_attached_to_the_connection_it_led_to(make_pcap):
    pk = lookup("github.com", S, T0, ms=19) + handshake(t=T0 + 1) + rtt_flow([40] * 3, base=T0 + 2)
    row = tcp_row(make_pcap, pk)
    assert row.domain == "github.com" and row.dns_latency_ms == pytest.approx(19, abs=0.01)
    assert row.tcp_handshake_ms == pytest.approx(30, abs=0.01)  # a different measurement, in its own field


def test_dns_latency_is_the_median_of_clean_lookups(make_pcap):
    pk = lookup("github.com", S, T0, ms=10, txid=1) + lookup("github.com", S, T0 + 1, ms=30, txid=2) + lookup("github.com", S, T0 + 2, ms=20, txid=3)
    row = perf(make_pcap, pk)[0][("UDP", 53)]
    assert row.dns_latency_ms == pytest.approx(20, abs=0.01) and row.dns_lookups == 3


def test_retransmitted_dns_query_is_not_timed(make_pcap):
    pk = [pf.dns_query(C, "8.8.8.8", "slow.example.org", txid=7, ts=T0), pf.dns_query(C, "8.8.8.8", "slow.example.org", txid=7, ts=T0 + 1),
          pf.dns_response(C, "8.8.8.8", "slow.example.org", txid=7, answers=[S], ts=T0 + 1.02)]
    rows, result = perf(make_pcap, pk)
    assert rows[("UDP", 53)].dns_latency_ms is None and rows[("UDP", 53)].measurement_confidence == "UNAVAILABLE"
    assert result.dns_statistics.avg_response_ms is not None  # the existing DNS statistics are unchanged


def test_unanswered_query_and_response_before_query(make_pcap):
    assert perf(make_pcap, [pf.dns_query(C, "8.8.8.8", "a.example.org", ts=T0)])[0][("UDP", 53)].dns_latency_ms is None
    odd = [pf.dns_response(C, "8.8.8.8", "a.example.org", answers=[S], ts=T0), pf.dns_query(C, "8.8.8.8", "a.example.org", ts=T0 + 1)]
    _, result = perf(make_pcap, odd, sort=False)  # response stamped before its query
    assert [m.dns_latency_ms for m in result.performance_statistics.metrics] == [None]


# ------------------------------------------------------------------ TCP RTT
def test_rtt_statistics_from_pure_acks(make_pcap):
    delays = [40 + 2 * i for i in range(10)]  # 40..58 ms
    row = tcp_row(make_pcap, handshake() + rtt_flow(delays))
    assert row.rtt_samples == 10 and row.measurement_confidence == "HIGH"
    assert row.min_rtt_ms == pytest.approx(40, abs=0.01) and row.max_rtt_ms == pytest.approx(58, abs=0.01)
    assert row.avg_rtt_ms == pytest.approx(49, abs=0.01) and row.median_rtt_ms == pytest.approx(49, abs=0.01)
    assert row.p95_rtt_ms == pytest.approx(58, abs=0.01)
    assert row.rtt_basis == "server_to_client"


def test_rtt_is_not_the_handshake_time(make_pcap):
    row = tcp_row(make_pcap, handshake() + rtt_flow([70] * 4))
    assert row.tcp_handshake_ms == pytest.approx(30, abs=0.01) and row.avg_rtt_ms == pytest.approx(70, abs=0.01)


def test_few_samples_lower_the_confidence_and_hide_p95(make_pcap):
    one = tcp_row(make_pcap, handshake() + rtt_flow([44]))
    assert (one.rtt_samples, one.measurement_confidence, one.p95_rtt_ms) == (1, "LOW", None)
    assert one.avg_rtt_ms == one.median_rtt_ms == one.min_rtt_ms == one.max_rtt_ms == pytest.approx(44, abs=0.01)
    assert any("P95" in n for n in one.notes)
    four = tcp_row(make_pcap, handshake() + rtt_flow([40, 41, 42, 43]))
    assert (four.measurement_confidence, four.p95_rtt_ms) == ("MEDIUM", None)
    five = tcp_row(make_pcap, handshake() + rtt_flow([40, 41, 42, 43, 44]))
    assert five.p95_rtt_ms == pytest.approx(44, abs=0.01)


def test_longer_leg_is_reported_and_basis_follows_it(make_pcap):
    # capture near the client: its own uploads are acked by the far server (60 ms); the server's data is acked locally (1 ms)
    pk = handshake()
    for i in range(4):
        t = T0 + 1 + i
        pk += [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001 + i * 50, ack=5001, payload=b"u" * 50, ts=t),
               pf.tcp(S, C, DPORT, SPORT, "A", seq=5001, ack=1051 + i * 50, ts=t + 0.060),
               server_data(5001 + i * 10, 10, t + 0.2), client_ack(5011 + i * 10, t + 0.201)]
    row = tcp_row(make_pcap, pk)
    assert row.avg_rtt_ms == pytest.approx(60, abs=0.01) and row.rtt_basis == "client_to_server" and row.rtt_samples == 4


def test_piggybacked_acks_are_not_samples(make_pcap):
    # request answered by response data carrying the ACK: includes server think time, so no RTT sample
    pk = handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=b"q" * 30, ts=T0 + 1),
                        pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1031, payload=b"r" * 30, ts=T0 + 1.5)]
    row = tcp_row(make_pcap, pk)
    assert row.rtt_samples == 0 and row.measurement_confidence == "UNAVAILABLE" and row.avg_rtt_ms is None


def test_ipv6_rtt(make_pcap):
    row = perf(make_pcap, handshake(c=C6, s=S6, v6=True) + rtt_flow([30, 31, 32, 33], c=C6, s=S6, v6=True))[0][("TCP", DPORT)]
    assert row.rtt_samples == 4 and row.avg_rtt_ms == pytest.approx(31.5, abs=0.01) and row.tcp_handshake_ms == pytest.approx(30, abs=0.01)


# ------------------------------------------------------------------ retransmissions
def test_retransmitted_segments_are_excluded_and_lower_confidence(make_pcap):
    pk = handshake() + rtt_flow([40] * 10)
    for i in range(3):  # three segments sent twice before being acknowledged
        t = T0 + 20 + i
        pk += [server_data(9001 + i * 100, 100, t), server_data(9001 + i * 100, 100, t + 0.2), client_ack(9101 + i * 100, t + 0.25)]
    row = tcp_row(make_pcap, pk)
    assert row.rtt_samples == 10 and row.avg_rtt_ms == pytest.approx(40, abs=0.01)  # 0.25 s samples never counted
    assert row.max_rtt_ms == pytest.approx(40, abs=0.01)
    assert row.measurement_confidence == "MEDIUM"  # HIGH lowered: 3 of 16 segments were retransmissions
    assert any("retransmitted or reordered" in n for n in row.notes)


def test_a_retransmission_also_poisons_later_cumulatively_acked_segments(make_pcap):
    pk = handshake() + [server_data(5001, 100, T0 + 1), server_data(5101, 100, T0 + 1.01),
                        server_data(5001, 100, T0 + 1.3),  # seg 1 retransmitted
                        client_ack(5201, T0 + 1.34)]       # acks both: neither gives a trustworthy sample
    pk += [server_data(5201, 100, T0 + 3), client_ack(5301, T0 + 3.05)]  # a clean one afterwards
    row = tcp_row(make_pcap, pk)
    assert row.rtt_samples == 1 and row.avg_rtt_ms == pytest.approx(50, abs=0.01)


def test_retransmitted_syn_data_free_flow_has_no_rtt(make_pcap):
    row = tcp_row(make_pcap, [pf.tcp(C, S, SPORT, DPORT, "S", seq=1000, ts=T0), pf.tcp(C, S, SPORT, DPORT, "S", seq=1000, ts=T0 + 1)])
    assert row.rtt_samples == 0 and row.measurement_confidence == "UNAVAILABLE" and row.tcp_handshake_ms is None


# ------------------------------------------------------------------ out-of-order packets
def test_reordered_segments_do_not_produce_a_sample(make_pcap):
    pk = handshake() + [server_data(5101, 100, T0 + 1), server_data(5001, 100, T0 + 1.005),  # seg 2 captured before seg 1
                        client_ack(5201, T0 + 1.05),                                          # one cumulative ACK for both
                        server_data(5201, 100, T0 + 2), client_ack(5301, T0 + 2.04)]
    row = tcp_row(make_pcap, pk)
    assert row.rtt_samples == 1 and row.min_rtt_ms == pytest.approx(40, abs=0.01)


def test_ack_stamped_before_its_data_is_never_a_negative_sample(make_pcap):
    pk = handshake() + [server_data(5001, 100, T0 + 1), client_ack(5101, T0 + 0.5)]  # file order kept, timestamps inverted
    row = tcp_row(make_pcap, pk, sort=False)
    assert row.rtt_samples == 0 and row.min_rtt_ms is None


def test_packets_written_out_of_time_order_in_the_file(make_pcap):
    in_order = handshake() + rtt_flow([40, 45, 50, 55])
    shuffled = in_order[::-1]  # every ACK is read before its data
    row = tcp_row(make_pcap, shuffled, sort=False)
    assert row.rtt_samples == 0 and row.avg_rtt_ms is None  # nothing is invented from reversed capture order
    assert tcp_row(make_pcap, in_order).rtt_samples == 4


# ------------------------------------------------------------------ HTTP (cleartext)
def http_flow(req_t=T0 + 0.1, resp_t=T0 + 0.18, req=REQ, resp=RESP, **kw):
    return handshake(**kw) + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=req, ts=req_t),
                              pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1001 + len(req), payload=resp, ts=resp_t)]


def test_http_response_time_when_http_is_visible(make_pcap):
    row = tcp_row(make_pcap, http_flow())
    assert row.application_protocol == "HTTP" and row.encrypted is False
    assert row.application_response_ms == pytest.approx(80, abs=0.01) and row.application_response_samples == 1
    assert row.tcp_handshake_ms == pytest.approx(30, abs=0.01)  # not conflated with the handshake
    assert row.application_response_ms != row.tcp_handshake_ms
    assert any("does not include the TCP handshake" in n for n in row.notes)


def test_http_uses_the_last_request_packet_and_first_response(make_pcap):
    pk = handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=b"POST /u HTTP/1.1\r\nHost: x\r\n\r\n", ts=T0 + 0.1),
                        pf.tcp(C, S, SPORT, DPORT, "PA", seq=1033, ack=5001, payload=b"b" * 100, ts=T0 + 0.3),  # body
                        pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1133, payload=RESP, ts=T0 + 0.35)]
    assert tcp_row(make_pcap, pk).application_response_ms == pytest.approx(50, abs=0.01)


def test_retransmitted_http_request_keeps_the_original_time(make_pcap):
    pk = http_flow(req_t=T0 + 0.1, resp_t=T0 + 0.5) + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=REQ, ts=T0 + 0.3)]
    assert tcp_row(make_pcap, pk).application_response_ms == pytest.approx(400, abs=0.01)


def test_interim_100_continue_is_not_the_response(make_pcap):
    pk = handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=b"PUT /f HTTP/1.1\r\nExpect: 100-continue\r\n\r\n", ts=T0 + 0.1),
                        pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1048, payload=b"HTTP/1.1 100 Continue\r\n\r\n", ts=T0 + 0.12),
                        pf.tcp(C, S, SPORT, DPORT, "PA", seq=1048, ack=5027, payload=b"b" * 10, ts=T0 + 0.2),
                        pf.tcp(S, C, DPORT, SPORT, "PA", seq=5027, ack=1058, payload=RESP, ts=T0 + 0.26)]
    assert tcp_row(make_pcap, pk).application_response_ms == pytest.approx(60, abs=0.01)


def test_pipelined_requests_are_not_timed(make_pcap):
    pk = handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=REQ, ts=T0 + 0.1),
                        pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001 + len(REQ), ack=5001, payload=REQ, ts=T0 + 0.11),
                        pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1001, payload=RESP, ts=T0 + 0.2)]
    row = tcp_row(make_pcap, pk)
    assert row.application_protocol == "HTTP" and row.application_response_ms is None
    assert any("not timed" in n for n in row.notes)


def test_request_without_response_and_response_without_request(make_pcap):
    unanswered = tcp_row(make_pcap, handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=REQ, ts=T0 + 0.1)])
    assert unanswered.application_protocol == "HTTP" and unanswered.application_response_ms is None
    assert any("could be matched" in n for n in unanswered.notes)
    _, result = perf(make_pcap, [pf.tcp(S, C, DPORT, SPORT, "PA", seq=5001, ack=1001, payload=RESP, ts=T0)])
    mid = result.performance_statistics.metrics[0]
    assert mid.application_response_ms is None and mid.application_protocol is None


def test_http_response_listed_before_its_request_is_not_fabricated(make_pcap):
    _, result = perf(make_pcap, http_flow()[::-1], sort=False)  # file order: response, request, ...
    row = result.performance_statistics.metrics[0]
    assert row.application_protocol == "HTTP" and row.application_response_ms is None


def test_multiple_http_exchanges_use_the_median(make_pcap):
    pk, seq_c, seq_s, t = handshake(), 1001, 5001, T0 + 1
    for delay in (0.05, 0.09, 0.30):
        pk += [pf.tcp(C, S, SPORT, DPORT, "PA", seq=seq_c, ack=seq_s, payload=REQ, ts=t),
               pf.tcp(S, C, DPORT, SPORT, "PA", seq=seq_s, ack=seq_c + len(REQ), payload=RESP, ts=t + delay)]
        seq_c, seq_s, t = seq_c + len(REQ), seq_s + len(RESP), t + 1
    row = tcp_row(make_pcap, pk)
    assert row.application_response_samples == 3 and row.application_response_ms == pytest.approx(90, abs=0.01)


# ------------------------------------------------------------------ HTTPS
def tls_flow(c=C, s=S, sport=SPORT, dport=DPORT, t=T0):
    pk = handshake(c=c, s=s, sport=sport, dport=dport, t=t)
    pk += [pf.tcp(c, s, sport, dport, "PA", seq=1001, ack=5001, payload=CLIENT_HELLO, ts=t + 0.1),
           pf.tcp(s, c, dport, sport, "PA", seq=5001, ack=1001 + len(CLIENT_HELLO), payload=SERVER_HELLO, ts=t + 0.165)]
    pk += [pf.tcp(c, s, sport, dport, "PA", seq=2000, ack=6000, payload=b"\x17\x03\x03" + b"\x00" * 60, ts=t + 0.3),
           pf.tcp(s, c, dport, sport, "PA", seq=6000, ack=2063, payload=b"\x17\x03\x03" + b"\x00" * 60, ts=t + 0.9)]
    return pk


def test_https_exposes_handshake_tls_rtt_and_duration_but_no_response_time(make_pcap):
    pk = lookup("github.com", S, T0 - 1, ms=19) + tls_flow() + rtt_flow([36, 37, 38, 39, 40], base=T0 + 2, seq0=20001)
    row = tcp_row(make_pcap, pk)
    assert row.application_protocol == "TLS" and row.encrypted is True
    assert row.application_response_ms is None and row.application_response_samples == 0
    assert row.tcp_handshake_ms == pytest.approx(30, abs=0.01)
    assert row.tls_server_hello_ms == pytest.approx(65, abs=0.01)
    assert row.dns_latency_ms == pytest.approx(19, abs=0.01) and row.domain == "github.com"
    assert row.avg_rtt_ms == pytest.approx(38, abs=0.01) and row.connection_duration_ms > 2000
    assert any("Encrypted (TLS)" in n for n in row.notes)


def test_retransmitted_client_hello_is_not_timed(make_pcap):
    pk = tls_flow() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=CLIENT_HELLO, ts=T0 + 0.13)]
    row = tcp_row(make_pcap, pk)
    assert row.encrypted and row.tls_server_hello_ms is None


def test_port_443_without_visible_tls_makes_no_encryption_claim(make_pcap):
    pk = handshake() + [pf.tcp(C, S, SPORT, DPORT, "PA", seq=1001, ack=5001, payload=b"\x99" * 50, ts=T0 + 0.1)]
    row = tcp_row(make_pcap, pk)
    assert row.application_protocol is None and row.encrypted is False and row.application_response_ms is None


# ------------------------------------------------------------------ missing measurements
def test_nothing_is_invented_when_packets_are_missing(make_pcap):
    row = tcp_row(make_pcap, [pf.tcp(C, S, SPORT, DPORT, "S", seq=1000, ts=T0)])
    for f in ("dns_latency_ms", "tcp_handshake_ms", "tls_server_hello_ms", "min_rtt_ms", "avg_rtt_ms", "median_rtt_ms",
              "p95_rtt_ms", "max_rtt_ms", "application_response_ms", "rtt_basis", "application_protocol", "domain"):
        assert getattr(row, f) is None, f
    assert row.rtt_samples == 0 and row.measurement_confidence == "UNAVAILABLE"


def test_udp_and_icmp_connections_have_no_tcp_metrics(make_pcap):
    rows, _ = perf(make_pcap, [pf.udp(C, "8.8.4.4", 41000, 5000, b"q", ts=T0), pf.udp("8.8.4.4", C, 5000, 41000, b"r", ts=T0 + 0.1),
                               pf.icmp_echo(C, "8.8.4.4", ts=T0 + 1)])
    udp = rows[("UDP", 5000)]
    assert udp.measurement_confidence == "UNAVAILABLE" and udp.avg_rtt_ms is None and udp.dns_latency_ms is None
    assert udp.connection_duration_ms == pytest.approx(100, abs=0.01)


def test_connection_without_dns_still_has_metrics(make_pcap):
    row = tcp_row(make_pcap, handshake() + rtt_flow([40, 41, 42]))
    assert row.domain is None and row.dns_latency_ms is None and row.rtt_samples == 3


# ------------------------------------------------------------------ per-domain aggregation
def test_domain_aggregation(make_pcap):
    pk = lookup("google.com", S, T0, ms=20, txid=1) + lookup("google.com", S2, T0 + 0.5, ms=30, txid=2)
    pk += handshake(s=S, sport=50001, t=T0 + 1) + rtt_flow([40 + 2 * i for i in range(10)], base=T0 + 2, s=S, sport=50001)
    pk += handshake(s=S2, sport=50002, t=T0 + 40) + rtt_flow([100 + 2 * i for i in range(10)], base=T0 + 41, s=S2, sport=50002)
    pk += lookup("quiet.example.org", "198.18.9.9", T0 + 90, txid=3)  # resolved but never connected to
    result = analyze(make_pcap, pk)
    domains = {d.domain: d for d in result.performance_statistics.domains}
    assert set(domains) == {"google.com"}
    g = domains["google.com"]
    assert g.connections == 2 and g.rtt_samples == 20 and g.measurement_confidence == "HIGH"
    assert g.avg_rtt_ms == pytest.approx(79, abs=0.01) and g.p95_rtt_ms == pytest.approx(116, abs=0.01)
    assert g.tcp_handshake_ms == pytest.approx(30, abs=0.01) and g.handshake_samples == 2
    assert g.dns_latency_ms == pytest.approx(25, abs=0.01) and g.dns_lookups == 2
    assert g.application_response_ms is None and g.encrypted_connections == 0


def test_domain_response_time_only_comes_from_visible_http(make_pcap):
    pk = lookup("plain.example.org", S, T0) + http_flow(t=T0 + 1, req_t=T0 + 1.1, resp_t=T0 + 1.15)
    pk += lookup("secure.example.org", S2, T0 + 5, txid=2) + tls_flow(s=S2, sport=50009, t=T0 + 6)
    domains = {d.domain: d for d in analyze(make_pcap, pk).performance_statistics.domains}
    assert domains["plain.example.org"].application_response_ms == pytest.approx(50, abs=0.01)
    assert domains["plain.example.org"].http_connections == 1
    assert domains["secure.example.org"].application_response_ms is None and domains["secure.example.org"].encrypted_connections == 1


def test_summary_and_notes_keep_handshake_and_response_time_apart(make_pcap):
    result = analyze(make_pcap, handshake() + rtt_flow([40] * 3))
    s = result.performance_statistics.summary
    assert s.tracked_connections == 1 and s.connections_with_rtt == 1
    assert any("not website or application response time" in n for n in s.notes)
    assert len(result.performance_statistics.metrics) == len(result.connections)


# ------------------------------------------------------------------ payload classification
@pytest.mark.parametrize("payload,expected", [
    (REQ, "http_request"),
    (b"POST /a?b=c HTTP/1.0\r\n\r\n", "http_request"),
    (RESP, "http_response"),
    (b"HTTP/1.1 404 Not Found\r\n", "http_response"),
    (b"HTTP/1.1 100 Continue\r\n\r\n", "http_continue"),
    (CLIENT_HELLO, "tls_client_hello"),
    (SERVER_HELLO, "tls_server_hello"),
    (b"\x17\x03\x03\x00\x20" + b"\x00" * 40, None),         # TLS application data
    (b"GET /no-version\r\n", None),                           # malformed request line
    (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", None),             # HTTP/2 preface is not HTTP/1.x
    (b"HELLO there", None),
    (b"", None),
])
def test_classify_tcp_payload(payload, expected):
    assert classify_tcp_payload(payload) == expected
