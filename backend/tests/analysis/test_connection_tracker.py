"""Connection tracking: TCP lifecycle/state, UDP flows, directions, domains, IPv4/IPv6, filtering."""
import pytest

import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis.connection_tracker import (
    CLOSED, CLOSING, ESTABLISHED, RESET, SYN_RECEIVED, SYN_SENT, UNKNOWN,
    ConnectionFilter, connection_id, filter_connections, flow_key, tcp_state,
)

C, S = "192.168.1.10", "142.250.80.46"
C6, S6 = "2001:db8::10", "2606:4700:4700::1111"


def conns(make_pcap, packets):
    result = analyze_pcap(make_pcap(sorted(packets, key=lambda p: p.time)))
    return result.connections, result.connection_summary


def one(make_pcap, packets):
    found, _ = conns(make_pcap, packets)
    assert len(found) == 1
    return found[0]


def handshake(c=C, s=S, sport=52341, dport=443, t=T0, step=0.01):
    return [pf.tcp(c, s, sport, dport, "S", seq=100, ts=t),
            pf.tcp(s, c, dport, sport, "SA", seq=500, ack=101, ts=t + step),
            pf.tcp(c, s, sport, dport, "A", seq=101, ack=501, ts=t + 2 * step)]


def data(c=C, s=S, sport=52341, dport=443, t=T0 + 0.1, up=200, down=1200):
    return [pf.tcp(c, s, sport, dport, "PA", seq=101, ack=501, payload=b"x" * up, ts=t),
            pf.tcp(s, c, dport, sport, "PA", seq=501, ack=101 + up, payload=b"y" * down, ts=t + 0.01)]


def close(c=C, s=S, sport=52341, dport=443, t=T0 + 0.5):
    return [pf.tcp(c, s, sport, dport, "FA", seq=301, ack=1701, ts=t),
            pf.tcp(s, c, dport, sport, "FA", seq=1701, ack=302, ts=t + 0.01),
            pf.tcp(c, s, sport, dport, "A", seq=302, ack=1702, ts=t + 0.02)]


# ------------------------------------------------------------------ TCP lifecycle
def test_tcp_handshake_only_is_established(make_pcap):
    c = one(make_pcap, handshake())
    assert (c.syn_seen, c.synack_seen, c.handshake_complete) == (True, True, True)
    assert c.state == ESTABLISHED and c.rst_seen is False and c.fin_seen is False
    assert c.packets == 3 and c.packets_client_to_server == 2 and c.packets_server_to_client == 1
    assert set(c.tcp_flags_seen) >= {"SYN", "ACK"}


def test_normal_tcp_connection_with_teardown(make_pcap):
    c = one(make_pcap, handshake() + data() + close())
    assert c.state == CLOSED and c.handshake_complete and c.fin_seen and not c.rst_seen
    assert (c.client_ip, c.client_port, c.server_ip, c.server_port) == (C, 52341, S, 443)
    assert c.start_time == T0 and c.end_time == pytest.approx(T0 + 0.52)
    assert c.duration_seconds == pytest.approx(0.52)
    assert c.resets == 0 and c.retransmissions == 0
    assert c.domain is None and c.domain_ambiguous is False


def test_half_closed_connection_is_closing(make_pcap):
    c = one(make_pcap, handshake() + data() + close()[:1])
    assert c.state == CLOSING


def test_tcp_reset(make_pcap):
    pk = handshake() + [pf.tcp(S, C, 443, 52341, "R", seq=501, ts=T0 + 0.2)]
    c = one(make_pcap, pk)
    assert c.state == RESET and c.rst_seen and c.resets == 1 and c.handshake_complete


def test_reset_of_unanswered_syn_counts_each_rst(make_pcap):
    pk = [pf.tcp(C, S, 52341, 81, "S", ts=T0), pf.tcp(S, C, 81, 52341, "RA", ts=T0 + 0.01),
          pf.tcp(S, C, 81, 52341, "R", ts=T0 + 0.02)]
    c = one(make_pcap, pk)
    assert c.state == RESET and c.resets == 2 and not c.handshake_complete


def test_incomplete_connections(make_pcap):
    syn_only = one(make_pcap, [pf.tcp(C, S, 52341, 443, "S", ts=T0)])
    assert syn_only.state == SYN_SENT and syn_only.handshake_complete is False and syn_only.packets_server_to_client == 0

    no_final_ack = one(make_pcap, handshake()[:2])
    assert no_final_ack.state == SYN_RECEIVED and no_final_ack.synack_seen and not no_final_ack.handshake_complete


def test_capture_starting_mid_connection_is_unknown_not_established(make_pcap):
    c = one(make_pcap, data())
    assert c.state == UNKNOWN and c.syn_seen is False and c.handshake_complete is False
    assert c.packets_client_to_server == 1 and c.packets_server_to_client == 1


def test_retransmissions_are_counted_per_connection(make_pcap):
    seg = pf.tcp(C, S, 52341, 443, "PA", seq=101, ack=501, payload=b"x" * 50, ts=T0 + 0.1)
    again = pf.tcp(C, S, 52341, 443, "PA", seq=101, ack=501, payload=b"x" * 50, ts=T0 + 0.4)
    other = handshake(sport=52342, t=T0 + 1)
    found, _ = conns(make_pcap, handshake() + [seg, again] + other)
    by_port = {c.client_port: c for c in found}
    assert by_port[52341].retransmissions == 1
    assert by_port[52342].retransmissions == 0


# ------------------------------------------------------------------ directions
def test_bidirectional_traffic_is_counted_per_direction(make_pcap):
    c = one(make_pcap, handshake() + data(up=200, down=1200))
    assert c.packets == c.packets_client_to_server + c.packets_server_to_client == 5
    assert c.bytes == c.bytes_client_to_server + c.bytes_server_to_client
    assert c.bytes_server_to_client > 1200 > c.bytes_client_to_server > 200


def test_both_directions_form_one_connection_and_first_sender_is_client(make_pcap):
    pk = [pf.tcp(S, C, 443, 52341, "PA", seq=1, payload=b"a", ts=T0), pf.tcp(C, S, 52341, 443, "A", seq=1, ack=2, ts=T0 + 0.1)]
    c = one(make_pcap, pk)
    assert (c.client_ip, c.server_ip) == (S, C)


# ------------------------------------------------------------------ UDP / other protocols
def test_udp_flow_has_no_tcp_fields(make_pcap):
    pk = [pf.udp(C, "8.8.4.4", 41000, 5000, b"q" * 20, ts=T0), pf.udp("8.8.4.4", C, 5000, 41000, b"r" * 100, ts=T0 + 0.25)]
    c = one(make_pcap, pk)
    assert c.protocol == "UDP" and c.packets == 2 and c.duration_seconds == pytest.approx(0.25)
    assert c.packets_client_to_server == 1 and c.packets_server_to_client == 1
    for field in ("state", "resets", "retransmissions", "handshake_complete", "syn_seen", "synack_seen"):
        assert getattr(c, field) is None
    assert c.domain is None


def test_one_way_udp_flow_stays_valid(make_pcap):
    c = one(make_pcap, [pf.udp(C, "8.8.4.4", 41000, 5000, b"q", ts=T0)])
    assert c.packets_server_to_client == 0 and c.duration_seconds == 0


# ------------------------------------------------------------------ IPv4 / IPv6
def test_ipv6_tcp_and_udp(make_pcap):
    tcp6 = [pf.ipv6_tcp(C6, S6, 50000, 443, "S", ts=T0), pf.ipv6_tcp(S6, C6, 443, 50000, "SA", ts=T0 + 0.01, seq=9, ack=1),
            pf.ipv6_tcp(C6, S6, 50000, 443, "A", ts=T0 + 0.02, seq=1, ack=10)]
    udp6 = [pf.ipv6_udp(C6, S6, 41000, 53, b"q", ts=T0 + 1), pf.ipv6_udp(S6, C6, 53, 41000, b"r", ts=T0 + 1.1)]
    found, summary = conns(make_pcap, tcp6 + udp6)
    by_proto = {c.protocol: c for c in found}
    assert by_proto["TCP"].client_ip == C6 and by_proto["TCP"].server_ip == S6
    assert by_proto["TCP"].state == ESTABLISHED
    assert by_proto["UDP"].server_port == 53 and by_proto["UDP"].packets == 2
    assert summary.by_protocol == {"TCP": 1, "UDP": 1}


def test_ipv4_and_ipv6_connections_get_distinct_ids(make_pcap):
    found, _ = conns(make_pcap, handshake() + [pf.ipv6_tcp(C6, S6, 52341, 443, "S", ts=T0 + 1)])
    assert len(found) == 2 and len({c.id for c in found}) == 2 and all(len(c.id) == 12 for c in found)


# ------------------------------------------------------------------ domains
def dns_lookup(name, ip, t, client=C):
    return [pf.dns_query(client, "8.8.8.8", name, ts=t), pf.dns_response(client, "8.8.8.8", name, answers=[ip], ts=t + 0.02)]


def test_connection_is_associated_with_domain_from_dns(make_pcap):
    found, _ = conns(make_pcap, dns_lookup("github.com", S, T0) + handshake(t=T0 + 1) + data(t=T0 + 1.1))
    tcp = next(c for c in found if c.protocol == "TCP")
    assert tcp.domain == "github.com" and tcp.domain_ambiguous is False
    dns_flow = next(c for c in found if c.server_port == 53)
    assert dns_flow.domain is None  # DNS itself is not website activity


def test_missing_dns_mapping_keeps_connection_valid(make_pcap):
    found, _ = conns(make_pcap, handshake() + data())
    assert len(found) == 1
    c = found[0]
    assert c.domain is None and c.server_ip == S and c.server_port == 443 and c.state == ESTABLISHED


def test_lookup_after_connection_does_not_attribute(make_pcap):
    found, _ = conns(make_pcap, handshake() + dns_lookup("github.com", S, T0 + 5))
    assert next(c for c in found if c.protocol == "TCP").domain is None


def test_shared_ip_domain_is_flagged_ambiguous(make_pcap):
    pk = dns_lookup("a.example.com", S, T0) + dns_lookup("b.example.com", S, T0 + 1) + handshake(t=T0 + 2)
    tcp = next(c for c in conns(make_pcap, pk)[0] if c.protocol == "TCP")
    assert tcp.domain == "b.example.com" and tcp.domain_ambiguous is True


# ------------------------------------------------------------------ summary + helpers
def test_summary_counts_tcp_states(make_pcap):
    pk = (handshake() + data() + close()
          + [pf.tcp(C, S, 60000, 81, "S", ts=T0 + 2)]
          + [pf.tcp(C, S, 60001, 82, "S", ts=T0 + 3), pf.tcp(S, C, 82, 60001, "RA", ts=T0 + 3.01)])
    _, summary = conns(make_pcap, pk)
    assert summary.by_state == {CLOSED: 1, SYN_SENT: 1, RESET: 1}
    assert summary.tcp_with_rst == 1 and summary.tcp_handshakes_complete == 1


def test_flow_key_and_id_are_direction_independent():
    a, b = ("10.0.0.1", 1234), ("93.184.216.34", 80)
    assert flow_key("TCP", a, b) == flow_key("TCP", b, a)
    assert connection_id(flow_key("TCP", a, b)) == connection_id(flow_key("TCP", b, a))
    assert connection_id(flow_key("TCP", a, b)) != connection_id(flow_key("UDP", a, b))


def test_tcp_state_table():
    base = dict(syn=False, synack=False, established=False, fin_client=False, fin_server=False, rst=False)
    assert tcp_state(**base) == UNKNOWN
    assert tcp_state(**{**base, "syn": True}) == SYN_SENT
    assert tcp_state(**{**base, "fin_server": True, "established": True}) == CLOSING
    assert tcp_state(**{**base, "fin_server": True, "fin_client": True}) == CLOSED
    assert tcp_state(**{**base, "rst": True, "fin_client": True, "fin_server": True}) == RESET


def test_filter_connections(make_pcap):
    pk = (dns_lookup("github.com", S, T0) + handshake(t=T0 + 1) + [pf.udp(C, "8.8.4.4", 41000, 5000, b"q", ts=T0 + 2)]
          + [pf.ipv6_tcp(C6, S6, 50000, 8443, "S", ts=T0 + 3)])
    found, _ = conns(make_pcap, pk)

    def ids(**kw):
        return {(c.protocol, c.server_port) for c in filter_connections(found, ConnectionFilter(**kw))}

    assert ids(domain="GitHub") == {("TCP", 443)}
    assert ids(protocol="udp") == {("UDP", 53), ("UDP", 5000)}
    assert ids(port=443) == {("TCP", 443)} and ids(port=52341) == {("TCP", 443)}
    assert ids(dst_ip=S) == {("TCP", 443)}
    assert ids(src_ip="2001:0db8:0:0:0:0:0:10") == {("TCP", 8443)}  # non-canonical IPv6 text still matches
    assert ids(state="syn_sent") == {("TCP", 8443)}
    assert ids(protocol="TCP", port=443, domain="github") == {("TCP", 443)}
    assert ids(domain="nothing") == set()
    with pytest.raises(ValueError):
        filter_connections(found, ConnectionFilter(src_ip="not-an-ip"))
