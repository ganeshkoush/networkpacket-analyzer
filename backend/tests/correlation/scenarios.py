"""Capture builders for correlation tests: realistic traffic with a security event and (optionally) a performance change."""
import pcap_factory as pf
from pcap_factory import T0

SERVER = "10.0.0.9"


def handshake(client, server, sport, dport, t, hs_ms, isn=100):
    hs = hs_ms / 1000
    return [pf.tcp(client, server, sport, dport, "S", seq=isn, ts=t), pf.tcp(server, client, dport, sport, "SA", seq=500, ack=isn + 1, ts=t + hs * 0.6),
            pf.tcp(client, server, sport, dport, "A", seq=isn + 1, ack=501, ts=t + hs)]


def flow(client, server, sport, dport, t, hs_ms=30.0, rtt_ms=None, segs=0, retrans=0, response_ms=None):
    """A completed connection; optionally `segs` server data segments each acked after rtt_ms, `retrans` repeated segments."""
    pk = handshake(client, server, sport, dport, t, hs_ms)
    t_data = t + hs_ms / 1000 + 0.05
    if response_ms is not None:
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        pk += [pf.tcp(client, server, sport, dport, "PA", seq=101, ack=501, payload=req, ts=t_data),
               pf.tcp(server, client, dport, sport, "PA", seq=501, ack=101 + len(req), payload=b"HTTP/1.1 200 OK\r\n\r\n", ts=t_data + response_ms / 1000)]
        t_data += response_ms / 1000 + 0.2
    seq = 1000
    for i in range(segs):
        ts = t_data + i * 0.3
        pk += [pf.tcp(server, client, dport, sport, "PA", seq=seq, ack=101, payload=b"d" * 100, ts=ts),
               pf.tcp(client, server, sport, dport, "A", seq=101, ack=seq + 100, ts=ts + (rtt_ms or 30) / 1000)]
        seq += 100
    for i in range(retrans):  # the same segment sent again (a retransmission indicator), later acked
        ts = t_data + segs * 0.3 + i * 0.6
        pk += [pf.tcp(server, client, dport, sport, "PA", seq=seq, ack=101, payload=b"r" * 100, ts=ts),
               pf.tcp(server, client, dport, sport, "PA", seq=seq, ack=101, payload=b"r" * 100, ts=ts + 0.25),
               pf.tcp(client, server, sport, dport, "A", seq=101, ack=seq + 100, ts=ts + 0.3)]
        seq += 100
    return pk


def syn_flood_scenario(slow_ms=180.0, normal_ms=40.0, *, with_slowdown=True, flood_start=60.0, flood_len=10.0, total=180.0, rate=300):
    """Legitimate clients complete handshakes to SERVER:80 every second; a SYN flood hits it for `flood_len` seconds."""
    pk = []
    for i in range(int(total)):
        t = T0 + i
        in_flood = flood_start <= i <= flood_start + flood_len + 5
        pk += handshake(f"10.0.1.{i % 200 + 1}", SERVER, 30000 + i, 80, t + 0.5, slow_ms if (in_flood and with_slowdown) else normal_ms)
    pk += pf.syn_flood_packets(SERVER, 80, int(flood_len * rate), t0=T0 + flood_start, per_second=rate)
    return pk


def dns_scenario(slow_ms=150.0, normal_ms=20.0, *, with_slowdown=True, total=200, burst_start=100.0, burst_len=10.0):
    """Three normal clients look names up every 1.5 s via 8.8.8.8; one client floods NXDOMAIN queries for `burst_len` seconds."""
    pk, n = [], 0
    for i in range(int(total / 1.5)):
        t = T0 + i * 1.5
        slow = with_slowdown and burst_start <= i * 1.5 <= burst_start + burst_len + 5
        for c in range(3):
            n += 1
            ms = (slow_ms if slow else normal_ms)
            pk += [pf.dns_query(f"10.0.2.{c + 1}", "8.8.8.8", f"site{n}.example.com", txid=n % 65000, sport=20000 + n % 30000, ts=t + c * 0.1),
                   pf.dns_response(f"10.0.2.{c + 1}", "8.8.8.8", f"site{n}.example.com", txid=n % 65000, dport=20000 + n % 30000, ts=t + c * 0.1 + ms / 1000)]
    for k in range(int(burst_len * 20)):
        n += 1
        t = T0 + burst_start + k / 20
        pk += [pf.dns_query("10.0.2.99", "8.8.8.8", f"nx{n}.example.org", txid=n % 65000, sport=20000 + n % 30000, ts=t),
               pf.dns_response("10.0.2.99", "8.8.8.8", f"nx{n}.example.org", txid=n % 65000, dport=20000 + n % 30000, rcode=3, answers=(), ts=t + 0.02)]
    return pk


def port_scan_scenario(*, with_scan=True, total=200.0, scan_start=100.0, ports=300, step=1 / 30):
    """Legitimate clients connect to SERVER:80 about every 2 s; one host scans its ports at ~30 SYN/s."""
    pk = []
    for i in range(int(total / 2)):
        pk += handshake(f"10.0.3.{i % 100 + 1}", SERVER, 31000 + i, 80, T0 + i * 2, 30.0)
    if with_scan:
        pk += pf.scan_packets("45.33.32.156", SERVER, range(1, ports + 1), t0=T0 + scan_start, step=step)
    return pk


def retransmission_scenario(*, rtt_with=120.0, rtt_without=30.0, resp_with=400.0, resp_without=60.0, with_effect=True):
    """100 clean connections, plus 40 whose segments are retransmitted; the latter are slower when `with_effect`."""
    pk = []
    for i in range(100):
        pk += flow(f"10.0.4.{i % 100 + 1}", f"172.16.0.{i % 5 + 1}", 32000 + i, 80, T0 + i * 0.7, rtt_ms=rtt_without, segs=4, response_ms=resp_without)
    for i in range(40):
        pk += flow(f"10.0.5.{i % 40 + 1}", f"172.16.1.{i % 4 + 1}", 33000 + i, 80, T0 + i * 1.5,
                   rtt_ms=rtt_with if with_effect else rtt_without, segs=4, retrans=2, response_ms=resp_with if with_effect else resp_without)
    return pk


def reset_scenario(*, refused=100, ok=30):
    """Many refused connections (SYN answered by RST) among normal ones."""
    pk = []
    for i in range(ok):
        pk += flow(f"10.0.6.{i % 30 + 1}", "172.16.2.1", 34000 + i, 80, T0 + i, segs=1)
    for i in range(refused):
        c, s = f"10.0.7.{i % 50 + 1}", "172.16.2.2"
        pk += [pf.tcp(c, s, 35000 + i, 8080, "S", seq=10, ts=T0 + 50 + i * 0.2), pf.tcp(s, c, 8080, 35000 + i, "RA", seq=0, ack=11, ts=T0 + 50 + i * 0.2 + 0.001)]
    return pk
