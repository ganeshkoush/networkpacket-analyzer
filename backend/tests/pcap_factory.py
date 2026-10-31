"""Helpers for building synthetic packets/captures for tests (no network access needed)."""
from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapNgWriter, wrpcap

# Fixed MACs: avoids Scapy trying to resolve them (which needs raw-socket privileges).
ETH = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
T0 = 1_700_000_000.0


def stamp(pkt, ts: float):
    pkt.time = ts
    return pkt


def tcp(src, dst, sport, dport, flags="A", seq=0, ack=0, payload=b"", ts=T0):
    return stamp(Ether(**ETH) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / payload, ts)


def udp(src, dst, sport, dport, payload=b"", ts=T0):
    return stamp(Ether(**ETH) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload, ts)


def dns_query(client, server, qname, txid=1, sport=40000, qtype="A", ts=T0):
    ip_layer = IPv6(src=client, dst=server) if ":" in client else IP(src=client, dst=server)
    return stamp(Ether(**ETH) / ip_layer / UDP(sport=sport, dport=53)
                 / DNS(id=txid, rd=1, qd=DNSQR(qname=qname, qtype=qtype)), ts)


def dns_response(client, server, qname, txid=1, dport=40000, rcode=0, answers=("93.184.216.34",), ts=T0, ttl=60):
    an = None
    for ip in answers if rcode == 0 else ():
        rr = DNSRR(rrname=qname, rdata=ip, ttl=ttl, type="AAAA" if ":" in ip else "A")
        an = rr if an is None else an / rr
    extra = {"an": an} if an is not None else {}
    ip_layer = IPv6(src=server, dst=client) if ":" in client else IP(src=server, dst=client)
    return stamp(Ether(**ETH) / ip_layer / UDP(sport=53, dport=dport)
                 / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname),
                       ancount=len(answers) if rcode == 0 else 0, **extra), ts)


def icmp_echo(src, dst, ts=T0):
    return stamp(Ether(**ETH) / IP(src=src, dst=dst) / ICMP(), ts)


def arp(ts=T0):
    return stamp(Ether(src=ETH["src"], dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.0.0.1", pdst="10.0.0.2"), ts)


def ipv6_tcp(src, dst, sport, dport, flags="S", ts=T0, seq=0, ack=0, payload=b""):
    return stamp(Ether(**ETH) / IPv6(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / payload, ts)


def write_pcap(path: Path, packets) -> Path:
    wrpcap(str(path), list(packets))
    return path


def write_pcapng(path: Path, packets) -> Path:
    writer = PcapNgWriter(str(path))
    for p in packets:
        writer.write(p)
    writer.close()
    return path


def tcp_session(client="10.0.0.5", server="93.184.216.34", sport=50000, dport=80, t=T0):
    """Handshake + one request/response + FIN teardown (all valid, no retransmissions)."""
    return [
        tcp(client, server, sport, dport, "S", seq=100, ts=t),
        tcp(server, client, dport, sport, "SA", seq=500, ack=101, ts=t + 0.01),
        tcp(client, server, sport, dport, "A", seq=101, ack=501, ts=t + 0.02),
        tcp(client, server, sport, dport, "PA", seq=101, ack=501, payload=b"GET / HTTP/1.1\r\n\r\n", ts=t + 0.03),
        tcp(server, client, dport, sport, "PA", seq=501, ack=119, payload=b"HTTP/1.1 200 OK\r\n\r\n", ts=t + 0.05),
        tcp(client, server, sport, dport, "FA", seq=119, ack=520, ts=t + 0.06),
        tcp(server, client, dport, sport, "FA", seq=520, ack=120, ts=t + 0.07),
    ]


def build_sample():
    """A small mixed capture used as the sample fixture."""
    pk = []
    pk += tcp_session(t=T0)
    pk += tcp_session(client="10.0.0.6", sport=50001, dport=443, t=T0 + 2)
    pk.append(dns_query("10.0.0.5", "8.8.8.8", "example.com", txid=1, ts=T0 - 1))
    pk.append(dns_response("10.0.0.5", "8.8.8.8", "example.com", txid=1, ts=T0 - 0.95))
    pk.append(dns_query("10.0.0.6", "8.8.8.8", "no-such-host.invalid", txid=2, sport=40001, ts=T0 + 1))
    pk.append(dns_response("10.0.0.6", "8.8.8.8", "no-such-host.invalid", txid=2, dport=40001, rcode=3, answers=(), ts=T0 + 1.04))
    pk.append(udp("10.0.0.5", "10.0.0.255", 5000, 5001, b"x" * 40, ts=T0 + 3))
    pk.append(icmp_echo("10.0.0.5", "10.0.0.1", ts=T0 + 4))
    pk.append(arp(ts=T0 + 4.5))
    # one data segment retransmitted
    pk.append(tcp("10.0.0.7", "10.0.0.9", 51000, 8080, "PA", seq=1, payload=b"abc", ts=T0 + 5))
    pk.append(tcp("10.0.0.7", "10.0.0.9", 51000, 8080, "PA", seq=1, payload=b"abc", ts=T0 + 6))
    # one host SYN-ing many ports
    for i, port in enumerate((21, 22, 23, 25, 80, 443, 3389)):
        pk.append(tcp("10.0.0.99", "10.0.0.9", 60000 + i, port, "S", seq=1000 + i, ts=T0 + 7 + i * 0.1))
    return sorted(pk, key=lambda p: p.time)


# ----------------------------------------------------------------- scenario builders
def arp_pkt(op, sender_mac, sender_ip, target_ip, target_mac="00:00:00:00:00:00", eth_src=None, ts=T0):
    """op: 1 = request, 2 = reply."""
    dst = "ff:ff:ff:ff:ff:ff" if op == 1 else target_mac
    return stamp(Ether(src=eth_src or sender_mac, dst=dst)
                 / ARP(op=op, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip), ts)


def scan_packets(src, dst, ports, t0=T0, step=0.01, open_ports=()):
    """SYN to each port; open ports answer SYN-ACK, others RST-ACK."""
    pk = []
    for i, port in enumerate(ports):
        t, sport = t0 + i * step, 40000 + i
        pk.append(tcp(src, dst, sport, port, "S", seq=1000 + i, ts=t))
        if port in open_ports:
            pk.append(tcp(dst, src, port, sport, "SA", seq=5000, ack=1001 + i, ts=t + 0.001))
        else:
            pk.append(tcp(dst, src, port, sport, "RA", seq=0, ack=1001 + i, ts=t + 0.001))
    return pk


def syn_flood_packets(target, port, count, t0=T0, per_second=500, single_source=None):
    """`count` SYNs at `per_second`, from spoofed-looking sources (or one source), never completed."""
    pk = []
    for i in range(count):
        src = single_source or f"198.51.{i // 250}.{i % 250 + 1}"
        pk.append(tcp(src, target, 10000 + i % 50000, port, "S", seq=i, ts=t0 + i / per_second))
    return pk


def busy_server_packets(server, port=80, clients=300, t0=T0, per_second=300):
    """Many clients completing handshakes and exchanging data with a server (legitimate load)."""
    pk = []
    for i in range(clients):
        client = f"10.1.{i // 250}.{i % 250 + 1}"
        pk += tcp_session(client=client, server=server, sport=30000 + i, dport=port, t=t0 + i / per_second)
    return pk


def random_label(rng, n=20):
    import string
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def build_attack_demo():
    """Synthetic capture mixing normal traffic with a port scan, SYN flood, ARP poisoning and DGA-like DNS."""
    import random
    rng = random.Random(3)
    pk = busy_server_packets("10.0.0.80", clients=40, per_second=40)                      # normal background
    pk += scan_packets("10.0.0.99", "10.0.0.9", range(1, 120), t0=T0 + 5)                # port scan
    pk += syn_flood_packets("10.0.0.9", 80, 1500, t0=T0 + 10, per_second=1000)           # SYN flood
    for i in range(12):                                                                        # ARP poisoning
        pk.append(arp_pkt(2, "cc:cc:cc:cc:cc:99", "10.0.0.1", "10.0.0.5", target_mac="bb:bb:bb:bb:bb:05", ts=T0 + 20 + i))
        pk.append(arp_pkt(2, "aa:aa:aa:aa:aa:01", "10.0.0.1", "10.0.0.5", target_mac="bb:bb:bb:bb:bb:05", ts=T0 + 20.5 + i))
    for i in range(30):                                                                        # DGA-ish lookups
        name = f"{random_label(rng, 22)}.com"
        pk.append(dns_query("10.0.0.7", "8.8.8.8", name, txid=i, sport=20000 + i, ts=T0 + 40 + i * 0.1))
        pk.append(dns_response("10.0.0.7", "8.8.8.8", name, txid=i, dport=20000 + i, rcode=3, ts=T0 + 40.02 + i * 0.1))
    return pk


def ipv6_udp(src, dst, sport, dport, payload=b"", ts=T0):
    return stamp(Ether(**ETH) / IPv6(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload, ts)
