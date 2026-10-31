"""IP address statistics: sources, destinations, top talkers, conversations."""
from __future__ import annotations

from collections import Counter

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import Conversation, IpCount, IpStatistics, Talker
from app.utils.net import is_private_ip

_MAX_TRACKED_CONVERSATIONS = 200_000


class IpAnalyzer:
    """Aggregates per-IP and per-IP-pair traffic from IP packets."""

    def __init__(self, top_n: int = 20, max_conversations: int = 100) -> None:
        self.top_n = top_n
        self.max_conversations = max_conversations
        # ip -> [packets_sent, bytes_sent, packets_received, bytes_received]
        self._hosts: dict[str, list[int]] = {}
        # (a, b) with a < b -> [pkts a->b, bytes a->b, pkts b->a, bytes b->a]
        self._convs: dict[tuple[str, str], list[int]] = {}
        self._versions: Counter[str] = Counter()
        self._conversations_dropped = 0

    def add(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip:
            return
        self._versions[f"IPv{pkt.ip_version}"] += 1
        src = self._hosts.setdefault(pkt.src_ip, [0, 0, 0, 0])
        src[0] += 1
        src[1] += pkt.size
        dst = self._hosts.setdefault(pkt.dst_ip, [0, 0, 0, 0])
        dst[2] += 1
        dst[3] += pkt.size

        forward = pkt.src_ip <= pkt.dst_ip
        key = (pkt.src_ip, pkt.dst_ip) if forward else (pkt.dst_ip, pkt.src_ip)
        conv = self._convs.get(key)
        if conv is None:
            if len(self._convs) >= _MAX_TRACKED_CONVERSATIONS:
                self._conversations_dropped += 1
                return
            conv = self._convs[key] = [0, 0, 0, 0]
        offset = 0 if forward else 2
        conv[offset] += 1
        conv[offset + 1] += pkt.size

    def result(self) -> IpStatistics:
        sources = [(ip, s[0], s[1]) for ip, s in self._hosts.items() if s[0]]
        destinations = [(ip, s[2], s[3]) for ip, s in self._hosts.items() if s[2]]

        def top(rows: list[tuple[str, int, int]]) -> list[IpCount]:
            rows.sort(key=lambda r: (r[2], r[1]), reverse=True)
            return [
                IpCount(ip=ip, packets=p, bytes=b, is_private=is_private_ip(ip))
                for ip, p, b in rows[: self.top_n]
            ]

        talkers = sorted(
            self._hosts.items(), key=lambda kv: (kv[1][1] + kv[1][3], kv[1][0] + kv[1][2]), reverse=True
        )[: self.top_n]
        top_talkers = [
            Talker(
                ip=ip,
                is_private=is_private_ip(ip),
                packets_sent=s[0],
                bytes_sent=s[1],
                packets_received=s[2],
                bytes_received=s[3],
                total_packets=s[0] + s[2],
                total_bytes=s[1] + s[3],
            )
            for ip, s in talkers
        ]

        convs = sorted(self._convs.items(), key=lambda kv: kv[1][1] + kv[1][3], reverse=True)
        conversations = [
            Conversation(
                ip_a=a,
                ip_b=b,
                packets=c[0] + c[2],
                bytes=c[1] + c[3],
                packets_a_to_b=c[0],
                bytes_a_to_b=c[1],
                packets_b_to_a=c[2],
                bytes_b_to_a=c[3],
            )
            for (a, b), c in convs[: self.max_conversations]
        ]
        return IpStatistics(
            unique_source_ips=len(sources),
            unique_destination_ips=len(destinations),
            ip_version_packets=dict(self._versions),
            top_sources=top(sources),
            top_destinations=top(destinations),
            top_talkers=top_talkers,
            conversations=conversations,
            total_conversations=len(self._convs) + self._conversations_dropped,
        )
