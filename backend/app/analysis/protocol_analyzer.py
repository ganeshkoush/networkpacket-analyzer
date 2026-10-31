"""Protocol distribution analyzer."""
from __future__ import annotations

from collections import Counter

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import ProtocolStat, ProtocolStatistics


class ProtocolAnalyzer:
    """Counts packets/bytes per most-specific protocol and per contained layer."""

    def __init__(self) -> None:
        self._packets: Counter[str] = Counter()
        self._bytes: Counter[str] = Counter()
        self._layers: Counter[str] = Counter()
        self._total = 0

    def add(self, pkt: PacketRecord) -> None:
        self._total += 1
        self._packets[pkt.protocol] += 1
        self._bytes[pkt.protocol] += pkt.size
        for layer in pkt.layers:
            self._layers[layer] += 1

    def result(self) -> ProtocolStatistics:
        distribution = [
            ProtocolStat(
                protocol=proto,
                packets=count,
                bytes=self._bytes[proto],
                percent_of_packets=round(100 * count / self._total, 2) if self._total else 0.0,
            )
            for proto, count in self._packets.most_common()
        ]
        return ProtocolStatistics(distribution=distribution, layer_packet_counts=dict(self._layers))
