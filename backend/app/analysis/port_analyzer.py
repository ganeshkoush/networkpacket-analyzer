"""TCP/UDP port statistics, including destination-port fan-out per source IP."""
from __future__ import annotations

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import PortCount, PortStatistics, SourcePortFanout
from app.utils.net import service_hint

_MAX_TRACKED_SOURCES = 50_000
_SAMPLE_PORTS = 20


class PortAnalyzer:
    """Counts source/destination ports for TCP and UDP packets."""

    def __init__(self, top_n: int = 20) -> None:
        self.top_n = top_n
        # (protocol, port) -> [packets, bytes]
        self._src_ports: dict[tuple[str, int], list[int]] = {}
        self._dst_ports: dict[tuple[str, int], list[int]] = {}
        # source ip -> [packets, set of (protocol, dst_port)]
        self._fanout: dict[str, tuple[list[int], set[tuple[str, int]]]] = {}
        self._sources_dropped: set[str] = set()

    @staticmethod
    def _bump(table: dict[tuple[str, int], list[int]], key: tuple[str, int], size: int) -> None:
        entry = table.get(key)
        if entry is None:
            table[key] = [1, size]
        else:
            entry[0] += 1
            entry[1] += size

    def add(self, pkt: PacketRecord) -> None:
        if pkt.transport not in ("TCP", "UDP") or pkt.src_port is None or pkt.dst_port is None:
            return
        self._bump(self._src_ports, (pkt.transport, pkt.src_port), pkt.size)
        self._bump(self._dst_ports, (pkt.transport, pkt.dst_port), pkt.size)

        if not pkt.src_ip:
            return
        entry = self._fanout.get(pkt.src_ip)
        if entry is None:
            if len(self._fanout) >= _MAX_TRACKED_SOURCES:
                self._sources_dropped.add(pkt.src_ip)
                return
            entry = self._fanout[pkt.src_ip] = ([0], set())
        entry[0][0] += 1
        entry[1].add((pkt.transport, pkt.dst_port))

    def _top(self, table: dict[tuple[str, int], list[int]]) -> list[PortCount]:
        rows = sorted(table.items(), key=lambda kv: (kv[1][0], kv[1][1]), reverse=True)
        return [
            PortCount(protocol=proto, port=port, packets=v[0], bytes=v[1], service_hint=service_hint(port))
            for (proto, port), v in rows[: self.top_n]
        ]

    def result(self) -> PortStatistics:
        fanout = sorted(self._fanout.items(), key=lambda kv: len(kv[1][1]), reverse=True)
        return PortStatistics(
            top_source_ports=self._top(self._src_ports),
            top_destination_ports=self._top(self._dst_ports),
            unique_source_ports=len({p for _, p in self._src_ports}),
            unique_destination_ports=len({p for _, p in self._dst_ports}),
            destination_ports_per_source=[
                SourcePortFanout(
                    source_ip=ip,
                    unique_destination_ports=len(ports),
                    packets=counter[0],
                    sample_ports=sorted({p for _, p in ports})[:_SAMPLE_PORTS],
                )
                for ip, (counter, ports) in fanout[: self.top_n]
            ],
            sources_not_tracked=len(self._sources_dropped),
        )
