"""Packet-rate-over-time analyzer."""
from __future__ import annotations

import math

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import TimelinePoint


class TimelineAnalyzer:
    """Buckets packets per second, then merges buckets to fit ``max_points``.

    Keeps one small counter per active second (not per packet). Empty seconds inside
    the capture are reported as zero-rate points so gaps are visible.
    """

    def __init__(self, max_points: int = 300) -> None:
        self.max_points = max_points
        self._buckets: dict[int, list[int]] = {}  # epoch second -> [packets, bytes]

    def add(self, pkt: PacketRecord) -> None:
        bucket = self._buckets.setdefault(int(math.floor(pkt.timestamp)), [0, 0])
        bucket[0] += 1
        bucket[1] += pkt.size

    @property
    def peak_packets_per_second(self) -> int | None:
        """Highest single-second packet count, or ``None`` for an empty capture."""
        return max((b[0] for b in self._buckets.values()), default=None)

    def result(self) -> list[TimelinePoint]:
        if not self._buckets:
            return []
        first, last = min(self._buckets), max(self._buckets)
        interval = max(1, math.ceil((last - first + 1) / self.max_points))
        points: list[TimelinePoint] = []
        for start in range(first, last + 1, interval):
            packets = size = 0
            for sec in range(start, min(start + interval, last + 1)):
                b = self._buckets.get(sec)
                if b:
                    packets += b[0]
                    size += b[1]
            points.append(TimelinePoint(
                start_time=float(start),
                offset_seconds=float(start - first),
                interval_seconds=interval,
                packets=packets,
                bytes=size,
                packets_per_second=round(packets / interval, 3),
            ))
        return points
