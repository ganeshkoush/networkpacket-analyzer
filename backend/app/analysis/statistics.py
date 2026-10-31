"""Overall packet/size/time statistics for a capture."""
from __future__ import annotations

from datetime import datetime, timezone

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import PacketStatistics, SizeBucket

# Upper bounds (inclusive) of the packet-size histogram buckets, in bytes.
_BOUNDS = (63, 127, 255, 511, 1023, 1517)
_LABELS = ("0-63", "64-127", "128-255", "256-511", "512-1023", "1024-1517", "1518+")


class StatisticsAnalyzer:
    """Tracks packet count, byte volume, size distribution and time range."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.min_size: int | None = None
        self.max_size: int | None = None
        self.first_time: float | None = None
        self.last_time: float | None = None
        self._histogram = [0] * len(_LABELS)

    def add(self, pkt: PacketRecord) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.size
        self.min_size = pkt.size if self.min_size is None else min(self.min_size, pkt.size)
        self.max_size = pkt.size if self.max_size is None else max(self.max_size, pkt.size)
        ts = pkt.timestamp
        self.first_time = ts if self.first_time is None else min(self.first_time, ts)
        self.last_time = ts if self.last_time is None else max(self.last_time, ts)
        slot = next((i for i, bound in enumerate(_BOUNDS) if pkt.size <= bound), len(_BOUNDS))
        self._histogram[slot] += 1

    @property
    def duration(self) -> float:
        """Seconds between the earliest and latest packet timestamps."""
        if self.first_time is None or self.last_time is None:
            return 0.0
        return self.last_time - self.first_time

    def result(self, peak_pps: int | None = None) -> PacketStatistics:
        duration = self.duration
        n = self.total_packets
        return PacketStatistics(
            total_packets=n,
            total_bytes=self.total_bytes,
            min_packet_size=self.min_size,
            max_packet_size=self.max_size,
            mean_packet_size=round(self.total_bytes / n, 2) if n else None,
            avg_packets_per_second=round(n / duration, 3) if duration > 0 else None,
            avg_bits_per_second=round(self.total_bytes * 8 / duration, 2) if duration > 0 else None,
            peak_packets_per_second=peak_pps,
            size_distribution=[SizeBucket(label=l, packets=c) for l, c in zip(_LABELS, self._histogram)],
        )


def iso_time(ts: float | None) -> str | None:
    """Format an epoch timestamp as an ISO-8601 UTC string."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
