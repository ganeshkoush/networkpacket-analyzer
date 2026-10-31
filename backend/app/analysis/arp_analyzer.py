"""ARP statistics: IP-to-MAC bindings, gratuitous/unsolicited replies, MAC/Ethernet mismatches."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import ArpBinding, ArpMacBinding, ArpMacUse, ArpStatistics

_MAX_TRACKED_IPS = 50_000
_MAX_PENDING_REQUESTS = 100_000
_MAX_IPS_PER_MAC = 200
_IGNORED_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


@dataclass(slots=True)
class _IpBinding:
    macs: dict[str, list] = field(default_factory=dict)  # mac -> [packets, first, last]
    last_mac: str | None = None
    changes: int = 0
    unsolicited: int = 0
    gratuitous: int = 0
    mismatch: int = 0


@dataclass(slots=True)
class _MacBinding:
    ips: set[str] = field(default_factory=set)
    packets: int = 0
    unsolicited: int = 0


class ArpAnalyzer:
    """Tracks which MAC addresses claim which IP addresses via ARP.

    Probes (sender IP 0.0.0.0) and invalid sender MACs are ignored for binding purposes.
    A reply is *unsolicited* when no still-unanswered request from its target to its sender
    was seen earlier in the capture (each request justifies one reply); gratuitous packets (sender IP == target IP) are counted apart.
    """

    def __init__(self, max_profiles: int = 100) -> None:
        self.max_profiles = max_profiles
        self._total = self._requests = self._replies = 0
        self._gratuitous = self._unsolicited = 0
        self._ips: dict[str, _IpBinding] = {}
        self._macs: dict[str, _MacBinding] = {}
        self._pending: set[tuple[str, str]] = set()  # (requester ip, asked ip)
        self._ips_dropped = 0

    def add(self, pkt: PacketRecord) -> None:
        if pkt.arp_op is None:
            return
        self._total += 1
        op = pkt.arp_op
        sender_ip, target_ip = pkt.arp_sender_ip, pkt.arp_target_ip
        mac = pkt.arp_sender_mac
        if op == 1:
            self._requests += 1
        elif op == 2:
            self._replies += 1
        gratuitous = bool(sender_ip and sender_ip == target_ip)
        if gratuitous:
            self._gratuitous += 1

        if op == 1 and sender_ip and target_ip and len(self._pending) < _MAX_PENDING_REQUESTS:
            self._pending.add((sender_ip, target_ip))
        unsolicited = False
        if op == 2 and not gratuitous and sender_ip and target_ip:
            if (target_ip, sender_ip) in self._pending:
                self._pending.discard((target_ip, sender_ip))  # one reply answers one request
            else:
                unsolicited = True
        if unsolicited:
            self._unsolicited += 1

        if not sender_ip or sender_ip == "0.0.0.0" or not mac or mac in _IGNORED_MACS:
            return
        binding = self._ips.get(sender_ip)
        if binding is None:
            if len(self._ips) >= _MAX_TRACKED_IPS:
                self._ips_dropped += 1
                return
            binding = self._ips[sender_ip] = _IpBinding()
        use = binding.macs.get(mac)
        if use is None:
            binding.macs[mac] = [1, pkt.timestamp, pkt.timestamp]
        else:
            use[0] += 1
            use[1], use[2] = min(use[1], pkt.timestamp), max(use[2], pkt.timestamp)
        if binding.last_mac is not None and binding.last_mac != mac:
            binding.changes += 1
        binding.last_mac = mac
        if gratuitous:
            binding.gratuitous += 1
        if unsolicited:
            binding.unsolicited += 1
        if pkt.eth_src and pkt.eth_src != mac:
            binding.mismatch += 1

        mb = self._macs.get(mac)
        if mb is None:
            mb = self._macs[mac] = _MacBinding()
        mb.packets += 1
        if len(mb.ips) < _MAX_IPS_PER_MAC:
            mb.ips.add(sender_ip)
        if unsolicited:
            mb.unsolicited += 1

    def result(self) -> ArpStatistics:
        multi = sorted(
            ((ip, b) for ip, b in self._ips.items() if len(b.macs) > 1),
            key=lambda kv: (kv[1].changes, len(kv[1].macs)), reverse=True,
        )[: self.max_profiles]
        multi_mac_ips = [
            ArpBinding(
                ip=ip,
                macs=[ArpMacUse(mac=m, packets=u[0], first_time=u[1], last_time=u[2])
                      for m, u in sorted(b.macs.items(), key=lambda kv: kv[1][1])],
                binding_changes=b.changes, unsolicited_replies=b.unsolicited,
                gratuitous_packets=b.gratuitous, eth_mismatch_packets=b.mismatch,
            )
            for ip, b in multi
        ]
        multi_ip = sorted(
            ((m, b) for m, b in self._macs.items() if len(b.ips) > 1),
            key=lambda kv: len(kv[1].ips), reverse=True,
        )[: self.max_profiles]
        return ArpStatistics(
            total_packets=self._total,
            requests=self._requests,
            replies=self._replies,
            gratuitous_packets=self._gratuitous,
            unsolicited_replies=self._unsolicited,
            unique_ips=len(self._ips),
            multi_mac_ips=multi_mac_ips,
            multi_ip_macs=[
                ArpMacBinding(mac=m, ip_count=len(b.ips), ips=sorted(b.ips)[:50],
                              packets=b.packets, unsolicited_replies=b.unsolicited)
                for m, b in multi_ip
            ],
            ips_not_tracked=self._ips_dropped,
        )
