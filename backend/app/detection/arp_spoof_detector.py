"""Possible ARP spoofing."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector, span
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, ArpBinding, ArpMacBinding


class ArpSpoofDetector(BaseDetector):
    """Looks for IP addresses claimed by more than one MAC, and MACs claiming many IPs.

    Evidence (``arp_statistics``): per-IP distinct sender MACs, how often the claimed MAC
    changed, unsolicited replies (no matching request captured), gratuitous announcements,
    and ARP-sender-MAC vs Ethernet-source-MAC mismatches. Two MACs for one IP is the
    *gate*; confidence then rises with flip-flopping, unrequested announcements and
    mismatches. A single clean change (e.g. a DHCP re-lease) scores only INFO.
    """

    name = "arp_spoof"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.arp
        if not cfg.enabled:
            return []
        findings = [self._multi_mac(b) for b in result.arp_statistics.multi_mac_ips
                    if len(b.macs) >= cfg.min_macs_per_ip]
        findings += [self._multi_ip(m) for m in result.arp_statistics.multi_ip_macs
                     if m.ip_count >= cfg.multi_ip_min_ips]
        return findings

    def _multi_mac(self, b: ArpBinding) -> Finding:
        cfg = self.config.arp
        w = cfg.weights
        unrequested = b.unsolicited_replies + b.gratuitous_packets
        factors = [
            ("multiple_macs", 1.0, w["multiple_macs"], f"{len(b.macs)} MACs claimed {b.ip}"),
            ("binding_changes", ramp(b.binding_changes, 1, cfg.changes_full), w["binding_changes"],
             f"claimed MAC changed {b.binding_changes} time(s)"),
            ("unrequested_announcements", ramp(unrequested, 0, cfg.unrequested_full), w["unrequested_announcements"],
             f"{b.unsolicited_replies} unsolicited replies + {b.gratuitous_packets} gratuitous"),
            ("eth_mac_mismatch", ramp(b.eth_mismatch_packets, 0, cfg.mismatch_full), w["eth_mac_mismatch"],
             f"{b.eth_mismatch_packets} packets where ARP sender MAC != Ethernet source MAC"),
            ("mac_count", ramp(len(b.macs), cfg.min_macs_per_ip, cfg.strong_macs_per_ip), w["mac_count"],
             f"{len(b.macs)} distinct MACs"),
        ]
        first = min(m.first_time for m in b.macs)
        last = max(m.last_time for m in b.macs)
        macs = [{"mac": m.mac, "packets": m.packets} for m in b.macs]
        return self.build(
            type=FindingType.ARP_SPOOFING, factors=factors, max_severity=cfg.max_severity,
            title=f"Possible ARP spoofing: multiple MACs claim {b.ip}",
            description=(
                f"{len(b.macs)} different MAC addresses ({', '.join(m.mac for m in b.macs)}) announced themselves as "
                f"{b.ip}; the claimed MAC changed {b.binding_changes} time(s), with {b.unsolicited_replies} unsolicited "
                f"replies and {b.gratuitous_packets} gratuitous packets. This is consistent with possible ARP "
                f"spoofing/poisoning (or an IP conflict) and requires investigation."
            ),
            evidence={"ip": b.ip, "macs": macs, "binding_changes": b.binding_changes,
                      "unsolicited_replies": b.unsolicited_replies, "gratuitous_packets": b.gratuitous_packets,
                      "eth_mac_mismatch_packets": b.eth_mismatch_packets,
                      "duration_seconds": round(span(first, last), 3)},
            reasoning=[f"One IP address was asserted by {len(b.macs)} MACs (minimum {cfg.min_macs_per_ip}).",
                       "Repeated flip-flopping, unrequested announcements and MAC mismatches raise confidence."],
            caveats=["DHCP lease reassignment, failover pairs (VRRP/HSRP/keepalived), NIC teaming, VM migration and "
                     "duplicate static addresses all cause one IP to appear with several MACs.",
                     "Proxy ARP devices answer for addresses that are not their own."],
            recommendation=(f"Identify which MAC is legitimate for {b.ip} (switch CAM/DHCP records), check for an "
                            f"address conflict, and inspect the other MAC's port and vendor (OUI). Consider "
                            f"Dynamic ARP Inspection on switches if confirmed."),
            source_ip=b.ip, key=b.ip, first_seen=first, last_seen=last,
        )

    def _multi_ip(self, m: ArpMacBinding) -> Finding:
        cfg = self.config.arp
        w = cfg.multi_ip_weights
        factors = [
            ("ip_count", ramp(m.ip_count, cfg.multi_ip_min_ips, cfg.multi_ip_strong_ips), w["ip_count"],
             f"{m.ip_count} IPs claimed by one MAC"),
            ("unsolicited", ramp(m.unsolicited_replies, 0, cfg.multi_ip_unsolicited_full), w["unsolicited"],
             f"{m.unsolicited_replies} unsolicited replies"),
        ]
        return self.build(
            type=FindingType.ARP_MULTI_IP_MAC, factors=factors, max_severity=cfg.multi_ip_max_severity,
            title=f"One MAC address ({m.mac}) claims {m.ip_count} IP addresses",
            description=(
                f"MAC {m.mac} sent ARP packets as {m.ip_count} different IP addresses, including {m.unsolicited_replies} "
                f"unsolicited replies. This is consistent with possible ARP poisoning of several hosts, but also with "
                f"routers, proxy-ARP devices or hosts with IP aliases; it requires investigation."
            ),
            evidence={"mac": m.mac, "ip_count": m.ip_count, "sample_ips": m.ips[:20], "packets": m.packets,
                      "unsolicited_replies": m.unsolicited_replies},
            reasoning=[f"A single MAC asserted {m.ip_count} IPs (threshold {cfg.multi_ip_min_ips})."],
            caveats=["Gateways, load balancers, firewalls with proxy ARP, and virtualization hosts commonly do this."],
            recommendation=f"Confirm whether {m.mac} belongs to a router/proxy-ARP device; if not, trace its switch port.",
            key=m.mac,
        )
