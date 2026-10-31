import pcap_factory as pf
from detection_helpers import assert_well_formed
from app.detection import DetectionConfig, FindingType, Severity
from app.detection.config import ArpConfig

GW, GW_MAC = "10.0.0.1", "aa:aa:aa:aa:aa:01"
VICTIM, VICTIM_MAC = "10.0.0.5", "bb:bb:bb:bb:bb:05"
ATTACKER_MAC = "cc:cc:cc:cc:cc:99"


def of_type(findings, t):
    return [f for f in findings if f.type == t]


def normal_arp(t0=pf.T0):
    return [
        pf.arp_pkt(1, VICTIM_MAC, VICTIM, GW, ts=t0),
        pf.arp_pkt(2, GW_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=t0 + 0.01),
        pf.arp_pkt(1, GW_MAC, GW, VICTIM, ts=t0 + 5),
        pf.arp_pkt(2, VICTIM_MAC, VICTIM, GW, target_mac=GW_MAC, ts=t0 + 5.01),
    ]


def test_normal_arp_not_flagged(detect):
    findings, result = detect(normal_arp())
    assert findings == []
    assert result.arp_statistics.requests == 2 and result.arp_statistics.replies == 2
    assert result.arp_statistics.unsolicited_replies == 0


def test_poisoning_pattern_detected(detect):
    pk = normal_arp()
    for i in range(12):  # attacker repeatedly tells the victim "the gateway is at my MAC"
        pk.append(pf.arp_pkt(2, ATTACKER_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 10 + i * 2))
        pk.append(pf.arp_pkt(2, GW_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 11 + i * 2))  # real gateway answers
    findings, _ = detect(pk)
    (f,) = of_type(findings, FindingType.ARP_SPOOFING)
    assert f.source_ip == GW
    assert {m["mac"] for m in f.evidence["macs"]} == {GW_MAC, ATTACKER_MAC}
    assert f.evidence["binding_changes"] >= 20 and f.evidence["unsolicited_replies"] >= 11
    assert f.severity in (Severity.MEDIUM, Severity.HIGH) and f.confidence >= 0.6
    assert_well_formed(f)


def test_ethernet_mac_mismatch_raises_confidence(detect):
    base = normal_arp() + [pf.arp_pkt(2, ATTACKER_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 10)]
    spoofed = normal_arp() + [pf.arp_pkt(2, ATTACKER_MAC, GW, VICTIM, target_mac=VICTIM_MAC, eth_src="dd:dd:dd:dd:dd:dd", ts=pf.T0 + 10)]
    a = of_type(detect(base)[0], FindingType.ARP_SPOOFING)[0]
    b = of_type(detect(spoofed)[0], FindingType.ARP_SPOOFING)[0]
    assert b.evidence["eth_mac_mismatch_packets"] == 1 and b.confidence > a.confidence


def test_false_positive_single_clean_change_is_info_only(detect):
    """DHCP re-lease / NIC replacement: new MAC answers a request once. Reported, but low."""
    pk = normal_arp() + [
        pf.arp_pkt(1, VICTIM_MAC, VICTIM, GW, ts=pf.T0 + 20),
        pf.arp_pkt(2, "ee:ee:ee:ee:ee:01", GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 20.01),
    ]
    (f,) = of_type(detect(pk)[0], FindingType.ARP_SPOOFING)
    # request VICTIM->GW then reply GW is-at new mac: solicited, one change
    assert f.severity in (Severity.INFO, Severity.LOW) and f.confidence < 0.5


def test_probes_and_invalid_macs_ignored(detect):
    pk = [pf.arp_pkt(1, "bb:bb:bb:bb:bb:05", "0.0.0.0", VICTIM, ts=pf.T0),          # ARP probe
          pf.arp_pkt(1, "bb:bb:bb:bb:bb:06", "0.0.0.0", VICTIM, ts=pf.T0 + 1),
          pf.arp_pkt(2, "00:00:00:00:00:00", GW, VICTIM, ts=pf.T0 + 2),             # invalid sender MAC
          pf.arp_pkt(2, GW_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 3)]
    findings, result = detect(pk)
    assert findings == [] and result.arp_statistics.unique_ips == 1


def test_gratuitous_arp_counted(detect):
    pk = [pf.arp_pkt(2, GW_MAC, GW, GW, target_mac="ff:ff:ff:ff:ff:ff", ts=pf.T0),
          pf.arp_pkt(2, ATTACKER_MAC, GW, GW, target_mac="ff:ff:ff:ff:ff:ff", ts=pf.T0 + 1)]
    findings, result = detect(pk)
    assert result.arp_statistics.gratuitous_packets == 2
    (f,) = of_type(findings, FindingType.ARP_SPOOFING)
    assert f.evidence["gratuitous_packets"] == 2


def test_one_mac_claiming_many_ips(detect):
    pk = [pf.arp_pkt(2, ATTACKER_MAC, f"10.0.0.{10 + i}", VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + i) for i in range(8)]
    findings, _ = detect(pk)
    (f,) = of_type(findings, FindingType.ARP_MULTI_IP_MAC)
    assert f.evidence["ip_count"] == 8 and f.evidence["mac"] == ATTACKER_MAC
    assert f.severity.rank <= Severity.MEDIUM.rank
    assert_well_formed(f)


def test_few_ips_per_mac_not_flagged(detect):
    pk = [pf.arp_pkt(2, ATTACKER_MAC, f"10.0.0.{10 + i}", VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + i) for i in range(4)]
    assert of_type(detect(pk)[0], FindingType.ARP_MULTI_IP_MAC) == []


def test_config_min_macs_and_disable(detect):
    pk = normal_arp() + [pf.arp_pkt(2, ATTACKER_MAC, GW, VICTIM, target_mac=VICTIM_MAC, ts=pf.T0 + 10)]
    assert of_type(detect(pk)[0], FindingType.ARP_SPOOFING)
    assert detect(pk, DetectionConfig(arp=ArpConfig(min_macs_per_ip=3)))[0] == []
    assert detect(pk, DetectionConfig(arp=ArpConfig(enabled=False)))[0] == []
