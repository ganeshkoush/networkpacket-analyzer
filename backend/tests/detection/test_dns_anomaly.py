import random

import pcap_factory as pf
from detection_helpers import assert_well_formed
from app.analysis.dns_analyzer import longest_consonant_run, looks_random, shannon_entropy
from app.detection import DetectionConfig, FindingType
from app.detection.config import DnsConfig

CLIENT, SERVER = "10.0.0.5", "8.8.8.8"


def of_type(findings, t):
    return [f for f in findings if f.type == t]


def lookups(names, client=CLIENT, t0=pf.T0, step=0.2, rcode=0, qtype="A"):
    """A query + response per name."""
    pk = []
    for i, name in enumerate(names):
        t = t0 + i * step
        sport = 20000 + i
        pk.append(pf.dns_query(client, SERVER, name, txid=i + 1, sport=sport, qtype=qtype, ts=t))
        pk.append(pf.dns_response(client, SERVER, name, txid=i + 1, dport=sport, rcode=rcode,
                                  answers=("93.184.216.34",) if rcode == 0 else (), ts=t + 0.02))
    return pk


# ----------------------------------------------------------------- normal
def test_normal_dns_not_flagged(detect):
    names = [f"{w}.example.com" for w in ("www", "mail", "api", "cdn", "login", "docs", "status", "img")] * 5
    findings, _ = detect(lookups(names, step=0.5))
    assert findings == []


def test_legitimate_long_names_do_not_look_random():
    # Plain entropy can't tell these from random strings (all > 3.3); the digit/consonant-run signal can.
    for name in ("internationalbusinessmachines", "stackoverflow", "developerdocumentation", "cloudflarenetworks",
                 "telecommunicationsnetwork", "universityofcalifornia", "wikipediaorganization"):
        assert not looks_random(name), name
    rng = random.Random(1)
    assert looks_random(pf.random_label(rng, 24))
    assert not looks_random("x7k2q9")  # too short to judge


def test_entropy_and_consonant_helpers():
    assert shannon_entropy("") == 0 and shannon_entropy("aaaa") == 0 and abs(shannon_entropy("abcd") - 2) < 1e-9
    assert longest_consonant_run("strengths") == 5 and longest_consonant_run("aeiou") == 0


# ----------------------------------------------------------------- NXDOMAIN
def test_nxdomain_storm_detected(detect):
    rng = random.Random(1)
    names = [f"{pf.random_label(rng, 8)}.example.net" for _ in range(60)]
    findings, _ = detect(lookups(names, rcode=3))
    (f,) = of_type(findings, FindingType.DNS_HIGH_NXDOMAIN)
    assert f.source_ip == CLIENT and f.evidence["nxdomain"] == 60 and f.evidence["nxdomain_ratio"] == 1.0
    assert_well_formed(f)


def test_nxdomain_edges_and_false_positives(detect):
    # few responses -> below the volume gate even though 100% NXDOMAIN
    assert of_type(detect(lookups([f"a{i}.test.org" for i in range(10)], rcode=3))[0], FindingType.DNS_HIGH_NXDOMAIN) == []
    # many responses but a normal ratio (20% NXDOMAIN)
    ok = lookups([f"h{i}.test.org" for i in range(40)]) + lookups([f"x{i}.test.org" for i in range(10)], rcode=3, t0=pf.T0 + 100)
    assert of_type(detect(ok)[0], FindingType.DNS_HIGH_NXDOMAIN) == []


# ----------------------------------------------------------------- DGA
def test_dga_like_domains_detected(detect):
    rng = random.Random(7)
    names = [f"{pf.random_label(rng, 20)}.com" for _ in range(25)]
    findings, _ = detect(lookups(names, rcode=3))
    (f,) = of_type(findings, FindingType.DNS_DGA_LIKE)
    assert f.source_ip == CLIENT and f.evidence["random_looking_domains"] == 25
    assert len(f.evidence["sample_domains"]) >= 3
    assert f.confidence >= 0.6
    assert_well_formed(f)


def test_dga_not_triggered_by_few_random_domains_or_normal_names(detect):
    rng = random.Random(7)
    few = [f"{pf.random_label(rng, 20)}.com" for _ in range(4)]  # below min_domains (5)
    assert of_type(detect(lookups(few))[0], FindingType.DNS_DGA_LIKE) == []
    words = [f"{w}.com" for w in ("internationalbusinessmachines", "stackoverflow", "accountprotection",
                                  "microsoftonline", "wikipediaorganization", "newspaperarchive")] * 2
    assert of_type(detect(lookups(words))[0], FindingType.DNS_DGA_LIKE) == []


def test_dga_confidence_higher_when_names_fail_to_resolve(detect):
    rng = random.Random(3)
    names = [f"{pf.random_label(rng, 20)}.com" for _ in range(15)]
    fail = of_type(detect(lookups(names, rcode=3))[0], FindingType.DNS_DGA_LIKE)[0]
    ok = of_type(detect(lookups(names, rcode=0))[0], FindingType.DNS_DGA_LIKE)[0]
    assert fail.confidence > ok.confidence


# ----------------------------------------------------------------- tunneling
def test_tunneling_like_pattern_detected(detect):
    rng = random.Random(11)
    names = [f"{pf.random_label(rng, 45)}.t.evil-example.com" for _ in range(120)]
    findings, _ = detect(lookups(names, qtype="TXT", step=0.05))
    (f,) = of_type(findings, FindingType.DNS_TUNNELING_LIKE)
    assert f.source_ip == CLIENT and f.evidence["base_domain"] == "evil-example.com"
    assert f.evidence["unique_names"] == 120 and f.evidence["txt_null_queries"] == 120
    assert f.confidence >= 0.6
    assert_well_formed(f)
    bigger = [f"{pf.random_label(rng, 45)}.t.evil-example.com" for _ in range(600)]
    (g,) = of_type(detect(lookups(bigger, qtype="TXT", step=0.01))[0], FindingType.DNS_TUNNELING_LIKE)
    assert g.confidence > f.confidence  # more unique names -> more confident


def test_cdn_style_short_labels_not_tunneling(detect):
    names = [f"a{i:05d}.cdn.example.com" for i in range(120)]  # many unique names but short, plain A queries
    assert of_type(detect(lookups(names, step=0.05))[0], FindingType.DNS_TUNNELING_LIKE) == []


def test_reverse_lookups_and_allowlist_ignored(detect):
    rng = random.Random(5)
    arpa = [f"{pf.random_label(rng, 30)}.in-addr.arpa" for _ in range(80)]
    assert of_type(detect(lookups(arpa, qtype="TXT", step=0.05))[0], FindingType.DNS_TUNNELING_LIKE) == []
    names = [f"{pf.random_label(rng, 45)}.t.vendor-av.com" for _ in range(80)]
    cfg = DetectionConfig(dns=DnsConfig(allowlisted_base_domains=["vendor-av.com"]))
    pk = lookups(names, qtype="TXT", step=0.05)
    assert of_type(detect(pk)[0], FindingType.DNS_TUNNELING_LIKE)
    assert of_type(detect(pk, cfg)[0], FindingType.DNS_TUNNELING_LIKE) == []


def test_few_names_below_threshold(detect):
    rng = random.Random(2)
    names = [f"{pf.random_label(rng, 45)}.t.example.org" for _ in range(30)]
    assert of_type(detect(lookups(names, qtype="TXT"))[0], FindingType.DNS_TUNNELING_LIKE) == []


# ----------------------------------------------------------------- excessive queries
def test_excessive_query_rate_detected_and_slow_rate_ignored(detect):
    fast = [pf.dns_query(CLIENT, SERVER, f"n{i % 40}.example.com", txid=i, sport=20000 + i % 3000, ts=pf.T0 + i * 0.005)
            for i in range(700)]
    (f,) = of_type(detect(fast)[0], FindingType.DNS_EXCESSIVE_QUERIES)
    assert f.evidence["queries"] == 700 and f.evidence["queries_per_second"] >= 100
    assert_well_formed(f)
    slow = [pf.dns_query(CLIENT, SERVER, f"n{i % 40}.example.com", txid=i, sport=20000 + i % 3000, ts=pf.T0 + i * 2)
            for i in range(700)]
    assert of_type(detect(slow)[0], FindingType.DNS_EXCESSIVE_QUERIES) == []


# ----------------------------------------------------------------- unsolicited responses
def test_unsolicited_responses_detected(detect):
    pk = [pf.dns_response(CLIENT, SERVER, f"x{i}.example.com", txid=i, dport=30000 + i, ts=pf.T0 + i * 0.1) for i in range(40)]
    (f,) = of_type(detect(pk)[0], FindingType.DNS_UNSOLICITED_RESPONSES)
    assert f.evidence["responses_without_query"] == 40 and f.evidence["share"] == 1.0
    assert_well_formed(f)


def test_unsolicited_edges(detect):
    few = [pf.dns_response(CLIENT, SERVER, f"x{i}.example.com", txid=i, dport=30000 + i, ts=pf.T0 + i) for i in range(19)]
    assert of_type(detect(few)[0], FindingType.DNS_UNSOLICITED_RESPONSES) == []
    matched = lookups([f"x{i}.example.com" for i in range(40)])
    assert detect(matched)[0] == []
