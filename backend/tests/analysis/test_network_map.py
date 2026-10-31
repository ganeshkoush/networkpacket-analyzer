"""Network map: hierarchy, local host, filters, health state, node budget, applications. Hand-made connections."""
import pytest

from app.analysis.network_map import build_network_map
from app.detection.models import Finding, FindingType
from app.detection.severity import Severity
from app.models.analysis import Connection, DomainPerformance, PerformanceMetrics, PerformanceStatistics
from app.models.process import ConnectionProcessMatch
from detection_helpers import T0, blank_result

LOCAL = "192.168.1.10"
GH, YT, CDN = "140.82.112.3", "142.250.80.46", "151.101.1.69"


def conn(cid, remote=GH, rport=443, *, domain="github.com", local=LOCAL, lport=50000, proto="TCP", bytes=10_000, start=T0 + 1, end=T0 + 30,
         hs=40.0, retr=0, status="completed", reason=None, inbound=False):
    client, cport, server, sport = (remote, rport, local, lport) if inbound else (local, lport, remote, rport)
    return Connection(id=cid, protocol=proto, client_ip=client, client_port=cport, server_ip=server, server_port=sport, packets=20, bytes=bytes,
                      packets_client_to_server=10, packets_server_to_client=10, bytes_client_to_server=bytes // 2, bytes_server_to_client=bytes // 2,
                      start_time=start, end_time=end, duration_seconds=end - start, domain=domain, tcp_handshake_time_ms=hs, retransmissions=retr,
                      handshake_status=status if proto == "TCP" else None, handshake_incomplete_reason=reason, state="ESTABLISHED" if proto == "TCP" else None)


def result(conns, rtts=None, domains=()):
    r = blank_result(connections=list(conns))
    r.metadata.first_packet_time, r.metadata.last_packet_time = T0, T0 + 100
    r.performance_statistics = PerformanceStatistics(
        metrics=[PerformanceMetrics(connection_id=k, protocol="TCP", avg_rtt_ms=v) for k, v in (rtts or {}).items()], domains=list(domains))
    return r


def finding(ip, *, dst=None, first=None, last=None, fid="PORT_SCAN-1", title="Possible port scan"):
    return Finding(id=fid, type=FindingType.PORT_SCAN, severity=Severity.HIGH, confidence=0.9, source_ip=ip, destination_ip=dst, title=title, description="d",
                   recommendation="r", detector="d", first_seen=first, last_seen=last)


def node(m, nid):
    return next(n for n in m.nodes if n.id == nid)


def edge(m, a, b):
    return next(e for e in m.edges if e.id == f"{a}>{b}")


def check_integrity(m):
    ids = [n.id for n in m.nodes]
    assert len(ids) == len(set(ids)) and "local" in ids or not m.nodes
    assert all(e.source in ids and e.target in ids for e in m.edges)
    assert len({e.id for e in m.edges}) == len(m.edges)


# ------------------------------------------------------------------ hierarchy and edge facts
def test_local_domain_ip_port_hierarchy_with_edge_facts():
    r = result([conn("a", bytes=6000), conn("b", bytes=4000, lport=50001)], rtts={"a": 70.0, "b": 74.0})
    m = build_network_map(r, [])
    # an address with a single port carries it in its label: no separate port node
    assert [(n.tier, n.kind, n.label) for n in m.nodes] == [(0, "local", LOCAL), (2, "domain", "github.com"), (3, "ip", f"{GH}:443")]
    assert {e.id for e in m.edges} == {f"local>domain:github.com", f"domain:github.com>ip:{GH}"}
    to_domain = edge(m, "local", "domain:github.com")
    assert (to_domain.connections, to_domain.bytes, to_domain.protocol, to_domain.ports, to_domain.latency_ms, to_domain.latency_kind) == (2, 10_000, "TCP", [443], 72.0, "rtt")
    addr = node(m, f"ip:{GH}")
    assert (addr.ip, addr.port, addr.protocol, addr.connections, addr.bytes) == (GH, 443, "TCP", 2, 10_000) and addr.connection_ids == ["a", "b"]
    assert edge(m, "domain:github.com", f"ip:{GH}").ports == [443]
    assert node(m, "domain:github.com").domain == "github.com" and node(m, "domain:github.com").sublabel == "1 address"
    assert m.total_connections == 2 and m.shown_connections == 2 and m.local == LOCAL and not m.hidden.destinations
    check_integrity(m)


def test_an_address_shared_by_two_domains_is_one_node_with_two_parents():
    r = result([conn("a", CDN, domain="github.com"), conn("b", CDN, domain="youtube.com", lport=50001)])
    m = build_network_map(r, [])
    assert [n.ip for n in m.nodes if n.kind == "ip"] == [CDN]
    assert {e.source for e in m.edges if e.target == f"ip:{CDN}"} == {"domain:github.com", "domain:youtube.com"}
    assert node(m, f"ip:{CDN}").connections == 2
    check_integrity(m)


def test_connections_without_a_domain_attach_the_address_to_the_local_host_directly():
    m = build_network_map(result([conn("a", "203.0.113.9", 8080, domain=None)]), [])
    assert [n.kind for n in m.nodes] == ["local", "ip"] and node(m, "ip:203.0.113.9").label == "203.0.113.9:8080" and {e.id for e in m.edges} == {"local>ip:203.0.113.9"}
    assert not any(n.kind == "domain" for n in m.nodes)


def test_latency_prefers_rtt_and_falls_back_to_handshake_without_mixing_them():
    both = build_network_map(result([conn("a", hs=40.0), conn("b", hs=900.0, lport=50001)], rtts={"a": 70.0}), [])
    e = edge(both, "local", "domain:github.com")
    assert (e.latency_ms, e.latency_kind) == (70.0, "rtt")             # b's handshake is not averaged in
    hs_only = build_network_map(result([conn("a", hs=40.0), conn("b", hs=60.0, lport=50001)]), [])
    e = edge(hs_only, "local", "domain:github.com")
    assert (e.latency_ms, e.latency_kind) == (50.0, "handshake")
    none = build_network_map(result([conn("a", hs=None)]), [])
    assert edge(none, "local", "domain:github.com").latency_ms is None


def test_udp_and_multiple_protocols_and_ports_on_one_address():
    r = result([conn("t", GH, 443), conn("u", GH, 443, proto="UDP", lport=50001, hs=None), conn("p", GH, 8443, lport=50002)])
    m = build_network_map(r, [])
    assert {n.label for n in m.nodes if n.kind == "port"} == {"TCP/443", "UDP/443", "TCP/8443"}
    e = edge(m, f"domain:github.com", f"ip:{GH}")
    assert e.protocol == "TCP+UDP" and e.ports[0] == 443 and set(e.ports) == {443, 8443}


def test_non_tcp_udp_and_portless_connections_are_not_drawn():
    icmp = Connection(**{**conn("i").model_dump(), "protocol": "ICMP", "client_port": None, "server_port": None})
    m = build_network_map(result([icmp]), [])
    assert m.nodes == [] and m.total_connections == 0 and any("no TCP or UDP connections" in n for n in m.notes)


# ------------------------------------------------------------------ the local host
def test_local_hosts_are_ranked_and_the_busiest_is_the_default():
    r = result([conn("a"), conn("b", lport=1), conn("c", local="192.168.1.20", lport=2)])
    m = build_network_map(r, [])
    assert m.local == LOCAL and [(o.ip, o.connections) for o in m.local_hosts] == [(LOCAL, 2), ("192.168.1.20", 1)] and node(m, "local").label == LOCAL
    other = build_network_map(r, [], local="192.168.1.20")
    assert other.local == "192.168.1.20" and other.shown_connections == 1
    everyone = build_network_map(r, [], local="all")
    assert everyone.local == "all" and node(everyone, "local").label == "Local network" and everyone.shown_connections == 3
    assert build_network_map(r, [], local="10.9.9.9").nodes == []


def test_the_private_end_is_local_even_when_the_remote_side_connected_first():
    m = build_network_map(result([conn("in", "45.33.32.156", 22, domain=None, inbound=True, lport=22)]), [])   # a real public address (203.0.113/24 counts as private)
    assert m.local == LOCAL and node(m, "local").label == LOCAL and node(m, "ip:45.33.32.156").ip == "45.33.32.156"


# ------------------------------------------------------------------ filters
def filtered():
    return result([conn("a", GH, 443, domain="github.com", start=T0 + 1, end=T0 + 10), conn("b", YT, 443, domain="youtube.com", lport=50001, start=T0 + 50, end=T0 + 60, proto="UDP", hs=None),
                   conn("c", "203.0.113.9", 8080, domain=None, lport=50002, start=T0 + 80, end=T0 + 90)])


def labels(m, kind):
    return sorted(n.label for n in m.nodes if n.kind == kind)


def ips(m):
    return sorted(n.ip for n in m.nodes if n.kind == "ip")


def test_protocol_filter():
    assert labels(build_network_map(filtered(), [], protocol="UDP"), "domain") == ["youtube.com"]
    assert labels(build_network_map(filtered(), [], protocol="TCP"), "domain") == ["github.com"]


def test_time_range_keeps_connections_active_in_it():
    r = filtered()
    assert labels(build_network_map(r, [], start=T0 + 45, end=T0 + 70), "domain") == ["youtube.com"]
    assert ips(build_network_map(r, [], start=T0 + 85)) == ["203.0.113.9"]            # still running at 85-90
    assert labels(build_network_map(r, [], end=T0 + 5), "domain") == ["github.com"]
    assert build_network_map(r, [], start=T0 + 95).nodes == []
    m = build_network_map(r, [], start=T0 + 45, end=T0 + 70)
    assert (m.applied_start, m.applied_end, m.capture_start, m.capture_end) == (T0 + 45, T0 + 70, T0, T0 + 100)
    assert any("whole lifetime" in n for n in m.notes)


def test_search_matches_domains_addresses_and_ports_and_all_words_must_match():
    r = filtered()
    assert labels(build_network_map(r, [], search="YOUTUBE"), "domain") == ["youtube.com"]
    assert ips(build_network_map(r, [], search="203.0.113")) == ["203.0.113.9"]
    assert ips(build_network_map(r, [], search="8080")) == ["203.0.113.9"]
    assert labels(build_network_map(r, [], search="github 443"), "domain") == ["github.com"]
    assert build_network_map(r, [], search="github 8080").nodes == []
    empty = build_network_map(r, [], search="nothing-like-this")
    assert empty.nodes == [] and any("No connections match" in n for n in empty.notes)


def test_filters_combine():
    assert ips(build_network_map(filtered(), [], protocol="TCP", search="203")) == ["203.0.113.9"]
    assert build_network_map(filtered(), [], protocol="UDP", search="github").nodes == []


# ------------------------------------------------------------------ health state
def test_state_is_healthy_only_when_something_was_measured():
    measured = build_network_map(result([conn("a", hs=40.0)]), [])
    assert node(measured, "domain:github.com").state == "healthy" or node(measured, f"ip:{GH}").state == "healthy"
    unmeasured = build_network_map(result([conn("a", hs=None, proto="UDP")]), [])
    assert {n.state for n in unmeasured.nodes if n.kind in ("ip", "port")} == {"unknown"}


def test_failed_handshakes_and_retransmissions_make_a_node_degraded_with_reasons():
    r = result([conn("a", status="incomplete", reason="no_synack", hs=None), conn("b", retr=5, lport=50001), conn("c", lport=50002), conn("d", lport=50003)])
    m = build_network_map(r, [])
    addr = node(m, f"ip:{GH}")
    assert addr.state == "degraded" and any("did not complete" in x for x in addr.state_reasons) and any("5 retransmitted segments" in x for x in addr.state_reasons)
    assert edge(m, "domain:github.com", f"ip:{GH}").state == "degraded"
    one_in_ten = build_network_map(result([conn("a", status="incomplete", reason="no_synack", hs=None)] + [conn(f"x{i}", lport=51000 + i) for i in range(9)]), [])
    assert node(one_in_ten, f"ip:{GH}").state == "healthy"        # 10 % is below the 25 % share


def test_a_domain_the_health_rules_rate_poor_is_degraded():
    poor = DomainPerformance(domain="github.com", connections=3, tcp_handshake_ms=450.0, handshake_samples=3, avg_rtt_ms=400.0, rtt_samples=40)
    m = build_network_map(result([conn("a")], domains=[poor]), [])
    d = node(m, "domain:github.com")
    assert d.state == "degraded" and any("handshake" in x.lower() or "RTT" in x for x in d.state_reasons)
    good = DomainPerformance(domain="github.com", connections=3, tcp_handshake_ms=30.0, handshake_samples=3, avg_rtt_ms=40.0, rtt_samples=40)
    assert node(build_network_map(result([conn("a")], domains=[good]), []), "domain:github.com").state == "healthy"


def test_an_address_named_by_a_finding_is_suspicious_down_the_tree_and_the_finding_is_listed():
    r = result([conn("a", "203.0.113.9", 22, domain="evil.example", lport=50001), conn("b", GH)])
    f = finding("203.0.113.9", dst=LOCAL)
    m = build_network_map(r, [f])
    bad = {n.id: n for n in m.nodes}
    assert bad["ip:203.0.113.9"].state == "suspicious" and bad["domain:evil.example"].state == "suspicious"
    assert bad["ip:203.0.113.9"].finding_ids == ["PORT_SCAN-1"] and any("Possible port scan" in x for x in bad["ip:203.0.113.9"].state_reasons)
    assert bad["domain:github.com"].state != "suspicious" and bad[f"ip:{GH}"].state != "suspicious"
    assert edge(m, "local", "domain:evil.example").state == "suspicious"
    assert [x.id for x in m.findings] == ["PORT_SCAN-1"] and m.findings[0].severity == "HIGH"
    assert [c.health for c in m.connections if c.id == "a"] == ["suspicious"]


def test_the_local_host_is_suspicious_only_if_a_finding_names_it():
    r = result([conn("a", "203.0.113.9", 22, domain=None)])
    assert node(build_network_map(r, [finding("203.0.113.9")]), "local").state != "suspicious"      # it merely talked to a flagged address
    named = node(build_network_map(r, [finding("203.0.113.9", dst=LOCAL)]), "local")
    assert named.state == "suspicious" and named.finding_ids == ["PORT_SCAN-1"]


def test_findings_outside_the_time_range_are_not_shown():
    r = result([conn("a", "203.0.113.9", 22, domain=None, start=T0 + 1, end=T0 + 5)])
    f = finding("203.0.113.9", first=T0 + 80, last=T0 + 90)
    assert node(build_network_map(r, [f]), "ip:203.0.113.9").state == "suspicious"
    assert node(build_network_map(r, [f], start=T0, end=T0 + 10), "ip:203.0.113.9").state != "suspicious"


def test_a_flagged_address_without_connection_detail_is_pinned_as_a_bare_node():
    m = build_network_map(result([conn("a")]), [finding("45.33.32.156", dst=LOCAL)])
    bare = node(m, "ip:45.33.32.156")
    assert bare.detail_available is False and bare.state == "suspicious" and bare.connections == 0 and bare.finding_ids == ["PORT_SCAN-1"]
    assert edge(m, "local", "ip:45.33.32.156").connections == 0
    assert not any(n.id == f"ip:{LOCAL}" for n in m.nodes)                     # the local host itself is not drawn as a destination
    assert not any(n.detail_available is False for n in build_network_map(result([conn("a")]), [finding("45.33.32.156")], search="github").nodes)
    check_integrity(m)


def test_health_filter():
    r = result([conn("a", status="incomplete", reason="reset", hs=None), conn("b", GH, lport=50001, domain="github.com"), conn("c", "203.0.113.9", 22, domain=None, lport=50002)])
    f = [finding("203.0.113.9")]
    assert {c.id for c in build_network_map(r, f, health="suspicious").connections} == {"c"}
    assert {c.id for c in build_network_map(r, f, health="degraded").connections} == {"a"}
    assert {c.id for c in build_network_map(r, f, health="healthy").connections} == {"b"}


# ------------------------------------------------------------------ the node budget
def many(n=100):
    return [conn(f"c{i}", f"198.51.{i // 200}.{i % 200 + 1}", 443, domain=f"site{i:03d}.example.com", lport=40000 + i, bytes=1000 + i * 10) for i in range(n)]


def test_the_map_never_grows_past_its_budget_and_folds_the_rest():
    m = build_network_map(result(many()), [], max_nodes=20)
    assert len(m.nodes) <= 20 and m.hidden.destinations > 80 and m.hidden.connections == m.hidden.destinations
    other = node(m, "other")
    assert other.kind == "other" and other.members == m.hidden.destinations and other.bytes == m.hidden.bytes and "narrow the filters" in other.state_reasons[0]
    assert edge(m, "local", "other").connections == m.hidden.connections
    assert m.shown_connections + m.hidden.connections == m.total_connections
    assert any("folded into one node" in n for n in m.notes)
    check_integrity(m)


def test_the_highest_traffic_destinations_are_kept():
    m = build_network_map(result(many()), [], max_nodes=20)
    domains = labels(m, "domain")
    assert "site099.example.com" in domains and "site000.example.com" not in domains


def test_a_flagged_destination_is_never_folded_away_even_if_tiny():
    conns = many() + [conn("tiny", "203.0.113.99", 22, domain="tiny.example", lport=39999, bytes=1)]
    m = build_network_map(result(conns), [finding("203.0.113.99")], max_nodes=20)
    assert "tiny.example" in labels(m, "domain") and node(m, "ip:203.0.113.99").state == "suspicious"


def test_a_small_map_has_no_other_node():
    m = build_network_map(result(many(5)), [], max_nodes=60)
    assert not any(n.kind == "other" for n in m.nodes) and m.hidden.destinations == 0


def test_connection_ids_per_node_are_bounded():
    m = build_network_map(result([conn(f"c{i}", lport=40000 + i) for i in range(60)]), [])
    assert len(node(m, f"ip:{GH}").connection_ids) == 25 and node(m, f"ip:{GH}").connections == 60 and len(m.connections) == 60


# ------------------------------------------------------------------ applications (OS information only)
def match(cid, app, process="Helper"):
    return ConnectionProcessMatch(connection_id=cid, process_name=process, pid=1, application=app, confidence="HIGH", snapshots_matched=1, reason="x")


def test_applications_become_a_tier_between_the_local_host_and_the_domains():
    r = result([conn("a"), conn("b", YT, domain="youtube.com", lport=50001), conn("c", GH, lport=50002)])
    m = build_network_map(r, [], matches={"a": match("a", "Visual Studio Code"), "b": match("b", "Google Chrome"), "c": match("c", "Visual Studio Code")})
    apps = [n for n in m.nodes if n.kind == "application"]
    assert {(n.label, n.tier, n.connections) for n in apps} == {("Visual Studio Code", 1, 2), ("Google Chrome", 1, 1)}
    assert {e.id for e in m.edges} >= {"local>app:Visual Studio Code", "app:Visual Studio Code>domain:github.com", "app:Google Chrome>domain:youtube.com"}
    assert "local>domain:github.com" not in {e.id for e in m.edges}
    assert [(c.application, c.process_name) for c in m.connections if c.id == "a"] == [("Visual Studio Code", "Helper")]
    check_integrity(m)


def test_unmatched_connections_keep_the_direct_path_and_a_plain_process_name_is_used_without_an_app_bundle():
    r = result([conn("a"), conn("b", YT, domain="youtube.com", lport=50001)])
    m = build_network_map(r, [], matches={"a": match("a", None, "curl")})
    assert [n.label for n in m.nodes if n.kind == "application"] == ["curl"]
    assert "local>domain:youtube.com" in {e.id for e in m.edges}


def test_without_process_information_there_are_no_application_nodes_and_the_reason_is_reported():
    m = build_network_map(result([conn("a")]), [], applications_status="Process information unavailable: no local process snapshot has been taken.")
    assert not any(n.kind == "application" for n in m.nodes)
    assert m.applications_status.startswith("Process information unavailable") and any("Process information unavailable" in n for n in m.notes)


def test_application_nodes_are_capped():
    conns = [conn(f"c{i}", f"198.51.100.{i + 1}", 443, domain=f"d{i}.example", lport=40000 + i, bytes=1000 + i) for i in range(20)]
    m = build_network_map(result(conns), [], matches={c.id: match(c.id, f"App{i:02d}") for i, c in enumerate(conns)}, max_nodes=200)
    labels_ = [n.label for n in m.nodes if n.kind == "application"]
    assert len(labels_) == 13 and "Other applications" in labels_


# ------------------------------------------------------------------ invariants
@pytest.mark.parametrize("kw", [{}, {"protocol": "UDP"}, {"search": "github"}, {"start": T0 + 20, "end": T0 + 60}, {"health": "healthy"}, {"max_nodes": 10}, {"local": "all"}])
def test_every_edge_connects_existing_nodes_whatever_the_filters(kw):
    r = result(many(40) + [conn("u", YT, 443, proto="UDP", domain="youtube.com", lport=60000, hs=None)])
    check_integrity(build_network_map(r, [finding("198.51.0.5")], **kw))


# ------------------------------------------------------------------ one address with very many ports (a scan)
def scan_conns(n=119):
    return [conn(f"s{i}", "10.0.0.9", 1 + i, domain=None, lport=40000 + i, bytes=100 + i) for i in range(n)]


def test_hundreds_of_ports_on_one_address_fold_into_one_node_even_when_the_address_is_flagged():
    m = build_network_map(result(scan_conns()), [finding("10.0.0.9")], max_nodes=60)
    ports = [n for n in m.nodes if n.kind == "port"]
    assert len(ports) == 8 and len(m.nodes) <= 15
    more = node(m, "ports:10.0.0.9")
    assert (more.kind, more.label, more.members, more.connections, more.tier) == ("other", "+111 more ports", 111, 111, 4)
    assert more.state == "suspicious" and any("folded" in r for r in more.state_reasons)
    assert edge(m, "ip:10.0.0.9", "ports:10.0.0.9").connections == 111 and len(m.connections) == 119     # every connection stays inspectable
    assert any("111 less-used port(s) on 1 address(es)" in x for x in m.notes)
    check_integrity(m)


def test_the_busiest_ports_stay_individual():
    m = build_network_map(result(scan_conns()), [], max_nodes=60)
    labels_ = {n.label for n in m.nodes if n.kind == "port"}
    assert "TCP/119" in labels_ and "TCP/1" not in labels_          # highest-traffic ports are kept


def test_a_few_ports_are_never_folded():
    m = build_network_map(result(scan_conns(8)), [], max_nodes=60)
    assert not any(n.id.startswith("ports:") for n in m.nodes) and len([n for n in m.nodes if n.kind == "port"]) == 8


# ------------------------------------------------------------------ single-port addresses carry their port
def test_an_address_with_one_port_is_labelled_ip_colon_port_and_has_no_port_node():
    m = build_network_map(result([conn("a", GH, 443), conn("b", GH, 443, lport=50001)]), [])
    assert not any(n.kind == "port" for n in m.nodes) and node(m, f"ip:{GH}").label == f"{GH}:443"


def test_ipv6_addresses_are_bracketed_in_the_label():
    m = build_network_map(result([conn("a", "2607:6bc0::10", 443, domain=None)]), [])
    n = node(m, "ip:2607:6bc0::10")
    assert n.label == "[2607:6bc0::10]:443" and n.ip == "2607:6bc0::10"


def test_an_address_with_several_ports_keeps_a_plain_label_and_port_nodes():
    m = build_network_map(result([conn("a", GH, 443), conn("b", GH, 22, lport=50001), conn("c", GH, 443, proto="UDP", lport=50002, hs=None)]), [])
    assert node(m, f"ip:{GH}").label == GH and node(m, f"ip:{GH}").port is None
    assert {n.label for n in m.nodes if n.kind == "port"} == {"TCP/443", "TCP/22", "UDP/443"}


def test_single_port_addresses_do_not_use_up_the_node_budget():
    m = build_network_map(result(many(30)), [], max_nodes=70)          # 30 x (domain + address) + local = 61 nodes: all fit
    assert m.hidden.destinations == 0 and len(m.nodes) == 61


# ------------------------------------------------------------------ addresses with no DNS name
def test_addresses_without_a_domain_share_one_group_when_the_map_has_domains():
    r = result([conn("a"), conn("b", "203.0.113.9", 8080, domain=None, lport=50001), conn("c", "198.18.20.5", 443, domain=None, lport=50002)])
    m = build_network_map(r, [])
    group = node(m, "group:no-dns")
    assert (group.kind, group.tier, group.label, group.sublabel, group.connections) == ("group", 2, "No DNS name", "2 addresses", 2)
    assert {e.id for e in m.edges} == {"local>domain:github.com", f"domain:github.com>ip:{GH}", "local>group:no-dns", "group:no-dns>ip:203.0.113.9", "group:no-dns>ip:198.18.20.5"}
    assert any("no domain name can be inferred" in x for x in group.state_reasons)
    check_integrity(m)


def test_without_any_domain_addresses_hang_directly_off_the_local_host():
    m = build_network_map(result([conn("a", "203.0.113.9", 8080, domain=None), conn("b", "198.18.20.5", 443, domain=None, lport=50001)]), [])
    assert not any(n.kind == "group" for n in m.nodes) and {e.id for e in m.edges} == {"local>ip:203.0.113.9", "local>ip:198.18.20.5"}


def test_every_edge_goes_down_exactly_one_tier_when_there_are_domains():
    r = result(many(6) + [conn("n1", "203.0.113.9", 8080, domain=None, lport=60001), conn("n2", "198.18.20.5", 22, domain=None, lport=60002)])
    m = build_network_map(r, [finding("198.18.20.5")])
    rows = {t: i for i, t in enumerate(sorted({n.tier for n in m.nodes}))}      # tiers that are present, as consecutive rows
    tier = {n.id: rows[n.tier] for n in m.nodes}
    skipping = [e.id for e in m.edges if tier[e.target] - tier[e.source] > 1 and not e.id.startswith("local>ip:")]
    assert skipping == []
    # (a flagged address with no connection detail hangs off the local host directly: it has no group to belong to)


def test_group_state_follows_its_addresses():
    r = result([conn("a"), conn("b", "203.0.113.9", 22, domain=None, lport=50001)])
    flagged = build_network_map(r, [finding("203.0.113.9")])
    assert node(flagged, "group:no-dns").state == "suspicious" and edge(flagged, "local", "group:no-dns").state == "suspicious"
    assert node(build_network_map(r, []), "group:no-dns").state == "healthy"
