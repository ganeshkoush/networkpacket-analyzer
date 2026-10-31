"""Interactive Network Map data: local host -> (applications) -> domains -> IP addresses -> ports.

Built from results that already exist; nothing is measured again and no packets are read:

* **Connections**: the analysis keeps detail for its largest connections (bounded), and the map shows exactly those, so
  it can never explode into thousands of nodes. It says so (``total_connections`` / ``notes``).
* **Domains** are inferred from DNS (never read from traffic). **Applications** appear only when OS process information
  matched (explicit snapshots), never from packets, and are optional.
* **State** is explainable. *Suspicious*: a security finding mentions the address. *Degraded*: a failed handshake,
  repeated retransmissions, or a domain rated fair/poor by the web-activity health rules. *Healthy*: measured, nothing wrong.
  *Unknown*: nothing measurable (never reported as healthy).
* **Node budget**: destinations are ranked by traffic and the tail is folded into one "more destinations" node; destinations
  that a finding mentions are never folded away.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import Counter
from dataclasses import dataclass, field

from app.analysis.web_activity import assess_health
from app.detection.models import Finding
from app.models.analysis import AnalysisResult, Connection
from app.models.network_map import (
    HiddenSummary, LocalHostOption, MapConnection, MapEdge, MapFinding, MapNode, MapState, NetworkMap,
)
from app.models.process import ConnectionProcessMatch

DEGRADED_RETRANSMISSIONS = 3     # retransmitted segments on one connection that make it "degraded"
DEGRADED_SHARE = 0.25            # share of a node's connections that are degraded before the node is
MAX_APPS = 12
MAX_CONNECTION_IDS = 25
MAX_PINNED_FINDING_NODES = 20
MAX_PORTS_PER_IP = 8             # a scan can touch hundreds of ports of one address: the rest fold into one node
MAX_EDGE_PORTS = 5
_RANK: dict[str, int] = {"unknown": 0, "healthy": 1, "degraded": 2, "suspicious": 3}


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


@dataclass
class _C:
    c: Connection
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    rtt: float | None
    handshake: float | None
    app: str | None = None
    process: str | None = None
    state: MapState = "unknown"
    reasons: list[str] = field(default_factory=list)

    @property
    def latency(self) -> tuple[float | None, str | None]:
        return (self.rtt, "rtt") if self.rtt is not None else (self.handshake, "handshake") if self.handshake is not None else (None, None)


def _orient(c: Connection, rtt: dict[str, float | None]) -> _C:
    """Which end is "local": the private endpoint (the client when both or neither are private)."""
    if not _is_local(c.client_ip) and _is_local(c.server_ip):
        return _C(c, c.server_ip, c.server_port, c.client_ip, c.client_port, rtt.get(c.id), c.tcp_handshake_time_ms)
    return _C(c, c.client_ip, c.client_port, c.server_ip, c.server_port, rtt.get(c.id), c.tcp_handshake_time_ms)


def _median_latency(items: list[_C]) -> tuple[float | None, str | None]:
    rtts = [x.rtt for x in items if x.rtt is not None]
    if rtts:
        return round(statistics.median(rtts), 1), "rtt"
    hs = [x.handshake for x in items if x.handshake is not None]
    return (round(statistics.median(hs), 1), "handshake") if hs else (None, None)


def _worst(states: list[MapState]) -> MapState:
    return max(states, key=lambda s: _RANK[s], default="unknown")


def build_network_map(
    result: AnalysisResult, findings: list[Finding], *, local: str | None = None, search: str = "", protocol: str | None = None,
    start: float | None = None, end: float | None = None, health: str | None = None, max_nodes: int = 60,
    matches: dict[str, ConnectionProcessMatch] | None = None, applications_status: str | None = None,
) -> NetworkMap:
    meta = result.metadata
    rtt = {m.connection_id: m.avg_rtt_ms for m in result.performance_statistics.metrics}
    perf = {d.domain: d for d in result.performance_statistics.domains}
    all_conns = [_orient(c, rtt) for c in result.connections if c.protocol in ("TCP", "UDP") and c.client_port is not None and c.server_port is not None]
    notes = ["Domains are inferred from DNS lookups, not read from the traffic.",
             "The map shows the connections the analysis keeps detail for (the largest by traffic), so very small flows may be absent."]

    hosts = Counter(x.local_ip for x in all_conns)
    options = [LocalHostOption(ip=ip, connections=n) for ip, n in hosts.most_common(10)]
    selected = "all" if local == "all" else (local if local else (options[0].ip if options else "all"))

    # ---- findings in scope (time range applied; findings without times are always in scope)
    def in_range(f: Finding) -> bool:
        if (start is None and end is None) or f.first_seen is None or f.last_seen is None:
            return True
        return (end is None or f.first_seen <= end) and (start is None or f.last_seen >= start)
    scoped = [f for f in findings if in_range(f)]
    flagged: dict[str, list[Finding]] = {}
    for f in scoped:
        for ip in {f.source_ip, f.destination_ip} - {None}:
            flagged.setdefault(ip, []).append(f)  # type: ignore[arg-type]

    # ---- per-connection state, application, and the user's filters
    for x in all_conns:
        if matches and x.c.id in matches:
            x.app, x.process = matches[x.c.id].application, matches[x.c.id].process_name
        c = x.c
        if x.remote_ip in flagged:
            x.state, x.reasons = "suspicious", [f"Security finding: {f.title}" for f in flagged[x.remote_ip]][:3]
        else:
            if c.handshake_status == "incomplete" and c.handshake_incomplete_reason in ("no_synack", "reset"):
                x.reasons.append("The TCP handshake did not complete" + (" (reset)" if c.handshake_incomplete_reason == "reset" else " (no answer)"))
            if (c.retransmissions or 0) >= DEGRADED_RETRANSMISSIONS:
                x.reasons.append(f"{c.retransmissions} retransmitted segments (a heuristic loss indicator)")
            measured = x.rtt is not None or x.handshake is not None
            x.state = "degraded" if x.reasons else "healthy" if measured else "unknown"

    terms = search.lower().split()

    def keep(x: _C) -> bool:
        if selected != "all" and x.local_ip != selected:
            return False
        if protocol and x.c.protocol != protocol:
            return False
        if start is not None and x.c.end_time < start or end is not None and x.c.start_time > end:
            return False
        if health and x.state != health:
            return False
        if terms:
            hay = " ".join(str(v).lower() for v in (x.c.domain or "", x.remote_ip, x.local_ip, x.remote_port or "", x.local_port or "", x.c.protocol, x.app or "", x.process or ""))
            return all(t in hay for t in terms)
        return True

    conns = [x for x in all_conns if keep(x)]
    filtering = bool(terms or protocol)

    # ---- destination subtrees (a domain with its IPs and ports, or a bare IP) and the node budget
    groups: dict[str, list[_C]] = {}
    for x in conns:
        groups.setdefault(f"domain:{x.c.domain}" if x.c.domain else f"ip:{x.remote_ip}", []).append(x)

    def subtree_nodes(key: str, items: list[_C]) -> set[str]:
        """Node ids this destination needs, counting ports after folding (at most MAX_PORTS_PER_IP per address plus one fold node)."""
        out = {key}
        per_ip: dict[str, Counter[tuple[str, int | None]]] = {}
        for x in items:
            out.add(f"ip:{x.remote_ip}")
            per_ip.setdefault(x.remote_ip, Counter())[(x.c.protocol, x.remote_port)] += x.c.bytes + 1
        for ip, c in per_ip.items():
            ranked = c.most_common()
            if len(ranked) == 1:
                continue                      # the only port is shown on the address node itself
            out |= {f"port:{ip}:{p}:{n}" for (p, n), _ in ranked[:MAX_PORTS_PER_IP]}
            if len(ranked) > MAX_PORTS_PER_IP:
                out.add(f"ports:{ip}")
        return out

    pinned = {k for k, items in groups.items() if any(x.remote_ip in flagged for x in items)}
    order = sorted(groups, key=lambda k: (k not in pinned, -sum(x.c.bytes for x in groups[k]), k))
    kept_keys: list[str] = []
    used: set[str] = set()
    for k in order:
        add = subtree_nodes(k, groups[k]) - used
        if k in pinned or len(used) + len(add) + 2 <= max_nodes:   # +2: the local host and the "more destinations" node
            kept_keys.append(k)
            used |= add
    folded = [x for k in order if k not in kept_keys for x in groups[k]]
    kept = [x for k in kept_keys for x in groups[k]]
    hidden = HiddenSummary(destinations=sum(1 for k in order if k not in kept_keys), connections=len(folded), bytes=sum(x.c.bytes for x in folded))

    # ---- applications (optional; only from matched OS process information)
    app_of: dict[str, str] = {}
    if matches:
        app_bytes: Counter[str] = Counter()
        for x in kept:
            if x.app or x.process:
                app_bytes[x.app or x.process or ""] += x.c.bytes
        keep_apps = {a for a, _ in app_bytes.most_common(MAX_APPS)}
        for x in kept:
            name = x.app or x.process
            if name:
                app_of[x.c.id] = name if name in keep_apps else "Other applications"

    # ---- the busiest ports of each address stay individual; the rest fold into one "+N more ports" node
    ports_of: dict[str, Counter[tuple[str, int | None]]] = {}
    for x in kept:
        ports_of.setdefault(x.remote_ip, Counter())[(x.c.protocol, x.remote_port)] += x.c.bytes + 1
    top_ports = {ip: {k for k, _ in c.most_common(MAX_PORTS_PER_IP)} for ip, c in ports_of.items()}
    single_port = {ip for ip, c in ports_of.items() if len(c) == 1}   # one port: shown as "ip:port" instead of a separate node
    folded_ports: dict[str, set[tuple[str, int | None]]] = {}

    # ---- nodes and edges
    nodes: dict[str, MapNode] = {}
    node_conns: dict[str, list[_C]] = {}
    edge_conns: dict[tuple[str, str], list[_C]] = {}

    def touch(node_id: str, kind, label: str, tier: int, x: _C, **kw) -> None:
        n = nodes.setdefault(node_id, MapNode(id=node_id, kind=kind, label=label, tier=tier, **kw))
        node_conns.setdefault(node_id, []).append(x)
        if len(n.connection_ids) < MAX_CONNECTION_IDS:
            n.connection_ids.append(x.c.id)

    def link(a: str, b: str, x: _C) -> None:
        edge_conns.setdefault((a, b), []).append(x)

    local_label = "Local network" if selected == "all" else selected
    has_domains = any(x.c.domain for x in kept)   # without any domain, addresses hang straight off the local host
    for x in kept:
        touch("local", "local", local_label, 0, x, ip=None if selected == "all" else selected)
        parent = "local"
        if x.c.id in app_of:
            app = app_of[x.c.id]
            touch(f"app:{app}", "application", app, 1, x)
            link(parent, f"app:{app}", x)
            parent = f"app:{app}"
        ip_id = f"ip:{x.remote_ip}"
        port_id = f"port:{x.remote_ip}:{x.c.protocol}:{x.remote_port}"
        folded_port = (x.c.protocol, x.remote_port) not in top_ports[x.remote_ip]
        if folded_port:
            port_id = f"ports:{x.remote_ip}"
            folded_ports.setdefault(x.remote_ip, set()).add((x.c.protocol, x.remote_port))
        if x.c.domain:
            touch(f"domain:{x.c.domain}", "domain", x.c.domain, 2, x, domain=x.c.domain)
            link(parent, f"domain:{x.c.domain}", x)
            link(f"domain:{x.c.domain}", ip_id, x)
        elif has_domains:   # keep the tiers regular: addresses with no DNS name share one group in the domain row
            touch("group:no-dns", "group", "No DNS name", 2, x)
            link(parent, "group:no-dns", x)
            link("group:no-dns", ip_id, x)
        else:
            link(parent, ip_id, x)
        touch(ip_id, "ip", x.remote_ip, 3, x, ip=x.remote_ip)
        if x.remote_ip in single_port:   # the address's only port is part of its label; no separate port node
            ip_node = nodes[ip_id]
            ip_node.port, ip_node.protocol = x.remote_port, x.c.protocol
            ip_node.label = f"[{x.remote_ip}]:{x.remote_port}" if ":" in x.remote_ip else f"{x.remote_ip}:{x.remote_port}"
            continue
        if folded_port:
            touch(port_id, "other", "more ports", 4, x, ip=x.remote_ip)
        else:
            touch(port_id, "port", f"{x.c.protocol}/{x.remote_port}", 4, x, ip=x.remote_ip, port=x.remote_port, protocol=x.c.protocol)
        link(ip_id, port_id, x)

    if folded:
        nodes["other"] = MapNode(id="other", kind="other", label=f"{hidden.destinations} more destination{'s' if hidden.destinations != 1 else ''}", tier=2,
                                 connections=len(folded), bytes=hidden.bytes, members=hidden.destinations,
                                 state="degraded" if any(x.state == "degraded" for x in folded) else "unknown",
                                 state_reasons=["Folded to keep the map readable; narrow the filters to see them."])
        nodes.setdefault("local", MapNode(id="local", kind="local", label=local_label, tier=0))
        edge_conns[("local", "other")] = folded

    # node summaries
    for nid, items in node_conns.items():
        n = nodes[nid]
        n.connections, n.bytes = len(items), sum(x.c.bytes for x in items)
        n.latency_ms, n.latency_kind = _median_latency(items)
        n.state, n.state_reasons = _node_state(n, items, perf, flagged)
        if n.kind == "ip":
            n.finding_ids = sorted({f.id for f in flagged.get(n.ip or "", [])})
        if n.id.startswith("ports:"):
            k = len(folded_ports[n.ip or ""])
            n.label, n.members = f"+{k} more port{'s' if k != 1 else ''}", k
            n.state_reasons = [*n.state_reasons, "Less-used ports of this address are folded into one node to keep the map readable."][:4]
        if n.kind == "group":
            k = len({x.remote_ip for x in items})
            n.sublabel = f"{k} address{'es' if k != 1 else ''}"
            n.state_reasons = [*n.state_reasons, "No DNS lookup preceded these connections in this capture, so no domain name can be inferred."][:4]
        if n.kind == "domain":
            n.sublabel = f"{len({x.remote_ip for x in items})} address{'es' if len({x.remote_ip for x in items}) != 1 else ''}"
        if n.kind == "ip" and (n.latency_ms is not None):
            n.sublabel = None
    if "local" in nodes and selected != "all":
        lf = flagged.get(selected, [])
        if lf:
            nodes["local"].finding_ids = sorted({f.id for f in lf})
            nodes["local"].state, nodes["local"].state_reasons = "suspicious", [f"Security finding: {f.title}" for f in lf][:3]

    # findings whose address has no connection detail (so it would otherwise be invisible) are pinned as bare nodes
    if not filtering and health in (None, "suspicious"):
        extra = [ip for ip in flagged if f"ip:{ip}" not in nodes and (selected == "all" or ip != selected) and not _is_selected_local(ip, hosts)]
        for ip in extra[:MAX_PINNED_FINDING_NODES]:
            nodes[f"ip:{ip}"] = MapNode(id=f"ip:{ip}", kind="ip", label=ip, tier=3, ip=ip, state="suspicious", detail_available=False,
                                        state_reasons=[f"Security finding: {f.title}" for f in flagged[ip]][:3], finding_ids=sorted({f.id for f in flagged[ip]}),
                                        sublabel="no connection detail kept")
            nodes.setdefault("local", MapNode(id="local", kind="local", label=local_label, tier=0))
            edge_conns[("local", f"ip:{ip}")] = []

    edges: list[MapEdge] = []
    for (a, b), items in edge_conns.items():
        lat, kind = _median_latency(items)
        protos = sorted({x.c.protocol for x in items})
        ports = sorted({x.remote_port for x in items if x.remote_port is not None}, key=lambda p: -sum(1 for x in items if x.remote_port == p))[:MAX_EDGE_PORTS]
        edges.append(MapEdge(id=f"{a}>{b}", source=a, target=b, connections=len(items), bytes=sum(x.c.bytes for x in items),
                             protocol="+".join(protos) or None, ports=ports if nodes[b].kind in ("port", "ip", "domain", "group") else [], latency_ms=lat, latency_kind=kind,
                             state=nodes[b].state, connection_ids=[x.c.id for x in items][:MAX_CONNECTION_IDS]))
    for e in edges:
        e.state = nodes[e.target].state

    shown = {x.c.id for x in kept}
    map_conns = [MapConnection(
        id=x.c.id, protocol=x.c.protocol, local_ip=x.local_ip, local_port=x.local_port, remote_ip=x.remote_ip, remote_port=x.remote_port, domain=x.c.domain,
        application=x.app, process_name=x.process, start_time=x.c.start_time, end_time=x.c.end_time, duration_seconds=x.c.duration_seconds, bytes=x.c.bytes,
        packets=x.c.packets, state=x.c.state, handshake_ms=x.handshake, rtt_ms=x.rtt, retransmissions=x.c.retransmissions, health=x.state, health_reasons=x.reasons)
        for x in kept]
    if not conns:
        notes.append("No connections match the current filters." if all_conns else "This capture has no TCP or UDP connections with detail to show.")
    if folded_ports:
        notes.append(f"{sum(len(v) for v in folded_ports.values())} less-used port(s) on {len(folded_ports)} address(es) are folded into \"more ports\" nodes.")
    if hidden.destinations:
        notes.append(f"{hidden.destinations} lower-traffic destination(s) ({hidden.connections} connections) are folded into one node to keep the map readable.")
    if start is not None or end is not None:
        notes.append("The time range selects connections that were active in it; each connection's figures cover its whole lifetime.")
    if applications_status:
        notes.append(applications_status)

    out_nodes = sorted(nodes.values(), key=lambda n: (n.tier, -n.bytes, n.label))
    return NetworkMap(
        nodes=out_nodes, edges=sorted(edges, key=lambda e: e.id), connections=map_conns,
        findings=[MapFinding(id=f.id, type=f.type.value, severity=f.severity.value, confidence=f.confidence, title=f.title, source_ip=f.source_ip, destination_ip=f.destination_ip)
                  for f in scoped if any(n.finding_ids and f.id in n.finding_ids for n in out_nodes)],
        local=selected, local_hosts=options, capture_start=meta.first_packet_time, capture_end=meta.last_packet_time, applied_start=start, applied_end=end,
        total_connections=len(all_conns), shown_connections=len(shown), hidden=hidden, applications_status=applications_status, notes=notes)


def _is_selected_local(ip: str, hosts: Counter) -> bool:
    return ip in hosts


def _node_state(n: MapNode, items: list[_C], perf, flagged) -> tuple[MapState, list[str]]:
    # The local host is only suspicious if a finding names it (handled by the caller), not for whom it talked to.
    suspicious = [x for x in items if x.state == "suspicious"] if n.kind != "local" else []
    if suspicious:
        return "suspicious", sorted({r for x in suspicious for r in x.reasons})[:3]
    degraded = [x for x in items if x.state == "degraded"]
    reasons: list[str] = []
    if n.kind == "domain":
        verdict, why = assess_health(perf.get(n.domain or ""), perf[n.domain].dns_latency_ms if n.domain in perf else None)
        if verdict in ("fair", "poor"):
            return "degraded", why[:3]
        if verdict == "good" and not degraded:
            return "healthy", []
    if degraded and len(degraded) / len(items) >= DEGRADED_SHARE:
        reasons = sorted({r for x in degraded for r in x.reasons})[:3]
        return "degraded", reasons
    if any(x.state == "healthy" for x in items):
        return "healthy", []
    return "unknown", []
