"""Domain / website activity: correlate DNS answers with the connections that follow them.

For each client, an A/AAAA answer records "client resolved <domain> to <ip> at time t". A TCP/UDP
flow that starts later from that client to <ip> is attributed to the most recent such domain.

This is inference from DNS, not observation of the connection: PacketMind never sees URLs, paths
or page content for HTTPS (or the TLS SNI name here). Known blind spots: DNS answered from a
client cache or sent over DoH/DoT (no visible lookup), shared CDN addresses (several domains per
IP; flagged as ambiguous), hosts that resolved before the capture started, and DNS captured at a
point that does not see the client's own lookups.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.analysis.connection_tracker import FlowKey, flow_key
from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import DomainActivity, DomainStatistics, DomainSummary

_MAX_DOMAINS = 100_000
_MAX_RESOLUTIONS = 200_000  # (client, ip) pairs
_MAX_FLOWS = 200_000
_MAX_DOMAINS_PER_PAIR = 8
_MAX_IPS_PER_DOMAIN = 20
_MAX_CLIENTS_PER_DOMAIN = 10
_MAX_PORTS_PER_DOMAIN = 10
_MAX_SERIES_DOMAINS = 5_000
_DNS_PORTS = {53, 5353}
_DOT_PORT = 853

BASE_NOTE = ("Domains are inferred by matching DNS answers to later connections. HTTPS URLs, paths and page "
             "content are encrypted and not visible; only the hostname a client resolved is known.")


@dataclass(slots=True)
class _Dom:
    first: float
    last: float
    queries: int = 0
    responses: int = 0
    ips: dict[str, None] = field(default_factory=dict)  # insertion-ordered set
    clients: dict[str, None] = field(default_factory=dict)
    ports: dict[int, int] = field(default_factory=dict)
    tcp: int = 0
    udp: int = 0
    sent: int = 0
    received: int = 0
    min_ttl: int | None = None
    max_ttl: int | None = None
    ambiguous: int = 0
    pkts_sent: int = 0
    pkts_recv: int = 0

    def touch(self, ts: float) -> None:
        self.first, self.last = min(self.first, ts), max(self.last, ts)


@dataclass(slots=True)
class _Flow:
    transport: str
    client: tuple[str, int | None]
    server: tuple[str, int | None]
    start: float
    end: float
    domain: str | None
    ambiguous: bool
    sent: int = 0
    received: int = 0
    sent_pkts: int = 0
    recv_pkts: int = 0


class _Bins:
    """Bytes per time bin for one domain. When there are more than ``cap`` non-empty bins the bin width doubles
    and neighbouring bins merge, so memory stays bounded however long the capture is."""

    __slots__ = ("width", "cap", "bins")

    def __init__(self, cap: int) -> None:
        self.width = 1
        self.cap = cap
        self.bins: dict[int, list[int]] = {}  # bin index -> [bytes sent, bytes received]

    def add(self, ts: float, direction: int, size: int) -> None:
        self.bins.setdefault(int(ts // self.width), [0, 0])[direction] += size
        while len(self.bins) > self.cap:
            merged: dict[int, list[int]] = {}
            for idx, (sent, recv) in self.bins.items():
                m = merged.setdefault(idx // 2, [0, 0])
                m[0] += sent
                m[1] += recv
            self.width *= 2
            self.bins = merged


def _valid_ip(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return None if ip.is_unspecified else str(ip)


class DomainAnalyzer:
    def __init__(self, max_domains: int = 500, max_series_points: int = 300) -> None:
        self.max_domains = max_domains
        self.max_series_points = max_series_points
        self._series: dict[str, _Bins] = {}
        self._doms: dict[str, _Dom] = {}
        self._resolved: dict[tuple[str, str], dict[str, float]] = {}  # (client, ip) -> {domain: time}
        self._ip_domains: dict[str, set[str]] = {}
        self._flows: dict[tuple, _Flow] = {}
        self._not_tracked = 0
        self._dns_queries = 0
        self._dns_flows = 0
        self._dot_flows = 0
        self._dropped_flows = 0

    # ------------------------------------------------------------------ intake
    def add(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip:
            return
        if pkt.dns is not None:
            self._on_dns(pkt)
        elif pkt.transport in ("TCP", "UDP"):
            self._on_packet(pkt)

    def _dom(self, name: str, ts: float) -> _Dom | None:
        dom = self._doms.get(name)
        if dom is None:
            if len(self._doms) >= _MAX_DOMAINS:
                self._not_tracked += 1
                return None
            dom = self._doms[name] = _Dom(first=ts, last=ts)
        dom.touch(ts)
        return dom

    def _on_dns(self, pkt: PacketRecord) -> None:
        dns = pkt.dns
        assert dns is not None and pkt.src_ip and pkt.dst_ip
        name = dns.qname
        # Skip empty questions, the root, and reverse lookups (PTR names are not "sites").
        if not name or name == "." or name.endswith(".arpa") or dns.qtype == "PTR":
            return
        ts = pkt.timestamp
        if not dns.is_response:
            self._dns_queries += 1
            dom = self._dom(name, ts)
            if dom is not None:
                dom.queries += 1
                self._add_client(dom, pkt.src_ip)
            return
        client = pkt.dst_ip
        dom = self._dom(name, ts)
        if dom is None:
            return
        dom.responses += 1
        self._add_client(dom, client)
        for ans in dns.answers:
            if ans.rtype not in ("A", "AAAA"):
                continue
            ip = _valid_ip(ans.data)
            if ip is None:
                continue
            if ans.ttl is not None:
                dom.min_ttl = ans.ttl if dom.min_ttl is None else min(dom.min_ttl, ans.ttl)
                dom.max_ttl = ans.ttl if dom.max_ttl is None else max(dom.max_ttl, ans.ttl)
            if len(dom.ips) < _MAX_IPS_PER_DOMAIN:
                dom.ips[ip] = None
            self._remember(client, ip, name, ts)

    @staticmethod
    def _add_client(dom: _Dom, ip: str) -> None:
        if ip in dom.clients or len(dom.clients) < _MAX_CLIENTS_PER_DOMAIN:
            dom.clients[ip] = None

    def _remember(self, client: str, ip: str, name: str, ts: float) -> None:
        key = (client, ip)
        entry = self._resolved.get(key)
        if entry is None:
            if len(self._resolved) >= _MAX_RESOLUTIONS:
                return
            entry = self._resolved[key] = {}
        entry[name] = ts
        if len(entry) > _MAX_DOMAINS_PER_PAIR:
            del entry[min(entry, key=entry.__getitem__)]
        shared = self._ip_domains.setdefault(ip, set())
        if len(shared) < 50:
            shared.add(name)

    def _lookup(self, client: str, server: str, ts: float) -> tuple[str, bool] | None:
        """Most recent domain `client` resolved to `server` before `ts`, and whether others compete."""
        entry = self._resolved.get((client, server))
        if not entry:
            return None
        usable = {d: t for d, t in entry.items() if t <= ts}
        if not usable:
            return None
        return max(usable, key=usable.__getitem__), len(entry) > 1

    def _on_packet(self, pkt: PacketRecord) -> None:
        a, b = (pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port)
        key = flow_key(pkt.transport or "", a, b)
        flow = self._flows.get(key)
        if flow is None:
            ports = {pkt.src_port, pkt.dst_port}
            if ports & _DNS_PORTS:
                self._dns_flows += 1  # DNS itself is not website activity
            elif pkt.transport == "TCP" and _DOT_PORT in ports:
                self._dot_flows += 1
            if len(self._flows) >= _MAX_FLOWS:
                self._dropped_flows += 1
                return
            client, server = a, b
            hit = self._lookup(client[0], server[0], pkt.timestamp)
            if hit is None and (hit := self._lookup(server[0], client[0], pkt.timestamp)):
                client, server = b, a  # capture began mid-flow: the first packet came from the server side
            if ports & _DNS_PORTS or (pkt.transport == "TCP" and _DOT_PORT in ports):
                hit = None
            flow = self._flows[key] = _Flow(pkt.transport or "", client, server, pkt.timestamp, pkt.timestamp,
                                            hit[0] if hit else None, hit[1] if hit else False)
        flow.end = max(flow.end, pkt.timestamp)
        outbound = a == flow.client
        if outbound:
            flow.sent += pkt.size
            flow.sent_pkts += 1
        else:
            flow.received += pkt.size
            flow.recv_pkts += 1
        if flow.domain:
            bins = self._series.get(flow.domain)
            if bins is None and len(self._series) < _MAX_SERIES_DOMAINS:
                bins = self._series[flow.domain] = _Bins(self.max_series_points)
            if bins is not None:
                bins.add(pkt.timestamp, 0 if outbound else 1, pkt.size)

    def domain_for_flow(self, key: FlowKey) -> tuple[str, bool] | None:
        """(domain, ambiguous) attributed to the flow with this ``flow_key``, or None if unattributed."""
        flow = self._flows.get(key)
        return (flow.domain, flow.ambiguous) if flow is not None and flow.domain else None

    # ------------------------------------------------------------------ output
    def result(self) -> DomainStatistics:
        attributed = ambiguous = 0
        unattributed = 0
        for flow in self._flows.values():
            ports = {flow.client[1], flow.server[1]}
            is_dns = bool(ports & _DNS_PORTS) or (flow.transport == "TCP" and _DOT_PORT in ports)
            if flow.domain is None:
                if not is_dns:
                    unattributed += 1
                continue
            dom = self._doms.get(flow.domain)
            if dom is None:
                continue
            attributed += 1
            dom.touch(flow.start)
            dom.touch(flow.end)
            if flow.transport == "TCP":
                dom.tcp += 1
            else:
                dom.udp += 1
            dom.sent += flow.sent
            dom.received += flow.received
            dom.pkts_sent += flow.sent_pkts
            dom.pkts_recv += flow.recv_pkts
            self._add_client(dom, flow.client[0])
            if flow.server[0] not in dom.ips and len(dom.ips) < _MAX_IPS_PER_DOMAIN:
                dom.ips[flow.server[0]] = None
            port = flow.server[1]
            if port is not None and (port in dom.ports or len(dom.ports) < _MAX_PORTS_PER_DOMAIN):
                dom.ports[port] = dom.ports.get(port, 0) + 1
            if flow.ambiguous:
                dom.ambiguous += 1
                ambiguous += 1

        ranked = sorted(self._doms.items(),
                        key=lambda kv: (kv[1].sent + kv[1].received, kv[1].tcp + kv[1].udp, kv[0]), reverse=True)
        domains = [self._to_model(name, d) for name, d in ranked[: self.max_domains]]
        with_conn = sum(1 for d in self._doms.values() if d.tcp + d.udp)
        notes = [BASE_NOTE]
        if unattributed and self._dns_queries == 0:
            notes.append("No DNS queries were captured, so connections cannot be mapped to domains. DNS may be "
                         "encrypted (DoH/DoT), cached on the host, or not visible from where this was captured.")
        elif unattributed:
            notes.append(f"{unattributed} connection(s) had no matching DNS lookup in this capture "
                         "(cached or pre-capture lookups, hard-coded IPs, or encrypted DNS) and are not listed.")
        if self._dot_flows:
            notes.append(f"{self._dot_flows} DNS-over-TLS flow(s) (TCP/853) were seen; their lookups are not visible.")
        if ambiguous:
            notes.append(f"{ambiguous} connection(s) went to an IP shared by several resolved domains; the most "
                         "recent lookup was chosen, so those attributions are less certain.")
        if self._dropped_flows or self._not_tracked:
            notes.append("Tracking limits were reached; domain activity is incomplete for very large captures.")
        return DomainStatistics(domains=domains, summary=DomainSummary(
            total_domains=len(self._doms), reported_domains=len(domains), domains_with_connections=with_conn,
            attributed_connections=attributed, unattributed_connections=unattributed,
            ambiguous_connections=ambiguous, dns_only_domains=len(self._doms) - with_conn,
            encrypted_dns_flows=self._dot_flows, domains_not_tracked=self._not_tracked, notes=notes))

    def _to_model(self, name: str, d: _Dom) -> DomainActivity:
        shared = sorted(ip for ip in d.ips if len(self._ip_domains.get(ip, ())) > 1)
        return DomainActivity(
            domain=name, resolved_ips=list(d.ips), clients=list(d.clients), first_seen=d.first, last_seen=d.last,
            dns_queries=d.queries, dns_responses=d.responses, connection_count=d.tcp + d.udp,
            tcp_connection_count=d.tcp, udp_connection_count=d.udp, total_bytes_sent=d.sent,
            total_bytes_received=d.received, min_ttl=d.min_ttl, max_ttl=d.max_ttl,
            ambiguous_connection_count=d.ambiguous, shared_ips=shared[:10],
            server_ports=[p for p, _ in sorted(d.ports.items(), key=lambda kv: -kv[1])],
            packets_sent=d.pkts_sent, packets_received=d.pkts_recv)

    def traffic_series(self, domain: str) -> tuple[int, list[tuple[float, int, int]]] | None:
        """(bin width in seconds, [(bin start, bytes sent, bytes received)]) for a domain, oldest first."""
        bins = self._series.get(domain)
        if bins is None:
            return None
        return bins.width, [(float(idx * bins.width), s, r) for idx, (s, r) in sorted(bins.bins.items())]
