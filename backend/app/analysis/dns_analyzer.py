"""DNS query/response statistics (UDP DNS, including mDNS)."""
from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass, field

from app.analysis.connection_tracker import FlowKey, flow_key
from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import (
    LookupSample,
    DnsClientStat,
    DnsCount,
    DnsDomainGroup,
    DnsQueryLogEntry,
    DnsStatistics,
)

_MAX_PENDING_QUERIES = 50_000
_MAX_LOOKUP_KEYS = 100_000  # distinct (client, name) / flow keys with recorded lookup latencies
_MAX_LOOKUPS_PER_KEY = 32
_MAX_LOOKUP_LOG = 100_000  # answered lookups kept (with time) for the correlation engine
_MAX_TRACKED_DOMAINS = 200_000
_MAX_CLIENTS = 50_000
_MAX_GROUPS = 100_000
_MAX_NAMES_PER_SET = 5_000
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
    "co.za", "co.in", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "co.kr",
}
_TUNNEL_QTYPES = {"TXT", "NULL"}


def base_domain(qname: str) -> str:
    """Registered-style base domain: last two labels, or three under known two-part suffixes.

    Heuristic (no public-suffix list): names under unlisted multi-part suffixes group by the
    suffix itself.
    """
    labels = qname.split(".")
    if len(labels) <= 2:
        return qname
    if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def longest_consonant_run(text: str) -> int:
    """Length of the longest run of consecutive consonant letters."""
    best = cur = 0
    for ch in text:
        cur = cur + 1 if ch in _CONSONANTS else 0
        best = max(best, cur)
    return best


def looks_random(label: str, *, min_length: int = 12, entropy_threshold: float = 3.2,
                 digit_share: float = 0.2, consonant_run: int = 5) -> bool:
    """Heuristic: does a domain label look randomly generated (DGA-style)?

    All of: length >= ``min_length`` and Shannon entropy >= ``entropy_threshold``, AND at least
    one of: digit share >= ``digit_share`` or a consonant run >= ``consonant_run``. Entropy
    alone cannot separate long English names from random strings; the second signal does
    (natural words rarely contain 5+ consecutive consonants or many digits). Random labels
    shorter than ~16 characters are often missed - a documented limitation.
    """
    if len(label) < min_length or shannon_entropy(label) < entropy_threshold:
        return False
    digits = sum(c.isdigit() for c in label) / len(label)
    return digits >= digit_share or longest_consonant_run(label) >= consonant_run


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


@dataclass(slots=True)
class _Client:
    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    names: set[str] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0
    entropy_bases: set[str] = field(default_factory=set)
    entropy_samples: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _Group:
    queries: int = 0
    names: set[str] = field(default_factory=set)
    max_len: int = 0
    sub_label_sum: int = 0
    sub_label_n: int = 0
    txt_null: int = 0
    clients: Counter = field(default_factory=Counter)


class DnsAnalyzer:
    """Aggregates DNS queries and responses and matches them by transaction.

    A response is matched to a query on (transaction id, client ip, client port,
    server ip). Queries still unmatched at the end count as unanswered - which in a
    partial capture may simply mean the response was not captured.
    """

    def __init__(self, top_n: int = 20, max_log: int = 500, max_profiles: int = 100,
                 entropy_threshold: float = 3.2, entropy_min_label_length: int = 12,
                 random_digit_share: float = 0.2, random_consonant_run: int = 5) -> None:
        self.top_n = top_n
        self.max_log = max_log
        self.max_profiles = max_profiles
        self.entropy_threshold = entropy_threshold
        self.entropy_min_label_length = entropy_min_label_length
        self.random_digit_share = random_digit_share
        self.random_consonant_run = random_consonant_run
        self._clients_stats: dict[str, _Client] = {}
        self._groups: dict[str, _Group] = {}
        self._queries = 0
        self._responses = 0
        self._domains: Counter[str] = Counter()
        self._types: Counter[str] = Counter()
        self._rcodes: Counter[str] = Counter()
        self._clients: Counter[str] = Counter()
        self._servers: Counter[str] = Counter()
        self._pending: dict[tuple[int, str, int | None, str], float] = {}
        # Per-lookup latency (ms) for matched query/response pairs. A query that was sent again with the
        # same transaction id is ambiguous (which one did the response answer?) and is never timed.
        self._retried: set[tuple[int, str, int | None, str]] = set()
        self._lookups: dict[tuple[str, str], list[float]] = {}  # (client ip, qname) -> ms
        self._flow_lookups: dict[FlowKey, list[float]] = {}  # UDP flow -> ms
        self._lookups_ambiguous = 0
        self._lookup_log: list[LookupSample] = []
        self._answered = 0
        self._orphan_responses = 0
        self._empty = 0
        self._latency_sum = 0.0
        self._latency_max = 0.0
        self._log: list[DnsQueryLogEntry] = []
        self._log_truncated = False

    def add(self, pkt: PacketRecord) -> None:
        dns = pkt.dns
        if dns is None or not pkt.src_ip or not pkt.dst_ip:
            return
        if not dns.is_response:
            self._on_query(pkt)
        else:
            self._on_response(pkt)

    def _on_query(self, pkt: PacketRecord) -> None:
        dns = pkt.dns
        assert dns is not None and pkt.src_ip and pkt.dst_ip
        self._queries += 1
        qname = dns.qname or "<no question>"
        if qname in self._domains or len(self._domains) < _MAX_TRACKED_DOMAINS:
            self._domains[qname] += 1
        self._types[dns.qtype or "UNKNOWN"] += 1
        self._clients[pkt.src_ip] += 1
        self._servers[pkt.dst_ip] += 1
        self._profile_query(pkt, qname, dns.qtype)
        if len(self._pending) < _MAX_PENDING_QUERIES:
            qkey = (dns.transaction_id, pkt.src_ip, pkt.src_port, pkt.dst_ip)
            if qkey in self._pending:
                self._retried.add(qkey)
            self._pending[qkey] = pkt.timestamp
        if len(self._log) < self.max_log:
            self._log.append(DnsQueryLogEntry(
                timestamp=pkt.timestamp, client_ip=pkt.src_ip, server_ip=pkt.dst_ip,
                qname=qname, qtype=dns.qtype or "UNKNOWN"))
        else:
            self._log_truncated = True

    def _profile_query(self, pkt: PacketRecord, qname: str, qtype: str | None) -> None:
        """Update per-client and per-base-domain profiles for one query."""
        ip, ts = pkt.src_ip, pkt.timestamp
        client = self._clients_stats.get(ip)  # type: ignore[arg-type]
        if client is None and len(self._clients_stats) < _MAX_CLIENTS:
            client = self._clients_stats[ip] = _Client(first=ts, last=ts)  # type: ignore[index]
        if qname == "<no question>":
            return
        base = base_domain(qname)
        if client is not None:
            client.queries += 1
            client.first, client.last = min(client.first, ts), max(client.last, ts)
            if len(client.names) < _MAX_NAMES_PER_SET:
                client.names.add(qname)
            label = base.split(".")[0]
            if (looks_random(label, min_length=self.entropy_min_label_length,
                             entropy_threshold=self.entropy_threshold, digit_share=self.random_digit_share,
                             consonant_run=self.random_consonant_run)
                    and base not in client.entropy_bases
                    and len(client.entropy_bases) < _MAX_NAMES_PER_SET):
                client.entropy_bases.add(base)
                if len(client.entropy_samples) < 10:
                    client.entropy_samples.append(base)

        group = self._groups.get(base)
        if group is None and len(self._groups) < _MAX_GROUPS:
            group = self._groups[base] = _Group()
        if group is not None:
            group.queries += 1
            if len(group.names) < _MAX_NAMES_PER_SET:
                group.names.add(qname)
            group.max_len = max(group.max_len, len(qname))
            if qname != base:
                group.sub_label_sum += len(qname.split(".")[0])
                group.sub_label_n += 1
            if qtype in _TUNNEL_QTYPES:
                group.txt_null += 1
            if ip and (ip in group.clients or len(group.clients) < 50):
                group.clients[ip] += 1

    def _on_response(self, pkt: PacketRecord) -> None:
        dns = pkt.dns
        assert dns is not None and pkt.src_ip and pkt.dst_ip
        self._responses += 1
        self._rcodes[dns.rcode or "UNKNOWN"] += 1
        client = self._clients_stats.get(pkt.dst_ip)
        if client is not None:
            client.responses += 1
            if dns.rcode == "NXDOMAIN":
                client.nxdomain += 1
        if dns.answer_count == 0:
            self._empty += 1
        qkey = (dns.transaction_id, pkt.dst_ip, pkt.dst_port, pkt.src_ip)
        sent_at = self._pending.pop(qkey, None)
        if sent_at is None:
            self._orphan_responses += 1
            return
        self._record_lookup(pkt, qkey, sent_at)
        self._answered += 1
        latency = max(0.0, pkt.timestamp - sent_at)
        self._latency_sum += latency
        self._latency_max = max(self._latency_max, latency)

    def _record_lookup(self, pkt: PacketRecord, qkey: tuple, sent_at: float) -> None:
        dns = pkt.dns
        assert dns is not None and pkt.src_ip and pkt.dst_ip
        if qkey in self._retried:
            self._retried.discard(qkey)
            self._lookups_ambiguous += 1
            return
        ms = (pkt.timestamp - sent_at) * 1000
        if ms < 0:  # response stamped before its query: capture ordering anomaly, not a measurement
            self._lookups_ambiguous += 1
            return
        if len(self._lookup_log) < _MAX_LOOKUP_LOG:
            self._lookup_log.append(LookupSample(t=sent_at, ms=ms, client_ip=pkt.dst_ip, server_ip=pkt.src_ip))
        keys = [(self._lookups, (pkt.dst_ip, dns.qname))] if dns.qname else []
        keys.append((self._flow_lookups, flow_key("UDP", (pkt.dst_ip, pkt.dst_port), (pkt.src_ip, pkt.src_port))))
        for table, key in keys:
            samples = table.get(key)  # type: ignore[call-overload]
            if samples is None:
                if len(table) >= _MAX_LOOKUP_KEYS:
                    continue
                samples = table[key] = []  # type: ignore[index]
            if len(samples) < _MAX_LOOKUPS_PER_KEY:
                samples.append(ms)

    # ------------------------------------------------------------------ latency lookups (read-only)
    def lookup_latency_ms(self, client_ip: str, domain: str) -> tuple[float, int] | None:
        """(median ms, lookups) for ``client_ip`` resolving ``domain``; None if no clean pair was seen."""
        samples = self._lookups.get((client_ip, domain))
        return (round(statistics.median(samples), 3), len(samples)) if samples else None

    def domain_lookup_latencies_ms(self) -> dict[str, list[float]]:
        """All clean lookup latencies per domain (every client)."""
        out: dict[str, list[float]] = {}
        for (_, name), samples in self._lookups.items():
            out.setdefault(name, []).extend(samples)
        return out

    def lookup_samples(self) -> list[LookupSample]:
        """Answered, unambiguous lookups in capture order (bounded)."""
        return list(self._lookup_log)

    def flow_lookup_latencies_ms(self, key: FlowKey) -> list[float]:
        """Clean query->response latencies of one DNS flow (client port to server port)."""
        return list(self._flow_lookups.get(key, ()))

    def _client_stats(self) -> list[DnsClientStat]:
        n = self.max_profiles
        items = list(self._clients_stats.items())
        chosen: dict[str, _Client] = {}
        for keyfn in (lambda kv: kv[1].queries, lambda kv: kv[1].nxdomain,
                      lambda kv: len(kv[1].entropy_bases)):
            for ip, c in sorted(items, key=keyfn, reverse=True)[:n]:
                chosen[ip] = c
        return [
            DnsClientStat(
                client_ip=ip, queries=c.queries, responses=c.responses, nxdomain=c.nxdomain,
                unique_domains=len(c.names), first_time=c.first, last_time=c.last,
                random_looking_domains=len(c.entropy_bases), random_looking_samples=c.entropy_samples,
            )
            for ip, c in sorted(chosen.items(), key=lambda kv: kv[1].queries, reverse=True)
        ]

    def _domain_groups(self) -> list[DnsDomainGroup]:
        ranked = sorted(self._groups.items(), key=lambda kv: len(kv[1].names), reverse=True)[: self.max_profiles]
        return [
            DnsDomainGroup(
                base_domain=base, queries=g.queries, unique_names=len(g.names),
                max_name_length=g.max_len,
                mean_subdomain_label_length=round(g.sub_label_sum / g.sub_label_n, 2) if g.sub_label_n else 0.0,
                txt_null_queries=g.txt_null,
                top_client=g.clients.most_common(1)[0][0] if g.clients else None,
                sample_names=sorted(g.names, key=len, reverse=True)[:3],
            )
            for base, g in ranked
        ]

    def result(self) -> DnsStatistics:
        def counts(counter: Counter[str]) -> list[DnsCount]:
            return [DnsCount(name=n, count=c) for n, c in counter.most_common(self.top_n)]

        return DnsStatistics(
            total_queries=self._queries,
            total_responses=self._responses,
            unique_domains=len(self._domains),
            query_types=dict(self._types),
            response_codes=dict(self._rcodes),
            nxdomain_responses=self._rcodes.get("NXDOMAIN", 0),
            empty_responses=self._empty,
            answered_queries=self._answered,
            unanswered_queries=len(self._pending),
            responses_without_query=self._orphan_responses,
            avg_response_ms=round(1000 * self._latency_sum / self._answered, 3) if self._answered else None,
            max_response_ms=round(1000 * self._latency_max, 3) if self._answered else None,
            top_domains=counts(self._domains),
            top_clients=counts(self._clients),
            top_servers=counts(self._servers),
            query_log=self._log,
            query_log_truncated=self._log_truncated,
            clients=self._client_stats(),
            domain_groups=self._domain_groups(),
        )
