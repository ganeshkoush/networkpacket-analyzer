"""Abnormal DNS activity: NXDOMAIN storms, DGA-like names, tunneling-like names, query floods."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector, span
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, DnsClientStat, DnsDomainGroup


class DnsAnomalyDetector(BaseDetector):
    """Five independent DNS checks, each with its own evidence and thresholds.

    * **High NXDOMAIN** - a client whose responses are mostly NXDOMAIN (name guessing, DGA
      malware, stale configuration).
    * **DGA-like** - a client querying many distinct registered domains whose name label looks
      random (long, high entropy, and digit- or consonant-heavy; see ``looks_random``).
    * **Tunneling-like** - one base domain with many unique, long subdomain labels, often
      TXT/NULL queries (data encoded in names).
    * **Excessive queries** - one client's average query rate far above normal.
    * **Unsolicited responses** - many responses whose query is absent from the capture.
    """

    name = "dns_anomaly"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.dns
        if not cfg.enabled:
            return []
        dns = result.dns_statistics
        findings: list[Finding] = []
        clients = {c.client_ip: c for c in dns.clients}
        for c in dns.clients:
            if (f := self._nxdomain(c)) is not None:
                findings.append(f)
            if (f := self._dga(c)) is not None:
                findings.append(f)
            if (f := self._excessive(c)) is not None:
                findings.append(f)
        for g in dns.domain_groups:
            if (f := self._tunnel(g, clients.get(g.top_client or ""))) is not None:
                findings.append(f)
        if (f := self._unsolicited(result)) is not None:
            findings.append(f)
        return findings

    # ------------------------------------------------------------------ NXDOMAIN
    def _nxdomain(self, c: DnsClientStat) -> Finding | None:
        cfg = self.config.dns
        if c.responses < cfg.nxdomain_min_responses:
            return None
        ratio = c.nxdomain / c.responses
        if ratio < cfg.nxdomain_min_ratio:
            return None
        w = cfg.nxdomain_weights
        factors = [
            ("nxdomain_ratio", ramp(ratio, cfg.nxdomain_min_ratio, cfg.nxdomain_strong_ratio), w["ratio"],
             f"{ratio:.0%} of {c.responses} responses were NXDOMAIN"),
            ("volume", ramp(c.responses, cfg.nxdomain_min_responses, cfg.nxdomain_strong_responses), w["volume"],
             f"{c.responses} responses (full score at {cfg.nxdomain_strong_responses})"),
        ]
        return self.build(
            type=FindingType.DNS_HIGH_NXDOMAIN, factors=factors, max_severity=cfg.nxdomain_max_severity,
            title=f"High NXDOMAIN rate from {c.client_ip}",
            description=(
                f"{c.nxdomain} of {c.responses} DNS responses to {c.client_ip} ({ratio:.0%}) were NXDOMAIN. "
                f"This is consistent with possible name guessing, DGA-style malware lookups or a misconfigured "
                f"client, and requires investigation."
            ),
            evidence={"client": c.client_ip, "queries": c.queries, "responses": c.responses, "nxdomain": c.nxdomain,
                      "nxdomain_ratio": round(ratio, 4), "unique_domains": c.unique_domains},
            reasoning=[f"NXDOMAIN ratio {ratio:.0%} (threshold {cfg.nxdomain_min_ratio:.0%}) over at least "
                       f"{cfg.nxdomain_min_responses} responses."],
            caveats=["Search-domain suffix expansion, stale DNS entries and typo-ridden configs cause NXDOMAIN bursts.",
                     "Some security tools probe non-existent names deliberately."],
            recommendation=(f"Inspect the failing names queried by {c.client_ip} (Wireshark filter: "
                            f"dns.flags.rcode == 3 && ip.dst == {c.client_ip}) and identify the originating process."),
            source_ip=c.client_ip, key=c.client_ip, first_seen=c.first_time, last_seen=c.last_time,
        )

    # ------------------------------------------------------------------ DGA
    def _dga(self, c: DnsClientStat) -> Finding | None:
        cfg = self.config.dns
        if c.random_looking_domains < cfg.dga_min_domains:
            return None
        nx_ratio = c.nxdomain / c.responses if c.responses else 0.0
        share = c.random_looking_domains / c.unique_domains if c.unique_domains else 0.0
        w = cfg.dga_weights
        factors = [
            ("domain_count", ramp(c.random_looking_domains, cfg.dga_min_domains, cfg.dga_strong_domains),
             w["domain_count"], f"{c.random_looking_domains} random-looking registered domains"),
            ("nxdomain_ratio", ramp(nx_ratio, cfg.dga_nxdomain_start, cfg.dga_nxdomain_full),
             w["nxdomain_ratio"], f"{nx_ratio:.0%} NXDOMAIN"),
            ("random_share", ramp(share, cfg.dga_share_start, cfg.dga_share_full), w["random_share"],
             f"{share:.0%} of queried names looked random"),
        ]
        return self.build(
            type=FindingType.DNS_DGA_LIKE, factors=factors, max_severity=cfg.max_severity,
            title=f"Possible algorithmically generated domains queried by {c.client_ip}",
            description=(
                f"{c.client_ip} queried {c.random_looking_domains} distinct domains with long, random-looking names "
                f"(e.g. {', '.join(c.random_looking_samples[:3])}). This is consistent with possible "
                f"domain-generation-algorithm (DGA) behaviour, but random-looking names also occur legitimately; "
                f"it requires investigation."
            ),
            evidence={"client": c.client_ip, "random_looking_domains": c.random_looking_domains,
                      "sample_domains": c.random_looking_samples, "unique_domains": c.unique_domains,
                      "nxdomain_ratio": round(nx_ratio, 4), "queries": c.queries},
            reasoning=[f"{c.random_looking_domains} registered domains whose name label is long, high in Shannon entropy and "
                       f"digit-heavy or consonant-heavy (minimum {cfg.dga_min_domains} such domains)."],
            caveats=["CDNs, cloud services, antivirus cloud lookups and tracking domains use random-looking labels.",
                     "Dictionary-word DGAs and short random labels (under ~16 characters) are often missed by this check."],
            recommendation=(f"Review the sampled domains (reputation lookup, registration age) and check the "
                            f"process on {c.client_ip} that issued them. Compare with DNS logs from the resolver."),
            source_ip=c.client_ip, key=c.client_ip, first_seen=c.first_time, last_seen=c.last_time,
        )

    # ------------------------------------------------------------------ excessive rate
    def _excessive(self, c: DnsClientStat) -> Finding | None:
        cfg = self.config.dns
        duration = span(c.first_time, c.last_time, cfg.min_duration_seconds)
        qps = c.queries / duration
        if c.queries < cfg.excessive_min_queries or qps < cfg.excessive_min_qps:
            return None
        w = cfg.excessive_weights
        factors = [
            ("query_rate", ramp(qps, cfg.excessive_min_qps, cfg.excessive_strong_qps), w["rate"], f"{qps:.0f} queries/s"),
            ("volume", ramp(c.queries, cfg.excessive_min_queries, cfg.excessive_strong_queries), w["volume"],
             f"{c.queries} queries"),
        ]
        return self.build(
            type=FindingType.DNS_EXCESSIVE_QUERIES, factors=factors, max_severity=cfg.excessive_max_severity,
            title=f"Unusually high DNS query rate from {c.client_ip}",
            description=(
                f"{c.client_ip} sent {c.queries} DNS queries at an average of {qps:.0f} per second. This is "
                f"consistent with possible DNS flooding, a runaway application or tunneling, and requires investigation."
            ),
            evidence={"client": c.client_ip, "queries": c.queries, "queries_per_second": round(qps, 1),
                      "unique_domains": c.unique_domains,
                      "duration_seconds": round(span(c.first_time, c.last_time), 3)},
            reasoning=[f"Average {qps:.0f} queries/s over {c.queries} queries (thresholds "
                       f"{cfg.excessive_min_qps:.0f}/s and {cfg.excessive_min_queries} queries)."],
            caveats=["Shared resolvers, NAT gateways and busy servers legitimately aggregate many clients' queries."],
            recommendation=f"Identify whether {c.client_ip} is a resolver/gateway; if not, find the process issuing the queries.",
            source_ip=c.client_ip, key=c.client_ip, first_seen=c.first_time, last_seen=c.last_time,
        )

    # ------------------------------------------------------------------ tunneling
    def _tunnel(self, g: DnsDomainGroup, client: DnsClientStat | None) -> Finding | None:
        cfg = self.config.dns
        if any(g.base_domain.endswith(s) for s in cfg.ignored_base_suffixes):
            return None
        if g.base_domain in cfg.allowlisted_base_domains:
            return None
        if g.unique_names < cfg.tunnel_min_unique_names:
            return None
        # Require some sign of data-in-names beyond name count alone: long labels or TXT/NULL use.
        txt_share = g.txt_null_queries / g.queries if g.queries else 0.0
        if g.mean_subdomain_label_length < cfg.tunnel_label_start and txt_share == 0:
            return None
        w = cfg.tunnel_weights
        factors = [
            ("unique_names", ramp(g.unique_names, cfg.tunnel_min_unique_names, cfg.tunnel_strong_unique_names),
             w["unique_names"], f"{g.unique_names} unique names"),
            ("label_length", ramp(g.mean_subdomain_label_length, cfg.tunnel_label_start, cfg.tunnel_label_full),
             w["label_length"], f"mean subdomain label {g.mean_subdomain_label_length:.0f} chars"),
            ("name_length", ramp(g.max_name_length, cfg.tunnel_name_len_start, cfg.tunnel_name_len_full),
             w["name_length"], f"longest name {g.max_name_length} chars"),
            ("txt_null_share", ramp(txt_share, 0.0, cfg.tunnel_txt_null_share_full), w["txt_null_share"],
             f"{txt_share:.0%} TXT/NULL queries"),
        ]
        return self.build(
            type=FindingType.DNS_TUNNELING_LIKE, factors=factors, max_severity=cfg.max_severity,
            title=f"Possible DNS tunneling pattern under {g.base_domain}",
            description=(
                f"{g.queries} queries produced {g.unique_names} unique names under {g.base_domain} with a mean "
                f"subdomain label of {g.mean_subdomain_label_length:.0f} characters and {txt_share:.0%} TXT/NULL "
                f"queries. This is consistent with possible DNS tunneling or data exfiltration over DNS and "
                f"requires investigation."
            ),
            evidence={"base_domain": g.base_domain, "queries": g.queries, "unique_names": g.unique_names,
                      "mean_subdomain_label_length": g.mean_subdomain_label_length,
                      "max_name_length": g.max_name_length, "txt_null_queries": g.txt_null_queries,
                      "top_client": g.top_client, "sample_names": g.sample_names},
            reasoning=[f"{g.unique_names} unique names under one base domain (threshold {cfg.tunnel_min_unique_names}).",
                       f"Long labels (>= {cfg.tunnel_label_start:.0f} chars on average) or TXT/NULL queries are present."],
            caveats=["CDNs, antivirus/reputation lookups, DKIM/SPF checks and reverse-lookup services create many long unique names.",
                     "Add known-good base domains to the allowlist in the detection config after verification."],
            recommendation=(f"Examine the sample names and the authoritative server for {g.base_domain}; check the "
                            f"querying host ({g.top_client or 'unknown'}) for tunneling tools. Compare with resolver logs."),
            source_ip=g.top_client, key=g.base_domain,
            first_seen=client.first_time if client else None, last_seen=client.last_time if client else None,
        )

    # ------------------------------------------------------------------ unsolicited responses
    def _unsolicited(self, result: AnalysisResult) -> Finding | None:
        cfg = self.config.dns
        d = result.dns_statistics
        if d.total_responses == 0 or d.responses_without_query < cfg.unsolicited_min_responses:
            return None
        share = d.responses_without_query / d.total_responses
        if share < cfg.unsolicited_min_share:
            return None
        w = cfg.unsolicited_weights
        factors = [
            ("share", ramp(share, cfg.unsolicited_min_share, 1.0), w["share"],
             f"{share:.0%} of responses had no captured query"),
            ("volume", ramp(d.responses_without_query, cfg.unsolicited_min_responses, cfg.unsolicited_strong_responses),
             w["volume"], f"{d.responses_without_query} such responses"),
        ]
        return self.build(
            type=FindingType.DNS_UNSOLICITED_RESPONSES, factors=factors, max_severity=cfg.unsolicited_max_severity,
            title="Many DNS responses without a matching query",
            description=(
                f"{d.responses_without_query} of {d.total_responses} DNS responses ({share:.0%}) had no matching query "
                f"in this capture. This is consistent with possible DNS spoofing/reflection traffic, but is equally "
                f"explained by a capture that missed the queries; it requires investigation."
            ),
            evidence={"responses_without_query": d.responses_without_query, "total_responses": d.total_responses,
                      "share": round(share, 4), "total_queries": d.total_queries},
            reasoning=[f"Share {share:.0%} (threshold {cfg.unsolicited_min_share:.0%}) and at least "
                       f"{cfg.unsolicited_min_responses} responses."],
            caveats=["Captures started mid-conversation, or taken on only one side of an asymmetric path, miss queries.",
                     "Queries sent over TCP or encrypted DNS are not matched."],
            recommendation="Check the capture point and direction coverage; if complete, review the responding servers and destinations.",
            key="global",
        )
