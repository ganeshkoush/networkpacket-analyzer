"""Fixtures/fakes for AI tests. No real Gemini key or network is ever used."""
from __future__ import annotations

import copy

from app.ai.provider import AIProvider, ProviderResponse
from app.ai.schemas import EvidenceBundle
from app.detection.models import Finding, FindingType
from app.detection.severity import Severity

SCANNER = "192.168.1.45"
TARGET = "10.0.0.5"

PORT_SCAN_EVIDENCE = {
    "source_ip": SCANNER, "destination_ip": TARGET, "unique_destination_ports": 612,
    "syn_packets": 1823, "syn_ack_packets": 14, "duration_seconds": 90,
}


def port_scan_finding() -> Finding:
    return Finding(
        id="PORT_SCAN-1", type=FindingType.PORT_SCAN, severity=Severity.HIGH, confidence=0.9,
        source_ip=SCANNER, destination_ip=TARGET, title="Possible TCP SYN port scan",
        description="Source contacted many ports with few replies, consistent with SYN scanning.",
        evidence=dict(PORT_SCAN_EVIDENCE), reasoning=["612 ports in 90 seconds"],
        caveats=["Authorized vulnerability scanner"], recommendation="Confirm whether the scan was authorized.",
        detector="port_scan", first_seen=1_700_000_000.0, last_seen=1_700_000_090.0)


def bundle() -> EvidenceBundle:
    return EvidenceBundle(data={"tcp_summary": {"syn_packets": 1823, "syn_ack_packets": 14}},
                          findings=[port_scan_finding()])


def raw_bundle() -> EvidenceBundle:
    """Evidence given as plain structured data, no detector finding objects."""
    return EvidenceBundle(data={"observation": dict(PORT_SCAN_EVIDENCE)})


GOOD_RESPONSE = {
    "investigation_summary": "The observed traffic is consistent with possible TCP SYN scanning.",
    "finding_type": "PORT_SCAN", "severity": "HIGH", "confidence": 0.9,
    "evidence": ["1823 SYN packets were observed.", "612 unique destination ports were contacted.",
                 "Only 14 SYN-ACK responses were observed.", f"The source was {SCANNER}."],
    "interpretation": "The pattern is consistent with TCP SYN scanning and may indicate reconnaissance.",
    "possible_explanations": ["Network service discovery", "Security scanning", "Potential reconnaissance activity"],
    "recommended_next_steps": ["Identify the process generating the connections.", "Review host security logs.",
                               "Check whether the activity was authorized."],
    "additional_evidence_needed": ["Process information from the source host", "Authentication logs"],
    "limitations": ["A PCAP alone cannot establish user intent."],
}


def good(**overrides) -> dict:
    d = copy.deepcopy(GOOD_RESPONSE)
    d.update(overrides)
    return d


class FakeProvider(AIProvider):
    """Mock provider: returns queued responses (dicts) or raises queued exceptions."""

    name = "fake"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def generate_structured(self, *, system_instruction, user_content, response_schema):
        self.calls.append({"system": system_instruction, "user": user_content, "schema": response_schema})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return ProviderResponse(data=item, model="fake-model")
