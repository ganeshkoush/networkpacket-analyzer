"""Investigation orchestration: evidence -> prompt -> provider -> validated, grounded result.

The model's output is treated as untrusted. Before it is returned it must (1) match the
pydantic schema, (2) mention only IP addresses present in the supplied evidence, (3) contain no
overclaiming language, and (4) not exceed the severity the local findings support. Evidence
items citing numbers that are not in the supplied data are dropped; command-like or
blocking/configuration recommendations are removed. Nothing the model says is ever executed.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any

from pydantic import ValidationError

from app.ai.prompts import DEFAULT_QUESTION, SYSTEM_INSTRUCTION, USER_TEMPLATE
from app.ai.provider import (
    AIProvider,
    AIProviderError,
    EmptyResponseError,
    InvalidOutputError,
    MalformedResponseError,
)
from app.ai.schemas import (
    MAX_CONFIDENCE,
    UNDETERMINED,
    EvidenceBundle,
    InvestigationReport,
    InvestigationResult,
)
from app.ai.tools import build_evidence_bundle, sanitize
from app.detection.models import Finding
from app.detection.severity import Severity
from app.models.analysis import AnalysisResult

logger = logging.getLogger(__name__)

MAX_EVIDENCE_CHARS = 150_000
MAX_ATTEMPTS = 2  # retries only for empty/malformed responses
_TRIM_ORDER = ("connections_by_host", "timeline", "dns_summary", "top_talkers", "port_summary", "protocol_summary")

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_NUMBER = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\w])")
_OVERCLAIM = re.compile(
    r"\b(definitely|certainly|undoubtedly|without (a )?doubt|proves?|proven|confirmed (attack|compromise|breach)"
    r"|is (clearly |definitely )?(an? )?(attack|malicious|malware))\b", re.I)
_UNSAFE_STEP = re.compile(
    r"`|\$\(|\b(sudo|iptables|ip6tables|nft|ufw|pfctl|netsh|firewall-cmd|ifconfig|rm\s+-|chmod|chown|kill(all)?)\b"
    r"|\broute\s+(add|del|delete)\b|\bip\s+(route|link|addr)\b|\b(curl|wget)\b.*\|"
    r"|\b(automatically|auto-)\s*(block|ban|blacklist|drop|quarantine)"
    r"|\b(block|blacklist|ban|null-?route|drop)\s+(the\s+)?(ip|address|host|traffic|source)",
    re.I)


# ------------------------------------------------------------------ grounding helpers
def _ips_in(text: str) -> set[str]:
    text = _MAC.sub(" ", text)
    found: set[str] = set()
    for m in (*_IPV4.findall(text), *_IPV6.findall(text)):
        try:
            found.add(str(ipaddress.ip_address(m)))
        except ValueError:
            continue
    return found


def _strip_addresses(text: str) -> str:
    return _IPV6.sub(" ", _IPV4.sub(" ", _MAC.sub(" ", text)))


def _numbers_in(text: str) -> set[float]:
    out: set[float] = set()
    for tok in _NUMBER.findall(_strip_addresses(text)):
        try:
            out.add(round(float(tok.replace(",", "")), 6))
        except ValueError:
            continue
    return out


def _allowed_numbers(evidence_text: str) -> set[float]:
    base = _numbers_in(evidence_text)
    derived = set(base)
    for n in base:  # tolerate ratios expressed as percentages and rounding
        derived.update({round(n * 100, 6), round(n * 100), round(n, 1), round(n, 2), round(n)})
    return derived


def _walk_text(result: InvestigationResult) -> list[tuple[str, str]]:
    d = result.model_dump()
    out = []
    for k in ("investigation_summary", "interpretation"):
        out.append((k, d[k]))
    for k in ("evidence", "possible_explanations", "recommended_next_steps", "additional_evidence_needed", "limitations"):
        out += [(k, s) for s in d[k]]
    return out


# ------------------------------------------------------------------ investigator
class Investigator:
    def __init__(self, provider: AIProvider | None = None):
        self._provider = provider

    @property
    def provider(self) -> AIProvider:
        if self._provider is None:
            from app.ai.gemini_client import GeminiClient  # default provider; swap via the constructor

            self._provider = GeminiClient()
        return self._provider

    def investigate_analysis(
        self, analysis: AnalysisResult, findings: list[Finding], question: str | None = None,
        finding_id: str | None = None,
    ) -> InvestigationReport:
        try:
            bundle = build_evidence_bundle(analysis, findings, finding_id)
        except ValueError as exc:
            raise InvalidOutputError(f"Cannot build evidence: {exc}.") from None
        return self.investigate(bundle, question)

    def investigate(self, bundle: EvidenceBundle, question: str | None = None) -> InvestigationReport:
        if not bundle.data and not bundle.findings:
            return self._insufficient()
        question = sanitize((question or DEFAULT_QUESTION).strip())[:1000]
        evidence_json = self._serialize(bundle)
        prompt = USER_TEMPLATE.format(question=question.replace("<", "(").replace(">", ")"), evidence_json=evidence_json)

        response = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self.provider.generate_structured(
                    system_instruction=SYSTEM_INSTRUCTION, user_content=prompt, response_schema=InvestigationResult)
                break
            except (EmptyResponseError, MalformedResponseError) as exc:
                logger.warning("AI attempt %d/%d failed: %s", attempt, MAX_ATTEMPTS, exc.code)
                if attempt == MAX_ATTEMPTS:
                    raise
        assert response is not None

        try:
            result = InvestigationResult.model_validate(response.data)
        except ValidationError as exc:
            # Log field locations and error types only - never the model's raw values.
            logger.warning("AI output failed validation: %s", [(".".join(map(str, e["loc"])), e["type"]) for e in exc.errors()][:10])
            raise InvalidOutputError() from None

        result, notes = self._ground(result, bundle, evidence_json, question)
        return InvestigationReport(result=result, model=response.model, provider=self.provider.name, notes=notes)

    # ---- internals
    @staticmethod
    def _serialize(bundle: EvidenceBundle) -> str:
        payload = {"findings": [f.model_dump(mode="json") for f in bundle.findings], **bundle.data}

        def dump(p: dict[str, Any]) -> str:
            # Escape angle brackets so evidence text cannot forge the prompt's delimiter tags.
            return json.dumps(p, default=str, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")

        text = dump(payload)
        for key in _TRIM_ORDER:
            if len(text) <= MAX_EVIDENCE_CHARS:
                break
            payload.pop(key, None)
            payload["_truncated"] = True
            text = dump(payload)
        if len(text) > MAX_EVIDENCE_CHARS:
            raise InvalidOutputError("Evidence is too large to send; reduce the number of findings.")
        return text

    @staticmethod
    def _insufficient() -> InvestigationReport:
        r = InvestigationResult(
            investigation_summary="No structured evidence was supplied, so no investigation was performed.",
            finding_type=UNDETERMINED, severity=Severity.INFO, confidence=0.0, evidence=[],
            interpretation="There is insufficient evidence to draw any conclusion.",
            possible_explanations=[], recommended_next_steps=["Run analysis and detection on a capture first."],
            additional_evidence_needed=["Analysis results or detector findings"],
            limitations=["No evidence was provided to the investigator."])
        return InvestigationReport(result=r, model="none", provider="local", notes=["No model call was made."])

    @staticmethod
    def _ground(result: InvestigationResult, bundle: EvidenceBundle, evidence_json: str, question: str):
        notes: list[str] = []
        for field in ("recommended_next_steps", "additional_evidence_needed"):
            items = getattr(result, field)
            safe = [i for i in items if not _UNSAFE_STEP.search(i)]
            if len(safe) != len(items):
                notes.append(f"{len(items) - len(safe)} item(s) removed from {field}: command-like or automated blocking/configuration action.")
                setattr(result, field, safe)

        evidence_ips = _ips_in(evidence_json)
        allowed_ips = evidence_ips | _ips_in(question)

        for field, text in _walk_text(result):
            if _OVERCLAIM.search(text):
                logger.warning("AI output rejected: overclaiming language in %s", field)
                raise InvalidOutputError("The model output made an unsupported certainty claim and was discarded.")
            mentioned = _ips_in(text)
            allowed = evidence_ips if field == "evidence" else allowed_ips
            if mentioned - allowed:
                logger.warning("AI output rejected: IP address not present in supplied evidence (field %s)", field)
                raise InvalidOutputError(
                    "The model referenced an IP address that is not in the supplied evidence; output discarded.")

        # Evidence items must be traceable: drop items citing numbers absent from the evidence.
        allowed_nums = _allowed_numbers(evidence_json)
        kept, dropped = [], 0
        for item in result.evidence:
            nums = {n for n in _numbers_in(item) if n >= 10}
            if nums - allowed_nums:
                dropped += 1
            else:
                kept.append(item)
        if dropped:
            notes.append(f"{dropped} evidence statement(s) removed: cited values not present in supplied evidence.")
        result.evidence = kept

        if not kept and result.finding_type != UNDETERMINED:
            raise InvalidOutputError("The model gave no verifiable evidence for its conclusion; output discarded.")

        # Never let the model drift from the detector findings it was given.
        if bundle.findings:
            types = {f.type.value for f in bundle.findings}
            if result.finding_type != UNDETERMINED and result.finding_type not in types:
                raise InvalidOutputError("The model reported a finding type that is not among the supplied findings.")
            ceiling = max((f.severity for f in bundle.findings), key=lambda s: s.rank)
            if result.severity.rank > ceiling.rank:
                notes.append(f"Severity lowered from {result.severity.value} to {ceiling.value} (highest local finding).")
                result.severity = ceiling

        if result.confidence > MAX_CONFIDENCE:
            result.confidence = MAX_CONFIDENCE
            notes.append(f"Confidence capped at {MAX_CONFIDENCE}.")

        return result, notes
