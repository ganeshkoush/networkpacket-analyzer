"""Replace IP addresses in saved reports with stable labels (host-1, host-2 ...) when 'Anonymize IP addresses' is on."""
from __future__ import annotations

import re

from app.models.report import ReportContent

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")


def anonymize_text(text: str) -> str:
    labels: dict[str, str] = {}

    def swap(m: re.Match) -> str:
        ip = m.group(0)
        if ip.count(":") and not any(c.isalnum() for c in ip.replace(":", "")):
            return ip  # a lone "::" is not an address
        return labels.setdefault(ip.lower(), f"host-{len(labels) + 1}")

    return _IPV6.sub(swap, _IPV4.sub(swap, text))


def anonymize_report(content: ReportContent) -> ReportContent:
    """The same report with every IP address replaced. The model is re-validated, so the result is still a valid report."""
    return ReportContent.model_validate_json(anonymize_text(content.model_dump_json()))
