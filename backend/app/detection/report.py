"""Plain-text rendering of findings (used by the CLI)."""
from __future__ import annotations

import json
import textwrap

from app.detection.models import Finding


def format_findings(findings: list[Finding], *, show_evidence: bool = True) -> str:
    """Render findings as readable text, most severe first (input order)."""
    title = "Detection findings"
    out = ["", title, "=" * len(title)]
    if not findings:
        out.append("  No findings: no detector threshold was exceeded.")
        out.append("  (That is not proof of safety - detectors only see what this capture contains.)")
        return "\n".join(out)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    out.append("  " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    for i, f in enumerate(findings, 1):
        where = " -> ".join(x for x in (f.source_ip, f.destination_ip) if x) or "capture-wide"
        out += ["", f"[{i}] {f.severity.value}  confidence {f.confidence:.2f}  {f.type.value}  ({where})",
                f"    {f.title}", f"    id: {f.id}"]
        out += textwrap.wrap(f.description, 100, initial_indent="    ", subsequent_indent="    ")
        if show_evidence:
            out.append("    evidence: " + json.dumps(f.evidence, default=str)[:600])
        out.append("    why: " + "; ".join(f.reasoning))
        out.append("    confidence factors: " + ", ".join(
            f"{c.name}={c.score:.2f}(w{c.weight:g})" for c in f.confidence_factors))
        out.append("    could also be: " + " | ".join(f.caveats))
        out += textwrap.wrap("Next step: " + f.recommendation, 100, initial_indent="    ", subsequent_indent="    ")
    out.append("\nFindings are possibilities with evidence, not verdicts.")
    return "\n".join(out)
