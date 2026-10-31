"""Render a saved report as HTML (printable), Markdown or JSON. All dynamic text is escaped."""
from __future__ import annotations

import html
import json
import re

from app.models.report import ReportContent, SavedReport

FORMATS = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8", "json": "application/json"}


def export_filename(saved: SavedReport, fmt: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", saved.content.title.lower()).strip("-")[:50] or "report"
    day = saved.content.investigation_timestamp.strftime("%Y%m%d")
    return f"packetmind-{slug}-{day}-{saved.id[:8]}.{fmt}"


def render(saved: SavedReport, fmt: str) -> bytes:
    if fmt == "json":
        return json.dumps({"id": saved.id, **json.loads(saved.content.model_dump_json())}, indent=2).encode()
    return (to_html(saved.content) if fmt == "html" else to_markdown(saved.content)).encode("utf-8")


def _ts(c: ReportContent) -> str:
    return c.investigation_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _ai_lines(res) -> list[tuple[str, list[str] | str]]:
    return [("Summary", res.investigation_summary), ("Interpretation", res.interpretation),
            ("Evidence cited", res.evidence), ("Possible explanations", res.possible_explanations),
            ("Recommended next steps", res.recommended_next_steps),
            ("Additional evidence needed", res.additional_evidence_needed), ("Limitations", res.limitations)]


# ------------------------------------------------------------------ HTML
_CSS = """
:root{color-scheme:light}body{font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1b1f24;max-width:880px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.7rem;margin:0}h2{font-size:1.15rem;border-bottom:2px solid #d0d7de;padding-bottom:.25rem;margin-top:2rem}h3{font-size:1rem;margin:.2rem 0}
.meta{color:#57606a}table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #d0d7de;padding:.3rem .55rem;text-align:left;vertical-align:top}
th{background:#f6f8fa}.num{text-align:right;font-variant-numeric:tabular-nums}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:#f6f8fa;border:1px solid #d0d7de;padding:.6rem;overflow-x:auto;white-space:pre-wrap}.finding{border:1px solid #d0d7de;border-radius:6px;padding:.8rem 1rem;margin:1rem 0;page-break-inside:avoid}
.sev{display:inline-block;padding:0 .45rem;border-radius:4px;font-weight:600;font-size:12px;color:#fff;background:#57606a}.sev-CRITICAL{background:#a40e26}.sev-HIGH{background:#cf222e}.sev-MEDIUM{background:#9a6700}.sev-LOW{background:#0969da}
.note{background:#fff8c5;border:1px solid #d4a72c;padding:.5rem .8rem;border-radius:6px}.ai{background:#f6f8fa;border-left:4px solid #0969da;padding:.5rem .9rem;margin:.6rem 0}
@media print{body{margin:0}}
"""


def to_html(c: ReportContent) -> str:
    e = html.escape

    def ul(items) -> str:
        return "<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in items) + "</ul>" if items else "<p class='meta'>None.</p>"

    def table(headers, rows, numeric=()) -> str:
        if not rows:
            return "<p class='meta'>None.</p>"
        head = "".join(f"<th>{e(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(
            f"<td class='{'num' if i in numeric else ''}'>{e(str(v))}</td>" for i, v in enumerate(r)) + "</tr>" for r in rows)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    def ai_block(res) -> str:
        parts = []
        for label, val in _ai_lines(res):
            body = f"<p>{e(val)}</p>" if isinstance(val, str) else ul(val)
            parts.append(f"<h3>{e(label)}</h3>{body}")
        return f"<div class='ai'><p class='meta'>Severity {e(res.severity.value)} · confidence {res.confidence:.2f} · type {e(res.finding_type)}</p>{''.join(parts)}</div>"

    s, cap = c.summary, c.capture
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
           f"<title>{e(c.title)}</title><style>{_CSS}</style></head><body>",
           f"<h1>{e(c.title)}</h1><p class='meta'>PacketMind investigation report · generated {e(_ts(c))} · v{e(c.app_version)}</p>",
           f"<p>{e(s.headline)}</p>"]
    if c.analyst_notes:
        out.append(f"<h2>Analyst notes</h2><p>{e(c.analyst_notes)}</p>")
    out.append("<h2>1. Capture information</h2>" + table(["Field", "Value"], [r for r in [
        ("Source", "Live capture" if cap.source_kind == "live" else "PCAP file"), ("Name", cap.name),
        ("Interface", cap.interface) if cap.interface else None, ("Format", cap.capture_format),
        ("Size", _fmt_bytes(cap.size_bytes)) if cap.size_bytes else None, ("SHA-256", cap.sha256) if cap.sha256 else None,
        ("Packets", f"{cap.packets:,}"), ("Duration", f"{cap.duration_seconds:.1f} s"),
        ("First packet", cap.first_packet_time_iso or "n/a"), ("Last packet", cap.last_packet_time_iso or "n/a")] if r]))
    if cap.warnings:
        out.append(f"<div class='note'><strong>Capture warnings</strong>{ul(cap.warnings)}</div>")
    out.append("<h2>2. Analysis summary</h2>" + table(["Metric", "Value"], [
        ("Total packets", f"{s.total_packets:,}"), ("Total bytes", _fmt_bytes(s.total_bytes)),
        ("Average packets/s", s.avg_packets_per_second if s.avg_packets_per_second is not None else "n/a"),
        ("Peak packets/s", s.peak_packets_per_second if s.peak_packets_per_second is not None else "n/a"),
        ("Unique source / destination IPs", f"{s.unique_source_ips} / {s.unique_destination_ips}"),
        ("Findings", f"{s.finding_count}" + (f" ({', '.join(f'{v} {k}' for k, v in s.severity_counts.items())})" if s.severity_counts else ""))]))
    out.append("<h2>3. Protocol statistics</h2>" + table(["Protocol", "Packets", "Bytes", "Share"],
               [(p.protocol, f"{p.packets:,}", _fmt_bytes(p.bytes), f"{p.percent_of_packets:.1f}%") for p in c.protocols], numeric=(1, 2, 3)))
    out.append("<h2>4. Top talkers</h2>" + table(["Host", "Packets sent", "Packets received", "Total bytes"],
               [(t.ip, f"{t.packets_sent:,}", f"{t.packets_received:,}", _fmt_bytes(t.total_bytes)) for t in c.top_talkers], numeric=(1, 2, 3)))
    out.append("<h3>Top destination ports</h3>" + table(["Protocol", "Port", "Service hint", "Packets"],
               [(p.protocol, p.port, p.service_hint or "", f"{p.packets:,}") for p in c.top_ports], numeric=(3,)))
    if c.domains:
        out.append("<h3>Top domains (inferred from DNS, not exact URLs)</h3>" + table(["Domain", "Connections", "Sent", "Received"],
                   [(d.domain, f"{d.connections:,}", _fmt_bytes(d.bytes_sent), _fmt_bytes(d.bytes_received)) for d in c.domains], numeric=(1, 2, 3)))
    out.append("<h2>5. Findings</h2>")
    if not c.findings:
        out.append("<p>No detector threshold was exceeded.</p>")
    for i, f in enumerate(c.findings, 1):
        where = " → ".join(x for x in (f.source_ip, f.destination_ip) if x) or "capture-wide"
        times = f" · {f.first_seen_iso} – {f.last_seen_iso}" if f.first_seen_iso else ""
        out.append(
            f"<div class='finding'><h3>{i}. {e(f.title)}</h3>"
            f"<p><span class='sev sev-{e(f.severity.value)}'>{e(f.severity.value)}</span> confidence {f.confidence:.2f} · "
            f"{e(f.type)} · {e(where)}{e(times)}</p><p>{e(f.description)}</p>"
            f"<h3>Evidence</h3><pre>{e(json.dumps(f.evidence, indent=2, default=str))}</pre>"
            f"<h3>Investigation steps</h3>{ul(f.investigation_steps)}<h3>Possible benign explanations</h3>{ul(f.caveats)}"
            f"<h3>Recommendation</h3><p>{e(f.recommendation)}</p>"
            + (f"<h3>AI assessment</h3>{ai_block(f.ai_assessment)}" if f.ai_assessment else "") + "</div>")
    a = c.ai_investigation
    out.append("<h2>6. AI investigation summary</h2>")
    if a.status == "completed" and a.result:
        out.append(f"<p class='meta'>Generated by {e(a.provider or 'AI')} ({e(a.model or 'unknown model')}) from aggregated evidence only. "
                   f"AI output is advisory and may be wrong.</p>{ai_block(a.result)}")
        if a.notes:
            out.append(f"<p class='meta'>Safeguards applied: {e('; '.join(a.notes))}</p>")
    else:
        out.append(f"<p class='meta'>{e(a.message or 'No AI investigation is included in this report.')}</p>")
    out.append("<h2>7. Recommended actions</h2>")
    out.append("<ol>" + "".join(
        f"<li>{('<strong>' + e(x.priority.value) + '</strong> · ') if x.priority else ''}{e(x.action)} "
        f"<span class='meta'>({'AI' if x.source == 'ai' else 'detector'})</span></li>" for x in c.recommended_actions) + "</ol>"
        if c.recommended_actions else "<p class='meta'>None.</p>")
    out.append("<p class='meta'>Recommendations are manual investigative steps. PacketMind never blocks traffic or changes configuration.</p>")
    out.append("<h2>8. Limitations</h2>" + ul(c.limitations))
    out.append(f"<h2>9. Investigation timestamp</h2><p>{e(_ts(c))}</p></body></html>")
    return "".join(out)


# ------------------------------------------------------------------ Markdown
def _md(text: object) -> str:
    t = str(text).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", t)


def to_markdown(c: ReportContent) -> str:
    s, cap = c.summary, c.capture
    L = [f"# {_md(c.title)}", "", f"*PacketMind investigation report · generated {_ts(c)} · v{_md(c.app_version)}*", "", _md(s.headline), ""]

    def bullets(items):
        return [f"- {_md(i)}" for i in items] or ["- None."]

    def tbl(headers, rows):
        if not rows:
            return ["None.", ""]
        return ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)] + \
               ["| " + " | ".join(_md(v) for v in r) + " |" for r in rows] + [""]

    if c.analyst_notes:
        L += ["## Analyst notes", "", _md(c.analyst_notes), ""]
    L += ["## 1. Capture information", ""] + tbl(["Field", "Value"], [r for r in [
        ("Source", "Live capture" if cap.source_kind == "live" else "PCAP file"), ("Name", cap.name),
        ("Interface", cap.interface) if cap.interface else None, ("Format", cap.capture_format),
        ("SHA-256", cap.sha256) if cap.sha256 else None, ("Packets", f"{cap.packets:,}"),
        ("Duration", f"{cap.duration_seconds:.1f} s"), ("First packet", cap.first_packet_time_iso or "n/a"),
        ("Last packet", cap.last_packet_time_iso or "n/a")] if r])
    if cap.warnings:
        L += ["**Capture warnings**", ""] + bullets(cap.warnings) + [""]
    L += ["## 2. Analysis summary", ""] + tbl(["Metric", "Value"], [
        ("Total packets", f"{s.total_packets:,}"), ("Total bytes", _fmt_bytes(s.total_bytes)),
        ("Unique source / destination IPs", f"{s.unique_source_ips} / {s.unique_destination_ips}"),
        ("Findings", f"{s.finding_count}" + (f" ({', '.join(f'{v} {k}' for k, v in s.severity_counts.items())})" if s.severity_counts else ""))])
    L += ["## 3. Protocol statistics", ""] + tbl(["Protocol", "Packets", "Bytes", "Share"],
          [(p.protocol, f"{p.packets:,}", _fmt_bytes(p.bytes), f"{p.percent_of_packets:.1f}%") for p in c.protocols])
    L += ["## 4. Top talkers", ""] + tbl(["Host", "Packets sent", "Packets received", "Total bytes"],
          [(t.ip, f"{t.packets_sent:,}", f"{t.packets_received:,}", _fmt_bytes(t.total_bytes)) for t in c.top_talkers])
    L += ["### Top destination ports", ""] + tbl(["Protocol", "Port", "Service hint", "Packets"],
          [(p.protocol, p.port, p.service_hint or "", f"{p.packets:,}") for p in c.top_ports])

    if c.domains:
        L += ["### Top domains (inferred from DNS, not exact URLs)", ""] + tbl(["Domain", "Connections", "Sent", "Received"],
              [(d.domain, f"{d.connections:,}", _fmt_bytes(d.bytes_sent), _fmt_bytes(d.bytes_received)) for d in c.domains])

    def ai_md(res, level="####"):
        out = [f"*Severity {res.severity.value} · confidence {res.confidence:.2f} · type {_md(res.finding_type)}*", ""]
        for label, val in _ai_lines(res):
            out += [f"{level} {label}", ""] + ([_md(val), ""] if isinstance(val, str) else bullets(val) + [""])
        return out

    L += ["## 5. Findings", ""]
    if not c.findings:
        L += ["No detector threshold was exceeded.", ""]
    for i, f in enumerate(c.findings, 1):
        where = " → ".join(x for x in (f.source_ip, f.destination_ip) if x) or "capture-wide"
        ev = json.dumps(f.evidence, indent=2, default=str).replace("```", "'''")
        L += [f"### {i}. {_md(f.title)}", "", f"**{f.severity.value}** · confidence {f.confidence:.2f} · {_md(f.type)} · {_md(where)}"
              + (f" · {f.first_seen_iso} – {f.last_seen_iso}" if f.first_seen_iso else ""), "", _md(f.description), "",
              "#### Evidence", "", "```json", ev, "```", "", "#### Investigation steps", ""] + bullets(f.investigation_steps) + \
             ["", "#### Possible benign explanations", ""] + bullets(f.caveats) + ["", "#### Recommendation", "", _md(f.recommendation), ""]
        if f.ai_assessment:
            L += ["#### AI assessment", ""] + ai_md(f.ai_assessment, "#####")
    a = c.ai_investigation
    L += ["## 6. AI investigation summary", ""]
    if a.status == "completed" and a.result:
        L += [f"*Generated by {_md(a.provider or 'AI')} ({_md(a.model or 'unknown')}) from aggregated evidence only. AI output is advisory and may be wrong.*", ""] + ai_md(a.result)
    else:
        L += [_md(a.message or "No AI investigation is included in this report."), ""]
    L += ["## 7. Recommended actions", ""]
    L += [f"{i}. {('**' + x.priority.value + '** · ') if x.priority else ''}{_md(x.action)} *({'AI' if x.source == 'ai' else 'detector'})*"
          for i, x in enumerate(c.recommended_actions, 1)] or ["None."]
    L += ["", "*Recommendations are manual investigative steps. PacketMind never blocks traffic or changes configuration.*", "",
          "## 8. Limitations", ""] + bullets(c.limitations) + ["", "## 9. Investigation timestamp", "", _ts(c), ""]
    return "\n".join(L)
