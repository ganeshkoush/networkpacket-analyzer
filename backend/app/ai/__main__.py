"""Manual test: `python -m app.ai path/to/capture.pcap [--question "..."]` (needs GEMINI_API_KEY)."""
from __future__ import annotations

import argparse
import sys

from app.ai import AIProviderError, Investigator
from app.analysis import analyze_pcap
from app.detection import detect_threats


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the Gemini investigator on a capture (analysis stays local).")
    ap.add_argument("pcap")
    ap.add_argument("--question")
    ap.add_argument("--finding-id")
    args = ap.parse_args()
    analysis = analyze_pcap(args.pcap)
    findings = detect_threats(analysis)
    print(f"{len(findings)} local finding(s); sending structured evidence only (not the PCAP).", file=sys.stderr)
    try:
        report = Investigator().investigate_analysis(analysis, findings, args.question, args.finding_id)
    except AIProviderError as exc:
        print(f"Investigation failed [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
