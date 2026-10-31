"""Regenerate fixtures: `cd backend && .venv/bin/python tests/fixtures/build_fixtures.py`"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pcap_factory import build_attack_demo, build_sample, write_pcap  # noqa: E402

here = Path(__file__).parent
print("wrote", write_pcap(here / "sample.pcap", build_sample()))
print("wrote", write_pcap(here / "attack_demo.pcap", sorted(build_attack_demo(), key=lambda p: p.time)))
