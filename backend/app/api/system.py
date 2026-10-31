"""Read-only description of how this backend is configured. Never exposes secrets."""
from __future__ import annotations

import glob
import os
import sys
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import get_ai_settings, settings

router = APIRouter(prefix="/api", tags=["system"])


class AiInfo(BaseModel):
    configured: bool
    provider: str
    model: str


class LiveInfo(BaseModel):
    platform: str
    capture_library: bool
    # Best-effort guess only; the authoritative answer is whether a capture actually starts.
    privileges: Literal["likely", "unlikely", "unknown"]
    note: str


class SystemInfo(BaseModel):
    app: str
    version: str
    ai: AiInfo
    live: LiveInfo
    max_upload_bytes: int
    max_retained_analyses: int
    log_level: str
    data_dir: str
    captures_dir: str
    reports_dir: str


def _live_info() -> LiveInfo:
    try:
        import scapy  # noqa: F401
        lib = True
    except ImportError:
        lib = False
    if sys.platform == "darwin":
        bpf = glob.glob("/dev/bpf*")
        ok = any(os.access(p, os.R_OK | os.W_OK) for p in bpf)
        priv = "likely" if ok else "unlikely"
        note = "Capture needs read access to /dev/bpf* (ChmodBPF; see docs/live-capture.md)."
    elif sys.platform.startswith("linux"):
        priv = "likely" if os.geteuid() == 0 else "unknown"
        note = "Capture needs root or CAP_NET_RAW on the Python interpreter."
    else:
        priv = "unknown"
        note = "Capture needs Npcap on Windows; live capture is untested on this platform."
    return LiveInfo(platform=sys.platform, capture_library=lib, privileges=priv, note=note)


@router.get("/system", response_model=SystemInfo)
def system_info() -> SystemInfo:
    ai = get_ai_settings()
    return SystemInfo(
        app=settings.app_name, version=settings.version,
        ai=AiInfo(configured=ai.api_key_value() is not None, provider="Google Gemini", model=ai.gemini_model),
        live=_live_info(), max_upload_bytes=settings.max_upload_bytes,
        max_retained_analyses=settings.max_retained_analyses, log_level=settings.log_level,
        data_dir=str(settings.database_path_dir()), captures_dir=str(settings.captures_dir),
        reports_dir=str(settings.reports_dir),
    )
