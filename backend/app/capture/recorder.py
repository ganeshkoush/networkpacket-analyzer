"""Writes live packets to a standard .pcap / .pcapng file while a capture runs.

The file is the packets exactly as the capture library delivered them (with their timestamps): no custom format, nothing
added, nothing sent anywhere. Failures (disk full, permissions) are recorded, never raised into the packet path, and the
recorder stops writing so a half-broken file is never presented as complete.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

from app.analysis.pcap_parser import PcapParser, detect_format
from app.capture.sniffer import CaptureStartError
from app.models.capture import CaptureFormat

logger = logging.getLogger(__name__)

_FLUSH_EVERY = 200  # packets between flushes: bounds loss on a crash without a syscall per packet


def _headers_only(pkt: Any) -> Any:
    """A copy of ``pkt`` with the application payload bytes removed (Ethernet/IP/TCP/UDP headers and parsed DNS/ARP stay).

    The capture file then records the *original* packet length, exactly as a capture with a short snap length would, so the
    analysis still counts the real bytes and notes that packets were truncated.
    """
    from scapy.packet import Padding, Raw

    wire = getattr(pkt, "wirelen", None) or len(pkt)
    out = pkt.copy()
    for layer_type in (Raw, Padding):
        layer = out.getlayer(layer_type)
        if layer is not None and layer.underlayer is not None:
            layer.underlayer.remove_payload()
    out.time, out.wirelen = pkt.time, wire
    return out


class RecorderError(Exception):
    """The recording could not be completed or verified (the message is safe to show to the user)."""


def _disk_message(exc: BaseException) -> str:
    import errno

    if getattr(exc, "errno", None) == errno.ENOSPC:
        return "The disk is full, so the capture could not be saved. Free some space and capture again."
    if isinstance(exc, PermissionError):
        return "PacketMind is not allowed to write to its capture folder."
    return "Writing the capture file failed. The file is incomplete."


class CaptureRecorder:
    def __init__(self, target: Any, fmt: CaptureFormat = "pcap", headers_only: bool = False) -> None:
        """``target``: a path (the file already exists, created owner-only) or, for pcap, an open binary file."""
        from scapy.utils import PcapNgWriter, PcapWriter

        self.format = fmt
        self.headers_only = headers_only
        self._file = None if isinstance(target, (str, bytes, os.PathLike)) else target
        self._lock = threading.Lock()
        self._closed = False
        self._since_flush = 0
        self.packets = 0
        self.bytes = 0
        self.error: str | None = None
        try:
            self._writer = PcapNgWriter(str(target)) if fmt == "pcapng" else PcapWriter(str(target) if self._file is None else target, sync=False)
        except Exception as exc:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass
            raise CaptureStartError("capture_file_failed", _disk_message(exc)) from None

    def write(self, pkt: Any) -> bool:
        """Append one packet. False (and ``error`` set) once writing has failed; never raises."""
        with self._lock:
            if self._closed or self.error:
                return False
            try:
                out = _headers_only(pkt) if self.headers_only else pkt
                self._writer.write(out)
                self.packets += 1
                self.bytes += len(out)
                self._since_flush += 1
                if self._since_flush >= _FLUSH_EVERY:
                    self._writer.flush()
                    self._since_flush = 0
                return True
            except Exception as exc:
                logger.error("Capture write failed after %d packets: %s", self.packets, type(exc).__name__)
                self.error = _disk_message(exc)
                return False

    @property
    def approx_size(self) -> int:
        """Size of the file so far without touching the disk (global header + per-packet header + data)."""
        return 24 + self.packets * 16 + self.bytes

    def flush(self) -> None:
        with self._lock:
            if self._closed or self.error:
                return
            try:
                self._writer.flush()
                self._since_flush = 0
            except Exception as exc:
                self.error = _disk_message(exc)

    def close(self) -> None:
        """Flush and close the file. Idempotent; a failure here is reported through ``error``."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._writer.close()  # flushes pending packets and closes the file object
            except Exception as exc:
                logger.error("Closing the capture file failed: %s", type(exc).__name__)
                self.error = self.error or _disk_message(exc)
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass


def verify_capture_file(path, expected_packets: int | None = None) -> int:
    """Check a finished capture file exists, is a readable PCAP/PCAPNG and has packets; return its size in bytes.

    Reads only the first packet (streaming), so it is cheap whatever the file size.
    """
    from pathlib import Path

    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        raise RecorderError("The capture file is missing after saving.") from None
    try:
        detect_format(p)
    except Exception:
        raise RecorderError("The saved capture file is not a valid PCAP file.") from None
    if expected_packets:
        parser = PcapParser(p)
        first = next(iter(parser), None)
        if first is None:
            raise RecorderError("The saved capture file could not be read back.")
    return size
