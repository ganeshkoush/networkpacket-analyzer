"""Passive packet sources. Capture only: no injection, no modification, no filtering of traffic.

`PacketSource` is the seam between OS-level capture and the rest of PacketMind; tests substitute
a fake source. `ScapySource` opens a *listen-only* socket (libpcap/BPF on macOS, AF_PACKET on
Linux, Npcap on Windows) and never writes to it.
"""
from __future__ import annotations

import errno
import os
import logging
import sys
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class CaptureStartError(Exception):
    """Capture could not be started. `permission` marks privilege problems (shown as a warning)."""

    def __init__(self, code: str, message: str, hint: str | None = None, permission: bool = False):
        super().__init__(message)
        self.code, self.message, self.hint, self.permission = code, message, hint, permission


def permission_hint() -> str:
    if sys.platform == "darwin":
        script = os.environ.get("PACKETMIND_BPF_SCRIPT", "").strip()  # set by the installed app: the script it ships with
        if script:
            return ("macOS: PacketMind needs read/write access to /dev/bpf*. Open Terminal and run "
                    f"'sudo \"{script}\" install' (one-time, survives reboot; read the script first, it only changes /dev/bpf* "
                    "group access), then click Start capture again. Offline PCAP analysis does not need this.")
        return ("macOS: PacketMind needs read/write access to /dev/bpf*. In a terminal, from the project folder, run "
                "'sudo scripts/macos-bpf-access.sh install' (one-time, survives reboot), then click Start capture again. "
                "Alternative: run the backend with 'sudo -E' (note: this makes files it creates root-owned).")
    if sys.platform.startswith("linux"):
        return ("Linux: run the backend as root, or grant the Python interpreter capabilities: "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)")
    if sys.platform.startswith("win"):
        return "Windows: install Npcap (https://npcap.com, WinPcap API-compatible mode) and run the backend as Administrator."
    return "Run the backend with sufficient privileges to open raw capture sockets."


def classify_open_error(exc: BaseException) -> CaptureStartError:
    """Map whatever the OS/Scapy raised when opening the capture socket to a controlled error."""
    text = str(exc)
    low = text.lower()
    no = getattr(exc, "errno", None)
    if isinstance(exc, PermissionError) or no in (errno.EPERM, errno.EACCES) or "permission denied" in low \
            or "operation not permitted" in low or "run scapy as root" in low or "administrator" in low:
        return CaptureStartError("permission_denied", "Permission denied: PacketMind may not capture on this interface.",
                                 permission_hint(), permission=True)
    if any(s in low for s in ("npcap", "winpcap", "libpcap", "no libpcap", "wpcap", "pcap provider")):
        return CaptureStartError("capture_driver_missing",
                                 "The packet-capture driver/library was not found.", permission_hint())
    if no in (errno.ENODEV, errno.ENXIO, errno.ENETDOWN) or "no such device" in low or "not found" in low:
        return CaptureStartError("interface_unavailable", "The selected interface is not available (is it up?).")
    logger.warning("Capture start failed: %s: %s", type(exc).__name__, text[:200])
    return CaptureStartError("capture_failed", f"Could not start capture ({type(exc).__name__}).")


class PacketSource(ABC):
    """Delivers raw packets to a callback from a background thread until stopped."""

    @abstractmethod
    def start(self, interface: str, on_packet: Callable[[Any], None]) -> None:
        """Open the interface and begin delivering packets. Raise CaptureStartError on failure."""

    @abstractmethod
    def stop(self) -> None:
        """Stop delivering packets and release the interface. Safe to call repeatedly."""

    @abstractmethod
    def failure(self) -> str | None:
        """A message if capture died unexpectedly after starting, else None."""


class ScapySource(PacketSource):
    def __init__(self, promiscuous: bool = False) -> None:
        # Non-promiscuous by default: only traffic to/from this machine (plus broadcast/multicast).
        self.promiscuous = promiscuous
        self._sniffer: Any = None
        self._socket: Any = None
        self._lock = threading.Lock()

    def start(self, interface: str, on_packet: Callable[[Any], None]) -> None:
        try:
            from scapy.config import conf
            from scapy.sendrecv import AsyncSniffer

            # Open the listen socket synchronously so permission/driver errors surface here.
            sock = conf.L2listen(iface=interface, promisc=self.promiscuous)
        except BaseException as exc:  # Scapy raises many types, incl. Scapy_Exception and ImportError
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise classify_open_error(exc) from None
        try:
            sniffer = AsyncSniffer(opened_socket=sock, prn=on_packet, store=False)
            sniffer.start()
        except BaseException as exc:
            try:
                sock.close()
            except Exception:
                pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise classify_open_error(exc) from None
        with self._lock:
            self._socket, self._sniffer = sock, sniffer

    def stop(self) -> None:
        with self._lock:
            sniffer, sock, self._sniffer, self._socket = self._sniffer, self._socket, None, None
        if sniffer is not None:
            try:
                if sniffer.running:
                    sniffer.stop(join=True)
            except Exception:
                logger.debug("sniffer stop raised", exc_info=True)
        if sock is not None:
            try:
                sock.close()
            except Exception:
                logger.debug("socket close raised", exc_info=True)

    def failure(self) -> str | None:
        sniffer = self._sniffer
        if sniffer is None:
            return None
        exc = getattr(sniffer, "exception", None)
        if exc is not None:
            return f"{type(exc).__name__}"
        thread = getattr(sniffer, "thread", None)
        if thread is not None and not thread.is_alive():  # stop() clears self._sniffer first
            return "capture thread ended unexpectedly"
        return None
