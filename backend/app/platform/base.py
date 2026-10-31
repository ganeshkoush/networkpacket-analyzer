"""Platform abstraction for local process <-> network connection information.

A packet capture cannot say which application sent a packet. Where the operating system can (it keeps a socket table with
the owning process), a ``ProcessConnectionSource`` reads it. Each OS gets one implementation module (``macos.py`` today;
Linux and Windows can be added next to it) and registers in ``app.platform.get_process_source``. Sources must be
*read-only*: no firewall or network changes, no process control, no elevation.
"""
from __future__ import annotations

import abc

from app.models.process import ProcessSnapshot


class ProcessSourceError(Exception):
    """The OS could not be asked (tool missing, timed out, failed). The message is safe to show to the user."""


class ProcessConnectionSource(abc.ABC):
    """Reads the OS socket table and returns it as :class:`ProcessSnapshot`."""

    platform: str = "unknown"
    mechanism: str | None = None
    permission_note: str = ""

    @property
    def supported(self) -> bool:
        return True

    @abc.abstractmethod
    def snapshot(self, now: float) -> ProcessSnapshot:
        """The sockets that are open *now* and their owning processes.

        Raises:
            ProcessSourceError: the OS could not be queried.
        """


class UnsupportedProcessSource(ProcessConnectionSource):
    """Placeholder for platforms without an implementation yet: never guesses, always reports itself unavailable."""

    def __init__(self, platform: str) -> None:
        self.platform = platform
        self.permission_note = f"Process mapping is not implemented for {platform} yet; no process information is available."

    @property
    def supported(self) -> bool:
        return False

    def snapshot(self, now: float) -> ProcessSnapshot:
        raise ProcessSourceError(f"Process mapping is not supported on {self.platform}.")
