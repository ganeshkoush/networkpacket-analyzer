"""Operating-system specific, read-only information sources (process <-> connection mapping).

Add support for another OS by adding a module next to ``macos.py`` that subclasses ``ProcessConnectionSource`` and
registering it in ``get_process_source`` below. Note: this package is ``app.platform``; code here uses ``sys.platform``.
"""
import sys

from app.platform.base import ProcessConnectionSource, ProcessSourceError, UnsupportedProcessSource


def get_process_source(platform_name: str | None = None) -> ProcessConnectionSource:
    """The process source for this OS, or an honest 'unsupported' placeholder (never a guess)."""
    name = platform_name or sys.platform
    if name == "darwin":
        from app.platform.macos import MacOSProcessSource

        return MacOSProcessSource()
    # Linux (e.g. /proc + ss) and Windows (e.g. GetExtendedTcpTable) would be registered here.
    return UnsupportedProcessSource({"linux": "Linux", "win32": "Windows"}.get(name, name))


__all__ = ["ProcessConnectionSource", "ProcessSourceError", "UnsupportedProcessSource", "get_process_source"]
