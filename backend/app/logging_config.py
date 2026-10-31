"""Central logging setup. Logs never include packet payloads, request bodies or API keys."""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_MARK = "_packetmind_handler"


def configure_logging(level: str = "INFO", log_file: Path | None = None) -> None:
    """Idempotent: safe to call from `main.py` and again from the app factory."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if any(getattr(h, _MARK, False) for h in root.handlers):
        return
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.handlers.RotatingFileHandler(
                log_file, maxBytes=2 * 1024**2, backupCount=3, encoding="utf-8"))
        except OSError:
            logging.getLogger(__name__).warning("Could not open log file %s; logging to console only", log_file)
    for h in handlers:
        h.setFormatter(logging.Formatter(_FORMAT))
        setattr(h, _MARK, True)
        root.addHandler(h)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # would otherwise log request URLs from the AI SDK


def reconfigure_logging(level: str, log_file: Path | None, *, save_logs: bool = True, max_bytes: int = 2 * 1024**2, rotation: bool = True) -> None:
    """Apply the Diagnostics settings to the running backend: level, whether logs are saved, their size and rotation."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in [h for h in root.handlers if getattr(h, _MARK, False) and isinstance(h, logging.FileHandler)]:
        root.removeHandler(h)
        h.close()
    if not any(getattr(h, _MARK, False) for h in root.handlers):
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(_FORMAT))
        setattr(console, _MARK, True)
        root.addHandler(console)
    if save_logs and log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handler: logging.Handler = (logging.handlers.RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=3, encoding="utf-8")
                                        if rotation else logging.FileHandler(log_file, encoding="utf-8"))
            handler.setFormatter(logging.Formatter(_FORMAT))
            setattr(handler, _MARK, True)
            root.addHandler(handler)
        except OSError:
            logging.getLogger(__name__).warning("Could not open log file %s; logging to console only", log_file)
