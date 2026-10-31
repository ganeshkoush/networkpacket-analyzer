"""Backend entry point: `python main.py` starts the local API on 127.0.0.1 (also the entry point of the packaged backend)."""
import os
import signal
import sys
import threading
import time

import uvicorn

from app.config import settings
from app.logging_config import configure_logging


def _exit_when_parent_dies(parent_pid: int) -> None:
    """The desktop app starts this process and stops it on quit. If the app is killed instead (crash, force quit), stop too,
    so no orphaned backend keeps a port and the database open."""
    def watch() -> None:
        while True:
            time.sleep(1.0)
            if os.getppid() != parent_pid:  # re-parented to launchd => the parent is gone
                os.kill(os.getpid(), signal.SIGTERM)
                return
    threading.Thread(target=watch, name="parent-watchdog", daemon=True).start()


def main() -> None:
    configure_logging(settings.log_level, settings.log_file)
    parent = os.environ.get("PACKETMIND_PARENT_PID", "").strip()
    if parent.isdigit():
        _exit_when_parent_dies(int(parent))
    from app.main import app  # imported object (not a string) so it also works inside the PyInstaller bundle

    uvicorn.run(app, host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    sys.exit(main())
