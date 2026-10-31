"""Validation of file locations that come from outside (a path chosen in the OS save dialog).

Used by every feature that writes a file the user asked for (capture export, database backup, diagnostic report, settings
export). It never creates folders and never touches anything it does not have to.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.services.capture_store import sanitize_display_name


class PathRejected(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def validate_destination(raw: str, *, extensions: tuple[str, ...], default_extension: str, protected_dirs: tuple[Path, ...] = (),
                         overwrite: bool = False) -> Path:
    """A safe file path to write to: absolute, no ``..``, an existing writable folder, not a managed folder, not a link."""
    if "\x00" in raw or "\n" in raw or "\r" in raw:
        raise PathRejected(400, "invalid_destination", "That destination is not a valid file path.")
    if raw.rstrip().endswith(("/", "\\")):
        raise PathRejected(400, "invalid_destination", "Enter a file name, not just a folder.")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise PathRejected(400, "invalid_destination", "Choose a full destination path in the save dialog.")
    if ".." in candidate.parts:
        raise PathRejected(400, "invalid_destination", "The destination must not contain '..'.")
    if candidate.is_dir():
        raise PathRejected(400, "invalid_destination", "That is a folder; enter a file name.")
    name = sanitize_display_name(candidate.name, default="")
    if not name:
        raise PathRejected(400, "invalid_destination", "Enter a file name.")
    if not name.lower().endswith(extensions):
        name += default_extension
    try:
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise PathRejected(400, "destination_folder_missing", "The destination folder does not exist.") from None
    if not parent.is_dir():
        raise PathRejected(400, "destination_folder_missing", "The destination is not a folder.")
    for protected in protected_dirs:
        root = protected.resolve()
        if parent == root or root in parent.parents:
            raise PathRejected(400, "invalid_destination", "Choose a folder outside PacketMind's own data folders.")
    dest = parent / name
    if dest.is_symlink():
        raise PathRejected(400, "invalid_destination", "The destination is a link; choose a regular file name.")
    if dest.exists():
        if not dest.is_file():
            raise PathRejected(400, "invalid_destination", "The destination is not a regular file.")
        if not overwrite:
            raise PathRejected(409, "destination_exists", f"'{name}' already exists in that folder.")
    if not os.access(parent, os.W_OK):
        raise PathRejected(403, "destination_not_writable", "PacketMind is not allowed to write to that folder.")
    return dest
