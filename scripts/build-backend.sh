#!/bin/sh
# Packages the Python backend into a self-contained folder (no Python needed on the user's Mac).
# Output: build/backend-dist/packetmind-backend/   (the desktop build bundles this folder)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY="$ROOT/backend/.venv/bin/python"
[ -x "$PY" ] || { echo "Missing $PY. Create the venv first: cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt" >&2; exit 1; }
"$PY" -m PyInstaller --version >/dev/null 2>&1 || { echo "PyInstaller missing. Run: backend/.venv/bin/pip install -r backend/requirements-dev.txt" >&2; exit 1; }
cd "$ROOT/backend"
"$PY" -m PyInstaller --noconfirm --clean --distpath "$ROOT/build/backend-dist" --workpath "$ROOT/build/backend-work" packaging/packetmind-backend.spec
echo "Backend packaged: $ROOT/build/backend-dist/packetmind-backend"
