#!/bin/sh
# Smoke-tests the packaged backend on its own: starts it from a neutral folder with a temporary data dir and a token, then checks
# readiness, token enforcement, a real PCAP analysis, and clean shutdown. Needs no network and no privileges.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${1:-$ROOT/build/backend-dist/packetmind-backend/packetmind-backend}"
[ -x "$BIN" ] || { echo "Backend bundle not found: $BIN (run scripts/build-backend.sh)" >&2; exit 1; }
WORK=$(mktemp -d); trap 'kill "$PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
cd "$WORK"
PACKETMIND_DATA_DIR="$WORK/data" PACKETMIND_PORT=$PORT PACKETMIND_API_TOKEN=verify-token "$BIN" >"$WORK/backend.log" 2>&1 &
PID=$!
i=0; until curl -fs "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; do
  i=$((i+1)); [ $i -le 120 ] || { echo "FAIL: backend not ready in 120 s"; tail -20 "$WORK/backend.log"; exit 1; }
  kill -0 "$PID" 2>/dev/null || { echo "FAIL: backend exited during startup"; tail -20 "$WORK/backend.log"; exit 1; }
  sleep 1
done
echo "ok   ready after ~${i}s"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code "http://127.0.0.1:$PORT/api/settings")" = 401 ] || { echo "FAIL: API open without token"; exit 1; }; echo "ok   API rejects requests without the token"
[ "$(code -H 'X-PacketMind-Token: verify-token' "http://127.0.0.1:$PORT/api/settings")" = 200 ] || { echo "FAIL: token rejected"; exit 1; }; echo "ok   API accepts the token"
JOB=$(curl -fs -H 'X-PacketMind-Token: verify-token' -X POST -H 'X-Filename: sample.pcap' --data-binary @"$ROOT/backend/tests/fixtures/sample.pcap" "http://127.0.0.1:$PORT/api/analyses" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
i=0; while :; do
  ST=$(curl -fs -H 'X-PacketMind-Token: verify-token' "http://127.0.0.1:$PORT/api/analyses/$JOB" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))')
  [ "$ST" = completed ] && break; [ "$ST" = failed ] && { echo "FAIL: analysis failed"; exit 1; }
  i=$((i+1)); [ $i -le 60 ] || { echo "FAIL: analysis did not finish (status: $ST)"; exit 1; }; sleep 1
done
echo "ok   PCAP analysis completed"
[ -f "$WORK/data/packetmind.db" ] && ls "$WORK/data/captures"/*.pcap >/dev/null 2>&1 || { echo "FAIL: data not written under PACKETMIND_DATA_DIR"; exit 1; }; echo "ok   database and capture written to the data dir"
kill -TERM "$PID"; i=0; while kill -0 "$PID" 2>/dev/null; do i=$((i+1)); [ $i -le 20 ] || { echo "FAIL: did not stop on SIGTERM"; exit 1; }; sleep 0.5; done
echo "ok   stopped cleanly on SIGTERM"; trap 'rm -rf "$WORK"' EXIT
