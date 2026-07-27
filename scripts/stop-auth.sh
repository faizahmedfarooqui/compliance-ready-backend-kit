#!/usr/bin/env bash
#
# Stop whatever is listening on the auth service port.
#
# Kill BY PORT, not by process-name pattern. Pattern matching is how you end up with a stale
# server still holding the port: `nest start --watch` runs the app as
# `node --enable-source-maps <abs path>/dist/main` (note: no `.js`), so an obvious-looking
# `pkill -f "node dist/main.js"` matches nothing and reports success. A later start then fails
# with EADDRINUSE, and any test suite pointed at the port is quietly talking to the old build.
#
# Usage: ./scripts/stop-auth.sh   (honours PORT, default 3011)

set -euo pipefail

PORT="${PORT:-3011}"

pids=$(lsof -tnP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)

if [ -z "$pids" ]; then
  printf 'Nothing listening on :%s\n' "$PORT"
  exit 0
fi

# TERM first so shutdown hooks run and the database pools close cleanly.
for pid in $pids; do
  printf 'Stopping pid %s on :%s\n' "$pid" "$PORT"
  kill "$pid" 2>/dev/null || true
done

for _ in $(seq 1 20); do
  sleep 0.25
  [ -z "$(lsof -tnP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)" ] && {
    printf 'Port :%s is free\n' "$PORT"
    exit 0
  }
done

# Still there. A watcher can respawn its child, so escalate.
for pid in $(lsof -tnP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true); do
  printf 'pid %s did not exit, sending KILL\n' "$pid"
  kill -9 "$pid" 2>/dev/null || true
done

sleep 0.5
if [ -n "$(lsof -tnP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)" ]; then
  printf 'Could not free :%s\n' "$PORT" >&2
  exit 1
fi
printf 'Port :%s is free\n' "$PORT"
