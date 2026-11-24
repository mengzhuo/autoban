#!/usr/bin/env bash
# End-to-end demo using the dummy action and /tmp paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p /tmp/autoban-demo /tmp/autoban "$ROOT/bin"
: > /tmp/autoban-demo/auth.log
rm -f /tmp/autoban/autoban.db /tmp/autoban/autoban.log /tmp/autoban/actions.log /tmp/autoban/autoban.pid /tmp/autoban/autoban.sock

make build >/dev/null

./bin/autoban -config "$ROOT/config" &
SERVER_PID=$!
cleanup() {
  ./bin/autoban-ctl -config "$ROOT/config" stop >/dev/null 2>&1 || true
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  wait "$SERVER_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  if ./bin/autoban-ctl -config "$ROOT/config" ping >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

echo "== injecting three failed SSH logins =="
for _ in 1 2 3; do
  echo "$(date '+%b %e %H:%M:%S') demo sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4444 ssh2" \
    >> /tmp/autoban-demo/auth.log
done
sleep 2

echo
echo "== status =="
./bin/autoban-ctl -config "$ROOT/config" status sshd
echo
echo "== banned =="
./bin/autoban-ctl -config "$ROOT/config" banned sshd
echo
echo "== action log =="
cat /tmp/autoban/actions.log
echo
echo "== unban =="
./bin/autoban-ctl -config "$ROOT/config" unbanip sshd 203.0.113.7
echo
echo "== autoban-regex =="
./bin/autoban-regex -config "$ROOT/config" /tmp/autoban-demo/auth.log sshd
