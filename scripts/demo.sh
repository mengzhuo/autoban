#!/usr/bin/env bash
# End-to-end demo using the dummy action and /tmp paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p /tmp/gojail-demo /tmp/gojail "$ROOT/bin"
: > /tmp/gojail-demo/auth.log
rm -f /tmp/gojail/gojail.db /tmp/gojail/gojail.log /tmp/gojail/actions.log /tmp/gojail/gojail.pid /tmp/gojail/gojail.sock

make build >/dev/null

./bin/gojail -config "$ROOT/config" &
SERVER_PID=$!
cleanup() {
  ./bin/gj -config "$ROOT/config" stop >/dev/null 2>&1 || true
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  wait "$SERVER_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  if ./bin/gj -config "$ROOT/config" ping >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

echo "== injecting three failed SSH logins =="
for _ in 1 2 3; do
  echo "$(date '+%b %e %H:%M:%S') demo sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4444 ssh2" \
    >> /tmp/gojail-demo/auth.log
done
sleep 2

echo
echo "== status =="
./bin/gj -config "$ROOT/config" status sshd
echo
echo "== banned =="
./bin/gj -config "$ROOT/config" banned sshd
echo
echo "== action log =="
cat /tmp/gojail/actions.log
echo
echo "== unban =="
./bin/gj -config "$ROOT/config" unbanip sshd 203.0.113.7
echo
echo "== gj-regex =="
./bin/gj-regex -config "$ROOT/config" /tmp/gojail-demo/auth.log sshd
