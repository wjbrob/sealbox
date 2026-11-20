#!/usr/bin/env bash
# Start (or reuse) the local GreenMail server used by G3/G4/G8. Idempotent. Prints when IMAP answers.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
docker compose -p sealbox -f "$HERE/docker-compose.yml" up -d --wait --quiet-pull 2>&1 | tail -1 || true
for i in $(seq 1 40); do
  if (exec 3<>/dev/tcp/127.0.0.1/3143) 2>/dev/null; then
    exec 3>&- ; echo "greenmail: imap 127.0.0.1:3143 smtp 127.0.0.1:3025 (users alice/bob/carol @sealbox.test, pw <name>pw)"; exit 0
  fi
  sleep 0.5
done
echo "greenmail: not reachable on 3143" >&2; exit 1
