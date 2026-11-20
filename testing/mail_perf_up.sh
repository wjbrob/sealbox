#!/usr/bin/env bash
# Start (or reuse) the PERFORMANCE GreenMail `mail-perf` (container sealbox-mail-perf, compose
# profile `perf`): IMAP 127.0.0.1:3243, SMTP 127.0.0.1:3125, users p01..p03 / <login>pw.
# Only that service is touched — the shared `mail` GreenMail the gates use is never started,
# stopped or seeded by this script. Idempotent. Finishes when IMAP greets (Docker's userland
# proxy accepts TCP on a published port before GreenMail listens, so a bare connect is not
# readiness). See docs/PERFORMANCE.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
docker compose -p sealbox -f "$HERE/docker-compose.yml" --profile perf up -d --quiet-pull mail-perf 2>&1 | tail -1 || true
imap_greets() {
  timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/3243; read -r -t 3 l <&3; [[ "$l" == "* OK"* ]]' 2>/dev/null
}
for _ in $(seq 1 120); do
  if imap_greets; then
    echo "greenmail-perf: imap 127.0.0.1:3243 smtp 127.0.0.1:3125 (users p01..p03 @sealbox.test, pw <login>pw)"
    exit 0
  fi
  sleep 0.5
done
echo "greenmail-perf: IMAP on 127.0.0.1:3243 never greeted (docker logs sealbox-mail-perf)" >&2
exit 1
