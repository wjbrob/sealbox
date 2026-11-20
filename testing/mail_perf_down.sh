#!/usr/bin/env bash
# Stop and remove ONLY the performance GreenMail (sealbox-mail-perf). Its mailboxes live in the
# JVM heap, so this also discards every seeded message. The shared `mail` service is untouched.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
docker compose -p sealbox -f "$HERE/docker-compose.yml" --profile perf rm -s -f mail-perf 2>&1 | tail -1
