#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
docker compose -p sealbox -f "$HERE/docker-compose.yml" down -v 2>&1 | tail -1
