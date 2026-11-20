#!/usr/bin/env bash
# Stop and remove the local Stalwart container and its volumes (GreenMail is untouched).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -p sealbox -f "$HERE/docker-compose.yml" --profile stalwart)
"${COMPOSE[@]}" rm -sfv stalwart 2>&1 | tail -1 || true
for v in stalwart-etc stalwart-data; do
  id="$(docker volume ls -q --filter label=com.docker.compose.project=sealbox --filter "label=com.docker.compose.volume=$v")"
  [ -n "$id" ] && docker volume rm "$id" >/dev/null && echo "removed volume $id"
done
rm -f "$HERE/stalwart/.local-state" "$HERE/stalwart/.local-state.bootstrap.json"
