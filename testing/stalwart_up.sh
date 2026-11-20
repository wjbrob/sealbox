#!/usr/bin/env bash
# Start (or reuse) the local Stalwart mail server that backs the hosted "Create a new Sealbox
# address" flow (gate G22). Idempotent: safe to run repeatedly; finishes when IMAP greets.
#
# What it does on a fresh volume (Stalwart v1.0.0, see testing/docker-compose.yml):
#   1. `docker compose --profile stalwart up -d stalwart`  (GreenMail is untouched)
#   2. Stalwart starts in *bootstrap mode* (no /etc/stalwart/config.json yet) and serves only the
#      setup wizard on HTTP 8080 (host 8084). The wizard is a JMAP call — `x:Bootstrap/set` on
#      the singleton (data store RocksDB, internal directory, default domain hosted.sealbox.test,
#      no ACME, no DKIM, logs to stdout) — authenticated as the recovery administrator that the
#      compose file pins via STALWART_RECOVERY_ADMIN (dev-only credential). Stalwart honours
#      that credential in normal mode too, so every later management call (this script and
#      sealbox-server) uses the same deterministic login.
#   3. Restart into normal mode, then enable what the Sealbox client needs locally and nothing
#      more: plaintext IMAP (143) + submission (587) listeners, `Imap.allowPlainTextAuth`, and
#      SASL PLAIN/LOGIN on the submission port without TLS. Production keeps TLS-only ports and
#      real certificates — see docs/HOSTED_MAILBOX.md.
#   4. Restart once more so the new listeners bind; wait until IMAP on 127.0.0.1:1143 greets.
#
# Env overrides: STALWART_HTTP (default http://127.0.0.1:8084), STALWART_ADMIN_USER/SECRET
# (must match the compose file), SEALBOX_HOSTED_DOMAIN (default hosted.sealbox.test).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -p sealbox -f "$HERE/docker-compose.yml" --profile stalwart)
HTTP="${STALWART_HTTP:-http://127.0.0.1:8084}"
ADMIN_USER="${STALWART_ADMIN_USER:-admin}"
ADMIN_SECRET="${STALWART_ADMIN_SECRET:-sealbox-stalwart-dev-admin}"
DOMAIN="${SEALBOX_HOSTED_DOMAIN:-hosted.sealbox.test}"
HOSTNAME_="mail.${DOMAIN}"
IMAP_PORT=1143
SUBMISSION_PORT=1587
STATE_DIR="$HERE/stalwart"   # .local-state* files are gitignored

log() { printf 'stalwart: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# One JMAP method call against the management API (registry objects are `x:<Object>/get|set`);
# prints the raw JSON response.
jmap() {  # jmap <x:Object/method> <json-args>
  curl -sS --max-time 30 -u "$ADMIN_USER:$ADMIN_SECRET" -H 'Content-Type: application/json' \
    "$HTTP/jmap" --data-binary "{\"using\":[\"urn:ietf:params:jmap:core\",\"urn:stalwart:jmap\"],\"methodCalls\":[[\"$1\",$2,\"c0\"]]}"
}
# Evaluate a python expression over the parsed JSON on stdin (bound to `r`). No jq dependency.
py() { python3 -I -c 'import json,sys; r=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

# Docker's userland proxy accepts TCP on a published port even when nothing listens inside the
# container, so readiness must read the protocol greeting, never just connect.
imap_greets() {
  timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/'"$IMAP_PORT"'; read -r -t 3 l <&3; [[ "$l" == "* OK"* ]]' 2>/dev/null
}
wait_http() {
  for _ in $(seq 1 120); do
    curl -fsS --max-time 2 "$HTTP/healthz/live" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  die "management HTTP $HTTP never became healthy (docker logs sealbox-stalwart)"
}
wait_imap() {
  for _ in $(seq 1 120); do
    imap_greets && return 0
    sleep 0.5
  done
  return 1
}
in_bootstrap_mode() {  # x:Bootstrap/get lists the singleton only while in bootstrap mode
  jmap 'x:Bootstrap/get' '{"ids":null}' | py 'len(r["methodResponses"][0][1].get("list",[])) if r["methodResponses"][0][0]!="error" else 0' | grep -qx 1
}
# Settings objects (Bootstrap, Imap, MtaStageAuth, ...) are singletons with the literal id
# "singleton"; a never-written singleton is not listed by `get` with ids=null, so always name it.
SINGLETON=singleton
check_set() {  # die if a /set response reports an error or notCreated/notUpdated
  local r="$1" what="$2"
  if echo "$r" | py 'bool(r["methodResponses"][0][0]=="error" or r["methodResponses"][0][1].get("notCreated") or r["methodResponses"][0][1].get("notUpdated"))' | grep -qx True; then
    die "$what failed: $r"
  fi
}

"${COMPOSE[@]}" up -d --quiet-pull stalwart 2>&1 | grep -v '^$' | tail -1 >&2 || true
wait_http

if in_bootstrap_mode; then
  log "fresh server: bootstrapping domain $DOMAIN (hostname $HOSTNAME_)"
  R="$(jmap 'x:Bootstrap/set' "{\"update\":{\"$SINGLETON\":{
      \"defaultHostname\":\"$HOSTNAME_\",\"defaultDomain\":\"$DOMAIN\",
      \"requestTlsCertificate\":false,\"generateDkimKeys\":false,
      \"dataStore\":{\"@type\":\"RocksDb\",\"path\":\"/var/lib/stalwart/\"},
      \"blobStore\":{\"@type\":\"Default\"},\"searchStore\":{\"@type\":\"Default\"},
      \"inMemoryStore\":{\"@type\":\"Default\"},\"directory\":{\"@type\":\"Internal\"},
      \"dnsServer\":{\"@type\":\"Manual\"},
      \"tracer\":{\"@type\":\"Stdout\",\"enable\":true,\"level\":\"info\",\"ansi\":false}}}}")"
  check_set "$R" "x:Bootstrap/set"
  # The wizard hands out the permanent admin@<domain> secret exactly once; keep it locally
  # (gitignored, 0600) for anyone who wants the WebUI. Automation uses the recovery admin.
  echo "$R" | py 'json.dumps(r["methodResponses"][0][1]["updated"])' > "$STATE_DIR/.local-state.bootstrap.json" 2>/dev/null || true
  chmod 600 "$STATE_DIR/.local-state.bootstrap.json" 2>/dev/null || true
  log "bootstrap accepted; restarting into normal mode"
  "${COMPOSE[@]}" restart stalwart >/dev/null 2>&1
  wait_http
fi

if ! imap_greets; then
  log "configuring dev listeners (IMAP $IMAP_PORT, submission $SUBMISSION_PORT) and plaintext auth"
  R="$(jmap 'x:Imap/set' "{\"update\":{\"$SINGLETON\":{\"allowPlainTextAuth\":true}}}")"
  check_set "$R" "x:Imap/set allowPlainTextAuth"
  # Stalwart serialises Map<T>/List<T> as objects ({"value":true} / {"0":{...}}), not arrays.
  R="$(jmap 'x:MtaStageAuth/set' "{\"update\":{\"$SINGLETON\":{\"saslMechanisms\":{\"match\":{\"0\":{\"if\":\"local_port != 25\",\"then\":\"[plain, login]\"}},\"else\":\"false\"}}}}")"
  check_set "$R" "x:MtaStageAuth/set saslMechanisms"
  EXISTING="$(jmap 'x:NetworkListener/get' '{"ids":null}' | py '" ".join(o["name"] for o in r["methodResponses"][0][1]["list"])')"
  CREATE=""
  grep -qw imap <<<"$EXISTING" || CREATE="$CREATE\"l1\":{\"name\":\"imap\",\"bind\":{\"[::]:143\":true},\"protocol\":\"imap\",\"useTls\":false,\"implicitTls\":false},"
  grep -qw submission <<<"$EXISTING" || CREATE="$CREATE\"l2\":{\"name\":\"submission\",\"bind\":{\"[::]:587\":true},\"protocol\":\"smtp\",\"useTls\":false,\"implicitTls\":false},"
  if [ -n "$CREATE" ]; then
    R="$(jmap 'x:NetworkListener/set' "{\"create\":{${CREATE%,}}}")"
    check_set "$R" "x:NetworkListener/set"
  fi
  log "restarting so the listeners bind"
  "${COMPOSE[@]}" restart stalwart >/dev/null 2>&1
  wait_http
fi

wait_imap || die "IMAP never greeted on 127.0.0.1:$IMAP_PORT (docker logs sealbox-stalwart)"
date -u +%FT%TZ > "$STATE_DIR/.local-state"
echo "stalwart: imap 127.0.0.1:$IMAP_PORT (plain)  submission 127.0.0.1:$SUBMISSION_PORT (plain)  management $HTTP (user $ADMIN_USER)  domain $DOMAIN"
