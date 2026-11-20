# Push relay (`sealbox-relay`, gate G16)

A mobile OS will not keep an IMAP connection open for a backgrounded app, so "you have new mail"
has to come from somewhere else. `sealbox-relay` is that somewhere: a small, separate process
that holds **one IMAP IDLE session per registered mailbox** and, when the server reports new
mail, sends a **content-free push** to the registration's transport. The app then wakes, syncs
over IMAP itself (decrypting locally as always) and renders its own notification.

Code: `crates/sealbox-relay` (`src/lib.rs` has the module map). Gate: G16
(`crates/sealbox-relay/tests/gate_g16.rs`, against GreenMail users u76–u80).

## What it is and what it is not

**A push says *that* a folder got new mail and *when*. Nothing else.** The whole wire payload is:

```json
{"registration_id":"Zk3…32 chars…","event":"new_mail","folder":"INBOX","sent_at":"2026-10-29T12:00:00.000Z"}
```

- `registration_id`: the opaque random id the relay issued at registration (192 bits, URL-safe
  base64). It identifies the registration, not the person or the address.
- `event`: always `"new_mail"` today.
- `folder`: the folder the client asked to watch (`INBOX` by default).
- `sent_at`: RFC 3339 UTC, millisecond precision.

Never in a push: subject, sender, recipients, body, Message-ID, UID, message count, size, the
username or the address. This holds by construction, not by filtering. The worker only ever issues
`EXAMINE` (read-only) and `IDLE`; it never `FETCH`es, `SEARCH`es, `STORE`s or `SELECT`s, so it
never sees a header, never sets `\Seen` and changes no flag. What it keeps per folder is three
counters (`UIDVALIDITY`, `UIDNEXT`, `EXISTS`), and none of them goes into the push. The gate
asserts this at byte level: remove the id and the timestamp from a real push and exactly
`{"registration_id":"<id>","event":"new_mail","folder":"INBOX","sent_at":"<ts>"}` is left, with
not a single digit in it.

A push is a **hint, not a count**: a burst of arrivals is coalesced into one push (see the
debounce below), and a push whose delivery fails is not retried (the next arrival pushes again).
On every push the app should sync the folder. It should also sync when it comes to the
foreground, whether or not a push arrived.

**Credentials live in memory only.** The relay writes nothing to disk. A registration lasts until
it is unregistered or the process ends, and a parked one at most `--parked-ttl` (24 h) longer than
its last login attempt. After a relay restart, or when an OAuth access token expires (the worker
then reports `state: "error"` with the server's refusal, and after three rejected logins parks
the registration, see [rejected credentials](#5-rejected-credentials-are-parked-then-evicted)),
the client registers again with fresh credentials. The relay never holds an OAuth *refresh* token.

It is not a mail server and not a sync service. It does not store mail, does not see mail and
cannot decrypt anything.

## HTTP API

All bodies are JSON. Every response carries `Cache-Control: no-store`. Errors are
`{"error": "<message>"}`, and messages describe the shape of the request or the rule it broke,
never a value from it: a type mismatch reports a line and column, an unknown enum variant is
reported without the offending value (listing the allowed ones instead), and a refused IMAP host
or webhook URL is never repeated back.

### Auth

When the relay has an API token (`--api-token` / `SEALBOX_RELAY_API_TOKEN`), every
`/v1/push/*` route requires `Authorization: Bearer <api token>` (compared in constant time).
Anything else (no header, a wrong token, another scheme) gets **401** `{"error":"unauthorized"}`.
`GET /v1/health` is always open. **The token is mandatory as soon as the relay listens beyond
loopback**: the binary refuses to start otherwise (see
[no open relay off loopback](#1-no-open-relay-off-loopback)). Without a token on a loopback bind
the relay is open to every local process; it warns, and that is only acceptable during
development.

### `POST /v1/push/register`

```json
{
  "imap": {"host": "imap.example.com", "port": 993, "security": "tls"},
  "username": "user@example.com",
  "password": "app-password",
  "folder": "INBOX",
  "transport": {"kind": "webhook", "url": "https://push.example.com/hook?cap=…", "bearer": "per-registration-secret"}
}
```

| field | rules |
|---|---|
| `imap.host` | 1–253 bytes, no whitespace or control characters, and it must pass the [IMAP destination policy](#3-imap-destinations-the-imap-guard) (public addresses only, optional allow-list) |
| `imap.port` | 1–65535 |
| `imap.security` | `"tls"` (implicit TLS, e.g. 993), `"starttls"`, `"plain"` (no TLS: **only for a local IMAP host**, see [plain IMAP](#4-plain-imap-only-to-local-hosts)) |
| `username` | 1–320 bytes, no control characters |
| `password` / `oauth_token` | exactly one, non-empty, no control characters (CR/LF/NUL can never be sent as an IMAP string or SASL response, so such a value is refused with a 400 naming the field instead of failing every login). `oauth_token` is an access token for SASL XOAUTH2 and is accepted only with its provider's own IMAP host (Google / Microsoft mail hosts — `sealbox-mail` never presents a bearer elsewhere), else 400 |
| `folder` | optional, default `"INBOX"`, ≤ 255 bytes, no control characters |
| `transport` | `{"kind":"webhook","url":…,"bearer":…}` (`url`: http(s) with a host, ≤ 2048 bytes, and it must pass the [webhook destination policy](#2-webhook-destinations-the-ssrf-guard); `bearer` optional, non-empty, must be a valid header value) or `{"kind":"log"}` (development: the push is only logged) |

Unknown fields are rejected at every level (`deny_unknown_fields`), so a client that sends
something the relay would ignore finds out immediately.

| status | when |
|---|---|
| **201** `{"registration_id":"…","state":"connecting"}` | accepted; the IMAP login happens asynchronously, so watch `state` |
| **400** | validation failure: the message names the field and the rule (the policy reasons are [listed verbatim below](#the-4xx-reasons-verbatim)) |
| **401** | missing or wrong API token |
| **413** | body larger than `max_body_bytes` (64 KiB); axum's own plain-text body |
| **429** `{"error":"registration limit reached"}` | `max_registrations` live registrations already exist |
| **429** + `Retry-After: <s>` `{"error":"too many registrations from this client address; retry after the Retry-After delay"}` | the client address used up its [registration rate limit](#6-registration-rate-limit) |

The IMAP destination (allow-list, DNS, every address public) and the webhook URL (allow-list,
scheme, DNS) are checked **before** anything is stored. The credentials are **not** checked before
the 201: the worker logs in in the background. A rejected password shows up in `GET status` as
`state: "error"` with `last_error`, for example
`IMAP: login to imap.example.com rejected (LOGIN): NO [AUTHENTICATIONFAILED] Invalid credentials`
(GreenMail: `… rejected (LOGIN): NO LOGIN failed. Invalid login/password for user id u77`): the
text of `sealbox-mail`'s typed `ImapError::LoginRejected`, which has every form of the credential
redacted, scrubbed once more of every secret the registration holds. After the third rejection in a
row the worker stops: `state` becomes `parked`, `parked_reason` `credentials_rejected` and
`last_error` `credentials rejected by the server; register again with fresh credentials`.

### `GET /v1/push/status/{id}`

**200**:

```json
{"registration_id":"…","state":"idle","folder":"INBOX","transport":"webhook",
 "created_at":"2026-10-29T12:00:00.000Z","pushes":1,"last_push_at":"2026-10-29T12:03:10.512Z","last_error":null,
 "parked_reason":null}
```

`state`: `connecting` (logging in / taking the baseline / reconnecting), `idle` (an IDLE session is
up and pushes will be sent for mail arriving from now on), `error` (the last session failed;
the worker retries with backoff), `parked` (the worker gave up for good and connects no more:
`parked_reason` says why: `credentials_rejected` (three rejected logins) or `xoauth2_not_offered` (the
registration only has an OAuth token and the server's CAPABILITY has no `AUTH=XOAUTH2`, decided on
the first connection before any login — `last_error` is the fixed text "the server offers no
XOAUTH2, so the OAuth token can never be presented; register again with an app password or another
host") or `oauth_host_refused` (defence in depth: the token's host is not its provider's, which the
API already refuses at registration); the registration answers like this
until `DELETE` or until it is evicted `--parked-ttl` after parking, 24 h by default, and then 404;
only a new registration helps), `stopped` (only visible in a race with `DELETE`, eviction or
shutdown: a removed registration answers 404). `parked_reason` is `null` unless `state` is
`parked`. `transport` is the kind only: the status never contains the webhook URL, the bearer or
any credential. **404** `{"error":"not found"}` for an unknown id, including an evicted one.

### `DELETE /v1/push/register/{id}`

**204**: the registration is removed and its worker is cancelled and waited for (up to
`stop_grace`, 5 s, then aborted), so no new push starts after the 204. A parked registration is
removed the same way (its worker holds no connection and only waits for the parked TTL). A push that was already in
flight when the `DELETE` arrived can still reach the receiver. **404** for an unknown id,
including a second `DELETE`.

### `GET /v1/health`

**200** `{"status":"ok","version":"0.1.0","registrations":3,"max_registrations":1000}`. No auth,
no rate limit, and no field that reveals a registration.

### The webhook push

`POST <transport.url>` with `Content-Type: application/json`, `Authorization: Bearer <bearer>`
(when a bearer was registered), `User-Agent: sealbox-relay/<version>` and the payload above. The
receiver must answer 2xx within 10 s. Redirects are **not** followed (a redirect could carry the
bearer to a third host, and a redirect to an IP literal would bypass the destination check).
Before connecting, the relay resolves the host again and checks every address against the
[webhook destination policy](#2-webhook-destinations-the-ssrf-guard); it then connects only to
those checked addresses. A timeout, a connection error, a refused destination or a non-2xx
answer is recorded in `last_error` (scrubbed; the error text never contains the URL, which may
carry a capability token). The session keeps idling, and that push is not retried.

Example (a development relay: GreenMail on loopback needs `--imap-allow-private`, plain http to
loopback both development webhook flags):

```sh
sealbox-relay --bind 127.0.0.1:8090 --imap-allow-private --webhook-allow-private --webhook-allow-http-private &
curl -sS -X POST http://127.0.0.1:8090/v1/push/register -H 'Content-Type: application/json' \
  -d '{"imap":{"host":"127.0.0.1","port":3143,"security":"plain"},"username":"u76","password":"u76pw",
       "transport":{"kind":"webhook","url":"http://127.0.0.1:9000/hook","bearer":"hook-secret"}}'
```

## Running it

```sh
SEALBOX_RELAY_API_TOKEN="$(openssl rand -hex 32)" \
  sealbox-relay --bind 0.0.0.0:8090 --imap-allow-hosts imap.gmail.com,outlook.office365.com \
  --webhook-allow-hosts push.example.com --log-level info
```

| flag | env | default | |
|---|---|---|---|
| `--bind` | `SEALBOX_RELAY_BIND` | `127.0.0.1:8090` | listen address for the API |
| `--api-token` | `SEALBOX_RELAY_API_TOKEN` | unset | **required off loopback**. Prefer the env var: a flag is visible in `ps` |
| `--allow-open-relay` | `SEALBOX_RELAY_ALLOW_OPEN_RELAY` | off | start without a token on a non-loopback bind anyway (loud warning) |
| `--max-registrations` | `SEALBOX_RELAY_MAX_REGISTRATIONS` | `1000` | each one holds one IMAP connection and one task |
| `--register-rate-limit` | `SEALBOX_RELAY_REGISTER_RATE_LIMIT` | `30` | registration attempts per client address per minute; `0` = no limit |
| `--imap-allow-hosts` | `SEALBOX_RELAY_IMAP_ALLOW_HOSTS` | unset | comma-separated; when set, the only IMAP hosts accepted: exact names, `.suffix` entries (`.office365.com` admits every name below it) and IP addresses |
| `--imap-allow-private` | `SEALBOX_RELAY_IMAP_ALLOW_PRIVATE` | off | **development / tests**: IMAP servers may be on loopback, private, link-local … addresses (a local GreenMail) |
| `--parked-ttl` | `SEALBOX_RELAY_PARKED_TTL` | `24h` | how long a parked registration stays visible before it is evicted: a whole number with `s` (default), `m`, `h` or `d`; `0` evicts at once |
| `--webhook-allow-hosts` | `SEALBOX_RELAY_WEBHOOK_ALLOW_HOSTS` | unset | comma-separated; when set, the only webhook hosts accepted (a name admits its subdomains) |
| `--webhook-allow-private` | `SEALBOX_RELAY_WEBHOOK_ALLOW_PRIVATE` | off | **development / tests**: webhooks may target loopback, private, link-local … addresses |
| `--webhook-allow-http-private` | `SEALBOX_RELAY_WEBHOOK_ALLOW_HTTP_PRIVATE` | off | **development**: plain `http://` webhooks to a non-public destination (needs `--webhook-allow-private` too) |
| `--log-level` | `SEALBOX_RELAY_LOG` | `info` | tracing `EnvFilter` syntax, e.g. `sealbox_relay=debug` |

Boolean environment variables take `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`. A refused
configuration (an open relay off loopback, a malformed IMAP or webhook allow-list, a malformed
`--parked-ttl`) is logged or printed to stderr and ends the process with **exit status 2** before
any port is bound. The startup log line `sealbox-relay listening` carries `authenticated`,
`register_rate_limit`, `imap_allow_private`, `imap_allow_hosts` (the number of entries; the
entries follow in their own line), `parked_ttl_secs` and the three webhook policy settings, and
every development flag in use is logged as a warning.

The binary speaks plain HTTP. Anything beyond loopback belongs behind a TLS-terminating reverse
proxy (mind the [rate limit's caveat](#6-registration-rate-limit) there). On SIGINT or SIGTERM
in-flight requests finish, every worker is cancelled and waited for, and the process exits 0. The
SIGTERM handler is installed before the listener is bound, so a SIGTERM that arrives right after
the `sealbox-relay listening` line is a graceful shutdown too. The gate checks this against the real binary. Logs carry
registration ids, states and scrubbed errors, but no credentials, bearers, webhook URLs, client
addresses or mail content.

Timing knobs (`WorkerConfig`: `connect_timeout` 30 s, `idle_timeout` 25 min, `debounce` 1 s,
`backoff_min` 1 s, `backoff_max` 5 min, `max_auth_failures` 3) and `Options` (`max_body_bytes`
64 KiB, `stop_grace` 5 s, `register_rate_window` 60 s) are library settings, not flags;
`WorkerConfig::parked_ttl` (24 h) is `--parked-ttl`.

## Exposure policies (threat-model R9)

A relay holds live mailbox credentials and opens connections on its clients' behalf, so the
prototype's open defaults became enforced policy on 2026-10-29. Every default below is the
production setting; the escape hatches are explicit flags.

### 1. No open relay off loopback

`src/bind_policy.rs`, applied in `src/main.rs` before anything is bound. `--bind` is resolved
once; the decision and the listener use the same addresses.

| bind | API token | `--allow-open-relay` | outcome |
|---|---|---|---|
| any | set | any | starts; every `/v1/push/*` call needs the token |
| loopback only (`127.0.0.0/8`, `::1`, their IPv4-mapped form, `localhost`) | unset | any | starts with a warning (development) |
| anything else (`0.0.0.0`, `::`, a LAN address, a mix) | unset | no | **refuses to start**, exit 2 |
| anything else | unset | yes | starts with a loud `OPEN RELAY` warning (log and stderr) |

A whitespace-only token counts as none. The refusal reads:
`refusing to start: --bind 0.0.0.0:8090 is not a loopback address and no API token is set, so
anyone who can reach it could register mailboxes. Set SEALBOX_RELAY_API_TOKEN (or --api-token),
bind to 127.0.0.1, or pass --allow-open-relay to run an open relay anyway`.

### 2. Webhook destinations (the SSRF guard)

`src/webhook_guard.rs`. Whoever registers chooses the webhook URL, so without a policy the relay
would POST to anything it can reach: the cloud metadata service, an admin port on loopback, a
database in the private network. At registration, before anything is stored:

1. **Allow-list** (if `--webhook-allow-hosts` is set): the URL's host must be one of the entries
   or a subdomain of one (domain-boundary match: `push.example.com` admits
   `eu.push.example.com`, not `evilpush.example.com` or `push.example.com.evil.net`). IP entries
   match exactly. Entries are normalised like URL hosts (lowercase, punycode, no trailing dot);
   wildcards, ports and paths are rejected at startup. Decided without DNS. The allow-list
   restricts further: an allow-listed host still has to pass 2–4.
2. **Scheme**: `https` only. Plain `http` is accepted only when `--webhook-allow-http-private`
   is set *and* (step 4) every address is non-public.
3. **Resolution**: the host is resolved with the system resolver (`tokio::net::lookup_host`, 5 s
   timeout). IP-literal hosts are taken as they are, after `Url` has normalised every IPv4
   spelling (`0x7f000001`, `2130706433`, `127.1` all become `127.0.0.1`).
4. **Addresses**: *every* resolved address must be public. Refused unless
   `--webhook-allow-private`: loopback (`127/8`, `::1`), RFC 1918 (`10/8`, `172.16/12`,
   `192.168/16`), link-local (`169.254/16` with the metadata address `169.254.169.254`,
   `fe80::/10`), unique-local `fc00::/7`, carrier-grade NAT `100.64/10` (Alibaba Cloud's metadata
   service is `100.100.100.200`), multicast, unspecified (`0.0.0.0`, `::`; on Linux these reach
   the local host) and the reserved ranges (`0/8`, `192.0.0/24`, documentation and benchmarking
   ranges, `240/4`, deprecated IPv6 forms, `2001::/23`, `2001:db8::/32`, anything outside
   `2000::/3`). IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`)
   addresses are judged by the IPv4 address they carry. A name with one public and one private
   address is refused.

**At every delivery** the same check runs again. The webhook HTTP clients (one for https, one for
http) are built with a reqwest DNS resolver (`GuardedResolver`) that resolves the name, applies
step 4 (and the http rule) to every address and hands reqwest only those addresses. Check and
connect use the same DNS answer, so a name that rebinds to `127.0.0.1` after the registration
gets `last_error` `webhook destination refused: transport.url resolves to a non-public address
(…)` and **no connection is opened**. reqwest still takes the `Host` header, the TLS SNI and the
certificate name from the URL; only the socket address comes from the resolver (a unit test
checks the `Host` header of a pinned delivery). IP-literal URLs never reach a resolver, so the
transport re-checks the literal before each send. These clients ignore `HTTP(S)_PROXY` (a proxy
would resolve the name itself, out of the guard's reach) and follow no redirects.

What the delivery-time check covers, and what it does not:

- **Covered**: DNS rebinding between registration and delivery; a name whose answer changes
  between deliveries (each new connection resolves and checks again); IP literals; IPv4 numeric
  tricks; IPv4-mapped, NAT64 and 6to4 IPv6 forms; redirects (not followed); proxies (disabled).
- **Not covered**: a pooled keep-alive connection is reused for up to 90 s without re-resolving.
  It was opened to a checked address, so it cannot reach a new destination, but a change in DNS
  only takes effect on the next new connection. A *public* address that forwards to internal
  services (an open proxy, a port-forward) is outside any address check. The guard trusts the
  relay's own resolver: a compromised resolver can still only hand out addresses that pass the
  check. The address classes are a fixed table in the relay; a newly reserved range needs a code
  change.

### 3. IMAP destinations (the IMAP guard)

`src/imap_guard.rs`, applied in `src/api.rs` at registration and in `src/worker.rs` before every
connect. Whoever registers also chooses `imap.host` and `imap.port`, so without a policy a token
holder could make the relay open TCP connections to anything it can reach (the cloud metadata
service, an admin port on loopback, a database in the private network), send a TLS ClientHello or
read a banner there, and learn the outcome from `state` and `last_error`. At registration, after
validation and the plain-IMAP rule (policy 4) and before anything is stored:

1. **Allow-list** (if `--imap-allow-hosts` is set): the host must equal an exact entry
   (`imap.gmail.com` admits `imap.gmail.com` only, not `gmail.com` or `x.imap.gmail.com`) or lie
   below a `.suffix` entry on a label boundary (`.office365.com` admits `outlook.office365.com`,
   not `office365.com`, `evil-office365.com` or `office365.com.evil.net`). IP entries match
   exactly. Case-insensitive, one trailing dot ignored, decided without DNS; wildcards, ports,
   schemes and paths are refused at startup. The allow-list restricts further: an allow-listed
   host still has to pass 2 and 3.
2. **Resolution**: a name is resolved with the system resolver within 5 s (the webhook guard's
   timeout and code); an IP literal is taken as it is.
3. **Addresses**: *every* address must be public, by the same table as webhook destinations
   (`host_class::classify`, policy 2 step 4): loopback, RFC 1918, link-local with
   `169.254.169.254`, unique-local, carrier-grade NAT, multicast, unspecified and the reserved
   ranges are refused, and IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address
   they carry. A name with one public and one private address is refused. `--imap-allow-private`
   (development and tests: a local GreenMail) accepts them.

**Before every connect** of the worker, the first one and every reconnect, steps 1–3 run again
and the session dials only the addresses that passed (`ImapClient::connect_pinned` in
`sealbox-mail`; TLS still checks the certificate against the registered name, the transport
policy still applies to it). Check and connect use the same DNS answer, so a name that rebinds to
`127.0.0.1` after the registration gets `state: "error"` with `last_error`
`IMAP destination refused: imap.host resolves to a non-public address (…)`, and no connection is
opened. A refused destination is retried with the usual backoff (DNS may change back); it is not a
credential rejection and never parks the registration.

What it covers, and what it does not:

- **Covered**: internal destinations given as literals (every IPv4 spelling the resolver accepts
  counts as a name and is resolved first) or as names; DNS rebinding between the registration and
  any later connect (an IMAP session is one long-lived connection, and every new one resolves and
  checks again); IPv4-mapped, NAT64 and 6to4 forms.
- **Not covered**: the port stays the client's choice, so without an allow-list a token holder can
  still make the relay connect to any port of any *public* host and tell "connect failed" from
  other failures in `last_error`. A public address that forwards to internal services is outside
  any address check. The allow-list is opt-in: without it every public host is accepted. The
  guard trusts the relay's own resolver, like the webhook guard.

### 4. Plain IMAP only to local hosts

`src/host_class.rs` (`plain_imap_allowed`), applied in `src/api.rs` at registration.
`"security": "plain"` sends the password in clear, so it is accepted only when the IMAP host is
local **by its literal string** (no DNS): a loopback, RFC 1918 (including the Android emulator's
`10.0.2.2`), link-local or unique-local address (IPv4-mapped forms included), `localhost`, or a
name with at least one label in front of `.test`, `.local`, `.localhost`, `.internal`, `.lan`,
`.home` or `.invalid` (every label `[A-Za-z0-9_-]{1,63}`). Strings that only the system resolver
would read as an address (`127.1`, `2130706433`) count as names and are refused, as are scoped
`fe80::1%eth0` literals. `tls` and `starttls` are accepted for any host that passes policy 3.
Every local host is a non-public destination, so a `plain` registration passes policy 3 only on a
relay started with `--imap-allow-private`: a production relay accepts no plaintext IMAP at all.

**Duplication, still:** `sealbox-mail` has the equivalent client-side rule (`net_policy`, R12),
and the relay keeps its own small `host_class` helper; both have landed, and merging them into one
helper is a follow-up. The relay's set is a subset of the client's (no `SEALBOX_ALLOW_PLAIN_HOSTS`
override, no `%zone` literals), so a registration the relay accepts is never refused again by its
IMAP client, which applies `net_policy` to the registered name on every connect.

### 5. Rejected credentials are parked, then evicted

`src/worker.rs`, `src/registry.rs`. Providers lock accounts that keep failing logins, so after
**3** credential rejections with no successful login in between, the worker stops connecting and
parks the registration: `state: "parked"`, `parked_reason: "credentials_rejected"`, `last_error`
`credentials rejected by the server; register again with fresh credentials` (fixed text: no user,
host or server message). A parked registration holds no connection. It answers `GET status` like
that until `DELETE`, or until it is **evicted `--parked-ttl` after parking** (default 24 h), which
frees its slot and drops the rejected credentials from memory; from then on its id answers 404.
Both ways out are logged without content: `parked registration evicted` with the id, the reason
category and the TTL, or the `unregistered` line with `parked=credentials_rejected`. The client
registers again with fresh credentials.

A rejection is `sealbox-mail`'s typed `ImapError::LoginRejected`: the server answered `NO` or
`BAD` to `LOGIN` or to `AUTHENTICATE XOAUTH2` (also after first sending an XOAUTH2 error
challenge, Gmail's way), except when its RFC 5530 response code is a temporary one
(`[UNAVAILABLE]`, `LoginCode::is_temporary`). A failure before the login (a refused or dropped
connection, a timeout, TLS, a `BYE` greeting from a busy server, a server without
`AUTH=XOAUTH2`), a refused IMAP destination (policy 3) and an `[UNAVAILABLE]` answer neither count
nor reset the tally, and keep the capped exponential backoff. A successful login resets it,
including one whose session then fails for another reason (a missing folder, a dropped IDLE). The
decision is made on the typed error and its parsed response code, never on the server's wording.
`LoginRejected`'s message carries the server's answer with every form of the credential redacted
(as sent, IMAP-quoted, `Debug`-escaped, and for XOAUTH2 the SASL response raw and in base64),
control characters replaced and the text cut at 300 characters.

### 6. Registration rate limit

`src/rate_limit.rs`, a middleware on `POST /v1/push/register` only. **30 attempts per client
address per minute** (`--register-rate-limit`; a burst of 30, then one every 2 s), beyond that
**429** with `Retry-After` in seconds. Every *authenticated* attempt counts, whatever its outcome
(a refused one has cost a DNS lookup too); a request without a valid token is answered 401 before
the limiter and does not count. Clients are keyed by IPv4 address, by IPv6 `/64`, and IPv4-mapped
IPv6 counts as its IPv4 address. The address comes from the TCP connection (`ConnectInfo`), never
from a header. The table tracks at most 65 536 clients: when it is full, clients whose budget has
fully refilled are dropped, and if it is still full a *new* client is refused (fail closed).
**Behind a reverse proxy** every client has the proxy's address, so the limit becomes relay-wide;
`X-Forwarded-For` is deliberately not trusted.

### Development escape hatches, and why they exist

| setting | why it exists | never in production because |
|---|---|---|
| no API token on a loopback bind | a developer's relay on their own machine | every local process could register |
| `--allow-open-relay` | a disposable test network where the relay is reachable but a token is impractical | anyone who can reach it controls the relay |
| `--webhook-allow-private` | the gate's webhook receiver and a developer's local receiver are on `127.0.0.1` | it re-opens the SSRF surface: metadata services, loopback admin ports, the private network |
| `--webhook-allow-http-private` | those receivers speak plain http | pushes and bearers would cross the network in clear |
| `--imap-allow-private` | GreenMail (`127.0.0.1:3143`) and other local test servers are on loopback | it re-opens the request-forgery surface through `imap.host`: loopback ports, the private network, metadata services |
| `plain` IMAP to local hosts | GreenMail (`127.0.0.1:3143`) and local test servers | (not a flag: never accepted for a public host, and only with `--imap-allow-private` at all) |
| `--parked-ttl 0` | a client that would rather see 404 than `parked` | the client cannot learn why its registration stopped |
| `register_rate_limit: 0` (library) | load tests | removes the per-client bound |

The G16 gate runs with `imap_allow_private`, `webhook_allow_private` and
`webhook_allow_http_private` set explicitly (the binary with `--imap-allow-private
--webhook-allow-private --webhook-allow-http-private`), and proves that the same registration is
refused without the IMAP flag and without either webhook flag.

### The 4xx reasons (verbatim)

| status | `error` |
|---|---|
| 400 | `imap.security "plain" (no TLS) is accepted only for a local IMAP host: a loopback, private (RFC 1918), link-local or unique-local address, localhost, or a name under .test, .local, .localhost, .internal, .lan, .home or .invalid; use "tls" or "starttls"` |
| 400 | `imap.host is not on this relay's IMAP allow-list` |
| 400 | `imap.host could not be resolved` |
| 400 | `imap.host resolves to a non-public address (loopback, private, link-local, unique-local, shared, multicast, unspecified or reserved), which this relay does not connect to` |
| 400 | `transport.url host is not on this relay's webhook allow-list` |
| 400 | `transport.url must use https (plain http is accepted only for a private destination, on a relay started with --webhook-allow-http-private)` |
| 400 | `transport.url host could not be resolved` |
| 400 | `transport.url resolves to a non-public address (loopback, private, link-local, unique-local, shared, multicast, unspecified or reserved), which this relay does not push to` |
| 429 | `too many registrations from this client address; retry after the Retry-After delay` (with `Retry-After`) |

None of them contains the URL, the host, an address or the port. When the IMAP check fails at
connect time instead, `last_error` is `IMAP destination refused: ` followed by the same reason.
The reasons do distinguish "does not resolve" from "resolves to a non-public address", for IMAP
hosts as for webhook hosts, so a token holder can learn whether a name resolves to a private
address through the relay's resolver (a one-bit DNS oracle, bounded by the rate limit).

### Still open

- **The relay holds live credentials** (A8 can read, send and delete mail). Unchanged by these
  policies; see the threat notes below.
- **Public IMAP hosts and every port stay client-chosen without `--imap-allow-hosts`**: a token
  holder can make the relay connect to any port of any public host (policy 3, "not covered").
  A production relay should allow-list the providers it serves.
- **One shared API token** for all clients. Per-device credentials are not built.
- The rate limit is per address and relay-wide behind a reverse proxy (see above).
- The webhook keep-alive window (≤ 90 s, policy 2) and the one-bit DNS oracle (policies 2, 3).
- `host_class` (relay) and `net_policy` (`sealbox-mail`) still duplicate the local-host rule
  (policy 4).

Closed on 2026-10-29 (second pass): internal IMAP destinations through `tls` / `starttls`
(policy 3), parked registrations holding their slot and credentials until `DELETE` (policy 5),
and the 3-strike rule matching server text (typed `ImapError::LoginRejected`, policy 5).

## The IDLE lifecycle (one worker per registration)

1. **Connect**: the IMAP guard checks the host again (policy 3), then a TCP connect to the
   checked addresses only, TLS or STARTTLS as registered, then LOGIN (password) or AUTHENTICATE
   XOAUTH2 (token), through `sealbox-mail`'s `ImapClient::connect_pinned` (which decides what to
   do with a server that does not advertise `AUTH=XOAUTH2`, R14). A server that does not
   advertise `IDLE` is an error.
2. **Baseline**: `EXAMINE folder` (read-only) gives the watermark (`UIDVALIDITY`, `UIDNEXT`,
   `EXISTS`). Mail that was already in the folder never pushes. State becomes `idle`.
3. **IDLE round**: at most `idle_timeout`, clamped to **29 min** (RFC 2177: servers may drop an
   IDLE that lasts 30 min), and hard-capped even if the server sends `* OK` keep-alives.
4. **Wake-up**: an untagged `EXISTS`/`RECENT`/`EXPUNGE`/`FETCH` arrives. The worker keeps
   idling for the **debounce** window (1 s from the first notification), so a burst becomes one
   re-check. Then it re-`EXAMINE`s and pushes **if `UIDNEXT` advanced** within the same
   `UIDVALIDITY`. Servers without `UIDNEXT` fall back to a growing `EXISTS`. An expunge or a flag
   change therefore never pushes.
5. **Round timeout**: re-`EXAMINE` anyway, which catches anything a quiet server did not
   announce, then start the next round.
6. **Errors** (connection lost, timeout, rejected login, missing folder, refused destination):
   state `error`, scrubbed `last_error`, then reconnect after an exponential **backoff** (1 s
   doubling to 5 min, reset by the next successful session). **The watermark survives the
   reconnect**: mail that arrived while the connection was down is pushed once, as soon as the new
   session's `EXAMINE` sees it. The third rejected login in a row parks the registration instead
   (policy 5 above).
7. **`UIDVALIDITY` changed** (folder recreated): the counters are not comparable, so the baseline
   is reset without a push.
8. **Cancel** (`DELETE` or shutdown): the worker stops promptly from any of these states.

Two details matter for correctness, and both have regression tests against GreenMail:

- **The gap before the IDLE continuation.** Mail that lands between an `EXAMINE` and the
  server's `+` reply to `IDLE` (for example while the previous push is still being delivered) is
  announced by GreenMail 2.1.3 *before* the `+`. async-imap 0.12 files such responses in its
  unsolicited queue rather than waking the IDLE wait, so a plain `idle_wait` would sleep through
  them until the round ends, 25 minutes later. The worker uses
  `ImapClient::idle_wait_gapless` (`sealbox-mail`), which discards stale queued responses, enters
  IDLE, and treats anything announced while entering as a wake-up.
- **Reconnects** (point 6 above). Without the carried-over watermark, an outage would silently
  swallow the notification for every mail that arrived during it.

What GreenMail 2.1.3 actually does (observed 2026-10-29 with raw IMAP sessions on u76): it
advertises `IDLE` (`CAPABILITY IMAP4rev1 LITERAL+ UIDPLUS SORT IDLE MOVE QUOTA`). During IDLE it
sends `* n EXISTS` about 0.2 s after an SMTP delivery, and repeats `* n EXISTS` / `* n RECENT`
after `DONE`. Mail that landed between commands is announced before the `+ OK` continuation. It
does **not** re-announce stale counts after a fresh `EXAMINE`. It stores a message before it
answers SMTP `DATA` with 250. It rejects a wrong password with `NO LOGIN failed. Invalid
login/password for user id …` and did not lock u77 after the gate's rejected logins (the process
test logs in to u77 with the right password in the same run). So no polling fallback was needed,
and none exists.

## FCM / APNs (next transports)

`src/push/mobile.rs` builds the payloads, but nothing sends them yet:

- **FCM HTTP v1** (`POST https://fcm.googleapis.com/v1/projects/{project}/messages:send`): a
  data-only message, with `message.token` set to the device token and `message.data` set to the
  four push fields (all strings). It also carries `android.priority = "high"` so a dozing device
  wakes, plus an embedded `apns` block (`apns-push-type: background`, `apns-priority: 5`,
  `aps.content-available: 1`) for iOS-through-FCM.
- **APNs** (`POST /3/device/{device_token}`): headers `apns-push-type: background`,
  `apns-priority: 5`, `apns-topic: <bundle id>`; payload `{"aps":{"content-available":1}, …the four
  fields…}`.

Either way Google or Apple learns that *some* mailbox behind this device got mail at this moment,
and nothing else.

Still missing:

- **Credentials** (owner-provided): an FCM
  service account for the Firebase project; an APNs auth key (`.p8`), key id, team id and the
  app's bundle id. All of them stay outside the repo.
- **The senders**: an OAuth2 service-account token for FCM, an ES256 JWT for APNs over HTTP/2.
  Their destinations are fixed provider hosts, so they need no webhook guard.
- **The API side**: `transport.kind = "fcm" | "apns"` with a device token.
  `PushError::NotConfigured` is the placeholder error.

Apple throttles **background** pushes (Apple's guidance is not to rely on more than a few per hour).
For prompt mail notifications on iOS, the likely design is a visible alert push with generic text
and `mutable-content: 1`, plus a Notification Service Extension that syncs and decrypts locally to
replace that text. The payload would still be content-free. This is a design note, not yet built.

## Limits

- `max_registrations` (default 1000): one IMAP connection plus one tokio task each; **429** when
  full. Providers cap concurrent IMAP connections per account, and the relay's session counts
  against that cap alongside the user's own clients. A parked registration holds no connection,
  only a sleeping task, and keeps its slot until `DELETE` or until it is evicted `--parked-ttl`
  (24 h) after parking.
- One folder per registration (IMAP IDLE watches the selected mailbox only). To watch several
  folders, register several times.
- Request body ≤ 64 KiB (**413**); field limits as in the table above; webhook timeout 10 s; no
  redirects; DNS lookups for IMAP and webhook hosts time out after 5 s.
- 30 registration attempts per client address per minute (**429** + `Retry-After`).
- No persistence (by design). A missing folder, an unreachable server or a refused destination
  is retried with backoff (up to every 5 min) until unregistered; rejected credentials stop after
  three attempts, and the parked registration is evicted after `--parked-ttl`.

## Threat notes

**What a compromised relay learns:**

- The mailbox credentials of every live registration (an app password, or an OAuth access token
  until it expires) and therefore, *while they are valid*, full access to those mailboxes,
  content included. The content-free push protects against the push providers, logs and
  observability pipelines. It does **not** protect against the relay host itself.
- The IMAP host and username of each registration, and the webhook URLs and bearers.
- The timing of new mail per mailbox: metadata, even with every payload content-free.
- What it never had: decrypted content. Sealbox mail is end-to-end encrypted, so even a relay that
  abused its IMAP session would read OpenPGP ciphertext for encrypted messages. It would still
  read plaintext mail and headers.

**Mitigation plan** (not yet built):

- Hand the relay OAuth access tokens, not passwords, with the narrowest IMAP scope the provider
  offers. Microsoft has `IMAP.AccessAsUser.All` without `SMTP.Send`. Google's only IMAP scope is the
  full `https://mail.google.com/`, so a Gmail token held by the relay could also send mail. Tokens
  should be short-lived (about an hour) and re-registered by the client; the relay never holds a
  refresh token.
- Register **per device**, so that revoking one device's registration (or its token) leaves the
  others alone.
- Replace the relay-wide shared API token with per-device credentials.

**Request-forgery surface:** a client with the API token chooses the IMAP host and port and the
webhook URL. The webhook side is guarded at registration and at every delivery (policy 2): https
only, public destinations only, an optional allow-list, DNS rebinding closed by checking the very
answer the connection uses. The IMAP side is guarded the same way at registration and before every
connect (policy 3): public addresses only, the session dials exactly the checked addresses, an
optional allow-list, and `plain` only to local hosts on a development relay (policy 4). What
remains is the client's choice among *public* hosts and of the port: without an allow-list a
token holder can make the relay connect to any port of any public host (a blind TCP probe from the
relay's address). Before the relay is exposed beyond trusted clients, set `--imap-allow-hosts` to
the provider hosts it serves.

**Registration ids are capabilities:** together with the API token, an id reveals when mail
arrived (`last_push_at`) and allows unregistering. Treat both as secrets on the device.

**Errors and logs:** `last_error` never carries the password or token: a refused login arrives as
`LoginRejected`, whose text already has every form of the credential redacted, and the stored
text is scrubbed once more of every secret the registration holds, the bearer included. While the
worker is still retrying it can carry server text that names the account (GreenMail: "Invalid
login/password for user id u77") or the IMAP host (`login to <host> rejected`, a connect error).
The parked credentials-rejected text and a refused destination carry neither. `last_error` is
returned only to API clients holding the token.

## What the gate proves, and how to run it

```sh
testing/mail_up.sh && cargo test -p sealbox-relay --test gate_g16 -- --ignored   # ~15 s
# add -- --nocapture to see the measured latencies
cargo test -p sealbox-relay   # unit tests + tests/startup_policy.rs (no docker)
```

Six tests, each on its own GreenMail mailbox (u77 is shared by two tests that cannot interfere:
one only presents a wrong password, the other the right one):

| test | mailbox | proves |
|---|---|---|
| `push_arrives_without_content_and_unregister_stops_it` | u76 | the gate's own registration (GreenMail on loopback, plain http to a loopback receiver) is refused with **400** by a relay with the production policies, by one with both webhook flags but without `imap_allow_private`, and by one with the IMAP flag and only one of the two webhook flags, each with the expected reason and without the URL, path, capability, bearer, host or port in the response; with both flags a real SMTP mail produces exactly one webhook push, POSTed to the registered URL with the bearer and `application/json`, byte-for-byte content-free (no subject, sender, body, Message-ID, username, credential, UID or count in body or headers); `GET status` shows `idle`, `pushes: 1` and no secret; after `DELETE` (204) a mail that demonstrably lands yields no push for 8 s, and status and a second `DELETE` give 404 |
| `api_requires_the_token_and_never_echoes_secrets` | u77 | no, wrong or empty token gives 401 on all three push routes, and so does a `Basic` header carrying the right token; health is open; a password GreenMail rejects, registered through a loopback proxy that counts IMAP connections, is tried **exactly 3 times**, then the registration is parked (`state: parked`, `parked_reason: credentials_rejected`, the fixed credentials-rejected `last_error`, no user, host or port), 3 s later (three times the longest test backoff) there is still no fourth connection, and once the gate's 5 s parked TTL has run out the registration is gone (404, health 0) without a fourth connection; no status along the way contains a secret; unknown fields (top level and nested), wrong types, unknown variants and `plain` IMAP to a public host give 400 without echoing the value |
| `relay_binary_runs_as_its_own_process` | u77 | the `sealbox-relay` binary, with its token from the environment and the three development flags, enforces the token, pushes a content-free webhook, exits 0 on SIGTERM, and logs no credential, token, bearer, URL capability or mail content |
| `burst_is_debounced` | u78 | three concurrent mails produce 1–3 pushes, and exactly 1 whenever all three were submitted within 900 ms (inside the 1 s debounce window) |
| `mail_landing_during_a_push_is_not_missed` | u79 | a mail delivered while the relay is still waiting on the previous webhook gets its own push (the pre-continuation `EXISTS` case) |
| `reconnect_pushes_mail_that_arrived_while_disconnected` | u80 | through a loopback TCP proxy: the live session is cut and reconnects are refused, a mail lands, and on reconnect exactly one push arrives; a later reconnect without new mail pushes nothing |

Observed on 2026-10-29 (GreenMail 2.1.3, debug build):

- push about 1.3 s after the SMTP submit started (about 0.27 s submit plus the 1 s debounce)
- three concurrent mails submitted within 0.27 s produced 1 push
- the in-flight mail's push came about 1.05 s after the held webhook answered
- the reconnect catch-up push came about 0.49 s after the outage ended (the gate reconnects with
  a 200 ms–1 s backoff; in production the wait is the current backoff, up to 5 min)
- the rejected login was parked after 3 IMAP connections, about 0.75 s after registration
  (200 ms and 400 ms backoffs in the gate), and evicted 5.02 s after parking (5 s TTL)

Reverting either worker fix (plain `idle_wait`, or no catch-up after a reconnect) makes the
corresponding test fail. `sealbox-mail/tests/imap_idle_gapless.rs` covers `idle_wait_gapless`
against a scripted server without docker.

The policies have unit tests that need no docker (`cargo test -p sealbox-relay`): the address
classes and the plain-IMAP rule (`host_class`), every refused IMAP address class, name resolution,
the IMAP allow-list (exact and `.suffix` entries, decided before DNS) and the resolver timeout
(`imap_guard`), the webhook policy matrix, allow-list parsing and
matching, registration-time refusals with a scripted resolver, a pinned delivery (the connection
goes to the checked address, the `Host` header keeps the name), a name that rebinds to loopback
after registration (refused at delivery, no connection opened), IP literals re-checked per send
(`webhook_guard`), the API's 400s and dev-flag combinations, the IMAP refusals without echo and a
host that rebinds to loopback after registration (refused before the worker's connect, nothing
dialled), a parked status, `DELETE` of a parked registration and its eviction freeing the slot
(`api`), the 3-strike parking against a scripted IMAP server, including that a successful login
resets the tally, that `BAD` counts, and that `BYE`, a dropped connection and `[UNAVAILABLE]`
neither count nor reset it, the typed classification, eviction after the TTL and not before, the
pinned dial (a `.test` name only the pin can reach) and the re-check before every reconnect
(`worker`), parking and self-eviction (`registry`), GCRA timing, IPv6 `/64` keys and the full-table
behaviour (`rate_limit`), the bind decision table (`bind_policy`), the `--parked-ttl` parser, and
the binary's refusals and exit status 2, including a malformed IMAP allow-list or TTL
(`tests/startup_policy.rs`). `sealbox-mail` tests `LoginRejected` (16 scripted-server and unit
tests in `imap.rs`) and `connect_pinned` (3). On 2026-10-29 twelve guards were mutation-checked
and each mutation made its test fail: the delivery-time resolver (not installed / not checking),
the per-send IP-literal re-check, the allow-list's domain boundary, the registration-time webhook
check, the plain-IMAP check, the rate limiter, the parking threshold, the tally reset on a
successful login, the `BYE` and `[UNAVAILABLE]` exclusions, and the bind decision. In the second
pass the same day another eighteen: counting `[UNAVAILABLE]`, a `BYE` or a network error as a
rejection; no redaction, kept control characters, no length cap and `UNAVAILABLE` not temporary
in `LoginRejected`; any IMAP address accepted, no registration-time IMAP check, no connect-time
check, no pinning (relay and `sealbox-mail`), a suffix match without a label boundary, the
allow-list after DNS; never evicting, evicting at once, and a parked state reading `error`.

**Not proven here:**

- FCM or APNs delivery (no credentials).
- TLS and XOAUTH2 against real providers (GreenMail is plaintext here and lacks `AUTH=XOAUTH2`),
  so neither a pinned TLS session's certificate check nor a provider's real XOAUTH2 refusal is
  exercised here; `LoginRejected` for XOAUTH2 is tested against scripted servers only.
- The IMAP guard with the system resolver beyond `localhost` (the unit tests use a scripted
  resolver).
- TLS SNI and certificate verification of a pinned https webhook (only the `Host` header of a
  pinned plain-http delivery is checked; SNI comes from the URL by reqwest's design).
- Behaviour at hundreds of registrations.
- A real 25-minute round expiring. The 29-minute clamp is unit-tested, and the round cap is tested
  against the scripted server.

The gate leaves its probe mails in u76–u80. GreenMail keeps mail in memory, so they go when the
container is recreated.
