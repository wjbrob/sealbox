# Hosted mailboxes — "Create a new Sealbox address" (gate G22)

Sealbox's promise is encryption on top of the mailbox you already have. Some people do not
have one they want to use (a fresh start, a throwaway for one contact, a child's first address).
For them the Sealbox server can mint `name@<hosted domain>` on a mail server we run —
[Stalwart](https://stalw.art) — and the app then treats it exactly like any other account:
IMAP + SMTP with an app password, an OpenPGP identity generated on the device, the same sync
and send pipelines. Nothing in the encryption path changes; the server only provisions the
mailbox and never sees a private key or a message body.

Status (2026-10-27): built and verified locally by `scripts/gate_g22.sh` against Stalwart
v1.0.0 in docker. Production needs a real domain and DNS (see "What production needs").

## How it works

```
 app / CLI                     sealbox-server                       Stalwart (docker locally)
 ─────────                     ──────────────                       ────────────────────────
 GET /v1/hosted/info  ───────▶ domain, rules, signup mode
 GET /v1/hosted/availability ▶ rules + own table + x:Account/query ▶ JMAP management API
 POST /v1/hosted/signup ─────▶ policy (closed/invite) → caps →
                               reserve row (UNIQUE) → generate
                               24-char password → x:Account/set ──▶ account created
                      ◀─────── 201 {email, password, imap, smtp}   (password hashed by Stalwart)
 add_account(manual servers, generated identity)  ───────────────▶ IMAP LOGIN / SMTP AUTH
```

* **`GET /v1/hosted/info`** → `{domain, signups: "open|invite|closed", invite_required,
  requirements: {min_length, max_length, pattern, reserved[], reserved_prefixes[]},
  imap: {host, port, security}, smtp: {host, port, security}}`
* **`GET /v1/hosted/availability?local_part=NAME`** → `{local_part (normalised), email,
  available, reason: null | too_short | too_long | invalid_characters | invalid_shape |
  reserved | taken, message}`
* **`POST /v1/hosted/signup`** `{local_part, invite_code?, recovery_email?}` →
  **201** `{email, login, password, domain, imap, smtp, created_at}` — the password is returned
  **once**. Errors: 400 (rules, closed, missing/invalid invite, bad recovery address),
  409 (name taken), 429 (attempt limiter or daily caps), 500 (Stalwart unreachable; the
  reservation is released), 404 (server has no hosted domain configured).

Names: 3–32 characters of `[a-z0-9._-]`, lower-cased, must start and end with a letter or
digit, no `..`, not reserved (`admin`, `postmaster`, `abuse`, `root`, `security`, `noreply`,
`support`, `sealbox`, the RFC 2142 role names and a few more — `sealbox-server/src/hosted/validate.rs`)
and not starting with `sealbox`.

What the server stores per signup (`hosted_signups` table in the server SQLite): the local part,
the address, **SHA-256 of the password** (never the password), SHA-256 of the optional recovery
address, a **keyed SHA-256 of the client IP** (`SEALBOX_HOSTED_IP_HASH_KEY`; random per process
when unset, which makes the daily caps forget on restart), the invite code used, Stalwart's
account id and the creation time. Passwords never appear in logs (handlers log address and
outcome only; `Debug` impls redact them).

The row is inserted *before* the Stalwart call, so two concurrent signups for one name cannot
both succeed (UNIQUE), and it is deleted again when Stalwart refuses or is down.

### Client side (`sealbox-core::hosted`, CLI)

* `Engine::hosted_info(server_url) -> HostedInfo`
* `Engine::hosted_availability(server_url, local_part) -> HostedAvailability`
* `Engine::hosted_signup(server_url, &HostedSignupRequest) -> HostedSignup` (raw; stores nothing)
* `Engine::create_hosted_account(HostedCreateRequest{server_url, local_part, invite_code?,
  recovery_email?, display_name?}) -> HostedCreated{account: AccountInfo, password}` — signup,
  then the normal `add_account` with manual servers (`UsernameForm::FullAddress`) and a freshly
  generated identity. The password is stored in the profile like any other account credential.
* `sealbox_core::hosted::create_hosted_account(&engine, server_url, local_part, invite)` —
  the free-function form.
* CLI: `sealbox account create-hosted --server URL --name NAME [--invite CODE]
  [--display-name N] [--recovery-email A] [--show-password]` and
  `sealbox account hosted-info --server URL [--check NAME]`. Exit codes: 2 for a refused name /
  closed / invite problems (user input), 3 when the server's caps refuse, 4 when the server or
  the new mailbox cannot be reached.

All types are plain `serde` structs, so the Flutter onboarding mirrors them 1:1 through the
bridge: show `hosted_info` (domain, rules, whether an invite is needed), call
`hosted_availability` while the user types, then `create_hosted_account` and continue to the
inbox with the returned `AccountInfo`.

## Abuse controls

| Control | Default | Env |
|---|---|---|
| Signup mode | `invite` | `SEALBOX_HOSTED_SIGNUPS=open|invite|closed` |
| Invite codes | none | `SEALBOX_HOSTED_INVITES=code1,code2` (constant-time compared) |
| Successful signups per IP per 24 h | 3 | `SEALBOX_HOSTED_PER_IP_DAILY` |
| Successful signups globally per 24 h | 200 | `SEALBOX_HOSTED_GLOBAL_DAILY` |
| Signup attempts per IP per hour (any outcome) | 20 | in code (`attempts_per_hour`) |
| Availability checks per IP per hour | 120 | in code |
| Reserved names / prefixes | see above | in code |

Behind a reverse proxy set `SEALBOX_TRUST_PROXY=1` so the per-IP controls see the real client.
Stalwart adds its own protections on the mailbox side (auth-failure bans, rate limits, quotas).

## Local setup (what the gate does)

```
testing/stalwart_up.sh        # docker compose --profile stalwart; bootstrap; dev listeners
scripts/gate_g22.sh           # server mock tests + real Stalwart + CLI e2e
testing/stalwart_down.sh      # remove container + volumes
```

Stalwart v1.0.0 (`stalwartlabs/stalwart`, pinned by digest in `testing/docker-compose.yml`,
compose profile `stalwart` so `mail_up.sh` never starts it). Bootstrap mechanism, verified:

1. With no `/etc/stalwart/config.json` the container runs in **bootstrap mode** and serves only
   the setup wizard on plain HTTP 8080 (host **8084**). The wizard is the JMAP management API:
   `POST /jmap` with `using: ["urn:ietf:params:jmap:core","urn:stalwart:jmap"]` and a
   `x:Bootstrap/set` update of the singleton (`"singleton"`) — hostname, default domain
   `hosted.sealbox.test`, RocksDB data store, internal directory, no ACME, no DKIM, logs to
   stdout. The response hands out `admin@hosted.sealbox.test` + a random secret once; the
   script keeps it in `testing/stalwart/.local-state.bootstrap.json` (gitignored, 0600) for the
   WebUI.
2. Authentication for every management call is the **recovery administrator**
   `STALWART_RECOVERY_ADMIN=admin:sealbox-stalwart-dev-admin` from the compose environment.
   Stalwart honours it in normal mode as well (it mints a full-permission token for the
   reserved recovery id), which makes the credential deterministic — no secret capture needed.
   It is a dev-only credential; see production below.
3. After a restart Stalwart creates its default listeners (25, 465, 993, 995, 4190, 443, 8080;
   all TLS where applicable, self-signed certificate). The Sealbox mail stack trusts only the
   Mozilla roots, so locally the script adds **plaintext** listeners `imap` (143 → host 1143) and
   `submission` (587 → host 1587), sets `x:Imap.allowPlainTextAuth=true` and
   `x:MtaStageAuth.saslMechanisms` to offer PLAIN/LOGIN on non-25 ports without TLS, then
   restarts once more. Stalwart serialises `Map`/`List` as objects (`{"[::]:143": true}`,
   `{"0": {...}}`), never arrays.
4. The server is then configured with `SEALBOX_HOSTED_*_SECURITY=plain` and the 1143/1587
   ports, so new accounts work with the existing `Security::Plain` transport. Nothing in
   `sealbox-mail` was changed for this; production uses `tls`/`starttls` on 993/587.

Host port 1025 (the natural SMTP/25 mapping) is already taken on this machine by another
project's mailpit, so SMTP/25 is published on **1026**; it is not used locally (both hosted
accounts live on the same server, so delivery is internal).

Management API shapes used (`sealbox-server/src/hosted/stalwart.rs`): `x:Domain/get {ids:null}`
→ `list[{id,name}]`; `x:Account/query {filter:{name}}` → `ids[]`;
`x:Account/set {create:{n:{"@type":"User", name, domainId, credentials:{"0":{"@type":"Password",
secret}}, roles:{"@type":"User"}, description}}}` → `created.n.id` or `notCreated.n.type`
(`primaryKeyViolation` = taken, `invalidProperties` = password policy); `x:Account/set
{destroy:[id]}`. Stalwart hashes the secret itself and enforces a zxcvbn strength policy — the
generated 24-character alphanumeric passwords pass it.

## What production needs from the human

1. **A domain** (or subdomain) dedicated to hosted addresses, e.g. `mail.sealbox.example` /
   addresses `@sealbox.example`. Decide the product domain first.
2. **A host** for Stalwart (2 vCPU / 4 GB is plenty to start; RocksDB on local SSD; the
   `/var/lib/stalwart` volume is the mailbox data), with ports 25, 465/587, 993, 443 reachable
   and **outbound port 25 unblocked** (most clouds block it until you ask).
3. **DNS**: `A`/`AAAA` for the mail host; `MX` for the domain; `PTR` (reverse DNS) matching the
   mail host name (set at the hosting provider); `SPF` (`v=spf1 mx -all`); `DKIM` (let Stalwart
   generate keys in the domain settings — `generateDkimKeys` was `false` locally — and publish
   the selector TXT records it shows); `DMARC` (`v=DMARC1; p=quarantine; rua=mailto:…`);
   `MTA-STS` + `TLS-RPT` optional but recommended. Stalwart's domain page lists every record
   with the exact values.
4. **TLS**: let Stalwart obtain certificates via ACME (`requestTlsCertificate: true` in the
   bootstrap, TLS-ALPN-01 needs port 443, or DNS-01 with a supported DNS provider), or mount
   your own. Then hand clients `SEALBOX_HOSTED_IMAP_PORT=993 SECURITY=tls` and
   `SEALBOX_HOSTED_SMTP_PORT=587 SECURITY=starttls`, and **remove the dev-only plaintext
   listeners and `allowPlainTextAuth`** (do not run `stalwart_up.sh` against production).
5. **Admin credential**: do not ship `STALWART_RECOVERY_ADMIN` as a static secret. Create a
   dedicated administrator (or an API key with only the `sysAccount*`/`sysDomainGet`
   permissions) in the WebUI and give `sealbox-server` that; keep the recovery admin for
   break-glass only, behind a firewall (8080/443 management reachable only from the server).
6. **Backups**: snapshot the `stalwart-data` volume (RocksDB) and the server SQLite (holds the
   signup ledger) daily; test a restore. Stalwart has `stalwart --export/--import`.
7. **Legal / policy**: an acceptable-use policy and abuse contact (`abuse@` and `postmaster@`
   must exist and be read — they are reserved names for that reason), a privacy notice covering
   what the signup ledger stores (hashed IP, hashed recovery address, timestamps), retention of
   mail, and the jurisdiction of the host. Decide whether to require invite codes at launch
   (`SEALBOX_HOSTED_SIGNUPS=invite`) — recommended until deliverability reputation is built.
8. **Deliverability warm-up**: new domains get greylisted; keep volume low for the first weeks,
   watch DMARC reports, make sure the PTR/SPF/DKIM all align before announcing.

## Cost notes

* A small VPS for Stalwart: roughly 5–15 €/month; storage grows with mailboxes (plan ~1 GB per
  active user; Stalwart supports per-account quotas — set `quotas` on creation when needed).
* The domain: 10–20 €/year. Certificates: free via ACME.
* Operational time is the real cost: abuse handling, deliverability, backups, upgrades
  (Stalwart publishes frequent releases; pin a tag, read `UPGRADING.md` before moving majors).
* Keep signups invite-only or capped until there is someone who reads `abuse@`.

## Files

| Path | What |
|---|---|
| `testing/docker-compose.yml` (service `stalwart`) · `testing/stalwart_up.sh` · `testing/stalwart_down.sh` | Stalwart in docker, bootstrap + dev listeners |
| `crates/sealbox-server/src/hosted/{mod,validate,store,stalwart}.rs` · `src/routes/hosted.rs` | provisioning service, rules, ledger, Stalwart client, endpoints |
| `crates/sealbox-server/tests/gate_g22_server.rs` | mocked-Stalwart tests + real-Stalwart case |
| `crates/sealbox-core/src/hosted.rs` | client API + serde types |
| `crates/sealbox-cli/src/cmd_hosted.rs` · `tests/gate_g22.rs` | CLI commands + e2e |
| `scripts/gate_g22.sh` | the gate |
