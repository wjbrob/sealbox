# `sealbox` — command-line client

The CLI is both the end-to-end test harness (gates G4/G8) and the first desktop client. It is
a thin shell over `sealbox-core`; everything it prints with `--json` is a `serde` struct of
that crate, so the Flutter app sees the same shapes through the bridge.

```
sealbox [--profile DIR] [--json] <command>
```

* `--profile DIR` — the profile directory (SQLite store, keys). Default `$SEALBOX_HOME`, else
  `$XDG_DATA_HOME/sealbox`, else `~/.local/share/sealbox`. Created `0700`; the database is `0600`.
* `--json` — machine-readable output (documented below). Errors are also JSON on stdout:
  `{"error": "...", "exit_code": N, "missing_keys": [...] | null}`.
* `SEALBOX_LOG=debug` — tracing to stderr. `SEALBOX_DIRECTORY_URL` — VKS key directory used as a
  fallback when a recipient has no local key. `SEALBOX_SERVER_URL` — Sealbox server for guest links.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | other error (store, crypto, MIME, …) |
| 2 | usage error (bad arguments, invalid input) |
| 3 | **policy refusal** — a recipient has no usable key and the policy forbids downgrading; nothing was sent |
| 4 | authentication / connection failure (IMAP, SMTP, autodiscover), including connections the transport policy refused before sending anything: `plain` towards a public host, an OAuth token for a host outside its provider, an OAuth login on an IMAP server without `AUTH=XOAUTH2` |

## Commands

```
sealbox account add --email A [--password P | --password-env VAR] [--name N] [--user LOGIN]
                    [--imap host:port:plain|tls|starttls --smtp host:port:plain|tls|starttls] [--dry-run]
sealbox account list
sealbox account remove --email A
sealbox sync [--account A]                      # INBOX + Sent; all accounts when omitted
sealbox watch --account A [--timeout SECS] [--once]   # IMAP IDLE
sealbox list [--account A] [--folder INBOX|Sent|*] [--limit N]
sealbox read ID [--raw] [--no-mark]             # marks \Seen unless --no-mark
sealbox send --from A --to B[,C] [--cc ..] [--bcc ..] --subject S (--body B | --body-file F|-)
             [--attach F]... [--policy auto|require|guest|plaintext] [--in-reply-to ID|Message-ID]
sealbox contacts
sealbox key show --address A | key export --address A [--file F] | key import --address A --file F|-
sealbox attachment save ID INDEX PATH
sealbox flag ID [--add F,..] [--remove F,..]
sealbox delete ID
```

`account add` without `--imap/--smtp` autodiscovers (built-in table → ISPDB → autoconfig → SRV →
MX → guesses); `--dry-run` only prints what was detected (the built-in table needs no network).
The login name defaults to what the provider wants (usually the full address); on an IMAP
authentication failure the bare local part is tried as well (GreenMail wants `alice`). If
neither `--password` nor `--password-env` is given and stdin is not a terminal, the password is
read from stdin. Passwords are never printed. OAuth accounts: `account add --oauth`, below.

`plain` (no TLS) is only accepted towards loopback (`127.0.0.1`, `::1`, `localhost`), private-network
(`10.x` — including the Android emulator's `10.0.2.2` —, `172.16–31.x`, `192.168.x`, `fc00::/7`),
link-local and `*.test` / `*.local` / `*.localhost` / `*.internal` / `*.lan` / `*.home` / `*.invalid`
hosts, judged from the host as written (no DNS). Anything else is refused before a connection is
made (`plaintext connection to H:P refused: …`, exit 4) — use `tls` / `starttls`, or list the exact
host in `SEALBOX_ALLOW_PLAIN_HOSTS=host1,host2` (exact names, case-insensitive; docs/PROVIDERS.md).
The same rule applies to autodiscovered settings and to `--dry-run`.

`list` output: `ID`, `*` when unseen, status glyphs — `🔒` decrypted, `✍️` good signature,
`⚠` undecryptable / bad or unknown signature, `·` plain — then date, account (unified view
only), sender, subject.

### Send policies

| policy | behaviour |
|---|---|
| `auto` (default) | encrypt + sign (PGP/MIME, protected Subject, outer Subject `...`) when **every** recipient has a usable key; otherwise exit 3 listing who lacks one. Never downgrades silently. |
| `require` | same as `auto` today (reserved for "no guest-link fallback" once `auto` offers one) |
| `guest` | encrypt when everyone has a key; otherwise upload a passphrase-protected guest envelope to `SEALBOX_SERVER_URL` and mail a short plaintext with the link; the passphrase is printed for out-of-band sharing (attachments are not included in guest messages) |
| `plaintext` | send plaintext (still carrying our `Autocrypt:` header so the recipient can encrypt back) |

Recipient keys come from, in order: our own accounts, the Autocrypt peer state (announced key,
then gossip), `key import`ed keys, the key directory. Encrypted mail is always also encrypted to
the sender's own key, signed, and carries `Autocrypt-Gossip` headers for the other To/Cc
recipients inside the encrypted part. A copy is appended to the Sent folder (`\Seen`), created
as `Sent` when the server has none.

## JSON output (stable; the G8 gate checks these keys)

`list` → array of **MessageSummary**; `read` → **MessageDetail** = MessageSummary + bodies.

```json
{
  "id": 7,                        // local id used by read / attachment / flag / delete
  "account": "alice@sealbox.test",
  "folder": "INBOX",
  "uid": 12,
  "message_id": "…@sealbox.test", // without angle brackets, null if absent
  "from": {"name": "Bob", "address": "bob@sealbox.test"},
  "to":   [{"name": null, "address": "alice@sealbox.test"}],
  "cc":   [],
  "subject": "secret subject",    // the protected Subject when the mail carried one
  "date": 1793075241,             // Date header, unix seconds, null if absent
  "received_at": 1793075260,      // when we fetched it
  "flags": ["\\Seen"],
  "seen": true,
  "was_encrypted": true,
  "decrypted": true,
  "was_signed": true,
  "signature": {"status": "good|bad|unknown_key|none", "fingerprint": "B579…6680", "signer": "bob@sealbox.test"},
  "protected_subject": true,
  "attachment_count": 1,
  "raw_size": 10153,
  "decrypt_error": null,
  // MessageDetail only:
  "text": "secret body\r\n",
  "html": null,
  "attachments": [{"index": 0, "filename": "blob.bin", "content_type": "application/octet-stream", "size": 3000}],
  "in_reply_to": ["…"],
  "references": ["…"]
}
```

Other commands:

* `account add` → **AccountInfo** `{id, email, display_name, imap:{host,port,security}, smtp:{…}, auth_kind:"password|o_auth", login, fingerprint, created_at}`;
  with `--dry-run` → `{email, servers: ServerConfig, login, auth_hint}` where `ServerConfig`
  is `{imap, smtp, auth_hint, display_name, source: "BuiltIn|Ispdb|DomainAutoconfig|Srv|Mx|Guess", username}`.
* `account list` → array of AccountInfo.
* `sync` → array of **SyncReport** `{account, new, decrypted, failed, folders:[{name,new,uidvalidity_reset}], new_ids:[…]}`.
* `watch` → one JSON event per line: `{"event":"idle","folder":"INBOX"}`, `{"event":"new_mail","report":SyncReport}`, `{"event":"timeout"}`.
* `send` → **SendReport** `{message_id, mode:"encrypted|plaintext|guest_link", encrypted, recipients:[{address, recommendation:"disable|discourage|available|encrypt", fingerprint, source:"autocrypt|gossip|imported|directory|own|none"}], guest:{url,passphrase,expires_at}|null, sent_copy_appended, sent_folder}`.
* `contacts` → array of **Contact** `{address, recommendation, fingerprint, source, prefer_encrypt:"mutual|no-preference", last_seen, autocrypt_timestamp, gossip_fingerprint}`.
* `key show` → `{address, fingerprint, source}` for own accounts, else a RecipientStatus;
  `key export` → `{address, armored|file, fingerprint}`; `key import` → Contact.
* `attachment save` → `{id, index, filename, content_type, size, path}`; `flag` → `{id, flags}`;
  `delete` → `{deleted}`; `account remove` → `{removed}`.

## Settings: signature (G23) and holiday auto-reply (G24)

```
sealbox settings show --account A                       # AccountSettings {signature, autoreply}
sealbox settings signature show --account A
sealbox settings signature set --account A [--text T | --text-file F|-] [--html-file F | --no-html]
        [--placement above-quote|below-quote] [--include-on new-only|new-and-replies|all] [--enable|--disable]
sealbox settings signature clear --account A
sealbox settings autoreply show --account A
sealbox settings autoreply set --account A [--enable|--disable] [--from DT|--no-from] [--to DT|--no-to]
        [--subject S] [--body B | --body-file F|-] [--once-per-days N] [--no-encrypt|--encrypt]
        [--only-known-contacts|--any-sender]
sealbox settings autoreply log --account A [--limit N]   # sent auto-replies, newest first
sealbox settings autoreply run --account A               # evaluate stored INBOX mail not yet considered
sealbox send ... [--quote] [--forward ID|Message-ID] [--no-signature]
```

* **Signature.** Text goes after the `-- ` separator line (RFC 3676); `set` with text or HTML
  enables it unless `--disable` is given. HTML is sanitised (allowlist `p br b i u strong em span
  div ul ol li`, `a[href=http(s)|mailto]`, `img[src=cid:|data:image/]`; no scripts, styles,
  event handlers or remote images) and only emitted — as `multipart/alternative` — when the
  message has an HTML body or the signature has one. In replies/forwards it sits above or
  below the quote (`--placement`); `--include-on` picks the message kinds. `--quote` on a
  reply inserts `On <date>, <from> wrote:` + `> ` lines; `--forward` inserts a
  `-------- Forwarded Message --------` block with headers and carries the attachments.
  Never applied to auto-replies.
* **Auto-reply (RFC 3834).** `DT` is `2026-12-20`, `"2026-12-20 18:00"` (UTC) or RFC 3339;
  `{subject}` in `--subject` is the original subject (default `Automatic reply: {subject}`).
  Evaluated after every `sync`/`watch` for new INBOX mail inside the window; at most one
  reply per sender per `--once-per-days` (0 = once per vacation period; switching on or
  moving `--from` starts a new period). Suppressed for `Auto-Submitted` ≠ `no`,
  `Precedence: bulk|list|junk`, `List-*`, `X-Auto-Response-Suppress`, `X-Autoreply`/
  `X-Autorespond`, null (`Return-Path: <>`) or system senders (`MAILER-DAEMON`, `postmaster`,
  `noreply`/`no-reply`/`do-not-reply`, `bounce…`), `multipart/report`, our own addresses and
  mail dated before the window. The reply goes to `Reply-To` (else `From`) with
  `Auto-Submitted: auto-replied`, `Precedence: auto_reply`, `X-Auto-Response-Suppress: All`,
  `In-Reply-To`/`References` and our `Autocrypt` header; it is encrypted + signed when the
  sender has a usable key and sent plaintext otherwise (`--no-encrypt` = always plaintext),
  never with a signature. `--only-known-contacts` answers only people this account has
  written to or whose key was imported.
* JSON: `settings show` → **AccountSettings** `{signature: SignatureSettings, autoreply:
  AutoReplySettings}`; `signature show|set|clear` → **SignatureSettings** `{enabled, text,
  html|null, placement:"above_quote|below_quote", include_on:"new_only|new_and_replies|all"}`;
  `autoreply show|set` → **AutoReplySettings** `{enabled, start|null, end|null (RFC 3339),
  subject_template, body, reply_once_per_sender_days, encrypt_when_possible,
  only_to_known_contacts}`; `autoreply log` → array of **AutoReplyLogEntry** `{id, account,
  sender, period_start, sent_at, message_id, in_reply_to, original_id, encrypted}`;
  `autoreply run` → **AutoReplyRunReport** `{account, active, evaluated, replied, skipped,
  failed, outcomes:[{message, sender, action:"replied|skipped|failed", …}]}`.

## Gates

```
testing/mail_up.sh
cargo test -p sealbox-cli --test gate_g4 -- --ignored   # first encrypted e2e, Autocrypt bootstrap
cargo test -p sealbox-cli --test gate_g8 -- --ignored   # desktop-client behaviours
cargo test -p sealbox-cli --test gate_g23 -- --ignored  # signatures (u11/u12)
cargo test -p sealbox-cli --test gate_g24 -- --ignored  # holiday auto-reply (u13–u20)
```

## OAuth accounts and the provider conformance suite (G21)

```
sealbox account add --email A --oauth google|microsoft [--client-id ID | --client-id-env VAR]
                    [--client-secret-env VAR] [--open-browser] [--oauth-timeout SECS] [--imap … --smtp …]
sealbox provider-test --account A [--json] [--probe-size-limit] [--skip-attachment] [--attachment-mib N]
                      [--arrival-timeout SECS] [--keep] [--label L] [--evidence-dir DIR]
```

`account add --oauth` runs the loopback PKCE flow: binds `127.0.0.1:<port>`, prints the
authorization URL (opens it with `xdg-open` only with `--open-browser`), waits for the redirect,
exchanges the code, verifies IMAP + SMTP with XOAUTH2 and stores the account with its tokens; the
engine refreshes the access token before every connection. Client ids default to
`$GOOGLE_OAUTH_CLIENT_ID`/`$GOOGLE_OAUTH_CLIENT_SECRET` and `$MS_OAUTH_CLIENT_ID`. With `--json` the
command emits one JSON object per line: `{"event":"oauth_start","url":…,"loopback_port":…}` then
`{"event":"account_added","account":AccountInfo,"oauth":{provider,expires_in_secs,has_refresh_token,
refresh_count,dev_hosts_allowed,…}}`. `SEALBOX_OAUTH_AUTH_URL` + `SEALBOX_OAUTH_TOKEN_URL` redirect
the flow to a mock identity provider (tests only; plain http is accepted for loopback hosts only).

The token is pinned to its provider: it is only ever presented — through SASL XOAUTH2, never as a
password — to Google's (`gmail.com`, `googlemail.com`, `google.com`) or Microsoft's (`office365.com`,
`outlook.com`, `live.com`, `hotmail.com`, `microsoft.com`) mail hosts. Manual `--imap/--smtp`
servers outside those domains are refused before the browser opens (`OAuth token not sent to H:
…`), and an IMAP server that does not advertise `AUTH=XOAUTH2` ends the flow with `H does not offer
OAuth sign-in over IMAP …` (exit 4). Only a token from a loopback mock IdP (both URLs above on
`127.0.0.1` / `localhost`) may also go to local/private hosts — that is how the G21 local test
reaches GreenMail (through a test-only XOAUTH2 front, since GreenMail's IMAP has no XOAUTH2).

`provider-test` prints `PASS|FAIL|SKIP  <ms>  <check>  <detail>` per check (or the full evidence
document with `--json`, plus `evidence_file`), writes `.gate/evidence/G21/<provider>[-label]-<date>.json`
(no secrets) and exits 1 when a check failed. Check list and per-provider expectations:
`docs/PROVIDERS_CONFORMANCE.md`. `delete ID` now moves to the provider's Trash folder (expunges
when the message already is in Trash).

## Folders by role, the server URL, the key directory

```
sealbox folders [--account A]                    # role → folder: learned from the server, else the provider default
sealbox sync [--account A] --role trash|junk|archive|inbox|sent|drafts|all|flagged
sealbox list [--account A] --role ROLE [--limit N]
sealbox move ID --to ROLE                        # MOVE (or COPY+EXPUNGE); the local copy returns when ROLE is synced
sealbox server show | server set-url URL | server set-url --clear
sealbox key publish [--account A]                # upload + request the verification mail
sealbox key complete-verification [--account A]  # sync, follow the directory's link, report the state
sealbox key directory-status [--account A]
```

`--account` may be left out when the profile has one account. Roles are the engine's special-use
roles (`spam` is accepted for `junk`); an unknown role is a usage error (exit 2). `move` of a
message that already is in the destination prints `… is already in …` (`"method": null`). The
server URL stored with `server set-url` (`http(s)://host[:port]`) wins over `SEALBOX_SERVER_URL`
and serves the key directory too unless `SEALBOX_DIRECTORY_URL` is set; `server show --json` →
`{server_url, source: settings|environment|none, directory_url}`. Without a server the `key`
commands refuse with exit 2 and name `sealbox server set-url`. Directory states (`--json`
`DirectoryStatus.state`): `published` · `other_key` · `unpublished` · `awaiting_verification` (no
challenge mail yet) · `verification_failed` (link expired or used: publish again).

## Spam detection and filters (gate G25)

```
sealbox spam status|learn --spam|--ham ID|explain ID|check FILE|eval --corpus DIR|settings show|set|reset|allow ADDR|block ADDR
sealbox filter add|list|rm|enable|test --account A …   # also spelled `filters`, and `rm` as `remove`
```
Design, thresholds, privacy (DNSBL is off by default) and the evaluation numbers: `docs/SPAM.md`.
