# Provider conformance (gate G21)

`sealbox provider-test --account A [--json]` runs the same battery of checks against any
account and writes secret-free evidence to `.gate/evidence/G21/<provider>-<date>.json`.
`scripts/gate_g21.sh` runs it (1) against GreenMail with a mock OAuth identity provider — the
half that needs nobody — and (2) against the real accounts listed in
`.gate/providers.local.env`. G21 is PASS only when Gmail, Outlook/Hotmail, Yahoo and iCloud all
have PASS evidence from today; until the human provides those accounts the gate exits **3 =
NEEDS_HUMAN** and prints exactly what is missing.

## The checks (in order)

| # | check | what passes |
|---|---|---|
| 1 | `connect_imap` | TCP + TLS (implicit or STARTTLS, webpki roots, hostname verified) + login; reports the SASL mechanism actually used |
| 2 | `capabilities` | CAPABILITY list after login; notes IDLE / MOVE / UIDPLUS / SPECIAL-USE / CONDSTORE; pre-login capabilities too |
| 3 | `auth_method` | IMAP mechanism (`XOAUTH2`, `LOGIN`); for OAuth accounts the token state (expiry, refresh token present, refresh count). **FAIL when an OAuth account did not use XOAUTH2** (there is no token-as-password fallback any more) |
| 4 | `special_use_folders` | `LIST` mapped to roles via RFC 6154 attributes, then name heuristics; Sent / Trash / Junk / Drafts must resolve (missing ones are created on first use, like a client would) |
| 5 | `select_inbox` | SELECT INBOX returns a UIDVALIDITY |
| 6 | `uidvalidity_handling` | after a sync the engine's stored UIDVALIDITY equals the server's (and resets are counted) |
| 7 | `send_encrypted_to_self` | `policy=require` send to the account itself goes out as PGP/MIME encrypted + signed |
| 8 | `arrival_via_idle` | the message shows up in INBOX within `--arrival-timeout` (60 s), observed through IDLE wake-ups |
| 9 | `decrypt_received` | after sync the stored message is decrypted, body byte-equal, signature good |
| 10 | `sent_copy_single` | **exactly one** copy in the Sent folder: either the provider stored it on SMTP submission (Gmail, Microsoft 365 → we do not APPEND) or we appended it; dedupe is by Message-ID on every provider |
| 11 | `flags_set_unset` | `\Flagged` set and cleared through the engine, verified on the server |
| 12 | `move_to_trash_and_back` | engine `move_message(Trash)` (UID MOVE, or COPY+EXPUNGE fallback), then back to INBOX and re-synced |
| 13 | `spam_folder_detection` | a Junk/Spam folder is mapped (`[Gmail]/Spam`, `Junk Email`, `Bulk Mail`, `Junk`, …) and STATUS works on it |
| 14 | `large_attachment_roundtrip` | a 5 MiB (`--attachment-mib`) random attachment, encrypted, arrives and decrypts byte-exact (`--skip-attachment` to skip) |
| 15 | `connection_limit_3` | three extra IMAP sessions opened concurrently; PASS when at least `min(profile.max_connections - 1, 3)` succeed, the count is recorded. The suite is already holding one session, so `cap - 1` is what the provider's own budget leaves for extras — demanding `cap` made the check unsatisfiable on Yahoo and iCloud (`max_connections: 1`) however well the engine behaved |
| 16 | `autocrypt_header_preserved` | the delivered raw message carries our `Autocrypt:` header with `addr` = account and keydata **byte-identical** to our minimal key |
| 17 | `protected_subject_preserved` | outer `Subject: ...`, inner (protected) subject restored by the engine |
| 18 | `message_size_limit_probe` | SKIP by default; `--probe-size-limit` sends 8/16/24/32 MiB attachments until the submission server refuses |
| 19 | `clean_logout` | LOGOUT acknowledged |

Test messages are moved to Trash at the end unless `--keep` is given. Exit code is 1 when any
check FAILed; the evidence JSON lists every check with `status`, `ms` and `detail`.

## Running it without a real mailbox (gate G21S)

`cargo test -p sealbox-cli --test gate_g21_sim` runs all nineteen checks against
`sealbox-fakeprov` for **every** `ProviderId`, asserting each result *and its detail text*
against expectations computed from that provider's `PROFILES` entry. No docker, no non-loopback
network, ~25 s. See `docs/GATES.md` for what it does and does not prove — in short: it tests the
engine against our beliefs about a provider, and is never evidence about the provider. Its
evidence files are labelled `-sim-`.

## Per-provider expectations (`sealbox_core::providers`)

| provider | auth | Sent / Trash / Junk defaults | SMTP saves Sent | IMAP connections | notes |
|---|---|---|---|---|---|
| Gmail / Google Workspace | OAuth2 (XOAUTH2), scope `https://mail.google.com/` | `[Gmail]/Sent Mail` · `[Gmail]/Trash` · `[Gmail]/Spam` (localised per account language → the `\Sent`/`\Trash`/`\Junk` LIST attributes decide) | **yes** → no APPEND | 10 (server cap 15) | label semantics: expunging from INBOX only archives; moving to `[Gmail]/Trash` is the delete; 25 MB messages |
| Outlook.com / Hotmail / M365 | OAuth2 only (Basic auth removed Sept 2024), scopes `IMAP.AccessAsUser.All SMTP.Send offline_access` | `Sent Items` · `Deleted Items` · `Junk Email` | **yes** → no APPEND (clients that append get duplicates) | 8 | Exchange drops IDLE after ~30 min; 20 MB |
| Yahoo / AOL | app password | `Sent` · `Trash` · `Bulk Mail` | no | **1** (serial, no parallel fetch) | OAuth needs Yahoo partner approval |
| iCloud | app-specific password (Apple ID with 2FA) | `Sent Messages` · `Deleted Messages` · `Junk` | no | **1** | SMTP 587 STARTTLS, full address as login; 20 MB |
| Fastmail | app password | `Sent` · `Trash` · `Spam` | no | 8 | full SPECIAL-USE; 50 MB |
| Zoho | app password (2FA) / password | `Sent` · `Trash` · `Spam` | no | 4 | IMAP must be enabled in settings |
| GMX / WEB.DE | password (IMAP enabled in web settings) | `Gesendet` · `Gelöscht` · `Spamverdacht` | no | 2 | German names; SPECIAL-USE attributes present |
| GreenMail (local) | password; SMTP accepts XOAUTH2 when bearer = password | `Sent` · `Trash` · `Junk` (created on first use) | no | 10 | no SPECIAL-USE, no `AUTH=XOAUTH2` on IMAP |
| generic IMAP | password | `Sent` · `Trash` · `Junk` | no | 2 | the live LIST mapping decides |

The engine remembers what `LIST` really said (`folder_roles` table, refreshed on every sync) and
prefers it over these defaults: `Engine::special_folder(email, role)` /
`providers::folder_for(role, &account)` are the single entry points the send (Sent copy), delete
(Trash), spam (Junk) and auto-reply paths use.

**No token-as-password fallback (day 2, threat-model R14).** An OAuth token only ever travels inside
`AUTHENTICATE XOAUTH2` / SMTP XOAUTH2, and only to the issuing provider's own hosts (Google:
gmail.com, googlemail.com, google.com; Microsoft: office365.com, outlook.com, live.com, hotmail.com,
microsoft.com — `sealbox_mail::net_policy`). An IMAP server without `AUTH=XOAUTH2` fails with
"… does not offer OAuth sign-in over IMAP …" and the token is not sent at all. GreenMail's IMAP has no
XOAUTH2, so the local gate reaches it through a test-only XOAUTH2 front (`tests/gate_g21_local.rs`:
19 XOAUTH2 logins, 0 `LOGIN` commands observed); GreenMail's SMTP takes XOAUTH2 directly. The mock
IdP's loopback endpoints give the token a `dev_idp` scope that additionally admits local/private hosts;
tokens from the real endpoints never get it. The suite's `auth_method` check FAILs any OAuth account
that did not authenticate with XOAUTH2.

## Adding an account

Password / app password (autodiscovers the servers from the built-in table):

```
sealbox account add --email you@yahoo.com --password-env YAHOO_APP_PW
sealbox provider-test --account you@yahoo.com
```

OAuth (Gmail, Outlook/Hotmail/M365) — the loopback PKCE flow:

```
set -a; . .gate/config.local.env; set +a            # GOOGLE_OAUTH_CLIENT_ID[/_SECRET], MS_OAUTH_CLIENT_ID
sealbox account add --email you@gmail.com   --oauth google    --open-browser
sealbox account add --email you@outlook.com --oauth microsoft --open-browser
```

`account add --oauth` binds `127.0.0.1:<ephemeral>` first, prints the authorization URL (opens it
only with `--open-browser`, via `xdg-open`), waits up to `--oauth-timeout` (300 s) for the
redirect, exchanges the code (PKCE S256), verifies IMAP and SMTP with XOAUTH2, generates or reuses
the OpenPGP identity and stores the account **and its tokens** (`oauth_tokens`: access token,
refresh token, expiry, provider, client id/secret, token endpoint, scopes). From then on every
IMAP/SMTP connection goes through `Engine::refresh_if_needed`: a token that expires within 5
minutes is refreshed first and the rotated refresh token is persisted. `--client-id ID`,
`--client-id-env VAR`, `--client-secret-env VAR` override the defaults; `--json` turns the flow
into an event stream (`{"event":"oauth_start",…}` then `{"event":"account_added",…}`).

For the gate, list the accounts in `.gate/providers.local.env` (template:
`testing/providers.local.env.example`):

```
PROVIDER_ACCOUNTS="gmail:you@gmail.com:oauth,outlook:you@outlook.com:oauth,yahoo:you@yahoo.com:password_env=YAHOO_APP_PW,icloud:you@icloud.com:password_env=ICLOUD_APP_PW"
YAHOO_APP_PW=…
ICLOUD_APP_PW=…
```

and put the same addresses into `TEST_ACCOUNTS` in `.gate/config.local.env` (the suite sends
encrypted test mail to the account itself; hard rule 6). The gate keeps its accounts in
`.gate/profiles/g21` (gitignored).

## The 5-minute human procedure (OAuth consent)

### Google (Gmail / Workspace) — once, about 5 minutes

1. <https://console.cloud.google.com/> → project picker → **New project** (any name) → Create.
2. **APIs & Services → OAuth consent screen** (now "Google Auth Platform"): User type **External**
   → Create. App name `Sealbox`, your e-mail as support and developer contact → Save.
   Leave publishing status **Testing**.
3. **Audience → Test users → Add users**: every Gmail address you will test with (up to 100).
4. **Clients (Credentials) → Create credentials → OAuth client ID** → Application type
   **Desktop app** → name `sealbox-cli` → Create. Copy the **Client ID** and the **Client secret**
   (desktop-app secrets are not confidential; Google requires them in the token request).
5. No scope registration is needed for Testing mode; the client asks for
   `https://mail.google.com/` (restricted scope — publishing to production would require Google
   verification; Testing mode is fine for our accounts).
6. Put into `.gate/config.local.env`:
   `GOOGLE_OAUTH_CLIENT_ID=….apps.googleusercontent.com` and `GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-…`.
7. Consent: `set -a; . .gate/config.local.env; set +a; sealbox --profile .gate/profiles/g21 account add --email you@gmail.com --oauth google --open-browser`
   → pick the account → "Google hasn't verified this app" → **Continue** → tick "Read, compose,
   send and permanently delete all your email from Gmail" → Continue. The terminal prints
   `added … via OAuth (google; …)`. Refresh tokens for Testing-mode apps expire after 7 days of
   inactivity on the consent; re-run the command when the gate reports `invalid_grant`.

### Microsoft (Outlook.com / Hotmail / Microsoft 365) — once, about 5 minutes

1. <https://entra.microsoft.com/> (or portal.azure.com) → **Identity → Applications → App
   registrations → New registration**.
2. Name `Sealbox`; **Supported account types**: *Accounts in any organizational directory and
   personal Microsoft accounts* (the "common" tenant); **Redirect URI**: platform
   **Mobile and desktop applications**, value `http://localhost` → Register.
3. **Authentication**: under *Advanced settings* set **Allow public client flows: Yes** → Save
   (no client secret is used; PKCE protects the exchange).
4. **API permissions → Add a permission** → tab *APIs my organization uses* → search
   `Office 365 Exchange Online` → **Delegated permissions** → tick `IMAP.AccessAsUser.All` and
   `SMTP.Send` → Add permissions. Then **Add a permission → Microsoft Graph → Delegated** →
   tick `offline_access`, `openid`, `email` → Add permissions. (No admin consent is needed for
   personal accounts; a work tenant's admin may have to grant consent once.)
5. **Overview** → copy the **Application (client) ID** → `.gate/config.local.env`:
   `MS_OAUTH_CLIENT_ID=…` (no secret).
6. Consent: `set -a; . .gate/config.local.env; set +a; sealbox --profile .gate/profiles/g21 account add --email you@outlook.com --oauth microsoft --open-browser`
   → sign in → "Let this app access your info?" → **Accept**. Outlook SMTP AUTH must be enabled
   for the mailbox (Outlook.com: Settings → Mail → Sync email → "Let devices and apps use POP"
   is not needed; IMAP/SMTP are on by default; M365 tenants: enable *Authenticated SMTP* for the
   user in the admin center).

**If IMAP says `NO Login failed` right after a successful consent:** the address you consented with is
probably an *alias* on the Microsoft account. Outlook IMAP accepts XOAUTH2 only under the account's primary
address (shown at the top of the consent page). Re-run the add with `--user <primary address>`; the account
keeps its own address for mail. Observed 2026-11-16 on a personal account whose primary is a Gmail address.

Since 2026-11-17 the CLI says this itself: a sign-in that gets a token and is then refused by IMAP
prints a hint naming `--user <primary address>` and stating that the token *was* issued, so the
part that worked is not re-done. It is a hint and not a diagnosis — the server never names the
address it wanted, and a login that is simply wrong is refused with the same bytes — so the CLI
never prints an address it cannot know. Pinned by `crates/sealbox-cli/tests/cli_oauth_alias.rs`
(gate G21S) against a simulated Outlook whose mailbox is an alias.

### Yahoo / iCloud app passwords — about 2 minutes each

* **Yahoo**: <https://login.yahoo.com/account/security> → *Generate app password* → name
  `Sealbox` → copy the 16 characters → `YAHOO_APP_PW=` in `.gate/providers.local.env`.
  (Yahoo removed "less secure apps"; an app password is the only way for IMAP clients.)
* **iCloud**: <https://account.apple.com/account/manage> → *Sign-In and Security →
  App-Specific Passwords → +* → label `Sealbox` → copy `xxxx-xxxx-xxxx-xxxx` → `ICLOUD_APP_PW=`.
  Requires two-factor authentication on the Apple ID; the login name is the full iCloud
  address (any alias works for IMAP, the primary address for SMTP).

Then: `scripts/gate_g21.sh`. It exits 0 once all four have PASS evidence for the day.

## Results

Refreshed by `scripts/gate_g21.sh` from `.gate/evidence/G21/*.json` (addresses masked).

<!-- G21-RESULTS-START -->
| date | provider | account | auth | result | pass/fail/skip | evidence |
|---|---|---|---|---|---|---|
| – | – | – | – | no runs yet | – | – |
<!-- G21-RESULTS-END -->

Local evidence (GreenMail, every run of `gate_g21_local`): `greenmail-<date>.json` (password
account u27) and `greenmail-oauth-<date>.json` (OAuth account u26 via the mock IdP) are written into
the test's temporary profile; the test asserts `result == PASS`, every check PASS (size probe
SKIP), and that neither the password nor a refresh token appears in the file.
