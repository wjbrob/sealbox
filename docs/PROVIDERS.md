# Provider realities (why "quick setup" needs OAuth for some and app-passwords for others)

| Provider | IMAP / SMTP | Auth that works for third-party apps (2026) | Setup UX in Sealbox |
|---|---|---|---|
| Gmail / Google Workspace | imap.gmail.com:993 · smtp.gmail.com:465/587 | **OAuth2 XOAUTH2** (scope `https://mail.google.com/`, restricted → Google verification for >100 users; "Testing" mode allows 100 test users). **App passwords** work only with 2-Step Verification on | OAuth button (PKCE, loopback/custom-scheme redirect) or app-password fallback with step-by-step help |
| Outlook.com / Hotmail / Live / Microsoft 365 | outlook.office365.com:993 · smtp.office365.com:587 | **OAuth2 only** (Basic auth removed for consumer accounts Sept 2024). Entra app registration, scopes `IMAP.AccessAsUser.All SMTP.Send offline_access`; consumer accounts need "Personal Microsoft accounts" audience | OAuth button; no password path |
| Yahoo / AOL | imap.mail.yahoo.com:993 · smtp.mail.yahoo.com:465 | **App password** (Yahoo "Generate app password"); OAuth needs partner approval | guided app-password flow |
| iCloud | imap.mail.me.com:993 · smtp.mail.me.com:587 | **App-specific password** (requires 2FA Apple ID) | guided app-password flow |
| Fastmail | imap.fastmail.com:993 · smtp.fastmail.com:465 | app password (or OAuth with registration) | guided |
| Zoho / GMX / Posteo / mailbox.org / Proton Bridge | per ISPDB | password / app password | autodiscover + password |
| Company IMAP / Exchange Online | ISPDB → SRV → guesses; Exchange Online IMAP needs OAuth (tenant consent) | password or OAuth | autodiscover; manual fields as last resort |

Autodiscover order: built-in table → `https://autoconfig.thunderbird.net/v1.1/{domain}` → `https://autoconfig.{domain}/mail/config-v1.1.xml` →
`_imaps._tcp` / `_submission._tcp` SRV (RFC 6186) → MX-based provider guess → common host guesses with STARTTLS/TLS probing.

Credentials never leave the device (platform keystore). Refresh tokens are stored encrypted.
OAuth client IDs for Google and Microsoft are *configuration*, see `docs/PROVIDERS_CONFORMANCE.md`.

## Transport policy (`sealbox-mail::net_policy`, docs/THREAT_MODEL.md R12 / R14)

* **No TLS (`plain`) only for local hosts.** IMAP/SMTP without TLS is refused unless the host is
  loopback (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`), a private network (`10/8` — this
  includes `10.0.2.2`, the Android emulator's address for the host machine —, `172.16/12`,
  `192.168/16`, `fc00::/7`), link-local (`169.254/16`, `fe80::/10`) or a name under `.test`, `.local`,
  `.internal`, `.lan`, `.home`, `.invalid`. The decision is made from the host as written, never by a
  DNS lookup. This applies to manual settings (`--imap host:port:plain`), to autodiscovery answers
  and to every connection. To use a plaintext server elsewhere (a lab machine on a routed network,
  say), list its exact host name(s) — no wildcards, no subdomains — in
  **`SEALBOX_ALLOW_PLAIN_HOSTS=host1,host2`** (read once per process; case and a trailing dot do
  not matter). The refusal says so: `plaintext connection to imap.example.com:143 refused: … use tls
  or starttls, or allow this exact host with SEALBOX_ALLOW_PLAIN_HOSTS=imap.example.com`.
* **OAuth tokens stay with their provider.** A Google token is only sent to hosts under
  `gmail.com`, `googlemail.com` or `google.com`; a Microsoft token only to hosts under
  `office365.com`, `outlook.com`, `live.com`, `hotmail.com` or `microsoft.com` — anything else fails
  before a connection is opened ("OAuth token not sent to …"). The token is only ever offered
  through SASL XOAUTH2: an IMAP server that does not advertise `AUTH=XOAUTH2` gets an error ("…
  does not offer OAuth sign-in over IMAP …"), never the token as a password. Tests that point
  `SEALBOX_OAUTH_AUTH_URL` / `SEALBOX_OAUTH_TOKEN_URL` at a loopback mock identity provider may
  also send that mock's tokens to local hosts (GreenMail); tokens from the real endpoints cannot.
