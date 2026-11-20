# Sealbox privacy policy (draft)

**Applies to:** Sealbox 0.1.0
**Status:** pre-release draft written by the engineering team, 2026-10-27. It has not been reviewed
by a lawyer, "Sealbox" is a codename, and the hosted backend is not yet operated for the public.
It is deliberately honest about what the software does *today*, including the parts that are not
finished. Keep it in step with the code: `scripts/gate_release.sh` (gate G26) refuses to pass unless
this file names the current version.

## 1. The short version

- Sealbox is a mail **client**. Your mail stays in the mailbox you already have (Gmail, Outlook,
  Yahoo, iCloud, your company's IMAP server). We do not run your mailbox and we cannot read it.
- Everything that matters — your private OpenPGP keys, your credentials, your messages — is stored
  **on your device**. Mail you send through Sealbox is encrypted end-to-end whenever the recipient
  can receive it; otherwise it goes out as a passphrase-protected *guest link*, or, only after you
  explicitly confirm, in plaintext.
- Sealbox has **no analytics, no advertising, no tracking and no crash reporting**. It contacts
  servers only to do what you asked (sync mail, look up a recipient's key, publish your own key,
  create a guest link, back up your keys).
- The optional **Sealbox backend** stores public keys, encrypted guest messages and
  client-encrypted key backups. It never receives a plaintext message body or a private key.

## 2. What Sealbox stores on your device

| Data | Why | Where / how |
|---|---|---|
| Account settings (address, IMAP/SMTP hosts, auth method) | to reach your mailbox | app data directory, per profile |
| Credentials: app password or OAuth 2.0 access + refresh tokens | to sign in to your provider | per-profile SQLite store (directory 0700, database 0600), **encrypted at rest** with XChaCha20-Poly1305 under a profile key held in the platform keystore/keyring or derived from your passphrase (`docs/SECRETS_AT_REST.md`). |
| Your OpenPGP key pair(s) (Ed25519/X25519), generated on the device | to decrypt mail sent to you and sign mail you send | same store, encrypted at rest |
| Mail: headers, decrypted bodies, attachments you opened | to show you your inbox, offline | same store; bodies, raw messages, previews and attachments are **encrypted at rest** (see above). Addresses, dates and protected subjects stay readable to the app for lists and sorting |
| Contacts and their keys (Autocrypt peer state, gossip, directory lookups) | to decide, per recipient, whether mail can be encrypted | same store |
| Preferences, filters, signatures, auto-reply settings | features you configure | same store |

Deleting the app (or the profile directory on desktop) deletes all of it. Export your keys first
if you want to keep reading old mail elsewhere.

## 3. What leaves your device, and to whom

| Recipient | What | When |
|---|---|---|
| **Your mail provider** (IMAP/SMTP over TLS) | your credentials/tokens; the mail you fetch; the mail you send. For encrypted mail the provider sees the ciphertext plus the unprotected envelope: From, To/Cc, Date, Message-ID, size, your `Autocrypt:` header (your public key), and `...` in place of the Subject (the real Subject travels inside the encrypted part). A Sent copy encrypted to yourself is stored in your mailbox. | every sync / send |
| **Google / Microsoft** (OAuth 2.0 with PKCE, in the system browser) | the standard sign-in flow; Sealbox receives tokens scoped to mail access | when you add such an account and when tokens are refreshed |
| **Autodiscovery services** | the *domain* of the address you type is sent to Mozilla's ISPDB (`autoconfig.thunderbird.net`); the provider's own autoconfig endpoint may receive the full address (that is how the protocol works); DNS SRV/MX queries go to your resolver. Known providers are resolved from a built-in table without any request. | only when you add an account for an unknown domain |
| **Key discovery services** | the e-mail addresses you are writing to, looked up at the Sealbox key directory, `keys.openpgp.org` and the recipient domain's WKD endpoint. This reveals *who* you write to, to those services. | when composing to someone whose key is not already known locally |
| **Sealbox backend — key directory** | your public key and address, an e-mail verification challenge, timestamps | only when you choose "Publish to directory" |
| **Sealbox backend — guest links** | the encrypted message (ciphertext), its size, an opaque id, creation/expiry timestamps, and later the recipient's encrypted reply. The passphrase never leaves your device; you give it to the recipient yourself. | only when you send to a recipient without a key and keep the guest-link default |
| **Sealbox backend — backups** | one blob, encrypted on your device, authenticated by a signature from your key | only when you turn on key backup |
| **A push relay** | *not built yet.* The design is content-free pushes ("something arrived") keyed by an account identifier. This policy will be updated before it ships. | — |

Nothing else. In particular: no usage statistics, no device identifiers, no contact-list upload,
no third-party SDKs (the app is Flutter + our own Rust code), no remote images or active content in
mail (also an anti-exfiltration measure).

## 4. What the backend keeps, and for how long

The backend (`sealbox-server`) is open source and self-hostable. When we operate it:

- **Stored:** the items in section 3 marked "Sealbox backend". No plaintext bodies, no private keys,
  no passphrases — it is designed so that the operator *cannot* learn more (threat model A3 in
  `docs/THREAT_MODEL.md`).
- **Logged:** request metadata needed to run the service and stop abuse — IP address, timestamp,
  endpoint, status, size. Rate limiting is per IP. Message bodies and keys are never written to logs;
  `scripts/gate_release.sh` audits the source for that on every release.
- **Retention:** guest messages and their replies expire and are deleted after a fixed period;
  verification challenges expire within hours; backups are overwritten by the newest one and deleted
  on request; access logs are rotated. *The exact periods must be fixed and written here before the
  hosted service opens to the public* (today it only runs locally in tests).
- **Location / processors:** to be filled in by the operator before launch (hosting provider,
  country, sub-processors).

## 5. What recipients and others can see

- Recipients of encrypted mail see what you sent them, including your public key (Autocrypt) and
  the keys of the other recipients (Autocrypt gossip), so that everyone can reply encrypted.
- Mail is end-to-end encrypted, but **metadata is not hidden**: anyone able to read your mailbox or
  the network path can see who writes to whom, when, and how much. The Subject is protected; From,
  To, Cc, Date and size are not. Traffic analysis is out of scope.
- Guest-link recipients open a web page served by the backend; the backend sees their IP address and
  the link id. Decryption happens in their browser with the passphrase you gave them; the passphrase
  is never sent to the server.
- Signature verification results are shown to you, never implied. Decryption failures are fatal, not
  partial (no EFAIL-style partial rendering).

## 6. Permissions

Android/iOS: network access. No contacts, location, microphone or camera access today (a camera
permission will be requested if/when QR-code key verification ships, and only when you open it).
Desktop: files you explicitly attach or save.

## 7. Children, legal bases, your rights

Sealbox is not directed at children under 16. Where the GDPR applies: the app processes personal
data on your device under your control; for the optional backend the legal basis is performance of
the service you request (Art. 6(1)(b)) and our legitimate interest in abuse prevention (Art. 6(1)(f)).
You can access, export and delete everything in the app yourself; backend data can be deleted on
request (deleting a key from the directory requires proving control of the address, like publishing
it). Contact details and a supervisory-authority note are to be added by the operator before
publication.

## 8. Changes

This document is versioned with the software (see "Applies to" above) and every change is listed in
`CHANGELOG.md`. Material changes to what leaves the device will be called out in the release notes.

## Open items before this can be published

- [ ] Operator identity, contact address and hosting/sub-processor details (section 4).
- [ ] Exact retention periods for guest messages, challenges, backups and logs.
- [ ] Legal review (GDPR, UK GDPR, CCPA wording; Apple App Store and Google Play privacy-label answers).
- [x] Keystore wrapping at rest (G27) — reflected in section 3.
- [ ] Update when the push relay (G16) or hosted mailboxes (G22) ship.
