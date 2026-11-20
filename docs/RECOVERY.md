# Recovery and multi-device (gate G15)

Sealbox keeps your secret key on your device. If the device is lost, so is the key, and with
it every encrypted mail you ever received. G15 gives two ways out:

1. **Recovery phrase + server backup**: 12 words you write down once. The app encrypts your
   keys, contacts and settings with them and stores the result on the Sealbox server. On a
   new device, the address + the 12 words bring everything back.
2. **Autocrypt Setup Message**: the standard way to move a key between mail apps (Delta Chat,
   Thunderbird, Sealbox). The key is mailed to yourself, encrypted with a 36-digit setup code
   shown only on the old device. Needs the old device; no server involved.

Code: `crates/sealbox-core/src/recovery.rs`. CLI: `crates/sealbox-cli/src/cmd_recovery.rs`.
Gate: `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g15 -- --ignored`.

## Lost phone: the walkthrough

Before (once, on the old device):

```
sealbox recovery phrase --account me@example.org          # 12 words, shown once: write them down
G15=... sealbox recovery backup --account me@example.org --server https://sealbox.example --phrase-env G15
```

After (new device, old one gone):

```
PH="the twelve words ..." PW="app-password" \
sealbox recovery restore --email me@example.org --server https://sealbox.example \
        --phrase-env PH --password-env PW
sealbox sync --account me@example.org                     # old encrypted mail opens again
```

`restore` needs to know which backup slot is yours (the slot is the fingerprint of your key).
It tries, in order: `--fingerprint` if given; the key directory on the same server (if you
published your key); the `Autocrypt:` header of the newest mail you sent (Sent folder, then
INBOX), which needs the mail password. With the password, `restore` also tests the login
before writing anything. Without it, the account is created without a credential and
`sealbox recovery set-password --account … --password-env …` adds it later.

Other commands: `recovery validate --phrase-env` (word list + checksum, no network),
`recovery status --account` (last backup from this device, reminder), `recovery
setup-export --account`, `recovery setup-import <id|Message-ID|file> --code-env`.

## How the phrase becomes keys

```
phrase  = 12 BIP39 English words: 128 bits from the OS RNG + 4-bit SHA-256 checksum
norm    = the words in lower case, single spaces (typed input: any case/separators,
          unique 4-letter prefixes accepted)
master  = Argon2id(norm, salt = "sealbox-recovery:" + lower(email)), 64 MiB, t = 3, p = 1
key     = HKDF-SHA256(master, info "sealbox-recovery-v1 backup-key")    -> XChaCha20-Poly1305
token   = base64url(HKDF-SHA256(master, info "sealbox-recovery-v1 backup-token"))  (43 chars)
```

The word list is the canonical BIP39 English list, vendored as
`crates/sealbox-core/src/bip39_english.txt` (SHA-256 `2f5eed53…24dbda`, checked by a unit
test). Unit tests cover the BIP39 reference vectors, checksum failures, KDF determinism and
separation (address, phrase), and a pinned token so a KDF change cannot silently orphan
existing backups.

128 bits of entropy cannot be brute-forced; Argon2id is defence in depth (a weaker phrase
format later, or a partially leaked phrase). The address in the salt means one phrase gives
different keys for different accounts.

## Bundle format

```
blob = "SBXR" | 0x01 | nonce (24) | XChaCha20-Poly1305(key, nonce, deflate(JSON), AAD) | tag (16)
AAD  = "SBXR" | 0x01 | "|" | lower(email) | "|" | FINGERPRINT
```

Uploaded with `PUT /v1/backup/{fingerprint}`: `X-Sealbox-Signature` = base64 of a detached
signature over the blob by the account key, `X-Sealbox-Key` = base64 of the armored public
key (the server pins it on the first upload), `X-Sealbox-Backup-Token` = the derived token.
A later backup replaces the blob **and** the token, so after backing up with a new phrase the
old phrase no longer opens anything (the gate checks this). Downloads are
`GET /v1/backup/{fingerprint}?token=…`; a wrong phrase gives a wrong token, the server answers
401 and the engine fails with `Error::Connection` (CLI exit 4) before touching the profile.
Restoring is one SQLite transaction; any error rolls it back.

JSON bundle v1 (`format: "sealbox-recovery-bundle"`, `version: 1`):

| Field | Contents |
|---|---|
| `account` | address, display name, IMAP/SMTP endpoints, auth kind, login; `credential` only with `include_credentials` |
| `identities` | the account's OpenPGP secret keys (armored, unprotected inside the encrypted bundle), primary first |
| `peers` | every Autocrypt peer state (contacts, their keys, prefer-encrypt, timestamps, gossip) |
| `keys` | imported and directory keys |
| `verified` | rows of any `*verif*` table (the G30 verified-contact marks), column by column; skipped on restore if the table is absent or shaped differently |
| `settings` | account and global settings: signature, auto-reply, spam settings (allow/block lists, thresholds, DNSBL), anything else stored as a setting |
| `filter_rules` | the account's filter rules |
| `spam_model_json` | the per-user Bayes spam model |

**Not in the backup:** mail (it stays on the mail server; the restored key decrypts it on the
next sync), the local message cache and attachments, sync state, the outbox, guest-link
secrets of links already sent, OAuth tokens, the auto-reply runtime state and its log, the
at-rest profile key, and (by default) the mail credential and `secret.*` settings.

On restore, peers and keys never overwrite newer state already on the device, global
settings are only filled in when unset, and the spam model is only restored into an empty one.

### Why credentials are not backed up by default

* The restore flow re-adds them anyway: on a new device you prove control of the mailbox again
  (app password or OAuth sign-in), which is also what the mail provider expects.
* With credentials in the bundle, someone who learns the 12 words (photo of the paper, shoulder
  surfing) gets the mailbox as well as the key. Without them, the phrase alone opens only the
  key and contacts; reading the mail still needs the mailbox.
* App passwords can be re-issued in a minute; OAuth refresh tokens are bound to a client and
  are rotated or revoked by providers on reuse, so a backed-up one is often dead anyway.

`--include-credentials` (`BackupOptions { include_credentials: true }`) exists for people who
want one-step restore and accept that trade-off. OAuth accounts restored that way still need a
fresh sign-in once the access token has expired.

## What the server learns

* The account key's fingerprint and public key (the slot name and the signature check) — the
  same public key that is in every mail you send.
* The size of the encrypted bundle and when it changes (compression happens before
  encryption, so the size tracks roughly how many contacts and settings you have).
* A SHA-256 hash of the token. Not the phrase, not the key, not your address (it is only in
  the AAD, which the server never sees), no plaintext. The gate greps the server database for
  mail bodies, the signature text, `PRIVATE KEY`, both phrases and the mail password.
* The client IP of uploads and downloads (rate limits).

The server cannot decrypt the bundle and cannot substitute one: the AAD binds address and
fingerprint, and AEAD rejects any modified byte (unit test flips header, nonce and ciphertext
bytes). It can delete or withhold a backup, and it can serve an *older* blob of the same slot
(rollback) as long as that old blob's token matched; keep the phrase and back up after
important changes.

## Phrase handling advice (copy for the app)

* Write the 12 words on paper, in order, and keep it where you keep important documents. Do
  not store them in your mail, cloud notes or a screenshot.
* Anyone with the words and your address can restore your keys from the server. Treat them
  like the key to your house.
* If you think someone saw them, create a new phrase and back up again: the old phrase stops
  working at once.
* Sealbox never asks for your phrase except in "Restore from recovery phrase" on a new device.

## Autocrypt Setup Message

`Engine::setup_message_export(email) -> SetupExport { setup_code, message_id }` creates a
36-digit code (`numeric9x4`, 9 blocks of 4 digits), encrypts the secret key with it
(SEIPDv1, iterated+salted S2K, `Passphrase-Begin` header), and mails it to yourself over the
account's SMTP: `Autocrypt-Setup-Message: v1`, From = To = you, a text part and an
`application/autocrypt-setup` attachment `autocrypt-setup-message.html` with the armored
message inside, the way Delta Chat writes it. The payload is read from the armor, so a bare `.asc` works too.
**Verified mechanically (day 2, gate G1 — `crates/sealbox-crypto/tests/interop_rnp_sq.rs`):** RNP 0.17,
the OpenPGP engine inside Thunderbird, opens our Setup Message with the setup code alone (and
refuses a wrong code), the payload is the account's secret key and RNP accepts it into its
keyring; the reverse — a passphrase message produced by RNP's symmetric encryption with the
same code, surrounded by text — opens in Sealbox. **Still unverified:** the import *through the
Thunderbird / Delta Chat UI* (header handling, attachment type, the code prompt) — that manual
step belongs with G12.

`Engine::setup_message_import(source, setup_code) -> AccountInfo` takes a local message id, a
Message-ID, or a file. For mail it requires the header, the attachment type and From = To. A
wrong code fails with "wrong setup code" and changes nothing. The key must have a User ID for
an account of this profile (the setup message carries only the key, so add the account first);
it becomes that account's primary key and the previous key stays as a secondary one, so mail
encrypted to either still opens. Messages that failed to decrypt are dropped from the local
cache and fetched again on the next sync, which then decrypts them.

## App flow (strings for the app builder)

Onboarding, first screen, secondary action: **"Restore from recovery phrase"**.

Restore screen:
* Title: "Restore your account"
* Fields: "Email address", "Recovery phrase (12 words)", then the normal mailbox sign-in
  (app password / OAuth). Validate the phrase as the user types with
  `Engine::recovery_phrase_validate` (word number N not in the list / checksum mismatch:
  "One of the words is wrong, or two words are swapped").
* Button: "Restore". Errors: 401 → "This recovery phrase does not match the backup for this
  address." No slot → "No backup found for this address on this server."
* Success: "Your keys and contacts are back. Fetching your mail…" then sync.

Show-once screen (Settings → Security → "Recovery phrase", and offered after onboarding):
* Title: "Your recovery phrase"
* Body: "Write these 12 words down on paper, in order. They are the only way to get your
  encrypted mail back if you lose this device. Sealbox does not keep a copy."
* The 12 words in a numbered 3×4 grid; screenshots blocked where the platform allows.
* Confirm step: "Type words 3, 7 and 11 to confirm you wrote them down."
* Then `backup_to_server` and: "Backup saved. Your keys, contacts and settings are encrypted
  with your phrase; the server cannot read them."

Reminder (from `Engine::backup_status`: `reminder` is non-null when there is no backup or the
last one is older than 30 days): banner "Back up your keys so you don't lose your encrypted
mail with this device." Action: "Back up now" (wording made platform-neutral on day 2, review item D1).

Move to another device without the server: Settings → Security → "Transfer to another
device" → `setup_message_export`, show the setup code large with "Open Sealbox, Delta Chat or
Thunderbird on the other device and enter this code when it asks."

## API summary

```rust
pub struct RecoveryPhrase { pub words: Vec<String>, pub checksum_ok: bool }
pub struct BackupReport { pub fingerprint: String, pub bytes: u64, pub server_url: String, pub created_at: i64 }
pub struct BackupStatus { pub email: String, pub last_backup: Option<BackupReport>, pub phrase_created_at: Option<i64>, pub reminder: Option<String> }
pub struct BackupOptions { pub include_credentials: bool }                     // default false
pub struct RestoreOptions { pub fingerprint: Option<String>, pub credentials: Option<AuthSpec>,
                            pub imap: Option<Endpoint>, pub smtp: Option<Endpoint>, pub login: Option<String> }
pub struct SetupExport { pub setup_code: String, pub message_id: String }

Engine::recovery_phrase_create(&self, email) -> Result<RecoveryPhrase>
Engine::recovery_phrase_validate(words: &str) -> Result<RecoveryPhrase>        // associated fn
Engine::backup_to_server(&self, email, server_url, phrase) -> Result<BackupReport>
Engine::backup_to_server_with(&self, email, server_url, phrase, &BackupOptions) -> Result<BackupReport>
Engine::backup_status(&self, email) -> Result<BackupStatus>
Engine::restore_from_server(&self, server_url, email, phrase) -> Result<AccountInfo>
Engine::restore_from_server_with(&self, server_url, email, phrase, &RestoreOptions) -> Result<AccountInfo>
Engine::set_account_credential(&self, email, &AuthSpec) -> Result<AccountInfo>
Engine::setup_message_export(&self, email) -> Result<SetupExport>
Engine::setup_message_import(&self, source, setup_code) -> Result<AccountInfo>
```

Local bookkeeping: two account settings, `recovery.last_backup` (the last `BackupReport`) and
`recovery.phrase_created_at` (a timestamp). Never the phrase or anything derived from it.
