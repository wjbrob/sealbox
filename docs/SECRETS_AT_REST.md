# Secrets at rest (gate G27)

Everything Sealbox keeps on a device lives in one SQLite file per profile,
`<profile>/sealbox.db` (0600 inside a 0700 directory). Since G27 the sensitive columns of that
file are encrypted with a key that never touches the disk in the clear. Code:
`crates/sealbox-core/src/vault.rs` (envelope, key sources, migration, rewrap) and
`crates/sealbox-core/src/store.rs` (wrap on write / unwrap on read). Gate: `scripts/gate_g27.sh`.

## What is wrapped

| Table.column | Contents | AAD row id |
|---|---|---|
| `identities.secret_armored` | the account's OpenPGP secret key | `id` |
| `accounts.credential` | IMAP/SMTP app password, or the OAuth credential JSON | `id` |
| `oauth_tokens.access_token`, `.refresh_token`, `.client_secret` | OAuth state used for refresh | `account_id` |
| `message_blobs.text_body`, `.html_body` | decrypted bodies (AAD table: `messages`, see below) | `message_id` |
| `message_blobs.raw` | the RFC 822 bytes as fetched (plaintext mail is readable here; AAD table: `messages`) | `message_id` |
| `messages.snippet` | the list preview: at most 160 characters of the body | `id` |
| `attachments.data` | attachment bytes | `id` |
| `drafts.subject`, `.body_text` | saved drafts | `id` |
| `draft_blobs.data` | files attached to saved drafts as stored copies (`draft attach`, the app) | `id` |
| `spam_model.model_json` | per-user Bayes token counts (derived from mail text) | `id` (=1) |
| `guest_links.secret` | passphrase of guest links we sent (G29) | `message_id` |
| `settings.value` where `key` starts with `secret.` | settings flagged secret | `scope/account/key` |

A feature module that adds a sensitive column wraps it through `store.vault()` (`seal_text`,
`seal_blob`, `open_text`, `open_blob`) and adds one `WrappedColumn` line to `vault::WRAPPED`,
which is what migration, rewrap and `profile_key_status()` iterate. A new secret setting just
uses a `secret.` key.

## Envelope and wire format

```
value  = "sbx1" ‖ nonce (24 bytes, random per write) ‖ XChaCha20-Poly1305(data_key, nonce, plaintext, AAD) ‖ tag (16)
AAD    = "<table>:<column>:<rowid>"            e.g. "messages:raw:42"
data_key = HKDF-SHA256(ikm = master, salt = none, info = "sealbox-profile-v1")
```

Wrapped values are stored as SQLite BLOBs. Legacy rows are TEXT (or BLOBs without the
`sbx1` prefix), so the two are distinguishable in SQL: `profile_key_status()` counts
`typeof(col)='blob' AND substr(col,1,4)=X'73627831'` as wrapped.

Because the AAD binds table, column and row, a ciphertext copied to another row or column
fails to open (`Error::SecretIntegrity`). Rows that carry a wrapped column get their id chosen
before the INSERT (`MAX(id)+1`, what SQLite would pick) so the AAD can carry it. `settings`
and `guest_links` have no INTEGER primary key, and their SQLite rowids can change on VACUUM, so
they use their real primary key instead. In a keyed profile an unwrapped value in a wrapped
column is refused, not trusted (so nobody can plant plaintext content).

**`message_blobs` keeps the `messages` AAD.** The bodies and the raw MIME moved out of the
`messages` row into `message_blobs` (one row per message, primary key `message_id` = `messages.id`,
`ON DELETE CASCADE`; `docs/PERFORMANCE.md`, phase 3). Their envelopes keep the AAD of the columns
they came from, `messages:text_body:<id>`, `messages:html_body:<id>`, `messages:raw:<id>`
(`WrappedColumn.aad_table`), so `store::migrate_message_blobs` moves an existing profile's
envelopes byte for byte when `Store::open` runs — before the key is known, which a reseal would
need — and then drops the old columns. The binding is unchanged: the row id is the message id, a
column's envelope does not open as another column's (`messages:snippet:<id>` included), and no other
table uses these labels. Migration, rewrap and `profile_key_status()` cover the new table through
`vault::WRAPPED`; a profile migrated from before G27 is moved first (plaintext) and then wrapped.

Key-check value: `profile_meta.kcv` is an envelope of a constant (AAD `profile_meta:kcv:1`).
Every open checks it before any row is read, and a missing or wrong key fails at once with
`Error::ProfileLocked` (CLI exit code 5). Nothing is read or written: the gate compares the
database bytes before and after a locked open.

## Key sources (`ProfileKeySource`, `EngineConfig.profile_key`)

| Source | Master key | Where | Platforms |
|---|---|---|---|
| `Keyring` (default) | random 32 bytes, created on first use | OS keyring: service `sealbox`, user `profile-<32 hex of SHA-256(abs profile dir)>` (stored base64) | Linux (Secret Service over pure-Rust zbus), macOS Keychain, Windows Credential Manager |
| `Passphrase(p)` | Argon2id(p, salt), m = 64 MiB, t = 3, p = 1, 32 bytes | salt: 16 random bytes in `<profile>/profile.salt` | all |
| `Raw(k)` | the 32 bytes the app hands in | the app's secure storage | Android / iOS (and the desktop app, if it uses app lock) |
| `None` | none: plaintext | only with `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1`; status reports it | all |

`profile_meta.kdf` records which source keyed the profile (`keyring` / `argon2id` / `raw`).
Opening a passphrase profile with `Keyring` uses `$SEALBOX_PROFILE_PASSPHRASE` if set, otherwise
it fails with a message to use `--profile-key passphrase`. Opening a raw-keyed profile with
anything other than `Raw` fails.

**The `keyring` crate is desktop-only** (a `cfg(any(linux, macos, windows))` dependency, pure
Rust: `async-secret-service` + `crypto-rust`, no libdbus or OpenSSL). rusqlite stays `bundled`
(no SQLCipher). On Android/iOS `Keyring` always counts as "unreachable". `scripts/gate_g27.sh`
step 2 checks that the Android and iOS dependency graphs contain no keyring crates, and
`cargo ndk -t arm64-v8a check -p sealbox-core` builds.

### Headless and CI (cron has no session bus)

Before talking to the Secret Service the engine checks for a session bus
(`DBUS_SESSION_BUS_ADDRESS` socket path, or `$XDG_RUNTIME_DIR/bus`). Each keyring call runs on
its own thread with a 20 s timeout, so a locked keyring waiting on a prompt nobody sees also
counts as unreachable. `SEALBOX_NO_KEYRING=1` forces "unreachable". When the keyring is
unreachable:

1. **A profile already keyed by the keyring stays locked (`ProfileLocked`).** It is never
   downgraded and never re-keyed.
2. A new or legacy (unkeyed) profile uses `$SEALBOX_PROFILE_PASSPHRASE` if set. The profile is
   then passphrase-keyed for good. One WARN is logged and `status.fallback` says why.
3. Otherwise plaintext, but only with `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1`. One WARN, and
   `status.source = "none"` with the reason in `fallback`.
4. Otherwise `ProfileLocked` with a message that names both options.

Scheduled (cron) runs need the user's session bus exported to reach the keyring. The test harness (`crates/sealbox-cli/tests/common`) always opens profiles with
`SEALBOX_PROFILE_KEY=passphrase` and a random per-profile passphrase, so the gates run on the
wrapped store and never write to the developer's keyring.

### CLI

```
sealbox --profile-key keyring|passphrase|none ...           # also $SEALBOX_PROFILE_KEY
sealbox --profile-passphrase-env VAR ...                    # passphrase from $VAR (implies passphrase)
sealbox profile status [--json]                             # source, kdf, wrapped_rows, plaintext_rows, fallback
SEALBOX_PROFILE_NEW_PASSPHRASE=... sealbox profile rewrap --to passphrase [--new-passphrase-env VAR]
sealbox profile rewrap --to keyring                         # new random key in the keyring (rotation)
SEALBOX_ALLOW_PLAINTEXT_PROFILE=1 sealbox profile rewrap --to none
```

The passphrase is read from `$SEALBOX_PROFILE_PASSPHRASE` by default. The variable name can be
changed with `$SEALBOX_PROFILE_PASSPHRASE_ENV` or `--profile-passphrase-env`.

## Migration (legacy plaintext profiles)

When a profile without `profile_meta.kcv` is opened with a key, `vault::install` runs one
`BEGIN IMMEDIATE` transaction. It writes `kcv`/`kdf`/`keyring_user` and re-encodes every non-NULL
value of every wrapped column (`recode_all`, row by row, so a large mailbox never sits in memory).
After the commit it scrubs the file: `PRAGMA wal_checkpoint(TRUNCATE); VACUUM;
wal_checkpoint(TRUNCATE)`. Every connection also runs with `PRAGMA secure_delete=ON`. Without the
scrub the old plaintext stays readable in free pages; the gate checks this: with the scrub
disabled, the legacy-migration test finds the body text in `sealbox.db`. If the transaction
fails, nothing changes. Once keyed, the profile cannot be opened unkeyed, even with the allow
flag.

## Rewrap (`Engine::rewrap_profile`, `sealbox profile rewrap`)

1. The new key is staged first: a new keyring entry `profile-<hash>-<unix time>`, or a new salt
   in `profile.salt.new`.
2. One IMMEDIATE transaction decodes every value with the old key, encodes it with the new key
   and replaces `profile_meta`.
3. After the commit, `profile.salt.new` is renamed over `profile.salt`, the old keyring entry is
   deleted and the file is scrubbed.

If step 2 fails, the staged key is removed and the old key keeps working. If the process dies
between the commit and the rename, the next passphrase open tries `profile.salt.new` and
finishes the rename. After a rewrap the old key fails with `ProfileLocked`.

## What stays plaintext, and why

| Kept in the clear | Why |
|---|---|
| addresses (`accounts.email`, `messages.from_addr`, `to_json`, `cc_json`, `peers`, `keys`) | account lookup, contacts, recipient policy and listing run as SQL (`WHERE email = ? COLLATE NOCASE`, joins) |
| subjects (`messages.subject`, `outbox.subject`, `guest_links.subject`) | the inbox list, threading and sorting read them on every list without unwrapping thousands of rows. **This includes decrypted protected subjects (RFC "protected headers").** |
| flags, dates, folder names, UIDs, sizes (`raw_size`, `attachments.size`), filenames, content types | sync state, ordering and the list UI |
| `spam_*` columns on messages, `filter_rules`, non-secret settings (signature, auto-reply) | per-message verdicts are needed by the list; settings are user configuration |
| public keys (`identities.public_armored`, `keys.armored`, Autocrypt `peers.state_json`) | public by definition |
| `message_id`, `in_reply_to_json`, `references_json` | threading and dedup lookups |

So someone with the file learns **who you correspond with, when, how much, and the subject
lines**, but not your secret key, your mail password or tokens, message bodies, raw messages,
attachments or guest passphrases. Wrapping subjects and addresses would need a blind index or
an encrypted search structure. That is a possible later step, not part of G27.

## Threat model

Protected (with a keyed profile):

* **Lost or stolen device, disk image, backup copy or synced folder of the profile.** Without
  the master key the file only shows the metadata above. A passphrase profile can be attacked
  offline at Argon2id(64 MiB, t=3) per guess, so passphrase strength matters. A keyring or raw
  profile has a random 256-bit master key.
* **Tampering with the file.** Swapped, moved, truncated or substituted ciphertexts fail to
  authenticate. Plaintext planted into a wrapped column is refused.
* **Another local user** (beyond the 0600/0700 permissions).

Not protected:

* **Malware running as the user while the profile is unlocked.** It can read the keyring entry
  (the Secret Service hands secrets to any process of the session once the collection is
  unlocked) and the process memory. App lock (below) narrows the window on mobile.
* **Metadata** listed above.
* **Rollback**: an attacker with write access can replace the whole file with an older copy
  of itself; AAD binds rows, not versions.
* **Row-id reuse**: after a row is deleted, SQLite can give its id to a new row. A saved
  ciphertext of the deleted row could then be replayed into the new row with the same id. This
  needs write access and only puts back data the user already had.
* Plaintext profiles (`None`), which are allowed only on explicit request and always reported.

## App integration (app lock)

The Flutter app keeps its own key and passes it in as `Raw`. Contract for the app builder:

1. On first run, generate 32 random bytes and store them with `flutter_secure_storage`
   (Android Keystore / iOS Keychain; desktop: libsecret / Keychain / DPAPI), behind the app's
   lock screen (PIN / biometrics).
2. After the lock screen succeeds, open the engine with the key:
   ```rust
   // app/rust/src/api/engine.rs (bridge)
   let cfg = sc::EngineConfig {
       profile_key: sc::ProfileKeySource::Raw(key),           // Vec<u8>, 32 bytes
       ..sc::EngineConfig::from_env()
   };
   let inner = sc::Engine::open_with(&profile_dir, cfg).map_err(err)?;
   ```
   `Error::ProfileLocked` means wrong or missing key: show the lock screen again, never retry
   with another source. `Error::InvalidInput` means the key is not 32 bytes.
3. Show `Engine::profile_key_status()` in Settings → Security: `source` (`raw` / `keyring` /
   `passphrase` / `none`), `plaintext_rows` (0 when healthy) and `fallback` (any downgrade or
   plaintext note).
4. An existing app profile created before G27 (plaintext) migrates on the first `Raw` open. A
   desktop profile that was already keyed by `Keyring` (opened with plain `Engine::open`) must be
   moved with `rewrap_profile(ProfileKeySource::Raw(key))` from an engine opened the old way.
   Opening it with `Raw` directly fails with `ProfileLocked` by design.
5. **Until the bridge passes `Raw`, Android/iOS cannot open a profile at all.** `Engine::open`
   defaults to `Keyring`, which does not exist on mobile, and there is no silent plaintext. The
   Linux desktop app keeps working through the Secret Service.
6. Dropping the engine on "Lock now" drops the data key: the store holds it in a `Zeroizing`
   buffer, and `EngineConfig` keeps no copy after `open_with`.

## Verification

`scripts/gate_g27.sh` (exit 0 only if everything passes):

1. The `sealbox-core` unit tests. Every engine unit test runs on a keyed store (the crate's
   test default is `Raw`). Vault/store tests cover:
   * round trip and wire format
   * AAD binding (swapped rows/columns fail)
   * tamper and wrong key
   * nonce uniqueness (2000 draws)
   * HKDF/Argon2id/KCV
   * headless keyring fallback (locked, passphrase, allow flag, never downgrade)
   * `None` needs the flag
   * legacy migration, wrong key, rewrap raw→passphrase→raw→none
   * every wrapped column is an envelope on disk
2. The Android and iOS dependency graphs contain no keyring crates.
3. `cargo test -p sealbox-cli --test gate_g27 -- --ignored`, against GreenMail u46–u50 and a
   local sealbox-server:
   * Passphrase profile, real plaintext + encrypted mail + attachment + guest link. Grep of
     `sealbox.db`/`-wal`/`-shm`/salt finds no body, attachment, guest passphrase, password,
     `PRIVATE KEY BLOCK` or profile passphrase. The subject is found, as a positive control.
   * Wrong passphrase: exit 5, nothing printed, database bytes unchanged. `none` and an
     unreachable keyring are locked as well.
   * Rewrap: the new passphrase works (read, sync with the wrapped credential, guest resend),
     the old one is locked.
   * A legacy plaintext profile holds its secrets in plaintext, then migrates on the first keyed
     open and is never opened unkeyed again.
4. G4 and G8 pass with the harness passphrase.

Optional: `SEALBOX_TEST_REAL_KEYRING=1` adds a real OS-keyring round trip (one entry written
and deleted). It passed on this box against gnome-keyring on 2026-10-27.
