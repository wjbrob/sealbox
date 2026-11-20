# Sealbox architecture (v0.1, 2026-10-27)

## The problem in one sentence
People keep the mailbox they have (Gmail, Outlook/Hotmail, Yahoo, iCloud, company IMAP) and
cannot or will not change DNS/MX or migrate; Sealbox gives them end-to-end encryption *on top* of
that mailbox, from a phone or a desktop, with a setup that is "type your address, sign in, done".

## Decisions (made; do not re-litigate without a measured reason)
| Area | Decision | Why |
|---|---|---|
| UI | **Flutter** (`app/`), one codebase for iOS, Android, Linux, macOS, Windows | mobile + desktop from one tree; mature; good Rust FFI |
| Core | **Rust** workspace, exposed to Flutter via **flutter_rust_bridge v2**; CLI for desktop/e2e | memory-safe crypto + networking, cross-compiles to every target (Delta Chat proves this stack) |
| Wire format | **OpenPGP (RFC 9580 crypto-refresh profile: Ed25519/X25519, AES-256, SEIPDv2 when peer supports it; v4 fallback)**, PGP/MIME (RFC 3156), protected headers | interoperates today with Thunderbird, Proton, FlowCrypt, Mailvelope, Delta Chat, FairEmail, gpg — network effect without MX changes |
| Key discovery | **Autocrypt Level 1** headers (opportunistic, automatic) + **Sealbox key directory** (VKS-style, email-verified) + keys.openpgp.org + WKD lookups | zero-config for app↔app, verified lookup for first contact |
| Recipients without PGP | **Guest link**: client encrypts with OpenPGP symmetric (SKESK, Argon2 S2K) under a passphrase, uploads ciphertext to the server, recipient opens `web/guest/` which decrypts in-browser (OpenPGP.js); reply from the page encrypts to the sender's public key | server stores ciphertext only; recipient needs nothing installed |
| Transport | **IMAP** (`async-imap`) + **SMTP** (`lettre`), SASL PLAIN / LOGIN / **XOAUTH2**; IMAP IDLE for push on desktop; mobile push via a relay later | universal across providers; no MX / DNS touch |
| Setup | **Autodiscover**: built-in provider table → Mozilla ISPDB (`autoconfig.thunderbird.net`) → RFC 6186 SRV → guesses; **OAuth2 PKCE** for Google and Microsoft, app-passwords for Yahoo/iCloud/others | the "quick setup" promise |
| OpenPGP library | **rPGP (`pgp` crate)** | pure Rust, cross-compiles to iOS/Android, battle-tested in Delta Chat |
| Local store | **SQLite (`rusqlite`, bundled)**; per-device key from the platform keystore (via Flutter secure storage) encrypts secret keys at rest | ubiquitous, embeddable |
| Backend | **Rust axum** + SQLite (Postgres later); stateless HTTP/JSON; serves the static guest viewer | one binary, trivial deploy; the desktop and mobile clients speak the same API |
| Interop oracle | `gpg` CLI in tests (isolated `GNUPGHOME`), OpenPGP.js in the browser viewer | "it decrypts in a different implementation" is the proof that we are standards-compliant |

## Components
```
┌────────────────────── Flutter app (iOS / Android / desktop) ──────────────────────┐
│  onboarding · unified inbox · thread view (lock badges) · compose (per-recipient  │
│  encryption status: 🔒 key known · 🔗 guest link · ⚠️ plaintext w/ consent) · keys  │
└───────────────┬───────────────────────────────────────────────────────────────────┘
                │ flutter_rust_bridge
┌───────────────▼───────────── sealbox-core (Rust) ────────────────────────────────┐
│ accounts · store (SQLite) · sync loop (IMAP) · send pipeline · recipient policy   │
│   ├─ sealbox-crypto : rPGP keys, encrypt/sign/decrypt/verify, Autocrypt, guest   │
│   └─ sealbox-mail   : MIME build/parse, IMAP, SMTP, XOAUTH2, autodiscover, OAuth  │
└───────────────┬────────────────────────────────────────┬─────────────────────────┘
                │ IMAP/SMTP (TLS)                        │ HTTPS/JSON
        user's existing provider                 sealbox-server (axum)
        (Gmail, Outlook, Yahoo, IMAP…)           key directory · guest msgs · backups
                                                 serves web/guest/ (OpenPGP.js viewer)
```

## Send pipeline (per recipient)
1. Resolve recipient key: local Autocrypt peer state → Sealbox directory → keys.openpgp.org / WKD.
2. Policy: all recipients have keys ⇒ **PGP/MIME encrypt+sign** (subject protected, "..." outside).
   Some lack keys ⇒ per-message choice: **guest link** for those (default) or plaintext with an
   explicit warning (only if the user confirms). Never silently downgrade.
3. Always add our `Autocrypt:` header (so replies to us can be encrypted) and, in encrypted mail,
   `Autocrypt-Gossip` for the other recipients.
4. SMTP submit via the account's own server; append a copy to Sent (encrypted to self).

## Receive pipeline
IMAP fetch (UID-based, incremental) → parse MIME → if `multipart/encrypted` decrypt with the
account key(s) → verify signatures → import Autocrypt / gossip keys → store (body encrypted at
rest) → UI. Autocrypt Setup Messages are honoured for key transfer between the user's devices.

**Sync at scale** (2026-10-29, `docs/PERFORMANCE.md` phase 2, gate G33). Per folder the store keeps
two watermarks (`folders.last_uid`, `folders.floor_uid`): every server UID in `[floor, last]` is
stored. A folder's *first* sync fetches only its newest `EngineConfig::sync_window` (500) UIDs,
newest batch first, so recent mail is listable within seconds; later `sync` runs fetch new mail
above `last_uid` oldest first (the watermark never skips a message), then backfill up to
`backfill_per_sync` (1,000) older messages below the floor, newest first, until the floor reaches
UID 1; `Engine::backfill(email, max)` pulls older mail on demand, `watch` never backfills, a
UIDVALIDITY change clears both marks. Fetches go in batches of ≤ 200 messages and ≤ 8 MiB (sizes
from one `UID FETCH … (RFC822.SIZE)` first); the next batch's `UID FETCH` is issued before the
current batch is processed (`tokio::join!` on the one connection, processing yields between
messages), so the server prepares batch k+1 while batch k is parsed, decrypted and stored. Each
batch is stored together with its watermarks in one SQLite transaction, then reported to the
caller (`Engine::sync_with_progress` / `backfill_with_progress`: `SyncProgress { account, folder,
phase, fetched, stored, planned, total_known, local, more_to_backfill }`). async-imap ends a FETCH
or SEARCH response silently on EOF or a tagged NO, so a short answer is checked (`NOOP`, one
re-fetch) and an empty backfill search of a non-empty folder is an error, never "nothing older".
Threading looks ancestors up in `message_refs` (one row per referenced Message-ID, indexed) instead
of scanning the JSON columns; a sync context reloads the signer keys only when the store's
`keys_generation` moved (triggers raise it on every write to identities, accounts, keys or a peer's key,
by any sync, UI or process; a `last_seen` bump does not) — checked at the start of every pass and before
a decryption; the list reads each folder's newest rows through `messages_folder_order` and
returns a sealed 160-character `snippet` per message (text body, else the HTML reduced to text).
The sealed bodies and the raw MIME live in `message_blobs` (one row per message, `raw` last), so the hot `messages` row is metadata only and its `UPDATE`s (spam verdict, thread merge, flags) no longer rewrite them; attachments are still stored twice, inside `raw` and decoded (`docs/PERFORMANCE.md`, phase 3).

**Convergence with the server** (2026-11-17, gate G35). Until this landed the sync only ever
*added*: `FLAGS` were read inside the body fetch of new UIDs and nothing removed a local message
whose UID had vanished, so mail deleted elsewhere stayed for ever, mail read elsewhere stayed
bold, and an emptied Trash stayed full. `Engine::reconcile_selected` runs at the end of each
folder's sync and each `watch` catch-up (also reachable on its own as
`Engine::reconcile_folder(email, folder)` / `sealbox reconcile`), and reports
`FolderSync.removed` / `.flags_changed`.

Deletion is driven by `UID SEARCH`, not by the flags fetch, and that separation is the safety
argument. A `UID FETCH (FLAGS)` answering for none of the UIDs it was asked about is, from the
reply alone, indistinguishable from "all of them are gone" — and that is an ordinary state of
affairs (we hold UID 1; another client expunged it and appended UID 2 we have never fetched), so
it cannot be rejected as a protocol failure either. So *which UIDs exist* is answered by one
`UID SEARCH UID 1:*`, under the same empty-answer guard as the backfill search (empty for a
non-empty mailbox is an error, and nothing is deleted); *what the flags are* by `UID FETCH
(FLAGS)` over the survivors in 500-UID chunks, whose worst failure costs a missed flag update
rather than a message. `\Recent` is filtered on both sides: it is set for one session per
message, so comparing it would make every message look changed on every sync for ever. A sync
that backfills hands its own `UID 1:*` to the reconcile and adds no round trip; a UIDVALIDITY
change resets the folder instead of reconciling against UIDs from the old incarnation.

**Opening a profile: migrations and the schema version.** `Store::open` (`store.rs::migrate`) runs the whole schema and every migration step — the module schemas, `spam::migrate`, message refs, threads, folder floor, snippet, Content-ID, the key-generation triggers — inside ONE `BEGIN IMMEDIATE` transaction: the write lock comes first, so each step's check (a column list, a table) is read under it, and of two connections opening the same profile at the same moment (the app next to the CLI) the second waits (busy timeout 10 s) and finds the work done; switching a new file to WAL retries briefly for the same reason. The blob move to `message_blobs` follows in its own 500-message transactions and survives a second connection doing the same. `meta.schema_version` is a real number (`store::SCHEMA_VERSION`, 2 since `message_blobs`), checked first inside that transaction and raised only when it changes (a current open writes nothing): a profile whose version is higher than the build's was written by a newer Sealbox, and the open fails with `Error::ProfileNewer { profile, engine }` before anything is written or the key is checked — the CLI prints "profile newer than this build: … update Sealbox to open it (nothing was changed)" and exits 5 like a locked profile; the bridge passes the same message through. Builds from before the guard cannot check it: an app or CLI older than `message_blobs` still breaks on a migrated profile, so they must be updated together once.

## Search and drafts (local, 2026-10-29)
Message bodies are sealed at rest (G27) while subjects and addresses are not, so the search index
must not put body words on disk: `Engine::search` (`crates/sealbox-core/src/search.rs`) queries an
FTS5 table in an **in-memory database ATTACHed to the store connection** (`sbx_search`), built
lazily by the first search of a process from the decrypted bodies (HTML-only bodies tag-stripped,
32 KiB of text per message) and kept current inside `Store::insert_message`, by TEMP triggers on
every `DELETE` (account cascades and other modules' raw deletes included) and content `UPDATE`, and
by a rebuild after another connection committed (`PRAGMA data_version`); in-place moves need
nothing because the folder is joined at query time, and the ranking query sorts ids and bm25 scores
only, so no plaintext reaches a sorter or temp file. Measured with 10,000 synthetic messages
(~120 words each): **17 MiB of RAM per 10k messages** (~1.8 KB per message, ~2 bytes per byte of
indexed text), first search including the build 0.13 s (release; 2.0 s debug), warm queries
0.2–27 ms (release; ≤ 53 ms debug). The CLI pays the build on every invocation, the app once per
launch. A keyed blind index on disk was rejected: deterministic token hashes leak which messages
share words and how often, and prefixes and snippets would need yet more stored hashes or
plaintext; a persistent, encrypted index stays on the roadmap. Drafts (`drafts.rs`, table
`drafts`) seal `subject` and `body_text` exactly like message bodies (vault AAD
`drafts:<column>:<id>`, listed in `vault::WRAPPED` so migration, rewrap and the status count cover
them), keep recipients plaintext like messages, hold each attachment as a sealed blob or a file
reference (below), never reuse ids, and are sent through `send_with`; IMAP Drafts-folder sync is a
known gap. In the app, a file attached to a draft is kept as a stored blob (`FrbCore.keepDraftAttachment`
returns a `blob:<id>` handle; threat-model R16, mitigated); plain copies that earlier builds made under
`<profile>/draft-attachments/` keep working and are swept at start-up once no draft names them.

**Draft attachments (2026-10-29).** A draft attachment is a *stored blob* or a *file reference*
(`DraftAttachment.blob_id` / `.path`, exactly one). `Engine::put_draft_blob` keeps a copy of the
file in table `draft_blobs` with `data` sealed like `attachments.data` (AAD `draft_blobs:data:<id>`,
in `vault::WRAPPED`, so migration, rewrap and the status count cover it; name, type and size stay
plaintext like a message attachment's). `save_draft` accepts a blob only for drafts of the account
that stored it; `send_draft` unseals it from the store; `send_draft` and `delete_draft` delete the
draft's blobs (those no other draft references) in the draft's own transaction, and a failed send
keeps both. `sweep_draft_blobs` deletes blobs no draft references once they are ten minutes old (a
client that died between storing a blob and saving the draft). A file reference is read at send
time and nothing of it is copied. Sending is single-flight per draft: `Engine.draft_sends`, an
in-memory set, makes a second `send_draft` of a draft being sent fail at once with
`Error::DraftBeingSent` (per engine; two processes sharing a profile are not serialised). CLI:
`draft attach|detach`; `draft show` marks stored copies.

**Drafts on the server (2026-10-29, `drafts_imap.rs`).** Each draft has a uuid (table `draft_sync`,
with a local and a synced revision) and one copy in the account's Drafts role folder (created when
missing): PGP/MIME encrypted **and signed to the account's own key only** — the subject a protected
header, `...` outside, no recipients in any header, flagged `\Draft`, `X-Sealbox-Draft: <uuid>` and,
when it has file references, `X-Sealbox-Draft-Files: <n>`; inside, a JSON manifest with every field
and the stored blobs as MIME parts (file references stay on the device). `push_draft` (the CLI runs
it after every save) APPENDs the new copy and only then flags the old UIDs of that uuid `\Deleted`
and expunges them (`UID EXPUNGE` with UIDPLUS); deleting or sending a draft leaves a tombstone
(`draft_sync.draft_id` → NULL) whose copy `purge_deleted_drafts` removes (`send_draft` does at once).
`sync_drafts` (`draft sync`, and after every `sync_folder_role(Drafts)`) fetches the copies found
by a zero-length `HEADER X-Sealbox-Draft` search, opens those the own key decrypts *and* signed
(anything else is `unreadable`: never imported, never deleted), keeps the newest copy per uuid,
imports unknown ones, takes a server copy newer than the last sync unless the local draft also
changed and is newer, uploads local changes, and deletes a local draft whose copy vanished only if
it was not edited here since the last sync. Clocks decide conflicts (`updated_at`, seconds).
Tombstones (drafts deleted or sent here, or removed here because their copy vanished) are kept 90 days
(`draft_sync.deleted_at`), so a re-appearing copy is deleted again rather than imported (R17). A
Drafts role sync stores the copies as messages too, but marks them (`draft_copies`: the header in the
account's Drafts role folder) so no message list and no search shows them twice. **In the app**
(`FrbCore`): every save — the autosave and leaving compose — pushes the draft in the background
(`push_draft`, coalesced per draft, never awaited by the UI; a failure waits for the next Drafts
sync); deleting a draft runs a drafts sync in the background to remove its copy; opening or
pulling the Drafts list runs `syncDrafts` for every account (a line above the list says when a
server could not be reached); a draft brought in from another device is tagged "From another
device", with "N files on the other device" when that device kept file references, and compose
explains those files when the draft is opened (`SavedDraft.origin`, `remote_files`). Expected on real
providers (only GreenMail is tested): Gmail's role folder is `[Gmail]/Drafts` (SPECIAL-USE), which
shows the copy as a draft titled `...` with an encrypted body — editing it in Gmail makes a plain
draft without our header, which the sync ignores — and expunging there drops the draft (Gmail's IMAP
expunge settings decide whether it lands in Trash); Outlook / Microsoft 365 use `Drafts` with
UIDPLUS, and where a server refuses the `HEADER` search the sync falls back to reading every
message's headers in the folder (slow for a large Drafts folder).

## Server API (v1)
- `GET  /v1/health`
- `GET  /vks/v1/by-email/{email}` · `POST /vks/v1/upload` · `POST /vks/v1/request-verify` (VKS-compatible subset; verification by signed email challenge)
- `POST /v1/guest` (ciphertext + metadata, returns id) · `GET /v1/guest/{id}` · `POST /v1/guest/{id}/reply`
- `PUT/GET /v1/backup/{account_fingerprint}` (client-encrypted key backup; proves possession via signature)
- `GET /g/{id}` → the static viewer

## Crate dependency graph
`sealbox-crypto` ← `sealbox-mail` ← `sealbox-core` ← `sealbox-cli`, `app/` (FRB)
`sealbox-spam` (rules + Bayes + filter rules) ← `sealbox-core`.
`sealbox-server` depends on `sealbox-crypto` only (to verify uploads and challenge signatures).
`sealbox-relay` (push relay, G16; `docs/PUSH_RELAY.md`) depends on `sealbox-mail` only: a separate
process that holds one IMAP IDLE session per registered mailbox and sends **content-free** pushes
(registration id, event kind, folder, timestamp — never subject, sender, UID or count); it keeps
credentials in memory only and clients re-register after a restart.
`fuzz/` (own workspace, nightly + libFuzzer/ASan, gate G13) links `sealbox-mail` and `sealbox-crypto`
to fuzz the untrusted-input parsers (PGP/MIME, OpenPGP message, Autocrypt header, guest envelope,
autoconfig XML); never part of the product build.

## Roadmap pointers
PQC (G14, done 2026-10-28): hybrid ML-KEM-768 + X25519 per `draft-ietf-openpgp-pqc` via rPGP 0.21's
`pqc` feature — proven in `sealbox-crypto` (identity with a PQC encryption subkey, round-trip, the
draft's sample vectors) but **off in the product build** until gpg and Thunderbird interoperate.
Push for mobile: `sealbox-relay` (above) is the prototype; APNs/FCM delivery needs credentials
(`docs/PROVIDERS_CONFORMANCE.md`). Encrypted search index; KT witnesses/gossip; reproducible builds.
Multi-device is done (G15: Autocrypt Setup Message + client-encrypted backups, `docs/RECOVERY.md`).
