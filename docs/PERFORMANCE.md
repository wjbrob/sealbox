# Sealbox on a real-sized mailbox — performance (phase 1: measurement · phase 2: fixes + gate G33 · phase 3: blobs out of the hot row)

## Phase 3 (2026-10-29) — blobs out of the hot row (phase-1 proposal 5)
Every `messages` row used to carry its sealed `raw` MIME and sealed `text_body` / `html_body`, so each
`UPDATE` of a row — the spam verdict of every new message, thread merges, flags — rewrote the whole
record with its overflow pages, into the WAL and then the file (`secure_delete=ON` zero-fills the freed
pages too). They now live in `message_blobs`:

| What changed | Detail |
|---|---|
| `message_blobs (message_id INTEGER PRIMARY KEY → messages(id) ON DELETE CASCADE, text_body, html_body, raw)` | one row per message, `raw` last (reading the bodies stops before the raw MIME's overflow pages); `messages` keeps the metadata, the sealed 160-character `snippet` and `thread_id` |
| writers | `insert_in` writes the metadata row and the blob row in the same transaction (a batch is still one transaction) |
| readers | `get_message` / `message_detail` / `message_html` and `message_by_message_id` through a `LEFT JOIN`; `message_raw` (spam, filters, auto-reply, recovery re-verification, `read --raw`) by primary key; the list reads the bodies only for a row without a stored snippet (a correlated subquery inside the `CASE`); the in-memory search index joins `message_blobs`, and a TEMP trigger on it marks a row dirty when a body changes (a rewrap) |
| AAD unchanged | the envelopes keep `messages:<column>:<id>` (`vault::WrappedColumn.aad_table`), so a profile's blobs move byte for byte without the key: `Store::open` migrates before the vault is unlocked. `vault::WRAPPED` lists the three `message_blobs` columns, so the legacy-plaintext migration, `profile rewrap` and `profile_key_status()` cover them (`docs/SECRETS_AT_REST.md`) |
| `store::migrate_message_blobs` | on the first open of an older profile: 500 messages per transaction, copy then empty (the pages a batch frees are reused by the next batch's blobs), then `ALTER TABLE messages DROP COLUMN` × 3 in one `IMMEDIATE` transaction (bundled SQLite 3.54.1); resumes after an interruption; a second connection migrating at the same time (the app next to the CLI) succeeds too; afterwards one `PRAGMA table_info` per open |

Same corpus, seeder, server and command as phase 2 (`scripts/perf_sync.sh --release --user p01 --no-app`;
the perf GreenMail restarted and warmed by the script), one run each:
before = `release-20261029T150507Z` (master `9a12e32`, load 8.0 → 5.4, server probe 541–554 ms per
200-message FETCH), after = `release-20261029T152454Z` (this change, built before the migration's race
fix, which the sync never reaches; load 5.9 → 3.7, probe 423–437 ms);
bytes written = `/usr/bin/time` file-system outputs × 512. Raw logs (gitignored): those run directories and
`gate-20261029T153152Z` in `.gate/evidence/perf/2026-10-29/`, the migration and scan logs in its
`storage-phase3/`.

| Scenario (10k = 10,000 messages, 399 MB of MIME) | before | **after** |
|---|---|---|
| First sync of 1,000 (`sync --backfill`) | 2.00 s · **304 MB written** · DB 69.5 MB | **1.31 s · 160 MB written** · DB 69.3 MB |
| same, `SEALBOX_LOG=warn` | 1.43 s · 304 MB | 1.75 s · 160 MB |
| First window of 10k (`sync`: newest 500) | 3.69 s · 156 MB | **2.33 s · 83 MB** |
| First sync of 10k (`sync --backfill`) | 31.35 s · user 7.45 s, sys 1.93 s · **3.19 GB written** · DB 711.4 MB · RSS 82 MB | **29.20 s** · user 6.63 s, sys 1.35 s · **1.69 GB written** · DB 712.0 MB · RSS 83 MB |
| … of it after the last message (spam pass over 9,500 backfilled, LIST, logout) | 5.11 s | 4.22 s |
| Incremental, 0 new / 50 new (10k profile) | 0.25 s / 1.23 s (10.2 MB written) | 0.24 s / 1.30 s (6.5 MB written) |
| `list --limit 50`, median of 7 — empty / 1k / 10k | 0.012 / 0.017 / 0.019 s · 484 `pread64` at 10k | 0.029 / 0.025 / 0.012 s · 160 `pread64` at 10k |
| `messages` table at 10k (`dbstat`) | 461 MB (blobs in the row) | **6.2 MB** (`message_blobs` 456 MB, `attachments` 247 MB) |
| A metadata scan of every row: `instr(references_json, ?) OR instr(in_reply_to_json, ?)` over 10,050 rows (sqlite3 3.46.1, warm, median of 5) | 15 ms | **3–4 ms** (fresh profile: the G33 run's) · 6 ms on a migrated copy, 3–4 ms on that copy after `VACUUM` |
| G33 (`scripts/perf_sync.sh --gate`) | PASS (phase 2, 3 runs: full sync 28.95–32.61 s) | **PASS**: window 2.36 s, first batch 1.34 s, full sync 29.81 s / 81 MB (1.69 GB written), +50 1.27 s, list 0.018 s; server 432 ms per FETCH (`gate-20261029T153152Z`) |

**Reading it.** Bytes written halve: 3.19 → 1.69 GB for the 10k first sync (1k: 304 → 160 MB, first
window 156 → 83 MB); the profile is the same size (712 MB) because the same bytes are stored, only in
another table. 1.69 GB for 712 MB is 2.4×, close to the floor of WAL mode, which writes every page twice
(the WAL, then the checkpoint into the file: 1.42 GB here); the rest is indexes, the per-message `UPDATE`s
of the now small rows, and the attachments. The `messages` table shrinks 74× (461 → 6.2 MB), so anything
that walks rows without an index reads a few MB instead of the whole mailbox, and a `list` at 10k reads
160 pages instead of 484. Wall times moved within the noise of one run each on a shared machine whose
server state differed (the before run's GreenMail answered ~20 % slower: 541–554 vs 423–437 ms per FETCH,
and the 10k first sync waits for the server — 51 FETCHes ≈ 22 s of the 29 s); user + sys time of the 10k
sync 9.4 → 8.0 s, the tail after the last message 5.1 → 4.2 s.

**Migrating an existing profile** (a copy of the before run's 10k profile, the release CLI's first open;
the key is not needed and was not available): 10,050 messages moved in **2.06 / 3.05 s** (two runs at load 8 / 5;
user 0.37–0.47 s, sys 1.4–2.4 s), **2.83–2.85 GB written** once (the blobs go through the WAL into the file, and `secure_delete` zero-fills the
overflow pages they leave, also through the WAL), file 713 → 760 MB (about one batch of growth, 5,589
free pages), `messages` 461 → 29 MB — sparse pages: the rows shrank in place. A `VACUUM` afterwards
would give 713 MB and a 5.8 MB `messages` table (and the scan 6 → 3–4 ms) for 4.3 s and 1.43 GB more
writes; the open path does not run it (it needs exclusive access and a second copy of the file in temp
space, too much for a phone's first start; `profile rewrap` does VACUUM).

### Attachments stored once (proposal 5's second half) — not done, and why
At 10k the decoded attachments are 247 MB of the 712 MB (2,090 parts) and are also inside `raw`
(base64). Dropping `attachments.data` and decoding on demand from `raw` is only safe where `raw` holds
the parts in the clear and the decoding is the sync's own:
- **Encrypted mail** (PGP/MIME, inline PGP): `raw` is the outer ciphertext; the parts exist only in the
  decrypted payload, which is not stored (re-decrypting on every open would need the secret key each
  time). Their `attachments.data` must stay.
- **Plaintext and signed-only mail**: the parts are in `raw`, but which parts become attachments, in
  which order (`idx`), with which filename and Content-ID, is decided by the sync — `MessageKind::Plain`
  parses `raw`, `PgpMimeSigned` parses the signed part (`take_inner`), inline PGP has none, and
  `NewAttachment::from` cleans the Content-ID. A reader that decodes differently returns another part
  for the same `(message, idx)` — silently, and the app's `cid:` images load parts by index.

What it would take: one function used by both the sync and the reader (`raw` + kind → the attachment
list); a test that, over the whole perf corpus, the on-demand bytes equal the stored ones part by part;
`attachments.data` nullable (a table rebuild: it is `NOT NULL`) and empty for `was_encrypted = 0` rows,
with a migration; the G4/G8/G27 attachment checks re-run. Expected: −247 MB at 10k (−35 % of the
profile) and as many bytes not written at sync; an attachment open then parses the whole message.

### Not verified / caveats (phase 3)
- One release run before and one after (plus the gate run); no confidence intervals; the server's speed
  differed between them (see above), so only bytes, sizes, page counts and CPU time compare cleanly.
- Not measured: the debug build (the gates' binary), the app's cold start (`--no-app`: the app bundle's
  engine is built from `app/rust` separately and predates this change), Android/iOS.
- The migration was timed twice, on one profile (a copy); the scan timings use the system sqlite3 3.46.1,
  the engine bundles 3.54.1.
- A profile opened by this build cannot be written by an older one (its `INSERT` names `messages.raw`):
  the app and the CLI on one profile must be updated together.
- Two *first* opens of an older profile at the same moment can still fail in the migrations before this
  one (two `ALTER TABLE … ADD COLUMN`s: `duplicate column name: spam_score`, or `database is locked`),
  found while testing this one; the blob migration itself is safe against that race (tested).

---
## Phase 2 (2026-10-29, engine changes) — results
Phase 1 below measured; phase 2 implemented its proposal 1–4, 6, 8 and part of 7 (commits 268bdd8 threading
index, c1d8a67 window + backfill, 2ef9e8e progress, fd29c76 batches + overlap, 1c06bbd + 6fdb88d key reloads,
ff89f22 one transaction per batch, f911b9b snippet + list index) and added the gate **G33**
(`scripts/perf_sync.sh --gate`). Same corpus, seeder, server and commands as phase 1 (release:
`scripts/perf_sync.sh --release --user p01 --no-app`; debug: `scripts/perf_sync.sh --user p01 --no-app`);
"first sync" now means two things, because a folder's first `sync` stores only its newest window:
`sync` (what a user sees first) and `sync --backfill` (the whole mailbox, comparable with phase 1).

| Scenario (10k = 10,000 messages, 399 MB) | phase 1, release | **phase 2, release** | phase 1, debug | **phase 2, debug** |
|---|---|---|---|---|
| First sync of 1,000 (`sync --backfill`) | 3.32 / 5.03 s | **1.44 s** (warn log 1.36 s) · RSS 50 MB | 125.2 s | **26.1 s** · RSS 73 MB |
| First window of 10k (`sync`: the newest 500 stored) | — (nothing visible for 276–321 s) | **2.28 s**; the first 200 newest stored at **1.16–1.22 s** (gate) | — | **14.1 s** |
| First sync of 10k (`sync --backfill`) | 321.4 / 276.4 s · user 72 s, sys 133 s · RSS 28 MB | **29.0 s** · user 6.7 s, sys 1.8 s · RSS 83 MB | 1,981 s | **257.4 s** · user 251 s · RSS 109 MB |
| Incremental, 0 new (10k profile) | 0.24 / 0.25 s | **0.25 s** | 0.43 s | **0.42 s** |
| Incremental, 50 new (10k profile) | 3.22 / 2.60 s | **1.25 s** | 11.42 s | **2.31 s** |
| `list --limit 50`, 7 runs, median — empty / 1k / 10k | 0.028 / 0.039 / 0.123 s | **0.034 / 0.028 / 0.028 s** | 0.04 / 0.05 / 0.19 s | not run¹ / not run¹ / **0.045 s** |
| GreenMail's own time for the whole 10k mailbox in 200-message `UID FETCH`es (raw IMAP, same run) | 25.6 s | 22.0 s (0.43 s per command) | 29.9 s | 24.8 s (0.48 s per command) |

Runs: release `release-20261029T122122Z`, debug `debug-20261029T122756Z` (`.gate/evidence/perf/2026-10-29/`);
load 1.1–1.5 (release), 2.6–4.8 (debug). ¹ The debug run's 1k warn-log, list and DB-stats steps were skipped:
the script file was edited while that run read it (bash reads scripts incrementally); its 10k rows are intact.
Same disk footprint as before (10k profile 711 MB, was 708 MB; the sync still writes 3.2 GB to produce it — blobs
in the row, see next steps).

**Where the 29 s go now (release, 10k):** the sync waits for the server. The 51 batch boundaries take a median
0.40 s, the server's cost per command (sum 21.6 s; the raw-IMAP baseline for the same mailbox is 22.0 s); processing a
message costs a median 0.05 ms (text 0.03, multipart/alternative 0.05, HTML-only 0.13, attachment 0.26, PGP/MIME
0.53 ms) and no longer grows with the number of stored messages (0.0–0.1 ms from the first to the tenth
thousand; phase 1: 1.9 → 24.7 ms); it is hidden under the next FETCH. What remains Sealbox's own: 1.1 s before the
first message (open, `UID SEARCH`, the `RFC822.SIZE` FETCH, the first batch) and 4.9 s after the last one — mostly
the unchanged spam pass over the 9,500 backfilled messages (re-read, unseal, re-parse, `UPDATE` each row).
**Debug** (the gates' binary): 257 s = the server time hidden under processing, plus storing each batch
(sealing and SQLite unoptimised: the batch-boundary median is 1.83 s per 200 messages, longer than the
overlapped 0.47 s FETCH), ~10 % of messages costing ~41 ms whatever their kind (the p90; inferred, not profiled:
the share of mail from the 12 Autocrypt senders, whose header key is parsed for every message), and the spam pass
(91 s after the last message; 93 s in phase 1). The per-message `refresh_keys` (90 % of the phase-1 debug samples)
no longer runs (2 reloads over 63 messages in the unit test); phase 2 took no stack samples.

| What changed | Measured effect |
|---|---|
| `message_refs` + `messages(account_id, message_id)`: threading by index | per-insert cost flat (test: VM steps 1,032 → 35,574 over 2k inserts before, flat after); release per-message 1.9 → 24.7 ms growth gone |
| First sync = newest 500, newest batch first; backfill below `floor_uid` | newest mail visible after 1.2 s instead of after the whole mailbox |
| 200 messages / 8 MiB per `UID FETCH` (sizes first), next FETCH overlapped | ~200 → 55 server commands for 10k (51 body FETCHes + 2 sizes + 2 searches); processing hidden under the server's time |
| Keys reloaded only after a key change (store generation, triggers) | debug 1k first sync 125 → 26 s with all changes together (phase 1 put 90 % of it in `refresh_keys`) |
| One transaction per batch (marks included) | a batch and its watermarks commit together (was one commit per message, marks separately); the spam pass and peer updates still commit per statement |
| `messages_folder_order` + per-folder top-N merge; sealed `snippet` | `list` at 10k 0.12 → 0.03 s; HTML-only mail gets a text snippet |

**The server's cost is bimodal (found today; phase 1 did not see it).** GreenMail 2.1.3 answers a
200-message `UID FETCH` of the 10k mailbox in 0.41–0.48 s — or in 1.69–1.75 s, CPU-bound in its JVM (one
thread at 98 % on a P-core). After each of 4 JVM starts, the first folder fetched stayed slow and folders fetched
later were fast; in 7 more runs with a small warm-up folder fetched first, the 10k INBOX was fast every time.
Not explained by load, SELECT vs EXAMINE, the seeding pattern, the PGP share, expunge, JIT warm-up (40 commands
in a row: flat) or the core type; once, 30 `SELECT`+`LOGOUT` sessions also moved a fast mailbox to the slow state. Two release runs today hit it (`release-20261029T113203Z`, `…115544Z`: full 10k sync 99.7 /
98.5 s with the server at 1.73–1.75 s per command, raw baseline 89.6 / 89.0 s — still 3× faster than phase 1,
all of it server). So `perf_sync.sh` now restarts the perf server and fetches a throwaway 1,000-message `Warmup`
folder first (`--no-restart` keeps the old behaviour), probes the server before each measured 10k sync
(`server_probe.txt`), and counts with `STATUS` instead of `SELECT`.

### G33 — the gate (`scripts/perf_sync.sh --gate`, exit 0 = `G33 PASS`)
Release build (`target/perf-release`, ~2 min cold), restarted + warmed perf GreenMail, user p02, the 10k corpus
with its PGP share; artifacts ~220 KB in `.gate/evidence/perf/<date>/gate-<stamp>/` (logs at warn). If the
server probe shows its slow state (> 1,000 ms per 200-message FETCH) the server is restarted, at most twice, then
the gate fails naming the server. Restarting discards every perf mailbox: never run it next to another
`perf_sync.sh` or the `cli_sync_window` test. Without an OS keyring (cron) it measures a plaintext profile and says so.

| Check | Threshold | Measured (3 gate runs, 2026-10-29) |
|---|---|---|
| g1 `sync` on a fresh profile stores exactly the newest 500, phase `initial` | wall ≤ 4.5 s | 2.38 / 2.27 / 2.94 s |
| g1 first stored batch (first progress event) | ≤ 2.0 s | 1.22 / 1.17 / 1.16 s |
| g2 `sync --backfill` stores all 10,000, nothing left to backfill | wall ≤ 45 s | 29.15 / 28.95 / 32.61 s |
| g2 peak RSS | ≤ 120 MB | 81 / 81 / 81 MB |
| g3 +50 new on the g2 profile, exactly 50 stored | wall ≤ 2.0 s | 1.20 / 1.13 / 1.20 s |
| g4 `list --limit 50` on the g2 profile, median of 7, ≥ 50 rows | ≤ 0.08 s | 0.028 / 0.041 / 0.012 s |
| perf server probe | ≤ 1,000 ms (else restart) | 422 / 410 / 428 ms |

One gate run takes ~65 s after the build. The thresholds catch the phase-1 behaviours: O(n) threading (+175 s),
no window (first window = whole mailbox), 50-message batches (+60 s of server round trips), the unindexed list
(0.12 s), unbounded batch memory.

### For the app (not wired yet; `app/**` is the app builder's)
`Engine::sync_with_progress(email, |p: SyncProgress| …)` and `Engine::backfill_with_progress(email,
Option<usize>, …)` (plain `sync` / `backfill` without the callback) call back after every committed batch with
`SyncProgress { account, folder, phase: Initial | Incremental | Backfill, fetched, stored, planned, total_known,
local, more_to_backfill }` — the batch is listable when the callback runs. Suggested bridge: a `StreamSink<SyncProgress>`
per sync; refresh the list on the first event and then at most every ~2 s ("Syncing {local} of {total_known}");
start `backfill(email, None)` in the background after the first sync while `more_to_backfill`.
`SyncReport.folders[*]` gained `more_to_backfill` and `older_pending`; `MessageSummary.snippet` replaces the
per-conversation `getMessage` for list previews (phase 1: ~800 calls per inbox load). `EngineConfig` gained
`sync_window` (500, `SEALBOX_SYNC_WINDOW`), `backfill_per_sync` (1,000, `SEALBOX_SYNC_BACKFILL`), `fetch_batch`
(200), `fetch_batch_bytes` (8 MiB).

### Next steps (measured, not done)
- ~~**Blobs out of the hot row**~~ (proposal 5): done in phase 3 above (3.19 → 1.69 GB written for the 10k
  first sync); attachments are still stored twice — what that would take is in phase 3.
- **The spam pass** (4.9 s release / 91 s debug at 10k): writing the verdict at insert would change behaviour
  (it classifies after the folder pass with the contacts known by then; a sender's Autocrypt key arriving later in
  the same sync would not count), so it was left as is. Cheaper without that change: read the summary without
  unsealing the bodies, batch the verdict `UPDATE`s in one transaction.
- **Autocrypt header keys parsed per message** (debug p90 41 ms): cache the parsed key per keydata in the sync
  context (sync.rs) and in `identity_observe` (identity.rs).
- The `RFC822.SIZE` FETCH costs one server round trip per fetch step (0.4 s on GreenMail; cheap on real servers).

### Not verified / caveats (phase 2)
- GreenMail is not Gmail (no TLS, latency or throttling); the bimodal server cost above is GreenMail's.
- The app was not measured: its bundle predates these engine changes and does not use progress or snippets yet.
- One release run and one debug run in the warmed server state, plus 3 gate runs; two more release runs in the
  slow server state; no confidence intervals. Android/iOS not measured.
- Newest-first order: signatures are verified when a message is stored (as before), so a newer message whose
  signer's key is only announced by an older one (processed later in the backfill) stays "unknown key"; a key
  rotation in the past no longer raises a key-change alert during a first sync. Threads group the same; a
  conversation's `thread_id` value may differ (the first stored member names it).

---
# Phase 1 (measurement only, earlier the same day)

Measured 2026-10-29 by `scripts/perf_sync.sh` (no engine code changed). Question: what happens when
a real user connects a mailbox with 10,000 messages? Raw logs (gitignored, local):
`.gate/evidence/perf/2026-10-29/` — one directory per run (`env.txt`, `summary.txt`,
`results.tsv`, `*.time` = `/usr/bin/time -v`, `*.err` = the engine's debug events, `manifest.jsonl`,
`app/*/` frames, `samples/` stack samples), plus `whatif/` and `scratch/`.

## Summary
- **First sync of 10k messages takes 276–321 s (two release runs, 31–36 msg/s) and nothing is
  visible until it ends**: the engine fetches oldest-first, so the newest mail is stored last, and the
  app shows "Fetching mail…" until `syncAll` returns (after 90 s in the app: 4,211 messages stored,
  none shown). 1k messages: 3.3–5.0 s. Debug build (what the gates run): 1k = 125 s, 10k = 1,981 s.
- **The cost per message grows with the number of stored messages** (1.8–1.9 ms → 24.5–24.7 ms over
  the 10k sync, both release runs): every insert runs 2 × (ancestors + 1) threading queries that scan every row of the
  account, reading through the raw-MIME blob stored in the same row. That is 54–58 % of the 10k
  sync; with an index the same lookups take 0.003–0.005 ms instead of 8–17 ms (measured on a copy).
- **The rest is the server**: GreenMail answers a `UID FETCH` of 50 messages in ~14 ms on a 1k
  mailbox but ~490–530 ms on a 10k mailbox (34–38 % of the 10k sync). This is GreenMail's cost, not
  Sealbox's, and Gmail's will differ (latency, throttling) — see the raw-IMAP baseline below.
- MIME parsing, decryption, sealing, the spam pass and SQLite inserts are all small in release
  (≤ 1.4 % of stack samples each; spam pass 5 s of 321 s). In the **debug** build one thing
  dominates instead: `refresh_keys` re-parses and re-verifies (Ed25519) every known public key on
  almost every message — 90 % of samples.
- Incremental sync on the 10k profile: 0.24–0.25 s with nothing new, 2.6–3.2 s for 50 new messages.
  `sealbox list --limit 50`: ~0.01–0.03 s (empty) / 0.02–0.04 s (1k) / 0.12 s (10k): the list query
  cannot use an index and visits every row of the folder (125,020 page reads for 50 rows at 10k;
  100 ms of the query → 0.18 ms with an index).
- Desktop app cold start to the first frame showing the inbox list: 1.84–1.96 s (1k profile, 2 runs),
  2.29–2.74 s (10k profile, 6 runs, median 2.58 s); the window is mapped at ~0.3 s, the rest is the
  inbox load (500 summaries, then one `getMessage` per conversation, for Inbox and again for Sent).
- Disk: the 10k profile is 708 MB for 399 MB of mail (attachments are stored twice: inside `raw`
  and decoded), and the sync wrote 3.5 GB to produce it (`/usr/bin/time` file-system outputs).
  Peak RSS stays small: 28 MB (release), 53 MB (debug).

## Setup
| | |
|---|---|
| Machine | i5-13600K (20 threads), 94 GB RAM, WD SN850X NVMe, Debian 13 (kernel 6.12.113); **shared** with other builders' compiles and tests — the 1-min load average is logged per step (release 10k sync: median 4.9, range 2.8–9.5) |
| Builds | **release**: the product's `[profile.release]` (thin LTO, codegen-units=1) + line tables so stack samples have names (code identical, only debug sections differ), `CARGO_TARGET_DIR=target/perf-release`; **debug**: `cargo build -q -p sealbox-cli` exactly as the gates build it. Each run copies its binary first (another builder's build can replace `target/*/sealbox` mid-run). Commits: release run 1 at `d4d66d2` and the debug run at `9f588c9`, both with other builders' uncommitted work in `crates/` (listed in each `env.txt`); release run 2 at `2ad11f1` with a clean `crates/` |
| Server | `sealbox-mail-perf` — GreenMail 2.1.3 in docker, in-memory, loopback, plain IMAP 127.0.0.1:3243 (`testing/mail_perf_up.sh`, compose profile `perf`; the shared GreenMail is never touched) |
| Profile | keyring-backed (`ProfileKeySource::Keyring`, the desktop default), every value sealed (XChaCha20-Poly1305); account added with `--imap 127.0.0.1:3243:plain --smtp 127.0.0.1:3125:plain`; one template profile per run (account + key, never synced) copied for every scenario |
| Corpus | `testing/seed_mailbox.py`, seed `2026`, deterministic: 20 % with a 30–200 KB attachment, 10 % HTML-only (5–40 KB), 30 % multipart/alternative, 39 % text/plain, ~0.9 % PGP/MIME encrypted + signed by gpg to the profile's key (88 of 10k; a quarter with an inner attachment; all decrypt), 30 % replies (In-Reply-To + References), 400 Zipf-distributed senders on reserved domains, 12 of them Autocrypt/PGP users, Gmail-like headers, dates over two years in UID order. 10k messages = 399 MB of MIME (mean 39 KiB, median 5 KiB). Seeding: ~500–800 msg/s over IMAP APPEND. Spam classifier result on it: 9,849 ham, 151 unsure, 0 spam (so no sync moved anything on the server) |

Commands (each run is one invocation; the debug run skips the app, which only exists as a release bundle):
```
scripts/perf_sync.sh --release --user p01 --samples 200 --sample-interval 4   # release-20261029T085709Z
scripts/perf_sync.sh --user p02 --no-app                                      # debug-20261029T092009Z
scripts/perf_sync.sh --release --user p01 --app-runs 3 --app-first-sync 90    # release-20261029T100111Z
scripts/perf_sync.sh --user p03 --small 300 --large 1500 --new 10 --no-app --list-runs 3 \
    --samples 60 --sample-interval 3                                          # debug-20261029T101736Z
python3 -I .gate/evidence/perf/2026-10-29/whatif/whatif.py <copy of the 10k profile's sealbox.db>
```

## Results
Release run 1 = `release-20261029T085709Z` (load 2.8–9.5 during the 10k sync), release run 2 =
`release-20261029T100111Z` (load 3.6 → 1.5), debug = `debug-20261029T092009Z` (load ~1.4–1.9).

| Scenario | release run 1 | release run 2 | debug (gates' build) |
|---|---|---|---|
| First sync, 1,000 messages | **3.32 s** · 301 msg/s · RSS 27 MB · DB 69 MB | 5.03 s (load 8.1) | **125.2 s** · 8.0 msg/s · RSS 52 MB |
| same, `SEALBOX_LOG=warn` (overhead check of the debug events) | 3.54 s | 3.72 s | 124.4 s |
| First sync, 10,000 messages (fresh profile, after seeding +9k) | **321.4 s** · 31.1 msg/s · user 72 s, sys 133 s · RSS 28 MB · DB 708 MB | **276.4 s** · 36.2 msg/s · user 69 s, sys 110 s · RSS 29 MB | **1,981.3 s** · 5.0 msg/s · user 1,701 s, sys 161 s · RSS 53 MB |
| Incremental, 0 new (10k profile) | **0.24 s** · RSS 18 MB | 0.25 s | 0.43 s |
| Incremental, 50 new (10k profile) | **3.22 s** · RSS 22 MB | 2.60 s | 11.42 s |
| `sealbox list --limit 50`, 7 runs, median — empty / 1k / 10k | 0.01 / 0.02 / **0.12 s** (10 ms resolution) | 0.028 / 0.039 / **0.123 s** (µs timer) | 0.04 / 0.05 / 0.19 s |
| one `list` call at 10k under `strace -c` | — | 125,020 `pread64` (the DB has 173k pages) | 125,020 `pread64` |
| App cold start → first frame showing the inbox list (release bundle of 07:30, Xvfb) | 1k: 1.96 s · 10k: 2.29 / 2.50 / 2.74 s | 1k: 1.84 s · 10k: 2.57 / 2.58 / 2.64 s | — |
| App on a fresh profile while it first-syncs the 10k mailbox (90 s of frames) | — | the inbox reads "Fetching mail…" for all 90 s; the engine had stored 4,211 messages by then | — |

The inbox frame is the first captured frame (every ~75 ms) whose list pane is no longer the empty
pane with the loading spinner (grey-level std-dev of the pane > 0.08: spinner frames ≤ 0.03, list
frames 0.13–0.15). Kept frames (`app/*/f*.png`): the spinner frame before it, the inbox frame, the
last frame, and one every 15 s for the first-sync capture (`app/d2_first_sync_in_app/`). Raw IMAP
server time for the whole 10,050-message mailbox (run 2 / debug run): batch 50 = 98.5 / 104.9 s,
200 = 25.6 / 29.9 s, 1,000 = 6.5 / 10.0 s.

## Where the time goes (release, 10k first sync)
**Timeline from the engine's own debug events** (`autocrypt peer state updated uid=N`, one per
processed message, joined with the seeder's manifest) for run 1 — run 2 in brackets: 0.74 s [0.72]
to the first message, 315.6 s [270.6] fetching and processing, 5.1 s [5.0] after the last message
(spam pass over all 10k, LIST, logout).
- The 192 messages that start a 50-UID `UID FETCH` batch wait a median **529 ms** [491] (sum 110.5 s
  [94.8]) — on
  the 1k mailbox the same wait is 14 ms. The raw-IMAP baseline (same commands, no Sealbox) puts
  that cost in GreenMail: on the same 10,050-message mailbox, a 50-UID `UID FETCH (UID FLAGS BODY.PEEK[])` from a
  bare socket client takes a median **518 ms** (201 commands, 104.9 s for the whole mailbox; batches of
  200: 51 commands, 29.9 s; of 1,000: 11 commands, 10.0 s; `UID SEARCH UID 1:*` 48 ms; a flags-only
  `UID FETCH 1:*` 679 ms). GreenMail charges ~0.5 s per command at this size, almost independent of
  how many messages it returns (`debug-…/e_server_baseline.txt`; the client pauses 0.1 s between
  commands, untimed, because back-to-back commands hit a ~40 ms delayed-ACK stall the engine never sees).
- The other messages cost a median 16.0 ms [14.8] (sum 194 s [166]), and the cost **grows with the number of
  messages already stored**: median 1.9 ms (0–1k stored), 4.7, 7.5, 9.3, 12.5, 19.4, 18.9, 19.7,
  22.3, **24.7 ms (9–10k)**. Same messages, same kinds: on the 1k sync they cost 1.8–2.4 ms
  (text 1.81, alternative 1.82, HTML-only 2.06, PGP 2.15, attachment 2.39 ms) — decryption adds
  ~0.3 ms, a 160 KB attachment ~0.6 ms.

**Stack samples** (71 gdb samples ~5 s apart over a whole 10k first sync, classified by the
deepest pipeline stage on the sync thread, `samples/stages.txt`): `threads_referencing` 42.3 %,
waiting on the server (process idle) 38.0 %, `threads_of_message` 15.5 %, everything else 4.2 %
(peer state, `refresh_keys`, open: one sample each). 59 % of samples are inside SQLite, 14 %
reading overflow pages. No sample landed in MIME parsing, decryption, sealing or the spam pass.

**Why the threading queries are slow** (`store.rs::thread_id_for`, run inside every
`insert_message`): for the message's own Message-ID and each ancestor it runs
`threads_of_message` and `threads_referencing`.
- `threads_referencing` is `instr(references_json, ?) OR instr(in_reply_to_json, ?)` — no index can
  serve it, so it visits every row of the account; the JSON columns sit after `text_body` /
  `html_body`, so rows with large bodies are read through their overflow pages.
- `threads_of_message` could use `messages_mid`, but without `ANALYZE` statistics the planner picks
  `messages_thread (account_id=?)` and also visits every row.
- Measured on a copy of the 10k DB (`whatif/whatif_run1.txt`, SQLite 3.46.1, per call):

| Query | as the engine runs it | alternative (built in the copy) | |
|---|---|---|---|
| `threads_referencing` | 17.1 ms | 0.003 ms — `message_refs(account_id, ref, msg_id)` + index | 5,700× |
| `threads_of_message` | 8.3 ms | 0.005 ms — index `(account_id, message_id)` + `ANALYZE` | 1,650× |
| `threads_referencing`, rows without the blobs (still a scan) | 17.1 ms | 1.5 ms | 12× |
| list query, INBOX, LIMIT 50 (CLI) | 100.4 ms | 0.18 ms — index on `(COALESCE(date, received_at) DESC, id DESC)` | 560× |
| list query, all folders, LIMIT 500 (the app's inbox load) | 135.6 ms | 4.2 ms | 32× |

With 1.42 lookup pairs per message in this corpus (14,293 for 10,050), 25.4 ms per pair at 10k rows predicts
≈ 180 s for the growth term over a 10k sync — the measured growth (194 s − 10k × 1.9 ms) is 175 s.

**System time**: the 10k sync spent 133 s in the kernel against 72 s in user space; a release sync
of 1,500 messages under `strace -c` made **4,104,747 `pread64`** calls (~2,700 page reads per
message), 205,747 `pwrite64` and 232 `fsync` (`scratch/release_sync_1500_strace_c.txt`): SQLite
reads its pages through syscalls (default 2 MB page cache, no mmap) while scanning.

**Write amplification**: 3.5 GB written for a 708 MB DB (1k: 334 MB for 69 MB). Every message
row carries its raw MIME, so each `UPDATE` of the row — the spam verdict for every new message,
thread merges, later flag changes — rewrites the whole record including its overflow pages, into the
WAL and then the DB; `secure_delete=ON` also zero-fills the freed pages. Attachments are stored
twice (inside `raw` and decoded in `attachments`: 247 MB of the 708 MB).

**Debug build** (the gates' binary; release optimisations change the picture completely): the
same 1k sync takes 125 s, ~119 ms per message (73 → 134 ms over the run); the 10k sync 1,981 s —
172 ms per message (120 → 205 ms by position), first-of-batch 692 ms (the server's ~520 ms plus one
message), and 93 s after the last message for the spam pass (5 s in release). 60 gdb samples of a
1,500-message debug sync (`debug-20261029T101736Z/samples/stages.txt`): **90.0 % in
`refresh_keys → known_signers`** (re-parsing every stored public key and verifying its binding
signatures with unoptimised curve25519-dalek), 3.3 % identity bookkeeping, 3.3 % `insert_message`,
1.7 % threading, 1.7 % other; only 1.7 % inside SQLite. `refresh_keys` runs whenever
`update_peer_from_header` reports a change, and a bumped `last_seen` counts as one — i.e. for almost
every message from someone else.

**What the app does on start** (from `app/lib/src/core/{core_providers,frb_core}.dart`; only the
totals above are measured): the inbox provider calls `listThreadsInRole(inbox)` and then
`listThreadsInRole(sent)`; each loads 500 summaries over every folder (the 136 ms query) and then
calls `getMessage` once per conversation for its snippet. With ~400 conversations that is ~800 FFI
calls that unseal bodies before the first frame. During a first sync nothing refreshes the list
until `syncAll` returns. (Also visible in the frames: HTML-only messages show raw
`<!DOCTYPE html><html><head>…` as their snippet.)

## Phase 2 — proposal (for the lead; implemented the same day except item 5 — results at the top)
Ordered by measured payoff; 1, 5, 6 change `store.rs` (after the search/drafts builder leaves it).
1. **Index the threading lookups**: `message_refs(account_id, ref, message_id)` (filled at insert + migration,
   index on `(account_id, ref)`), index `messages(account_id, message_id)`, `PRAGMA optimize` after big syncs.
   Measured 25.4 → 0.008 ms per lookup pair at 10k. Expected: 1.9 ms per message flat → 10k processing
   166–194 → ~19 s, total here 276–321 → ~120–135 s, +50 incremental 2.6–3.2 → ~1.5 s, sys time mostly gone.
2. **Initial-sync window, newest first**: `folders.floor_uid` beside `last_uid`. First sync: the newest N = 500
   UIDs of `UID SEARCH`, newest batch first. Later syncs: new mail above `last_uid` first, then backfill ≤ 1,000
   UIDs (or ≤ 10 s) below `floor_uid` until the lowest UID (UIDVALIDITY reset clears both). Expected first
   useful screen on 10k: 10 FETCHes × 0.5 s + 500 × 1.9 ms ≈ 6 s here (today 276–321 s, newest last).
3. **Progress to the app**: an FRB stream `{account, folder, done, total, phase}` per committed batch; the app
   refreshes the list after the first window batch, then every ~2 s ("Syncing 1,200 of 10,000").
4. **Bigger, overlapped fetches**: FETCH_BATCH 50 → adaptive (≤ 200 messages, ≤ 8 MB); send the next
   `UID FETCH` before processing the current batch. Measured whole-mailbox server time here: batch 50 =
   98–105 s (201 × ~0.5 s), 200 = 26–30 s, 1,000 = 6.5–10 s. With 1, a sync ≈ max(server, processing).
5. **Blobs out of the hot row**: `raw` + sealed bodies in their own table, attachments stored once. Measured
   scan 17.1 → 1.5 ms; no whole-record rewrites on spam/flag `UPDATE`s (3.5 GB written for 708 MB today);
   −247 MB at 10k.
6. **List query + app N+1**: index on `(COALESCE(date, received_at) DESC, id DESC)` or a stored `sort_ts`
   (measured 100 → 0.18 ms for 50, 136 → 4.2 ms for 500); a `snippet` in `MessageSummary` removes ~800
   `getMessage` calls per inbox load. Expected cold start on 10k ≈ 0.5 s (today 2.5 s; not measured).
7. **One transaction per batch, spam verdict at insert** (today a second pass re-reads, unseals, re-parses and
   rewrites every new message: 5.1 s at 10k) — small now, re-measure after 1 and 5.
8. **`refresh_keys` only when a key changed** (not on a `last_seen` bump), parsed keys cached: ~1 % in
   release with 13 keys, but 90 % of a debug sync (the gates run the debug CLI).

## Not verified / caveats
- **GreenMail is not Gmail.** In-memory, loopback, plain IMAP (no TLS, no network latency, no throttling);
  its `UID FETCH` cost grows with the mailbox size (14 ms per 50 at 1k, ~530 ms at 10k), so the server
  share (34–38 %) is specific to it. No real provider was measured (G21 accounts needed); Sealbox's
  own share (threading, sealing, parsing) does not depend on the server.
- **Shared, noisy machine**: other builders compiled and ran tests during the runs (load average per
  step in `steps.txt` / `results.tsv`, 5 s log in `load_during_runs.log`). The release scenarios ran
  twice (10k first sync 321 / 276 s), the debug ones once, `list` 7× and the app 3× per run; no
  confidence intervals.
- **Builds**: release run 1 and the debug run include other builders' uncommitted work in `crates/`
  (each `env.txt` lists it; run 2 was built from a clean `2ad11f1`); the release CLI has line tables
  (same code as the product's release profile); the app bundle is the one built at 07:30 today.
- **Warm caches only**: the OS page cache was warm (dropping it needs root); a first launch after boot
  and cold flash on phones are not measured. Android and iOS were not measured at all.
- **Partly inferred**: the app's cold-start split (list query vs N+1 `getMessage`) comes from reading
  the Dart code, not from a measurement. The what-if timings use the system SQLite 3.46.1 on a copy;
  the engine bundles 3.54.1. The proposal's expected gains are extrapolated from those measurements,
  except where a number is marked measured.
- **Corpus is synthetic**: realistic shapes and sizes, random words and random attachment bytes; only
  INBOX (GreenMail has no Sent folder here); 0 spam verdicts, so no per-message spam MOVE was
  exercised; Autocrypt from 12 senders only (more PGP contacts make item 8 grow).
- **Instrumentation**: per-message timings come from one debug event per message (overhead checked:
  3.32 vs 3.54 s for 1k with and without it); stack samples pause the process ~1.2 s each (those runs
  are not timed); release run 1 and the debug run timed `list` with 10 ms resolution (µs since run 2).
