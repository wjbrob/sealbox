# Spam detection and filtering (gate G25)

Crate `crates/sealbox-spam` (pure classifier + filter engine) · core integration
`crates/sealbox-core/src/spam.rs` and `filters.rs` · CLI `sealbox spam …` / `sealbox filter …`
(`crates/sealbox-cli/src/cmd_spam.rs`, `cmd_filter.rs`) · gate `scripts/gate_g25.sh`.

## Design

```
raw RFC 5322 bytes ─► features::extract ─► Features ─┬─► rules::evaluate ─► RuleHit*   (explainable, weighted)
                                                       ├─► BayesModel::log_odds        (per-user, hashed tokens)
                                                       └─► dnsbl::check (optional)  ─► RuleHit*
                                   Classifier::classify ─► Verdict { spam_probability, label, reasons }
```

* **Features** (`features.rs`): lower-cased word tokens of subject and body (plus subject and
  body bigrams), URL domains and TLDs, sender domain/TLD, display-name words, Reply-To domain,
  attachment extensions and content types, the first word of mailer/priority/content headers,
  and structural attributes (`A:html_only`, `A:hidden_text`, `A:tiny_font`, `A:caps_high`,
  `A:no_message_id`, `A:ip_url`, `A:replyto_mismatch`, `A:received:<bucket>`, `A:spf:<r>`, …).
  The HTML body is stripped to text with detection of hidden/zero-font text, comment
  obfuscation and image-only mails. The `Received` chain yields the **last external relay IP**
  (first public IP from the top). `Authentication-Results` (top-most header) is parsed into
  SPF/DKIM/DMARC results.
  *Never tokenised*: `Received`, `Return-Path`, `Delivered-To`, `To`/`Cc`, mailbox-state
  headers (`Status`, `X-Keywords`, …) and other filters' verdicts (`X-Spam-*`, `X-Razor*`,
  `X-Bogosity`, …) — a forged `X-Spam-Status: No` must not whitelist a message, and in the
  evaluation those headers would leak the label.
* **Rules** (`rules.rs`): hand-written checks, each with a stable code, a log-odds weight and
  a human-readable detail. Weights are in natural-log odds (+4 ≈ ×55 on the spam odds):

  | code | weight | fires when |
  |---|---|---|
  | `dangerous_attachment` | +4.0 | attachment extension in the executable list (`.exe .js .scr .vbs .iso .lnk .bat .cmd .hta .jar .ps1 .msi …`) |
  | `double_extension` | +1.5 | `invoice.pdf.exe`-style name |
  | `lookalike_sender` | +3.5 | sender domain imitates a contact's or own domain (confusable skeleton, 1 edit/transposition, `brand.tld.evil.example`, `secure-brand.example`) |
  | `lookalike_url` | +2.5 | a link host/domain imitates one of those |
  | `display_name_spoof` | +2.5 | display name shows an address / a contact that is not the sender |
  | `phish_language` | +2.5 (+0.5 with a login/verify link) | credential phrases ("verify your account", "unusual sign-in", …) **and** a link; +1.0 without a link (`phish_language_no_link`) |
  | `scam_language` | +1.5 / +2.5 (≥2 phrases) | lottery / advance-fee phrases |
  | `dmarc_fail` `dkim_fail` `spf_fail` | +2.0 / +1.5 / +1.0, +1.0 more for major domains | `Authentication-Results` says so |
  | `auth_missing_major` | +1.5 | From is gmail/outlook/paypal/… and nothing passed |
  | `reply_to_mismatch` | +0.6 (+0.8 if Reply-To is free webmail) | Reply-To domain ≠ From domain, no List-Id |
  | `raw_ip_url` / `raw_ip_from` | +1.5 / +2.0 | bare IP addresses |
  | `html_only` `hidden_text` `tiny_font` `comment_obfuscation` `image_only` | +0.3 / +1.5 / +1.0 / +1.5 / +1.0 | HTML tricks |
  | `missing_message_id` / `missing_date` | +1.0 / +0.5 | |
  | `empty_subject` / `link_only_body` | +0.5 / +1.5 (+1.0 when both) | |
  | `shouting` / `excessive_punctuation` | +0.5 / +0.5 | |
  | `known_sender` | **−2.0** | From is exactly a known contact and no authentication failed |
  | `dnsbl_zen_*` / `dnsbl_dbl_*` | +3.0 (SBL/CSS/XBL, DBL spam/phish/malware/botnet), +1.0 (PBL, abused legit) | DNSBL hits (opt-in) |

  "Contacts" are addresses the user has **sent to**, peers that announced an Autocrypt key, and
  imported/directory keys — not mere senders (otherwise repeat spammers would become "known").
* **Bayes** (`bayes.rs`): multinomial naive Bayes with Laplace smoothing (α = 1) over
  FNV‑1a‑64 hashed tokens; each message contributes its distinct tokens once (the boolean
  multinomial variant). Tokens never seen in either class are skipped. The class prior is not
  part of the model — the classifier supplies it. `learn` / `unlearn` are exact inverses, so a
  message re-labelled by the user is first unlearned from the old class.
  The model is one serde struct per profile (token counts), stored as JSON in `spam_model`.
* **Combination** (`classifier.rs`):
  `log-odds = logit(prior_spam) + clamp(bayes, ±12) · confidence + Σ rule weights`,
  `p = sigmoid(log-odds)`. `confidence = min(1, min(spam_learned, ham_learned) / 10)` so a model
  with a handful of examples cannot override the rules; the rules alone carry a fresh profile.
  With the default prior of 0.10 a message needs about +4.4 of evidence to reach the default
  spam threshold.

### Thresholds (per account, `SpamSettings`)

| field | default | meaning |
|---|---|---|
| `enabled` | `true` | classify new INBOX mail at all |
| `spam_threshold` | `0.90` | `p ≥` → label `spam`, moved to the junk folder, `\Seen` |
| `unsure_threshold` | `0.50` | `p ≥` → label `unsure` (shown, never moved) |
| `dnsbl_enabled` | `false` | Spamhaus ZEN/DBL lookups (privacy, see below) |
| `move_to_folder` | `"Spam"` | `"Spam"` means *the server's junk folder* (`\Junk` special-use → provider name → an existing `Spam` → create `Spam`); any other value is used verbatim (created when missing) |
| `allowlist` / `blocklist` | `[]` | addresses or domains (sub-domains match); allow forces `ham`, block forces `spam` |

### What the sync does

After each folder sync (`sync` and `watch`, INBOX only) `Engine::spam_after_sync` runs for the
newly stored messages: own mail (From = one of our accounts) is skipped; blocklist → spam,
allowlist → ham, a **good OpenPGP signature by a known contact** → ham; otherwise
rules (+ DNSBL when enabled) + Bayes. The verdict (`spam_score`, `spam_label`,
`spam_reasons_json`) is stored on the message row. `spam` → moved on the server to the junk
folder (IMAP `MOVE`, or `COPY`+`\Deleted`+`EXPUNGE`), flagged `\Seen`; the local row is pointed
at its new UID so the message stays visible under `list --folder Spam`, `explain` and `learn`.
**Nothing is ever deleted.** Non-spam messages then go through the user's filter rules.

### Filters (`filters.rs`)

`FilterRule { id, order, enabled, name, match: { field, op, value, case_insensitive }, action, stop }`
with `field ∈ from | to | cc | subject | list-id | header:NAME | body`,
`op ∈ contains | equals | regex | domain`, `action ∈ move:FOLDER | flag:NAME | read | star`
(`delete` is accepted and stored as `move:Trash` — a filter cannot destroy mail). Rules run in
`order`; flags / read / star accumulate, the **first** `move` wins, a matching rule with `stop`
ends the evaluation. Spam rules run first: user rules never see spam.

### Learning

`sealbox spam learn --spam|--ham ID` (`Engine::spam_learn`): unlearn the previous user label
if any, learn the new one, persist the model, mark the row (`spam_learned`), store the user's
label as the verdict (reason `user_feedback`), then move the message to the junk folder
(`--spam`) or back to INBOX (`--ham`). A later sync sees the moved copy under its new UID and
does not store it twice.

## Privacy

* Everything runs locally; the model never leaves the profile directory.
* **DNSBL is off by default.** When `dnsbl_enabled` is set, every new message causes DNS
  queries `<reversed-ip>.zen.spamhaus.org` (last external relay) and
  `<domain>.dbl.spamhaus.org` (link domains + sender domain, at most 5) — i.e. the configured
  DNS resolver, and Spamhaus, learn which IPs and domains appear in the user's incoming mail.
  Lookups time out after 2 s each / 5 s per message and never block a verdict. Spamhaus
  refuses queries from large public resolvers (returns `127.255.255.x`), which we treat as "no
  information". The CLI prints a reminder whenever the setting is on.
* Other filters' headers (`X-Spam-*`) are ignored, so a provider's verdict neither leaks in nor
  can be forged.

## Evaluation

Corpus: the SpamAssassin public corpus (`testing/corpus/fetch_corpus.sh`, cached under
`testing/corpus/.cache/`, gitignored): `20030228_easy_ham` (2500) + `20030228_easy_ham_2`
(1400) + `20030228_hard_ham` (250) = **4150 ham**; `20030228_spam` (500) + `20050311_spam_2`
(1396 after dropping one empty file) = **1896 spam**. Sizes are verified against the server's
`Content-Length` and a sanity floor, and each tarball is listed before extraction.

Protocol (`sealbox_spam::eval`): stratified split by a seeded splitmix64 shuffle of the sorted
file names (seed 42, 70 % train / 30 % held out); train the Bayes model on the training part;
score the held-out part with the **production pipeline** (rules + Bayes, default thresholds,
no DNSBL). A message counts as spam only when labelled `spam` (what would be moved).
Feature work was done with `--dev` (5-fold cross-validation **inside the training split**);
the held-out split was run twice in total, both after the feature set was frozen (the second
run only re-checked that a `lookalike_url` bug fix did not change the numbers — it did not).

| | precision | recall | F1 | accuracy | tp | fp | tn | fn |
|---|---|---|---|---|---|---|---|---|
| held-out (1245 ham / 569 spam) | **0.9892** | **0.9631** | 0.9760 | 0.9851 | 548 | 6 | 1239 | 21 |
| dev (5-fold in the 2905/1327 training split) | 0.9823 | 0.9601 | 0.9710 | 0.9820 | | | | |

G25 target: precision ≥ 0.98 and recall ≥ 0.85 — met. All six held-out false positives are
`hard_ham` HTML newsletters scored p≈1.0 by the Bayes model; in use they would be corrected by
one `learn --ham` (and the sender would usually be a contact, −2.0). Variants measured on the
dev split and rejected: class-balanced counts (precision 0.977), skipping hapax tokens
(recall 0.949), per-token clamping, top-N most informative tokens only (precision ≤ 0.979),
presence tokens for every header (precision 0.980). Caveat: the corpus is one person's 2002
mailboxes; the number says the pipeline works, not what any given user will see.

Re-run: `cargo run -q -p sealbox-cli -- spam eval --corpus testing/corpus/.cache/corpus`
(`--dev` for feature work, `--json` for the full `EvalReport`), or the example
`cargo run -p sealbox-spam --example eval -- --corpus DIR`.

## CLI

```
sealbox spam status [--account A]
sealbox spam learn --spam|--ham ID
sealbox spam explain ID
sealbox spam check FILE|- [--account A]              # classify raw bytes, store nothing
sealbox spam eval --corpus DIR [--seed N] [--train-fraction F] [--dev] [--min-precision P] [--min-recall R]
sealbox spam settings show|reset --account A
sealbox spam settings set --account A [--enabled B] [--spam-threshold X] [--unsure-threshold Y] [--dnsbl B] [--folder F]
sealbox spam allow|block ADDR --account A [--remove]
sealbox filter add --account A --field F --op OP --value V --action ACT [--case-sensitive] [--stop] [--name N] [--order K]
sealbox filter list|rm ID|enable ID [--off] --account A
sealbox filter test ID|--file FILE --account A        # dry run
```
`--json` prints the core structs (`SpamStatus`, `SpamLearnReport`, `SpamExplanation`,
`Verdict`, `EvalReport`, `SpamSettings`, `FilterRule`, `FilterTestReport`).

## Gate

`scripts/gate_g25.sh`: corpus (cached) → `cargo test -p sealbox-spam` and the core spam/filter
unit tests → `spam eval` must meet the thresholds (numbers printed) → GreenMail e2e
`cargo test -p sealbox-cli --test gate_g25 -- --ignored` (users u21–u25): ham stays in INBOX,
the obvious spam (lottery/phish wording, `prize-details.pdf.exe`, lookalike sender
`u22@sea1box.test`, lookalike link) is `\Seen` in u21's Spam folder on the server, `explain`
lists the reasons, `learn --ham` moves it back and updates the model without duplicating it
on the next sync, `learn --spam` moves it again, a `[newsletter]` rule moves the next matching
mail to `Newsletters`, a blocklisted domain is spam regardless of content, and disabling
detection stops the moves.

## Flutter settings UI (what it needs)

* Per account: `enabled` switch; `spam_threshold` slider 0.50–0.99 (default 0.90) and
  `unsure_threshold` slider 0.10–`spam_threshold` (default 0.50), validated
  `unsure ≤ spam`; `dnsbl_enabled` switch with the privacy sentence above; `move_to_folder`
  (text with folder picker, default "Spam", never INBOX); `allowlist` / `blocklist` as chip
  lists accepting an address or a bare domain (no spaces; lower-cased on save).
* Explain view for a message: label badge + probability gauge, the reasons list (code →
  human label, signed weight bar, detail text), the Bayes line (confidence %, strongest
  tokens), the feature summary (sender, reply-to, links, attachments, auth results, relay IP),
  and two buttons: "Not spam" / "Spam" (→ `spam_learn`), plus "what my filters would do".
* Filters screen: ordered list (drag to reorder = `order`), enable toggles, editor with field
  (incl. `header:` + name), op, value (regex validated live via `FilterRule::validate`), action
  with folder picker / flag name, `stop`, and a "test on this message" action.
