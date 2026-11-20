# Identity: key changes, verified contacts, key transparency (gate G30)

Code: `crates/sealbox-core/src/identity.rs` (client), `crates/sealbox-server/src/kt/`
and `routes/kt.rs` (server), `crates/sealbox-cli/src/cmd_identity.rs` (CLI).
Gate: `scripts/gate_g30.sh`.

Sealbox learns keys automatically (Autocrypt headers, gossip, the key directory). That is what
makes encryption work without setup, and it is also the weak spot. Whoever can put a key in
front of us for an address can read mail we send to that address. This module does three
things about that:

1. it **notices** when a correspondent's key changes,
2. it lets the user **verify** a key out of band, and
3. it makes the **directory auditable**: the server cannot quietly hand out a different key.

## 1. What a key change means

For every correspondent the profile remembers each key it has seen and where the key came from
(table `identity_keys`):

| source | vouches for continuity? | why |
|---|---|---|
| `autocrypt`: the sender's own Autocrypt header, once the Autocrypt peer state accepted it | yes | it came from the sender's own mail |
| `signature`: the key that made a good signature, when the signer is the sender | yes | proven by a signature |
| `import`: a key the user imported | yes | the user chose it |
| `verified`: a key the user verified | yes | the user checked it |
| `gossip`: Autocrypt-Gossip from a third party | **no** | anyone in Cc could plant it |
| `directory`: the key directory | **no** | the server could plant it (see section 3) |

A message raises an alert when its sender is already known and its Autocrypt key or signing key
is **not** among the sender's continuity keys. The first message from someone never raises an
alert, because there is nothing to compare it with yet (trust on first use). When a message
raises an alert:

* that message gets `SignatureSummary.key_changed = true`, and keeps it for good. It is a fact
  about how this message arrived.
* the contact gets `Contact.key_changed_at` (when) and `Contact.previous_fingerprint` (the key
  we trusted until then). These stay set until the user calls `Engine::acknowledge_key_change`
  (accept without checking) or `Engine::verify_contact` (accept after checking). Further
  messages with the new key do not raise new alerts, but the contact stays flagged until the
  user decides.

Usually a key change is harmless: the person reinstalled, switched apps or lost a device. It
is also exactly what an attacker who took over the address, or sits on the path, looks like.
The alert says so and offers to verify.

An Autocrypt header only counts once the Level 1 peer state has accepted it, so mail that
arrives out of order (an old message with an old key) does not flip anything. A key that was
seen before is never "new" again: going back to an older key raises no alert. Autocrypt itself
ignores such headers unless they are newer.

Profiles created before G30 have no history. Their first message after the upgrade is treated
as first contact.

## 2. Verification

* `Engine::fingerprint_qr_payload(email)` returns `OPENPGP4FPR:<40 hex>` (the OpenKeychain /
  Delta Chat convention) for one of our own keys. Show it as a QR code (`sealbox key qr`
  prints one in the terminal).
* `Engine::parse_fingerprint_qr(payload)` accepts that payload, case-insensitive, and ignores
  a `#a=…&n=…` suffix. It returns the upper-case fingerprint.
* `Engine::verify_contact(address, fingerprint)` takes hex (spaces and colons are allowed) or
  the QR payload. If the fingerprint is not the contact's **current** key (the one `send` would
  encrypt to), it fails with `Error::InvalidInput("fingerprint mismatch …")` and changes
  nothing. On success it sets `Contact.verified` / `verified_at` and clears a pending
  key-change alert.
* `Contact.verified` is true only while the verified fingerprint is still the current key. After
  a key change the contact shows as unverified (and flagged) until it is verified again.
* `SignatureSummary.signer_verified` is set on a message whose good signature was made by
  exactly the verified key of the sender.
* `Engine::unverify_contact(address)` removes the mark.

## 3. The key-transparency log

### Design

The server keeps an append-only Merkle tree (RFC 6962: SHA-256, leaf hash `H(0x00‖leaf)`, node
hash `H(0x01‖l‖r)`) over every change to the directory's published (address, key) pairs. Each
leaf is canonical JSON with alphabetical keys and no whitespace:

```json
{"action":"publish","email_hash":"<hex SHA-256 of the trimmed, lower-cased address>","fingerprint":"<UPPER-CASE HEX>","time":1793128100}
```

* **When.** `kt::record_directory_changes` compares the published pairs in `emails` with the
  state the log describes, and appends `unpublish` leaves, then `publish` leaves, for every
  difference. It is called by the VKS verify path (publishing an address on one key
  unpublishes it on all others) and by the upload path (addresses that vanish from a key). It
  also runs once at start-up, which backfills keys published before the log existed. The call
  is idempotent and self-healing: if an append fails, the next change or the next restart adds
  what is missing.
* **Tree heads.** Every append stores a signed tree head (`kt_heads`). The signed message is

  ```
  "sealbox-kt-sth-v1\n<tree_size>\n<root hex>\n<timestamp>\n"
  ```

  signed with Ed25519. The key is generated from the OS CSPRNG on first start and kept in the
  server database (`kt_signing_key`).
* **Storage.** SQLite tables `kt_leaves`, `kt_heads` and `kt_signing_key`, in the server's
  database.
* **Cost.** Proofs and roots are recomputed from all leaf hashes (O(n) per request). That is
  fine for tens of thousands of entries. A compact-range cache would be the next step.

### Endpoints

| | response |
|---|---|
| `GET /v1/kt/key` | `{"algorithm":"ed25519","public_key":"<64 hex>"}` |
| `GET /v1/kt/sth` | `{"tree_size":4,"root_hash":"<hex>","timestamp":1793128100,"signature":"<base64>"}` |
| `GET /v1/kt/proof/by-email/{email}[?tree_size=N]` | `{"tree_size":N,"leaf_index":3,"entry":{leaf},"leaf_hash":"<hex>","audit_path":["<hex>",…],"sth":{STH of size N}}`. The newest entry for the address within the first N leaves (default: the latest head); 404 if the address never appeared; 400 if N is larger than the log |
| `GET /v1/kt/consistency?from=M[&to=N]` | `{"from":M,"to":N,"proof":["<hex>",…]}` (RFC 6962 PROOF); 400 unless `0 ≤ M ≤ N ≤ size` |
| `GET /v1/kt/entries[?start=0&limit=100]` | `{"tree_size":…,"start":…,"entries":[{"index":0,"entry":{leaf},"leaf_hash":"<hex>"}]}`, limit ≤ 1000 |

### Client checks (`Engine::kt_audit(email)` → `KtAuditReport`)

```rust
pub struct KtAuditReport { log_size: u64, sth_verified: bool, own_key_included: bool,
                           consistency_ok: bool, alerts: Vec<String> }
```

1. **Pin.** The log key is pinned on first use, per server URL, in the profile table
   `kt_pins`. `KtAuditOptions.kt_key` (CLI `--kt-key`) uses a known key instead and stores it
   as the pin. If the server later presents a different key, the audit says so and keeps
   checking against the pin.
2. **`sth_verified`.** The tree head's signature verifies with the pinned key.
3. **`consistency_ok`.** The head extends the last head this profile accepted: same size means
   same root, a larger log needs an RFC 9162 §2.1.4.2 consistency proof, and a smaller log is a
   failure. On the first audit there is nothing to compare, so this is `true`. A head is
   remembered only when it verified and was consistent.
4. **`own_key_included`.** The newest log entry for the address publishes exactly the account's
   current fingerprint. Its leaf hash is recomputed locally (the server's `leaf_hash` is not
   trusted), and the RFC 9162 §2.1.3.2 inclusion proof is checked against the verified head.
   If the entry names another key, the alert starts with `SUBSTITUTION:`.

With `SEALBOX_KT_VERIFY_LOOKUPS=1`, a key fetched from the directory while sending is used only
if the same audit passes for that address and key. Otherwise the recipient is treated as having
no key.

The verifier (`sealbox_core::identity::kt`) shares no code with the server's tree
(`sealbox_server::kt::merkle`). Both are tested against the published certificate-transparency
vectors (roots for sizes 1–8, audit paths, consistency proofs), and against each other for
every size up to 33 or 40.

### What the server can and cannot do

**It cannot, without being caught by a client that audits:**
* hand out a different key for your address while its log says otherwise. Your audit checks
  that the newest entry is your key, and a lookup with `SEALBOX_KT_VERIFY_LOOKUPS=1` checks that
  the served key is the logged one.
* log a substituted key for your address. Your next audit reports `SUBSTITUTION: … published
  with key X, expected Y`.
* rewrite or drop past entries. Any client holding an older head sees a root mismatch (same
  size) or a failing consistency proof (larger size), and the gate demonstrates both.
* forge tree heads without the log key. The signature fails.

**It still can:**
* **Show different logs to different people (split view).** Each client only checks the view
  it is shown. Detecting this needs clients to compare heads with each other (gossip of STHs,
  or witnesses / cosigning). This is not built yet.
* **Lie to someone who never audits.** Sending to a directory key is only protected when the
  sender sets `SEALBOX_KT_VERIFY_LOOKUPS=1` *and* the key owner audits their own entry, because
  the owner is the only one who knows which key is really theirs.
* **Refuse service:** withhold proofs, or stop answering.
* **Learn who looks up whom,** as any directory can.
* **Expose which addresses are in the log.** Leaves carry an unsalted SHA-256 of the address,
  so anyone who guesses an address can confirm its presence and see its key history. Hiding
  this needs a VRF-based map (CONIKS / Key Transparency style). This is a known privacy gap.
* **Leak the signing key.** The key sits in the server database. Anyone holding a copy can sign
  heads, but still cannot make a fork consistent with heads that clients already hold.

Key-change alerts (sections 1 and 2) do not depend on the server at all. They work for every
key, including keys that never touched the directory.

## CLI

```
sealbox contacts                                   # ⚠ = key changed (unacknowledged), ✓ = verified
sealbox contacts ack ADDR                          # accept the new key
sealbox contacts verify ADDR --fingerprint FPR     # hex or OPENPGP4FPR:… ; mismatch → exit 2
sealbox contacts unverify ADDR
sealbox key qr --account A                         # payload + terminal QR code
sealbox kt audit --account A [--server URL] [--kt-key KEY]   # exit 6 if any check fails
sealbox kt entries [--server URL] [--start N] [--limit N]
sealbox list                                       # ⚠ also marks messages with key_changed
```
