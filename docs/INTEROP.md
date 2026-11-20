# Interoperability — what is proven by machines, and the five-minute human check (G12)

Sealbox speaks standard OpenPGP (RFC 9580 profile, v4 keys by default), PGP/MIME (RFC 3156) with
protected headers, Autocrypt Level 1 and the Autocrypt Setup Message. "Interop is the product":
every claim below is either a gate that runs daily or an explicitly human step.

## Proven mechanically, every day

| Oracle | What it proves | Where |
|---|---|---|
| **GnuPG 2.x** (`/usr/bin/gpg`, isolated `GNUPGHOME`) | 9 cases both directions: Sealbox encrypt+sign → gpg decrypts and verifies; gpg encrypt+sign → Sealbox decrypts and verifies; Autocrypt header round-trip; integrity (MDC) required | gate **G1**, `crates/sealbox-crypto/tests/gate_g1.rs` |
| **RNP 0.17** — the OpenPGP engine inside **Thunderbird** (`/usr/bin/rnp`, isolated `--homedir`) | Sealbox → a Sealbox key read by RNP (the "my Sealbox key imported into Thunderbird" case): plaintext equal, `Good signature` attributed to the sender's key; RNP (RSA default key) → Sealbox: `Good` from RNP's fingerprint, unknown signer never `Good`; RNP opens our **Autocrypt Setup Message** with the setup code alone, refuses a wrong code, and accepts the recovered secret key into its keyring; Sealbox opens an RNP-made passphrase message with text around the armor | gate **G1**, `crates/sealbox-crypto/tests/interop_rnp_sq.rs` (added day 2) |
| **Sequoia `sq` 1.3** (`/usr/bin/sq`, file-based keys, `--home` isolated) | Sealbox → sq: `Authenticated signature made by <Alice>`, exactly one; sq refuses the message when a different signer cert is demanded; sq → Sealbox: `Good` from sq's cert; a flipped base64 character in the ciphertext → integrity failure, never partial plaintext | gate **G1**, same file |
| **OpenPGP.js 6** (headless Chromium) | the guest viewer decrypts guest envelopes produced by `sealbox-crypto` in the browser; the wasm build of the core round-trips with gpg | gates **G7**, **G28** |
| **PGP/MIME structure** | `multipart/encrypted` / `multipart/signed` per RFC 3156, protected `Subject` inside, outer `...` placeholder, Autocrypt + gossip headers | gate **G2** |
| **Autodiscover** | Mozilla ISPDB (Thunderbird's own database), autoconfig, SRV, MX | gate **G5** |

Host prerequisite for G1: `sudo apt-get install gnupg rnp sq`.

## What only a human can confirm (G12) — about five minutes with Thunderbird

Thunderbird has no command line for OpenPGP, so the UI import and the real-provider path stay
manual. Evidence goes into the pull request or issue that records the run (screenshots
welcome, no secrets).

1. **Keys into Thunderbird (one of two ways).**
   - *Setup Message (preferred, tests the Autocrypt path):* `sealbox recovery setup-export --account you@example.com`
     mails the Autocrypt Setup Message to yourself and prints the 36-digit code. In Thunderbird:
     Account Settings → End-To-End Encryption → *Add Key…* → *Import an existing OpenPGP Personal Key*,
     or open the message and choose *Import* (Thunderbird 102+ recognises `Autocrypt-Setup-Message`),
     type the code.
   - *Plain export:* `sealbox key export --address you@example.com --file me.pub.asc` gives the public
     key; the secret key for Thunderbird comes from the Setup Message only (Sealbox never writes an
     unprotected secret key to disk on purpose).
   Expected: Thunderbird lists the key with the fingerprint shown by `sealbox key show --address you@example.com`.
2. **Sealbox → Thunderbird.** From a second Sealbox account (or the same one, encrypt-to-self):
   `sealbox send --account other@example.com --to you@example.com --subject "interop $(date +%s)" --body "hello" --policy require`.
   Open it in Thunderbird. Expected: the padlock/"Encrypted" indicator, "Digitally signed" with a
   *good* signature once the sender's public key is imported (Thunderbird learns it from the
   Autocrypt header: *View → Message Security Info*), the **protected Subject** replaces the
   `...` placeholder, attachments open.
3. **Thunderbird → Sealbox.** Reply encrypted from Thunderbird (it will have the key from the
   Autocrypt header; otherwise import `me.pub.asc`). Then `sealbox sync` and `sealbox read <id>`.
   Expected: `was_encrypted: true`, `decrypted: true`, `signature: good` with Thunderbird's key
   fingerprint, subject readable.
4. **Proton (optional).** Send to a Proton address with `--policy require` after importing their
   public key (`sealbox key import --address them@proton.me --file their.asc`, downloadable from the
   Proton contact card). Proton decrypts OpenPGP natively. Expected: readable in the Proton web app;
   a reply from Proton decrypts in Sealbox.
5. Record in the report: Thunderbird version, the three results, anything unexpected. If a step
   fails, keep the raw message (`sealbox read <id> --raw > msg.eml`, secret-free) for triage.

## Known limits (honest list)

- **SEIPDv2 / AEAD (RFC 9580)** is produced only when every recipient key advertises it. Sealbox's
  default v4 keys do not advertise it on purpose: gpg 2.4 and RNP 0.17 (Thunderbird) cannot read
  SEIPDv2. Do not set `KeyGenOptions::advertise_seipd_v2` for keys that will meet those clients.
- **PQC hybrid (ML-KEM-768 + X25519)** stays off in the product build (G14 proves the code path)
  until gpg and Thunderbird interoperate.
- **Setup Message through the Thunderbird / Delta Chat UI** is unverified (the engine-level open
  with RNP is proven; the UI's header/attachment handling is the human step above).
- v6 keys (`KeyVersion::V6`) are not used by default; third-party support is still uneven.
