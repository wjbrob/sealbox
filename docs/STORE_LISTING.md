# Store listing — Sealbox (draft, 2026-10-27)

Copy for Google Play, the App Store and the Linux/desktop download page. One source of truth: the
onboarding hero (`app/lib/src/features/onboarding/onboarding_screen.dart`) and the README use the
same headline and the same three steps — change them together.

**Honesty rule for this file:** every feature bullet must be true of the build being submitted.
Lines marked *(pending Gxx)* must be deleted from the submitted text until that gate passes under
`scripts/gate.sh` (see `docs/GATES.md`).

## Name and short texts

| Field | Limit | Text |
|---|---|---|
| App name | Play 30 / App Store 30 | **Sealbox — Private Email** |
| App Store subtitle | 30 | Encrypted mail, same address |
| Play short description | 80 | Private email, without changing your email address. |
| App Store promotional text | 170 | End-to-end encrypted email for the Gmail, Outlook, iCloud or work account you already have. No new address, no DNS changes. |
| Keywords (App Store) | 100 | encrypted email,openpgp,pgp,private mail,secure email,gmail,outlook,autocrypt,e2ee |

## Headline and the three steps

**Private email, without changing your email address.**

1. Connect your existing email account.
2. Compose and send encrypted messages as usual.
3. Write securely to other Sealbox or OpenPGP users, or send a secure guest link to anyone who
   uses neither. The encryption status is always shown.

## Long description (Play: 4000 chars max; App Store: 4000)

> Private email, without changing your email address.
>
> Sealbox adds end-to-end encryption to the email account you already have — Gmail, Outlook and
> Hotmail, iCloud, Fastmail, or your company's IMAP server. Type your address, Sealbox finds the mail
> servers and signs you in the way your provider allows. Nothing about your address changes: no
> new domain, no DNS or MX records, nothing to tell your IT department.
>
> HOW IT WORKS
> 1. Connect your existing email account.
> 2. Compose and send encrypted messages as usual.
> 3. Write securely to other Sealbox or OpenPGP users, or send a secure guest link to anyone who
>    uses neither.
>
> ALWAYS CLEAR WHAT IS PROTECTED
> Every recipient shows its state before you press Send: encrypted (they have a key), guest link
> (they don't), or plaintext — which Sealbox only sends after you confirm it, with a warning.
> Received messages carry a badge: encrypted, signed, or not encrypted.
>
> STANDARD, INTEROPERABLE ENCRYPTION
> Sealbox speaks OpenPGP (RFC 9580) and Autocrypt, so it works with Thunderbird, Delta Chat,
> FairEmail, Proton and other OpenPGP mail apps. Your key is generated on your device. Subjects of
> encrypted messages are protected too: your provider only sees "…".
>
> GUEST LINKS FOR EVERYONE ELSE
> Recipients without encryption get an email with a link to a secure page that decrypts the
> message in their browser; the Sealbox server only ever stores ciphertext. You choose how the
> link is protected, per message:
> • Passphrase (default) — share the passphrase with them by another channel, such as a call.
> • Email code — they confirm their address with a one-time code before the message opens.
> • One-click — anyone with the link can read it; this protects against the server and the
>   network only, and the app says so.
>
> YOUR DEVICE, YOUR KEYS
> Sealbox opens behind an app lock (PIN, or fingerprint / face unlock where the device has it)
> and locks itself after the time you choose.
>
> Sealbox uses only standard, published cryptography.

Lines that depend on gates not yet passed — remove from the submitted text until they pass:

- "You choose how the link is protected … Email code / One-click" *(pending G29 passing under
  `scripts/gate.sh` — the engine, server, viewer and app implement all three modes since
  2026-10-27; an engine without a mode makes the app show it as "coming soon")*.
- Any sentence claiming account passwords, tokens or message bodies are **encrypted on the
  device** *(pending G27 — secrets at rest)*. The current text deliberately says only "app lock".
- "Sign in with Google / Microsoft" *(pending the OAuth client ids, `docs/PROVIDERS_CONFORMANCE.md`;
  and Google's sign-in branding review before the phrase may appear in a listing)*.

## Feature bullets (website / feature graphic / App Store "What's new")

- Keep your address — Gmail, Outlook/Hotmail, iCloud and any IMAP account.
- No DNS or MX changes; nothing to set up on the server side.
- End-to-end encrypted with OpenPGP, signed by default, interoperable via Autocrypt.
- Per-recipient status before you send; plaintext only after an explicit confirmation.
- Secure guest links for people without encryption (passphrase by default).
- Protected subject lines for encrypted mail.
- App lock with PIN and biometrics, auto-lock after a chosen time.
- Unified inbox across accounts, threads, attachments, signature and out-of-office reply.
- Mobile (Android, iOS) and desktop (Linux; macOS and Windows builds pending).

## Screenshots

Captured by the review loops (`scripts/review_android.sh`, `scripts/review_desktop.sh`) against
GreenMail test accounts, so no real personal data appears. Store sets must be re-captured from
the release build of the version submitted; these are the screens to use and the source frames.

Phone (Play: 1080×2400 portrait; App Store 6.7": 1290×2796 — re-capture at that size on a
macOS runner):

| # | Caption | Source frame |
|---|---|---|
| 1 | Private email, without changing your email address. | `review/android/2026-10-27/wave2/03-onboarding-email.png` (onboarding hero) |
| 2 | Your provider is detected — just sign in. | `review/android/2026-10-27/wave2/12-onboarding-detected.png` |
| 3 | One inbox, encryption shown on every message. | `review/android/2026-10-27/wave2/06-inbox.png` |
| 4 | Encrypted and verified, at a glance. | `review/android/2026-10-27/wave2/07-thread.png` (re-seed with encrypted mail for the store frame) |
| 5 | Every recipient shows how they'll receive it. | `review/android/2026-10-27/wave2/09-compose-filled.png` |
| 6 | Guest links for people without encryption. | not yet captured on Android — desktop `review/desktop/2026-10-27/wave2/39-narrow-compose.png` / golden `compose_guest_sent_phone_dark.png` until a smoke step adds a key-less recipient |
| 7 | Locked with your PIN or fingerprint. | `review/android/2026-10-27/wave2/02-lock-setup.png` / `90-device-dark.png` |

Desktop / tablet (Linux 1280×800; also used for the website):

| # | Caption | Source frame |
|---|---|---|
| 1 | Unified inbox | `review/desktop/2026-10-27/wave2/16-inbox.png` |
| 2 | Encrypted thread | `review/desktop/2026-10-27/wave2/18-thread-encrypted.png` |
| 3 | Compose with per-recipient status | `review/desktop/2026-10-27/wave2/21-compose-encrypted.png` |
| 4 | Guest link | `review/desktop/2026-10-27/wave2/23-compose-guest-link.png` |
| 5 | Dark theme | `review/desktop/2026-10-27/wave2/33-inbox-dark.png` |
| 6 | Settings: your key | `review/desktop/2026-10-27/wave2/27-settings.png` |

Rules for the store frames: light theme for the primary set (one dark frame at most); no
`sealbox.test` addresses visible in the submitted frames — re-seed with presentable sample names
(e.g. `alice@example.com`) on a dedicated capture profile; never show a real passphrase or key.

## Privacy / data-safety answers (summary; full text `docs/PRIVACY_POLICY.md`)

- Data collected by the developer: none. Mail goes between the device and the user's own provider.
- Data shared: guest-link ciphertext is uploaded to the Sealbox server so the recipient can fetch
  it; the server cannot decrypt it. Email-code mode additionally stores the recipient's address
  to send the code *(pending G29)*.
- Encryption in transit: yes (TLS to providers and to the Sealbox server).
- Account deletion: removing the account in Settings deletes its local data; no developer account
  exists.
- Export compliance: standard algorithms only (see `docs/RELEASE.md`).
