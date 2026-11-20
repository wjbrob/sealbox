# Guest links: the three modes and what each one protects

A guest link lets you send an encrypted message to someone who does not use Sealbox and has
no OpenPGP key. Sealbox encrypts the message with a random secret on your device, uploads
only the ciphertext to the Sealbox server, and mails the recipient a link to the guest viewer.
The viewer decrypts in the recipient's browser. The secret is never sent to the server.

The question every mode answers differently is: **how does the secret get to the recipient?**

## Before G29 (the defect this fixes)

Every link carried the secret in its `#fragment`, while the notification mail said the
passphrase would be "shared separately". Anyone who could read the recipient's mailbox (a
compromised account, a mail provider, a shared computer, a forwarding rule) could open the
message. The text claimed a protection the mail did not give. Sealbox no longer does this.

## The modes

| | **Passphrase** (default) | **One-click** | **Email code** |
|---|---|---|---|
| What the mail contains | the bare link | the link with the secret in its fragment | the link with the secret in its fragment |
| What else the recipient needs | the passphrase, from you, another way | nothing | a 6-digit code the server mails to the recipient address |
| Server sees plaintext or the secret? | no | no | no |
| Someone on the network sees them? | no (HTTPS; the fragment is never sent) | no | no |
| Someone who reads the recipient's mailbox can open it? | **no**, unless they also get the passphrase | **yes** | **yes**: the code goes to the same mailbox |
| A forwarded or leaked link opens it? | no | **yes** | no: whoever holds the link also needs a code sent to the recipient's mailbox |
| The Sealbox server alone can open it? | no | no | no |

### Passphrase (default)

The mail contains only the link. The text says the passphrase is not in it and that you will
give it another way: in person, by phone, by text message or chat. Sealbox shows you the
passphrase after sending (`sealbox send` prints it; the app shows it with a copy button).

*Protects against:* the server, the network, and anyone who reads the recipient's mailbox or
gets hold of the link.
*Does not protect against:* anyone who gets both the link and the passphrase, for example if
you send the passphrase by e-mail to the same mailbox. Choose a different channel.

### One-click

The secret is part of the link (after `#`). Browsers never send that part to a server, so the
Sealbox server and the network still cannot read the message. The mail says plainly that anyone
who has the link can read the message and asks the recipient not to forward it. The viewer
removes the secret from the address bar once it has read it.

*Protects against:* the server and the network.
*Does not protect against:* anyone who can read the recipient's mailbox, anyone the mail is
forwarded to, or anyone who sees the link. Use it when convenience matters more than that.

### Email code

The secret is in the link, as in one-click. In addition the server keeps the ciphertext
locked: it releases it only after someone enters a one-time code that the server mails to the
recipient's address. The viewer asks the reader for their address, the server mails a code
only if that is the address the message was sent to (the answer looks the same either way),
and the reader types the code.

*Protects against:* the server, the network, and a link that leaks or is forwarded (a
screenshot, a shared document, a forwarding rule to another mailbox, a link-preview service).
*Does not protect against:* anyone who can read the recipient's mailbox, because the code
arrives there too. The notification mail says this.

Email code needs one recipient per message; with several recipients send one message each or
say which address receives the code (`--guest-recipient` / `guest_recipient_hint`).

## Server details (email code)

* The server stores a salted SHA-256 of the recipient address (salt: the message id), never
  the address. Addresses are guessable, so this keeps them out of database dumps and backups,
  not out of reach of someone who has the database and a list of candidate addresses.
* Codes are 6 random digits, valid 10 minutes, usable once, stored as a hash, and compared in
  constant time.
* After 5 wrong codes the message is locked for 15 minutes and the current code is discarded;
  after the lock a new code must be requested.
* Code mails are limited to 5 per message per hour and 20 requests per IP per hour; verify
  attempts to 60 per IP per hour. Someone holding the link can use up the hourly code budget
  for that message (a nuisance, not a disclosure).
* A correct code yields an access token valid 15 minutes, stored as a hash, good for that
  message only. The viewer uses it once to download the ciphertext.
* Residual risk of guessing: with the lock, someone holding the link gets at most about 20
  guesses an hour out of a million codes. Over a 30-day message lifetime that is roughly a
  1.4 % chance if they keep trying the whole time. Shorter lifetimes reduce it proportionally.
* Expired messages answer 404 and are purged with their gate state and tokens.

## Resending

`sealbox guest resend ID` (and `Engine::resend_guest_link`) mails a new notification for a
message already on the server: the same ciphertext, id, secret and mode, to the same
recipients, with a new Message-ID. It is refused once the message has expired. ID is the
Message-ID that `send` printed, the guest id, or the link.

## Where the secret is kept on your device

The sender's profile keeps the secret in the `guest_links` table of the local database, so the
passphrase can be shown again and a resend can rebuild a one-click or email-code link. In those
two modes the Sent copy of the notification contains the same link anyway. Once secrets-at-rest
wrapping (G27) is in place this column belongs in the wrapped set.

## Interfaces

* Core: `Draft::guest_mode: GuestMode { Passphrase (default), OneClick, EmailCode }`,
  `Draft::guest_recipient_hint`; `GuestLinkInfo { url, passphrase, mode, expires_at,
  secret_in_link, recipient_verification }`; `Engine::resend_guest_link(id) -> SendReport`.
* CLI: `sealbox send --policy guest [--guest-mode passphrase|one-click|email-code]
  [--guest-recipient ADDR] [--guest-expiry SECS]`; `sealbox guest resend ID`; `--json` output
  includes `guest.mode`, `guest.secret_in_link` and `guest.recipient_verification`.
* Server: see the module docs of `crates/sealbox-server/src/routes/guest.rs`.
* Gate: `scripts/gate_g29.sh`.
