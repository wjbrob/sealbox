# Security policy

Sealbox is encryption software, so vulnerability reports are its most valuable contributions.
Thank you for sending one.

## Reporting a vulnerability

**Please don't open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
on the repository, open **Security → Report a vulnerability**.

Please include:
- the affected component (crate, app, extension, server, relay or guest viewer) and version or commit;
- a description of the impact: what an attacker can read, forge or cause;
- steps to reproduce, or a proof of concept;
- any suggested fix.

## What to expect

| Step | Target time |
|---|---|
| Acknowledgement | 3 working days |
| First assessment (accepted or declined, with severity) | 10 working days |
| Fix or mitigation for critical and high severity | 30 days |
| Coordinated public disclosure | at most 90 days after the report, or earlier once a fix ships |

We credit reporters in the advisory unless you'd rather we didn't. There is no paid bug bounty
at present.

## Scope

In scope: everything in this repository. That covers the Rust crates, the Flutter app, the browser
extension, the guest viewer, the server and the relay, plus the official release artifacts built
from it.

Particularly interesting:
- confidentiality or integrity breaks in encryption, decryption, signing or verification;
- key substitution, including bypasses of Autocrypt, the key directory or the transparency log;
- leaks of plaintext, keys or credentials to disk, logs, the network or the server;
- guest-link envelope weaknesses;
- HTML or MIME parsing that leads to code execution, remote-content loading or spoofed sender or
  signature status;
- SSRF or credential misuse in the relay.

Out of scope:
- vulnerabilities in third-party services (Gmail, Outlook and similar), unless Sealbox's handling
  makes them worse;
- issues that need a compromised device or root access;
- the residual risks already documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), unless you
  show them to be worse than documented.

## Supported versions

Sealbox is pre-1.0. Only the latest release and `main` receive security fixes.

## Threat model

The design goals, attacker model and known residual risks are in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
