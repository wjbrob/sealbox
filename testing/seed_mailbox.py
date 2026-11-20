#!/usr/bin/env python3
"""Seed a GreenMail mailbox with a realistic, deterministic corpus over IMAP APPEND.

    seed_mailbox.py --user p01 --password p01pw --count 1000 [--offset 0]
                    [--host 127.0.0.1 --port 3243] [--folder INBOX] [--seed 2026]
                    [--span 10000] [--pgp-recipient-key p01.asc --gnupg-home DIR]
                    [--manifest FILE.jsonl] [--to p01@sealbox.test]

Message i of the corpus is a pure function of (--seed, i), so seeding offset 0 count 1000 and
then offset 1000 count 9000 yields exactly the corpus of offset 0 count 10000. Dates run
oldest -> newest over two years for i < --span (UIDs therefore ascend with dates, as in a real
mailbox); i >= --span are "new mail" dated after that window (the incremental-sync tests).

Mix (per message, decided by its own RNG draw):
  20 %  multipart/mixed with one 30-200 KB attachment (pdf / jpeg / xlsx / docx / zip / png)
  10 %  HTML-only (text/html, 5-40 KB, newsletter-like)
   1 %  PGP/MIME encrypted + signed to --pgp-recipient-key (protected headers; a quarter
        carry an inner attachment) -- only with --pgp-recipient-key, else counted as text
  30 %  multipart/alternative (text + HTML), the shape of most real mail
  39 %  text/plain
About 30 % are replies (In-Reply-To + References to an earlier message, "Re:" subject).
Senders follow a Zipf law over 400 addresses on reserved domains (RFC 2606 .example and
example.com/net/org); twelve of them are Autocrypt-capable PGP users whose messages all carry
an Autocrypt header (key made by gpg in --gnupg-home). Every message has a Gmail-like header
block (Received x3, Authentication-Results pass, DKIM-Signature, List-* for newsletters).
86 % are \\Seen, 2 % \\Flagged; the INTERNALDATE is the message date.

Encryption needs gpg (an isolated --gnupg-home; the gpg-agent it starts is stopped at the end).
APPENDs run in one IMAP session; the rate is printed at the end. Stdlib only.
Never sends mail: APPEND writes straight into the mailbox, nothing goes over SMTP."""

import argparse
import base64
import email.utils
import functools
import hashlib
import imaplib
import json
import os
import quopri
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

CRLF = "\r\n"
SPAN_START = datetime(2024, 10, 29, 6, 0, tzinfo=timezone.utc)
SPAN_DAYS = 730

FIRST = ("Maya Bob Carol Dmitri Elena Farid Grace Hiro Ines Jonas Kemal Lena Mateo Nora Oskar "
         "Priya Quentin Rosa Sven Tara Ugo Vera Wen Ximena Yusuf Zoe Ana Ben Chloe Diego Emma "
         "Felix Hanna Ivan Julia Karim Liam Mia Noah Olga Pablo Ravi Sara Tom Uma Viktor Will").split()
LAST = ("Okafor Nakamura Jensen Petrov Rossi Haddad Kim Tanaka Silva Weber Demir Novak Garcia "
        "Berg Larsen Patel Moreau Costa Lindqvist Singh Bianchi Kowalski Chen Ruiz Ahmed Fischer "
        "Martin Dubois Svensson Nowak Ivanova Murphy Kelly Schmidt Romero Haas Varga Sato").split()
ACCENTED = ["José Müller", "Zoë Lefèvre", "Ågot Nordström", "Łukasz Wiśniewski", "Çağrı Yılmaz",
            "François Dupré", "Søren Kierkegård", "Renée Ångström", "山田 太郎", "Αλέξης Παππάς"]
DOMAINS = ["example.com", "example.net", "example.org", "mail.example.com", "acme.example",
           "northwind.example", "contoso.example", "fabrikam.example", "uni.example",
           "studio.example", "lab.example.org", "team.example.net"]
NEWS_DOMAINS = ["news.example.com", "shop.example", "updates.example.net", "digest.example.org",
                "travel.example", "bank.example"]
WORDS = ("the of and to in is that for it as with was on be at by this had not are but from or "
         "have an they which one you were all we her she there would their will when who him "
         "been has more if no out so said what up its about than into them can only other new "
         "some could time these two may then do first any my now such like our over man me even "
         "most made after also did many before must through back years where much your way well "
         "down should because each just those people how too little state good very make world "
         "still own see men work long get here between both life being under never day same "
         "another know while last might us great old year off come since against go came right "
         "used take three meeting project budget draft review schedule invoice report release "
         "contract design team update proposal quarter numbers deadline call notes agenda client "
         "launch feedback version server deploy travel flight hotel dinner weekend photos family "
         "garden concert tickets lecture thesis paper results data analysis figure section").split()
TOPICS = ["Q{q} budget review", "Draft agenda for {day}", "Invoice {n}", "Re-scheduling our call",
          "Photos from the weekend", "Contract renewal {year}", "Release {v} notes",
          "Thesis chapter {n} comments", "Flight booking confirmation {code}", "Dinner on {day}?",
          "Server migration plan", "Lecture slides week {n}", "Team offsite logistics",
          "Feedback on the proposal", "Your order {code} has shipped", "Minutes: design review",
          "Garden club newsletter #{n}", "Concert tickets for {day}", "Data analysis results",
          "Quick question about section {n}", "Weekly digest #{n}", "Hotel reservation {code}"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
ATTACH_TYPES = [("application", "pdf", "report-{n}.pdf", b"%PDF-1.7\n"),
                ("image", "jpeg", "IMG_{n}.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
                ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                 "numbers-{n}.xlsx", b"PK\x03\x04"),
                ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document",
                 "draft-{n}.docx", b"PK\x03\x04"),
                ("application", "zip", "photos-{n}.zip", b"PK\x03\x04"),
                ("image", "png", "screenshot-{n}.png", b"\x89PNG\r\n\x1a\n")]
N_SENDERS = 400
PGP_RANKS = (2, 5, 9, 14, 22, 31, 45, 60, 80, 110, 150, 200)  # Zipf ranks of the PGP users


def b64_lines(data):
    return base64.encodebytes(data).decode("ascii").replace("\n", CRLF)


def qp(text):
    return quopri.encodestring(text.encode("utf-8")).decode("ascii").replace("\n", CRLF)


def hdr_text(s):
    """RFC 2047-encode a header text when it is not ASCII."""
    if s.isascii():
        return s
    return "=?utf-8?b?" + base64.b64encode(s.encode("utf-8")).decode("ascii") + "?="


def fmt_addr(name, addr):
    return email.utils.formataddr((name, addr), charset="utf-8")


@functools.lru_cache(maxsize=None)
def sender(rank):
    """(display name, address, is_newsletter) of the sender with Zipf rank `rank`."""
    r = random.Random(f"sender/{rank}")
    if rank % 9 == 4:  # newsletters / notifications
        dom = NEWS_DOMAINS[rank % len(NEWS_DOMAINS)]
        label = dom.split(".")[0].capitalize()
        return (f"{label} {r.choice(['Digest', 'Updates', 'Team', 'Notifications'])}",
                f"{r.choice(['news', 'noreply', 'updates', 'hello'])}{rank}@{dom}", True)
    if rank % 23 == 7:
        name = ACCENTED[rank % len(ACCENTED)]
    else:
        name = f"{r.choice(FIRST)} {r.choice(LAST)}"
    local = re.sub(r"[^a-z]", "", name.lower().split()[0]) or "user"
    return (name, f"{local}.{rank}@{DOMAINS[rank % len(DOMAINS)]}", False)


class Zipf:
    def __init__(self, n, s=0.85):
        w = [1.0 / (k ** s) for k in range(1, n + 1)]
        tot = sum(w)
        acc, self.cdf = 0.0, []
        for x in w:
            acc += x / tot
            self.cdf.append(acc)

    def draw(self, rng):
        u = rng.random()
        lo, hi = 0, len(self.cdf) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if self.cdf[mid] < u:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1


ZIPF = Zipf(N_SENDERS)


def words(rng, n):
    return " ".join(rng.choice(WORDS) for _ in range(n))


def paragraphs(rng, chars):
    out, size = [], 0
    while size < chars:
        p = ". ".join(words(rng, rng.randint(6, 18)).capitalize() for _ in range(rng.randint(2, 6))) + "."
        out.append(p)
        size += len(p) + 2
    return out


class Corpus:
    def __init__(self, seed, span, to_addr, to_name):
        self.seed, self.span, self.to_addr, self.to_name = seed, span, to_addr, to_name

    def rng(self, i, what=""):
        return random.Random(f"{self.seed}/{i}/{what}")

    def date(self, i):
        r = self.rng(i, "date")
        if i < self.span:
            base = SPAN_START + timedelta(days=SPAN_DAYS * i / self.span)
            jitter = timedelta(seconds=r.randint(-6 * 3600, 6 * 3600))
            return base + jitter
        return SPAN_START + timedelta(days=SPAN_DAYS, minutes=(i - self.span) * 7 + r.randint(0, 5))

    def rank(self, i):
        return ZIPF.draw(self.rng(i, "from"))

    def message_id(self, i):
        h = hashlib.sha256(f"{self.seed}/{i}".encode()).hexdigest()[:16]
        dom = sender(self.rank(i))[1].split("@", 1)[1]
        return f"<{h}.{i}@{dom}>"

    @functools.lru_cache(maxsize=None)
    def parent(self, i):
        r = self.rng(i, "thread")
        if i == 0 or r.random() >= 0.30:
            return None
        return max(0, i - 1 - int(r.expovariate(1 / 25.0)))

    @functools.lru_cache(maxsize=None)
    def references(self, i):
        p = self.parent(i)
        if p is None:
            return ()
        return (self.references(p) + (self.message_id(p),))[-10:]

    @functools.lru_cache(maxsize=None)
    def root_subject(self, i):
        p = self.parent(i)
        if p is not None:
            return self.root_subject(p)
        r = self.rng(i, "subject")
        return r.choice(TOPICS).format(q=r.randint(1, 4), day=r.choice(DAYS), n=r.randint(2, 9999),
                                       year=r.choice([2025, 2026]), v=f"{r.randint(1, 9)}.{r.randint(0, 20)}",
                                       code=f"{r.randint(100000, 999999)}")

    def kind(self, i, pgp_enabled):
        u = self.rng(i, "kind").random()
        if u < 0.20:
            return "attachment"
        if u < 0.30:
            return "html_only"
        if u < 0.31:
            return "pgp" if pgp_enabled else "text"
        if u < 0.61:
            return "alternative"
        return "text"


def html_doc(rng, paras, newsletter):
    links = "".join(
        f'<li><a href="https://www.example.com/{words(rng, 1)}/{rng.randint(1000, 99999)}" '
        f'style="color:#1a5fb4">{words(rng, rng.randint(2, 5)).capitalize()}</a></li>'
        for _ in range(rng.randint(2, 7)))
    body = "".join(f'<p style="margin:0 0 12px 0;line-height:1.5">{p}</p>' for p in paras)
    foot = ('<p style="color:#666;font-size:12px">You receive this because you subscribed. '
            '<a href="https://www.example.com/unsubscribe">Unsubscribe</a></p>') if newsletter else ""
    rows = "".join(f"<tr><td style=\"padding:4px 8px;border:1px solid #ddd\">{words(rng, 2)}</td>"
                   f"<td style=\"padding:4px 8px;border:1px solid #ddd\">{rng.randint(1, 9999)}</td></tr>"
                   for _ in range(rng.randint(0, 12)))
    table = f'<table style="border-collapse:collapse;margin:12px 0">{rows}</table>' if rows else ""
    return ('<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:Arial,'
            'sans-serif;color:#222}h1{font-size:20px}</style></head><body>'
            f'<div style="max-width:640px;margin:0 auto;padding:16px"><h1>{words(rng, 4).capitalize()}</h1>'
            f'{body}{table}<ul>{links}</ul>{foot}</div></body></html>')


def build(c, i, pgp):
    """Raw RFC 822 bytes, the kind and the flags of message i."""
    r = c.rng(i, "body")
    rank = c.rank(i)
    name, addr, newsletter = sender(rank)
    kind = c.kind(i, pgp is not None)
    if kind == "pgp" and (pgp is None or rank not in pgp.ranks):
        rank = PGP_RANKS[i % len(PGP_RANKS)]
        name, addr, newsletter = sender(rank)
    date = c.date(i)
    mid = c.message_id(i)
    parent = c.parent(i)
    subject = c.root_subject(i)
    if parent is not None:
        subject = "Re: " + subject
    dom = addr.split("@", 1)[1]
    h = [f"Received: from mx{r.randint(1, 40)}.{dom} (mx.{dom} [198.51.100.{r.randint(1, 254)}])"
         f"{CRLF}\tby mx.sealbox.test with ESMTPS id {r.randint(10**9, 10**10)}{CRLF}\t"
         f"for <{c.to_addr}>; {email.utils.format_datetime(date)}",
         f"Received: from [192.0.2.{r.randint(1, 254)}] by smtp.{dom} with ESMTPSA id "
         f"{r.randint(10**6, 10**7)};{CRLF}\t{email.utils.format_datetime(date - timedelta(seconds=r.randint(1, 30)))}",
         f"Authentication-Results: mx.sealbox.test;{CRLF}\tdkim=pass header.i=@{dom};{CRLF}\t"
         f"spf=pass smtp.mailfrom={addr};{CRLF}\tdmarc=pass (p=NONE) header.from={dom}",
         f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={dom}; s=s{r.randint(1, 9)};{CRLF}\t"
         f"h=from:to:subject:date:message-id; bh={base64.b64encode(r.randbytes(32)).decode()};{CRLF}\t"
         f"b={base64.b64encode(r.randbytes(128)).decode()}",
         f"From: {fmt_addr(name, addr)}",
         f"To: {fmt_addr(c.to_name, c.to_addr)}"]
    if r.random() < 0.15:
        cn, ca, _ = sender(ZIPF.draw(r))
        h.append(f"Cc: {fmt_addr(cn, ca)}")
    h += [f"Date: {email.utils.format_datetime(date)}", f"Message-ID: {mid}"]
    if parent is not None:
        h.append(f"In-Reply-To: {c.message_id(parent)}")
        h.append("References: " + (CRLF + " ").join(c.references(i)))
    if newsletter:
        h.append(f"List-Id: {dom.split('.')[0]} updates <list.{dom}>")
        h.append(f"List-Unsubscribe: <https://www.example.com/unsubscribe/{r.randint(10**5, 10**6)}>")
    if pgp is not None and rank in pgp.ranks:
        h.append(pgp.autocrypt_header(rank))
    h.append("MIME-Version: 1.0")

    text = (f"Hi {c.to_name.split()[0]},{CRLF}{CRLF}" +
            (CRLF + CRLF).join(paragraphs(r, int(r.lognormvariate(6.6, 0.8)) + 80)) +
            f"{CRLF}{CRLF}-- {CRLF}{name}{CRLF}")
    if parent is not None:
        text += f"{CRLF}On {email.utils.format_datetime(c.date(parent))} someone wrote:{CRLF}> " + \
                words(r, 30) + CRLF
    if any(ord(ch) > 127 for ch in name):
        text += f"{CRLF}Grüße / salutations{CRLF}"
    bnd = f"=_sbx{hashlib.md5(f'{c.seed}/{i}'.encode()).hexdigest()}"

    def text_part(t):
        if t.isascii():
            return f'Content-Type: text/plain; charset="utf-8"{CRLF}Content-Transfer-Encoding: 7bit{CRLF}{CRLF}{t}'
        return (f'Content-Type: text/plain; charset="utf-8"{CRLF}Content-Transfer-Encoding: '
                f'quoted-printable{CRLF}{CRLF}{qp(t)}')

    def html_part(doc):
        return (f'Content-Type: text/html; charset="utf-8"{CRLF}Content-Transfer-Encoding: '
                f'quoted-printable{CRLF}{CRLF}{qp(doc)}')

    if kind == "html_only":
        doc = html_doc(r, paragraphs(r, r.randint(4000, 36000)), newsletter)
        body_block = html_part(doc)
    elif kind == "alternative":
        doc = html_doc(r, text.split(CRLF + CRLF), newsletter)
        body_block = (f'Content-Type: multipart/alternative; boundary="{bnd}a"{CRLF}{CRLF}'
                      f"--{bnd}a{CRLF}{text_part(text)}{CRLF}--{bnd}a{CRLF}{html_part(doc)}{CRLF}--{bnd}a--{CRLF}")
    elif kind == "attachment":
        mt, st, fn, magic = ATTACH_TYPES[r.randrange(len(ATTACH_TYPES))]
        size = r.randint(30 * 1024, 200 * 1024)
        data = magic + r.randbytes(size - len(magic))
        fn = fn.format(n=r.randint(1000, 9999))
        body_block = (f'Content-Type: multipart/mixed; boundary="{bnd}m"{CRLF}{CRLF}'
                      f"--{bnd}m{CRLF}{text_part(text)}{CRLF}--{bnd}m{CRLF}"
                      f'Content-Type: {mt}/{st}; name="{fn}"{CRLF}Content-Disposition: attachment; '
                      f'filename="{fn}"{CRLF}Content-Transfer-Encoding: base64{CRLF}{CRLF}'
                      f"{b64_lines(data)}--{bnd}m--{CRLF}")
    elif kind == "pgp":
        inner_h = (f'Subject: {hdr_text(subject)}{CRLF}From: {fmt_addr(name, addr)}{CRLF}'
                   f"To: {fmt_addr(c.to_name, c.to_addr)}{CRLF}Date: {email.utils.format_datetime(date)}"
                   f"{CRLF}Message-ID: {mid}{CRLF}")
        if r.random() < 0.25:
            data = b"%PDF-1.7\n" + r.randbytes(r.randint(10 * 1024, 60 * 1024))
            inner = (f'Content-Type: multipart/mixed; boundary="{bnd}i"; protected-headers="v1"{CRLF}'
                     f"{inner_h}{CRLF}--{bnd}i{CRLF}{text_part(text)}{CRLF}--{bnd}i{CRLF}"
                     f'Content-Type: application/pdf; name="scan.pdf"{CRLF}Content-Disposition: '
                     f'attachment; filename="scan.pdf"{CRLF}Content-Transfer-Encoding: base64{CRLF}{CRLF}'
                     f"{b64_lines(data)}--{bnd}i--{CRLF}")
        else:
            inner = (f'Content-Type: text/plain; charset="utf-8"; protected-headers="v1"{CRLF}'
                     f"Content-Transfer-Encoding: quoted-printable{CRLF}{inner_h}{CRLF}{qp(text)}")
        armored = pgp.encrypt(inner.encode("utf-8"), rank)
        subject = "..."
        body_block = (f'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; '
                      f'boundary="{bnd}e"{CRLF}{CRLF}This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'
                      f"{CRLF}--{bnd}e{CRLF}Content-Type: application/pgp-encrypted{CRLF}"
                      f"Content-Description: PGP/MIME version identification{CRLF}{CRLF}Version: 1{CRLF}{CRLF}"
                      f'--{bnd}e{CRLF}Content-Type: application/octet-stream; name="encrypted.asc"{CRLF}'
                      f'Content-Description: OpenPGP encrypted message{CRLF}Content-Disposition: inline; '
                      f'filename="encrypted.asc"{CRLF}{CRLF}{armored.replace(chr(10), CRLF)}{CRLF}--{bnd}e--{CRLF}')
    else:
        body_block = text_part(text)
    h.insert(h.index(f"Date: {email.utils.format_datetime(date)}"), f"Subject: {hdr_text(subject)}")
    raw = CRLF.join(h) + CRLF + body_block
    if not raw.endswith(CRLF):
        raw += CRLF
    fr = c.rng(i, "flags")
    flags = []
    if i < c.span and fr.random() < 0.86:
        flags.append("\\Seen")
    if fr.random() < 0.02:
        flags.append("\\Flagged")
    return raw.encode("utf-8"), kind, flags, date


class Pgp:
    """gpg in an isolated home: twelve sender identities + the recipient's public key."""

    def __init__(self, home, recipient_key, corpus):
        if shutil.which("gpg") is None:
            sys.exit("seed_mailbox: --pgp-recipient-key needs gpg on PATH")
        self.home = home
        os.makedirs(home, mode=0o700, exist_ok=True)
        os.chmod(home, 0o700)
        self.ranks = set(PGP_RANKS)
        out = self.gpg(["--import", recipient_key], check=True)
        fprs = re.findall(r"^fpr:+([0-9A-F]{40,64}):", self.gpg(
            ["--with-colons", "--fingerprint", "--import-options", "show-only", "--import",
             recipient_key]).stdout, re.M)
        if not fprs:
            sys.exit(f"seed_mailbox: no key in {recipient_key} ({out.stderr.strip()})")
        self.recipient = fprs[0]
        self.senders, self.keydata = {}, {}
        for rank in PGP_RANKS:
            name, addr, _ = sender(rank)
            fpr = self.fpr_of(addr)
            if fpr is None:
                self.gpg(["--passphrase", "", "--quick-gen-key", f"{name} <{addr}>", "ed25519",
                          "sign", "never"], check=True)
                fpr = self.fpr_of(addr)
                self.gpg(["--passphrase", "", "--quick-add-key", fpr, "cv25519", "encr", "never"],
                         check=True)
            self.senders[rank] = fpr
            exp = subprocess.run(["gpg", "--homedir", home, "--batch", "--export",
                                  "--export-options", "export-minimal", fpr],
                                 capture_output=True, check=True).stdout
            self.keydata[rank] = base64.b64encode(exp).decode("ascii")

    def gpg(self, args, check=False, data=None):
        return subprocess.run(["gpg", "--homedir", self.home, "--batch", "--yes", "--quiet",
                               "--pinentry-mode", "loopback"] + args, input=data,
                              capture_output=True, check=check,
                              text=data is None)

    def fpr_of(self, addr):
        out = self.gpg(["--with-colons", "--list-secret-keys", f"<{addr}>"]).stdout
        m = re.search(r"^fpr:+([0-9A-F]{40,64}):", out, re.M)
        return m.group(1) if m else None

    def autocrypt_header(self, rank):
        _, addr, _ = sender(rank)
        kd = self.keydata[rank]
        folded = (CRLF + " ").join(kd[k:k + 72] for k in range(0, len(kd), 72))
        return f"Autocrypt: addr={addr}; prefer-encrypt=mutual; keydata={CRLF} {folded}"

    def encrypt(self, inner, rank):
        p = self.gpg(["--trust-model", "always", "--armor", "--sign", "--encrypt",
                      "--local-user", self.senders[rank], "--recipient", self.recipient,
                      "--output", "-"], check=True, data=inner)
        return p.stdout.decode("ascii").strip()

    def close(self):
        subprocess.run(["gpgconf", "--homedir", self.home, "--kill", "all"], capture_output=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3243)
    ap.add_argument("--folder", default="INBOX")
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--span", type=int, default=10000,
                    help="messages 0..span-1 share the two-year date window (default 10000)")
    ap.add_argument("--seed", default="2026")
    ap.add_argument("--to", help="recipient address (default <user>@sealbox.test)")
    ap.add_argument("--to-name", default="Perf User")
    ap.add_argument("--pgp-recipient-key", help="armored public key: enables the PGP/MIME share")
    ap.add_argument("--gnupg-home", help="isolated GNUPGHOME for the sender keys (reused across runs)")
    ap.add_argument("--manifest", help="append one JSON line per message (index, uid, kind, bytes)")
    a = ap.parse_args()
    to = a.to or f"{a.user}@sealbox.test"
    if not to.endswith("@sealbox.test"):
        sys.exit("seed_mailbox: --to must be a @sealbox.test address")
    corpus = Corpus(a.seed, a.span, to, a.to_name)
    pgp = None
    if a.pgp_recipient_key:
        if not a.gnupg_home:
            sys.exit("seed_mailbox: --pgp-recipient-key needs --gnupg-home")
        t = time.monotonic()
        pgp = Pgp(a.gnupg_home, a.pgp_recipient_key, corpus)
        print(f"gpg: recipient {pgp.recipient}, {len(pgp.senders)} sender keys "
              f"({time.monotonic() - t:.1f} s)", flush=True)
    imap = imaplib.IMAP4(a.host, a.port)
    # imaplib writes an APPEND literal and its trailing CRLF separately; with Nagle on, the
    # CRLF waits for the server's delayed ACK (~40 ms per message on Linux loopback).
    imap.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    imap.login(a.user, a.password)
    man = open(a.manifest, "a") if a.manifest else None
    kinds, total_bytes, t_gen, t_app = {}, 0, 0.0, 0.0
    t0 = time.monotonic()
    try:
        for i in range(a.offset, a.offset + a.count):
            tg = time.monotonic()
            raw, kind, flags, date = build(corpus, i, pgp)
            ta = time.monotonic()
            typ, data = imap.append(a.folder, "(" + " ".join(flags) + ")" if flags else None,
                                    imaplib.Time2Internaldate(date.timestamp()), raw)
            te = time.monotonic()
            if typ != "OK":
                sys.exit(f"seed_mailbox: APPEND {i} failed: {data!r}")
            t_gen += ta - tg
            t_app += te - ta
            m = re.search(rb"APPENDUID \d+ (\d+)", data[0] or b"")
            uid = int(m.group(1)) if m else None
            kinds[kind] = kinds.get(kind, 0) + 1
            total_bytes += len(raw)
            if man:
                man.write(json.dumps({"i": i, "uid": uid, "kind": kind, "bytes": len(raw),
                                      "reply": corpus.parent(i) is not None,
                                      "date": int(date.timestamp())}) + "\n")
            done = i - a.offset + 1
            if done % 1000 == 0 and done < a.count:
                el = time.monotonic() - t0
                print(f"  {done}/{a.count} appended, {done / el:.0f} msg/s", flush=True)
    finally:
        if man:
            man.close()
        try:
            imap.logout()
        except Exception:
            pass
        if pgp:
            pgp.close()
    el = time.monotonic() - t0
    mb = total_bytes / 1e6
    print(f"seeded {a.count} messages ({mb:.1f} MB, mean {total_bytes / max(a.count, 1) / 1024:.1f} KiB) "
          f"into {a.user}/{a.folder} offset {a.offset} in {el:.1f} s: {a.count / el:.0f} msg/s, "
          f"{mb / el:.1f} MB/s (generate {t_gen:.1f} s, APPEND {t_app:.1f} s)")
    print("kinds: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))


if __name__ == "__main__":
    main()
