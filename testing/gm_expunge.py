#!/usr/bin/env python3
"""Empty one GreenMail folder over IMAP: gm_expunge.py LOGIN PASSWORD FOLDER [HOST PORT].

Prints how many messages the folder held. GreenMail's REST API can only purge every
mailbox at once, so test scripts reset their own users this way, one folder at a time
(the review loops and gate G17 own u01–u05; see docs/GATES.md for the allocation).
A missing folder counts as empty (exit 0, prints 0)."""
import imaplib
import sys

login, password, folder = sys.argv[1:4]
host = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"
port = int(sys.argv[5]) if len(sys.argv) > 5 else 3143
imap = imaplib.IMAP4(host, port)
imap.login(login, password)
typ, data = imap.select(folder)
n = int(data[0]) if typ == "OK" and data and data[0] else 0
if n:
    imap.store("1:*", "+FLAGS.SILENT", "(\\Deleted)")
    imap.expunge()
if typ == "OK":
    imap.close()
imap.logout()
print(n)
