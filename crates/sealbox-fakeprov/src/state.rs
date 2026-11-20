//! The mailbox the fake IMAP and SMTP servers share, plus the command log a test reads back.
//!
//! Seeded from the stateful scripted server in `sealbox-core/src/sync.rs` (the one the
//! newest-first window and reconcile tests drive) and generalised: several folders instead of
//! one, per-message flags, label semantics, and a log per connection so a test can assert what
//! the client actually put on the wire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::quirks::Quirks;

/// One stored message. `uid` is per folder, as IMAP requires.
#[derive(Clone, Debug)]
pub struct SimMessage {
    pub uid: u32,
    pub raw: Vec<u8>,
    pub flags: Vec<String>,
}

impl SimMessage {
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
    }
}

/// One mailbox.
#[derive(Clone, Debug, Default)]
pub struct SimMailbox {
    pub messages: Vec<SimMessage>,
    pub uidvalidity: u32,
    pub uidnext: u32,
}

impl SimMailbox {
    fn new(uidvalidity: u32) -> Self {
        Self {
            messages: Vec::new(),
            uidvalidity,
            uidnext: 1,
        }
    }

    pub fn uids(&self) -> Vec<u32> {
        self.messages.iter().map(|m| m.uid).collect()
    }

    pub fn get(&self, uid: u32) -> Option<&SimMessage> {
        self.messages.iter().find(|m| m.uid == uid)
    }

    pub fn get_mut(&mut self, uid: u32) -> Option<&mut SimMessage> {
        self.messages.iter_mut().find(|m| m.uid == uid)
    }
}

/// Everything the fake provider holds, shared between its IMAP, SMTP and IdP servers.
#[derive(Debug)]
pub struct SimState {
    pub quirks: Quirks,
    /// Folder name (as `LIST` reports it) → mailbox. Lookup is case-insensitive for INBOX
    /// only, as IMAP requires.
    folders: HashMap<String, SimMailbox>,
    /// Commands each IMAP connection sent, in order.
    pub imap_log: Vec<Vec<String>>,
    /// Lines each SMTP connection sent.
    pub smtp_log: Vec<Vec<String>>,
    /// Messages submitted over SMTP, as `(envelope_from, rcpt, raw)`.
    pub submitted: Vec<(String, Vec<String>, Vec<u8>)>,
    /// IMAP connections currently open — `max_connections` is enforced against this.
    pub imap_open: u32,
    /// Peak of [`SimState::imap_open`]: what the client actually held at once.
    pub imap_peak: u32,
    /// IMAP connections refused because the limit was reached.
    pub imap_refused: u32,
    /// Access tokens the bundled IdP has issued and not expired.
    pub live_tokens: Vec<String>,
    /// Logins that were rejected, with why — `primary_vs_alias` shows up here.
    pub rejected_logins: Vec<(String, String)>,
    next_uidvalidity: u32,
    /// Bumped whenever a folder's contents change, so a connection parked in `IDLE` can be
    /// told rather than having to poll. A `watch` channel because a late subscriber only cares
    /// that *something* changed since it last looked, not about each individual change.
    changes: watch::Sender<u64>,
}

pub type Shared = Arc<Mutex<SimState>>;

impl SimState {
    pub fn new(quirks: Quirks) -> Self {
        let mut folders = HashMap::new();
        for f in &quirks.folders {
            folders.insert(f.name.clone(), SimMailbox::new(7));
        }
        Self {
            quirks,
            folders,
            imap_log: Vec::new(),
            smtp_log: Vec::new(),
            submitted: Vec::new(),
            imap_open: 0,
            imap_peak: 0,
            imap_refused: 0,
            live_tokens: Vec::new(),
            rejected_logins: Vec::new(),
            next_uidvalidity: 8,
            changes: watch::channel(0).0,
        }
    }

    /// A receiver that reports every later change to any folder.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Announce that a folder's contents changed. Called by every mutation here; a test that
    /// reaches past them into [`SimMailbox`] directly should call it itself.
    pub fn announce_change(&self) {
        self.changes.send_modify(|n| *n += 1);
    }

    /// Case-insensitive for `INBOX` (RFC 3501 §5.1), exact for everything else.
    pub fn resolve(&self, name: &str) -> Option<String> {
        let want = name.trim().trim_matches('"');
        if want.eq_ignore_ascii_case("INBOX") {
            return self
                .folders
                .keys()
                .find(|k| k.eq_ignore_ascii_case("INBOX"))
                .cloned();
        }
        self.folders.contains_key(want).then(|| want.to_string())
    }

    pub fn folder(&self, name: &str) -> Option<&SimMailbox> {
        let key = self.resolve(name)?;
        self.folders.get(&key)
    }

    pub fn folder_mut(&mut self, name: &str) -> Option<&mut SimMailbox> {
        let key = self.resolve(name)?;
        self.folders.get_mut(&key)
    }

    /// Append a message, as `APPEND` or an SMTP-filed Sent copy would. Returns its new UID.
    pub fn append(&mut self, folder: &str, raw: Vec<u8>, flags: Vec<String>) -> Option<u32> {
        let mb = self.folder_mut(folder)?;
        let uid = mb.uidnext;
        mb.uidnext += 1;
        mb.messages.push(SimMessage { uid, raw, flags });
        self.announce_change();
        Some(uid)
    }

    /// Seed `n` messages into a folder (UIDs 1..=n when the folder is empty).
    pub fn seed(&mut self, folder: &str, n: u32) -> Vec<u32> {
        (1..=n)
            .filter_map(|i| {
                let raw = seed_message(i);
                self.append(folder, raw, Vec::new())
            })
            .collect()
    }

    /// Copy a message between folders, as `UID COPY` does. Under label semantics the original
    /// stays where it is *and* the copy appears, which is the whole point of the quirk.
    pub fn copy(&mut self, from: &str, uid: u32, to: &str) -> Option<u32> {
        let msg = self.folder(from)?.get(uid)?.clone();
        self.append(to, msg.raw, msg.flags)
    }

    /// Remove the `\Deleted` messages of a folder, honouring label semantics: on Gmail an
    /// expunge from anywhere but Trash only unlabels — the message survives in All Mail.
    /// Returns the UIDs that left this folder.
    pub fn expunge(&mut self, folder: &str, only: Option<&[u32]>) -> Vec<u32> {
        let (label_semantics, all_mail, trash) = {
            let q = &self.quirks;
            (q.label_semantics, q.all_mail(), q.trash_folder())
        };
        let Some(key) = self.resolve(folder) else {
            return Vec::new();
        };
        let gone: Vec<(u32, SimMessage)> = {
            let Some(mb) = self.folders.get(&key) else {
                return Vec::new();
            };
            mb.messages
                .iter()
                .filter(|m| m.has_flag("\\Deleted"))
                .filter(|m| only.is_none_or(|u| u.contains(&m.uid)))
                .map(|m| (m.uid, m.clone()))
                .collect()
        };
        if let Some(mb) = self.folders.get_mut(&key) {
            mb.messages
                .retain(|m| !gone.iter().any(|(uid, _)| *uid == m.uid));
        }
        // Label semantics: leaving a folder is unlabelling, and All Mail keeps the message —
        // unless the folder it left *was* All Mail or Trash, where a delete is a real delete.
        if label_semantics && !key.eq_ignore_ascii_case(&trash) {
            if let Some(all) = all_mail.filter(|a| !a.eq_ignore_ascii_case(&key)) {
                for (_, msg) in &gone {
                    let already = self
                        .folder(&all)
                        .is_some_and(|mb| mb.messages.iter().any(|m| m.raw == msg.raw));
                    if !already {
                        let mut flags = msg.flags.clone();
                        flags.retain(|f| !f.eq_ignore_ascii_case("\\Deleted"));
                        self.append(&all, msg.raw.clone(), flags);
                    }
                }
            }
        }
        if !gone.is_empty() {
            self.announce_change();
        }
        gone.into_iter().map(|(uid, _)| uid).collect()
    }

    /// Bump a folder's UIDVALIDITY, as a server does after a restore or a rebuild. Every UID
    /// the client holds becomes meaningless.
    pub fn bump_uidvalidity(&mut self, folder: &str) -> u32 {
        let next = self.next_uidvalidity;
        self.next_uidvalidity += 1;
        if let Some(mb) = self.folder_mut(folder) {
            mb.uidvalidity = next;
        }
        next
    }

    /// Every folder name, in `LIST` order.
    pub fn folder_names(&self) -> Vec<String> {
        self.quirks.folders.iter().map(|f| f.name.clone()).collect()
    }

    /// Message count of a folder (0 when it does not exist).
    pub fn count(&self, folder: &str) -> usize {
        self.folder(folder).map_or(0, |m| m.messages.len())
    }

    /// Every IMAP command any connection sent, flattened.
    pub fn imap_commands(&self) -> Vec<String> {
        self.imap_log
            .iter()
            .flat_map(|c| c.iter().cloned())
            .collect()
    }

    /// Whether any connection sent a command whose upper-cased form contains `needle`.
    pub fn imap_saw(&self, needle: &str) -> bool {
        let up = needle.to_ascii_uppercase();
        self.imap_commands()
            .iter()
            .any(|l| l.to_ascii_uppercase().contains(&up))
    }
}

/// A plausible RFC 5322 message, so a client that parses what it fetched is not fighting the
/// fake. Deterministic in `i` and distinct per message.
pub fn seed_message(i: u32) -> Vec<u8> {
    format!(
        "From: Bob <bob@fakeprov.test>\r\nTo: you@fakeprov.test\r\n\
         Subject: seeded {i}\r\nMessage-ID: <seed-{i}@fakeprov.test>\r\n\
         Date: Mon, 2 Mar 2026 10:{:02}:00 +0000\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nmessage number {i}\r\n",
        i % 60
    )
    .into_bytes()
}

/// `1`, `1:3`, `4:*`, `1,4:5` against a mailbox's highest UID (RFC 3501 sequence set).
pub fn parse_uid_set(set: &str, max: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let num = |s: &str| -> Option<u32> {
        if s == "*" {
            Some(max)
        } else {
            s.trim().parse().ok()
        }
    };
    for part in set.split(',') {
        match part.split_once(':') {
            Some((a, b)) => {
                let (Some(a), Some(b)) = (num(a), num(b)) else {
                    continue;
                };
                out.extend(a.min(b)..=a.max(b));
            }
            None => out.extend(num(part)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbox_core::providers::ProviderId;

    fn state(id: ProviderId) -> SimState {
        SimState::new(Quirks::for_provider(id))
    }

    #[test]
    fn inbox_is_case_insensitive_and_other_folders_are_not() {
        let s = state(ProviderId::Outlook);
        assert_eq!(s.resolve("inbox").as_deref(), Some("INBOX"));
        assert_eq!(s.resolve("InBoX").as_deref(), Some("INBOX"));
        assert_eq!(s.resolve("Sent Items").as_deref(), Some("Sent Items"));
        assert_eq!(s.resolve("sent items"), None, "exact, per RFC 3501");
        assert_eq!(s.resolve("No Such"), None);
    }

    #[test]
    fn uids_are_per_folder_and_never_reused() {
        let mut s = state(ProviderId::Fastmail);
        assert_eq!(s.seed("INBOX", 3), vec![1, 2, 3]);
        assert_eq!(
            s.seed("Sent", 2),
            vec![1, 2],
            "per folder, so Sent starts at 1"
        );

        // Deleting the top message does not lower uidnext.
        s.folder_mut("INBOX").unwrap().get_mut(3).unwrap().flags = vec!["\\Deleted".into()];
        assert_eq!(s.expunge("INBOX", None), vec![3]);
        assert_eq!(s.append("INBOX", seed_message(9), vec![]), Some(4));
    }

    #[test]
    fn gmail_expunge_from_inbox_only_archives_but_from_trash_deletes() {
        let mut s = state(ProviderId::Gmail);
        s.seed("INBOX", 1);
        s.folder_mut("INBOX").unwrap().get_mut(1).unwrap().flags = vec!["\\Deleted".into()];
        s.expunge("INBOX", None);
        assert_eq!(s.count("INBOX"), 0);
        assert_eq!(
            s.count("[Gmail]/All Mail"),
            1,
            "an expunge from INBOX is an archive: it survives in All Mail"
        );

        // From Trash it is a real delete, and nothing is re-filed.
        let all = "[Gmail]/All Mail";
        s.copy(all, 1, "[Gmail]/Trash");
        let uid = s.folder("[Gmail]/Trash").unwrap().uids()[0];
        s.folder_mut("[Gmail]/Trash")
            .unwrap()
            .get_mut(uid)
            .unwrap()
            .flags = vec!["\\Deleted".into()];
        let before = s.count(all);
        s.expunge("[Gmail]/Trash", None);
        assert_eq!(s.count("[Gmail]/Trash"), 0);
        assert_eq!(s.count(all), before, "deleting from Trash re-files nothing");
    }

    #[test]
    fn without_label_semantics_an_expunge_is_simply_a_delete() {
        let mut s = state(ProviderId::Icloud);
        s.seed("INBOX", 2);
        s.folder_mut("INBOX").unwrap().get_mut(1).unwrap().flags = vec!["\\Deleted".into()];
        s.expunge("INBOX", None);
        assert_eq!(s.count("INBOX"), 1);
        assert_eq!(s.count("Archive"), 0, "nothing is secretly kept");
    }

    #[test]
    fn uid_expunge_removes_only_the_named_messages() {
        let mut s = state(ProviderId::Fastmail);
        s.seed("INBOX", 3);
        for uid in [1, 2, 3] {
            s.folder_mut("INBOX").unwrap().get_mut(uid).unwrap().flags = vec!["\\Deleted".into()];
        }
        assert_eq!(s.expunge("INBOX", Some(&[2])), vec![2]);
        assert_eq!(
            s.folder("INBOX").unwrap().uids(),
            vec![1, 3],
            "the other two are still \\Deleted but still there"
        );
    }

    #[test]
    fn a_uidvalidity_bump_is_per_folder() {
        let mut s = state(ProviderId::Zoho);
        let before = s.folder("INBOX").unwrap().uidvalidity;
        let after = s.bump_uidvalidity("INBOX");
        assert_ne!(before, after);
        assert_eq!(s.folder("INBOX").unwrap().uidvalidity, after);
        assert_eq!(
            s.folder("Sent").unwrap().uidvalidity,
            before,
            "Sent was not rebuilt"
        );
    }

    #[test]
    fn sequence_sets_parse_the_way_a_client_writes_them() {
        assert_eq!(parse_uid_set("1", 9), vec![1]);
        assert_eq!(parse_uid_set("1:3", 9), vec![1, 2, 3]);
        assert_eq!(parse_uid_set("4:*", 6), vec![4, 5, 6]);
        assert_eq!(parse_uid_set("1,4:5", 9), vec![1, 4, 5]);
        assert_eq!(parse_uid_set("3:1", 9), vec![1, 2, 3], "either order");
        assert_eq!(parse_uid_set("", 9), Vec::<u32>::new());
    }
}
