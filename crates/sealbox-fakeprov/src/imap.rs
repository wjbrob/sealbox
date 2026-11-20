//! The fake IMAP server.
//!
//! Seeded from the two scripted servers already in the tree — the stateful one in
//! `sealbox-core/src/sync.rs` (mailbox, command log, fault injection) and the login-rejection
//! one in `sealbox-mail/src/imap.rs` — and widened to a whole provider: several folders with
//! special-use attributes, per-message flags, XOAUTH2, label semantics, connection limits,
//! throttling and the missing-MOVE and alias-rejection quirks.
//!
//! It implements what Sealbox actually sends and nothing else. An unimplemented command gets a
//! tagged `BAD`, which is far better than a plausible-looking lie: a gap shows up as a failing
//! check rather than as a passing one.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::quirks::SimAuth;
use crate::state::{parse_uid_set, Shared};

/// Start the IMAP side on an ephemeral loopback port. Returns the port.
pub async fn start(state: Shared) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let st = state.clone();
            tokio::spawn(async move {
                serve(sock, st).await;
            });
        }
    });
    Ok(port)
}

/// Per-connection state.
struct Conn {
    idx: usize,
    authed: bool,
    login: String,
    selected: Option<String>,
    read_only: bool,
    commands: u32,
    idle_tag: Option<String>,
}

async fn serve(sock: TcpStream, state: Shared) {
    // The connection limit is per account, and this fake serves one account.
    let (idx, over_limit) = {
        let mut s = state.lock().unwrap();
        s.imap_log.push(Vec::new());
        let idx = s.imap_log.len() - 1;
        // Only a stated hard limit refuses; the profile's `max_connections` is our own budget.
        let limit = s.quirks.connection_hard_limit.map_or(u32::MAX, u32::from);
        if s.imap_open >= limit {
            s.imap_refused += 1;
            (idx, true)
        } else {
            s.imap_open += 1;
            s.imap_peak = s.imap_peak.max(s.imap_open);
            (idx, false)
        }
    };
    let (rd, mut wr) = sock.into_split();
    if over_limit {
        // What a real server does when an account holds too many sessions: greet with a BYE
        // and hang up, rather than accept and misbehave later.
        let _ = wr
            .write_all(b"* BYE [UNAVAILABLE] Too many simultaneous connections\r\n")
            .await;
        return;
    }
    let mut c = Conn {
        idx,
        authed: false,
        login: String::new(),
        selected: None,
        read_only: false,
        commands: 0,
        idle_tag: None,
    };
    let greeting = {
        let s = state.lock().unwrap();
        format!(
            "* OK [CAPABILITY {}] fakeprov ready\r\n",
            s.quirks.capabilities()
        )
    };
    if wr.write_all(greeting.as_bytes()).await.is_err() {
        release(&state);
        return;
    }
    let mut lines = BufReader::new(rd).lines();
    let mut changes = state.lock().unwrap().subscribe();
    'session: loop {
        // A connection parked in `IDLE` is waiting to be *told*. While idling, a change to the
        // mailbox is pushed as an untagged `EXISTS` — without this the fake answers `+ idling`
        // and then says nothing ever, so a client waiting for new mail only ever finds it by
        // polling after its own timeout, and `arrival_via_idle` would measure the timeout
        // rather than IDLE. `Lines::next_line` keeps a partial line in its own buffer, so
        // losing this race to a change does not lose input.
        let next = if c.idle_tag.is_some() {
            loop {
                tokio::select! {
                    line = lines.next_line() => break line,
                    Ok(()) = changes.changed() => {
                        let exists = c
                            .selected
                            .as_deref()
                            .and_then(|f| state.lock().unwrap().folder(f).map(|mb| mb.messages.len()));
                        if let Some(n) = exists {
                            if wr
                                .write_all(format!("* {n} EXISTS\r\n").as_bytes())
                                .await
                                .is_err()
                            {
                                break 'session;
                            }
                        }
                    }
                }
            }
        } else {
            lines.next_line().await
        };
        let Ok(Some(line)) = next else { break };
        state.lock().unwrap().imap_log[c.idx].push(line.clone());

        // `DONE` ends an IDLE and carries no tag of its own.
        if line.eq_ignore_ascii_case("DONE") {
            if let Some(tag) = c.idle_tag.take() {
                if wr
                    .write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            continue;
        }

        c.commands += 1;
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next().unwrap_or("*").to_string();
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").to_string();

        // Throttling: a real provider answers a flood with a temporary failure and expects the
        // client to back off, not to treat it as a permanent error.
        let throttled = {
            let s = state.lock().unwrap();
            s.quirks
                .throttle_after
                .is_some_and(|n| c.commands > n && cmd != "LOGOUT")
        };
        if throttled {
            let _ = wr
                .write_all(
                    format!("{tag} NO [THROTTLED] Too many commands, slow down\r\n").as_bytes(),
                )
                .await;
            continue;
        }

        let out = match cmd.as_str() {
            "CAPABILITY" => {
                let caps = state.lock().unwrap().quirks.capabilities();
                Reply::text(format!(
                    "* CAPABILITY {caps}\r\n{tag} OK CAPABILITY completed\r\n"
                ))
            }
            "LOGIN" => do_login(&state, &mut c, &tag, &rest),
            "AUTHENTICATE" => {
                match do_authenticate(&state, &mut c, &tag, &rest, &mut wr, &mut lines).await {
                    Ok(r) => r,
                    Err(()) => break,
                }
            }
            "LOGOUT" => {
                let _ = wr
                    .write_all(format!("* BYE\r\n{tag} OK LOGOUT completed\r\n").as_bytes())
                    .await;
                break;
            }
            "NOOP" => Reply::text(format!("{tag} OK NOOP completed\r\n")),
            _ if !c.authed => Reply::text(format!("{tag} NO Authenticate first\r\n")),
            "LIST" | "LSUB" => do_list(&state, &tag),
            "SELECT" | "EXAMINE" => do_select(&state, &mut c, &tag, &rest, cmd == "EXAMINE"),
            "CREATE" => do_create(&state, &tag, &rest),
            "APPEND" => match do_append(&state, &tag, &rest, &mut wr, &mut lines).await {
                Ok(r) => r,
                Err(()) => break,
            },
            "EXPUNGE" => do_expunge(&state, &c, &tag, None),
            "IDLE" => {
                c.idle_tag = Some(tag.clone());
                Reply::text("+ idling\r\n".to_string())
            }
            "UID" => do_uid(&state, &mut c, &tag, &rest),
            "STATUS" => do_status(&state, &tag, &rest),
            other => Reply::text(format!("{tag} BAD unimplemented command {other}\r\n")),
        };
        if wr.write_all(out.bytes.as_bytes()).await.is_err() {
            break;
        }
        if out.close {
            break;
        }
    }
    release(&state);
}

fn release(state: &Shared) {
    let mut s = state.lock().unwrap();
    s.imap_open = s.imap_open.saturating_sub(1);
}

struct Reply {
    bytes: String,
    close: bool,
}

impl Reply {
    fn text(bytes: String) -> Self {
        Self {
            bytes,
            close: false,
        }
    }
}

/// `LOGIN "user" "pass"` — also the place the alias quirk and OAuth-only refusals land.
fn do_login(state: &Shared, c: &mut Conn, tag: &str, rest: &str) -> Reply {
    let (user, pass) = split_two(rest);
    let mut s = state.lock().unwrap();
    match s.quirks.auth.clone() {
        SimAuth::XOAuth2 => {
            s.rejected_logins
                .push((user.clone(), "password auth disabled".into()));
            Reply::text(format!(
                "{tag} NO [AUTHENTICATIONFAILED] Basic authentication is disabled; use OAuth\r\n"
            ))
        }
        SimAuth::Password(expected) => {
            if pass == expected {
                c.authed = true;
                c.login = user;
                Reply::text(format!("{tag} OK LOGIN completed\r\n"))
            } else {
                s.rejected_logins.push((user, "wrong password".into()));
                Reply::text(format!(
                    "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"
                ))
            }
        }
    }
}

/// `AUTHENTICATE XOAUTH2 <base64>` (and `PLAIN`), including the continuation form where the
/// client waits for `+` before sending the payload.
async fn do_authenticate(
    state: &Shared,
    c: &mut Conn,
    tag: &str,
    rest: &str,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    lines: &mut tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
) -> Result<Reply, ()> {
    let mut it = rest.splitn(2, ' ');
    let mech = it.next().unwrap_or("").to_ascii_uppercase();
    let mut payload = it.next().unwrap_or("").trim().to_string();

    let offered = state.lock().unwrap().quirks.capabilities();
    if !offered.contains(&format!("AUTH={mech}")) {
        return Ok(Reply::text(format!(
            "{tag} NO [CANNOT] {mech} is not available\r\n"
        )));
    }
    if payload.is_empty() {
        // Ask for the payload, as a client that sends the mechanism alone expects.
        if wr.write_all(b"+ \r\n").await.is_err() {
            return Err(());
        }
        match lines.next_line().await {
            Ok(Some(l)) => {
                state.lock().unwrap().imap_log[c.idx].push("<auth payload>".into());
                payload = l.trim().to_string();
            }
            _ => return Err(()),
        }
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.as_bytes())
        .unwrap_or_default();
    let decoded = String::from_utf8_lossy(&decoded).into_owned();

    let mut s = state.lock().unwrap();
    match mech.as_str() {
        "XOAUTH2" => {
            // `user=<login>\x01auth=Bearer <token>\x01\x01`
            let user = xoauth2_field(&decoded, "user=");
            let token = xoauth2_field(&decoded, "auth=Bearer ");
            if !s.live_tokens.contains(&token) {
                s.rejected_logins
                    .push((user, "unknown or expired bearer".into()));
                return Ok(Reply::text(format!(
                    "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n"
                )));
            }
            // The Outlook alias quirk: the token is good, the login is an alias of the
            // mailbox, and the server refuses anyway.
            if let Some(primary) = s.quirks.primary_login.clone() {
                if !user.eq_ignore_ascii_case(&primary) {
                    s.rejected_logins.push((
                        user,
                        format!("XOAUTH2 is only accepted for the primary address {primary}"),
                    ));
                    return Ok(Reply::text(format!(
                        "{tag} NO [AUTHENTICATIONFAILED] AUTHENTICATE failed\r\n"
                    )));
                }
            }
            c.authed = true;
            c.login = user;
            Ok(Reply::text(format!(
                "{tag} OK [CAPABILITY {}] AUTHENTICATE completed\r\n",
                s.quirks.capabilities()
            )))
        }
        "PLAIN" => {
            // `\0user\0pass`
            let mut f = decoded.split('\0');
            let _ = f.next();
            let user = f.next().unwrap_or("").to_string();
            let pass = f.next().unwrap_or("").to_string();
            match s.quirks.auth.clone() {
                SimAuth::Password(expected) if pass == expected => {
                    c.authed = true;
                    c.login = user;
                    Ok(Reply::text(format!("{tag} OK AUTHENTICATE completed\r\n")))
                }
                _ => {
                    s.rejected_logins.push((user, "wrong password".into()));
                    Ok(Reply::text(format!(
                        "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"
                    )))
                }
            }
        }
        other => Ok(Reply::text(format!(
            "{tag} NO [CANNOT] {other} unsupported\r\n"
        ))),
    }
}

/// The value after `key` up to the next `\x01` (XOAUTH2's field separator). Shared with the
/// submission side, which parses the same SASL payload.
pub(crate) fn xoauth2_field(s: &str, key: &str) -> String {
    s.split('\x01')
        .find_map(|f| f.strip_prefix(key))
        .unwrap_or("")
        .to_string()
}

fn do_list(state: &Shared, tag: &str) -> Reply {
    let s = state.lock().unwrap();
    let q = &s.quirks;
    let mut out = String::new();
    for f in &q.folders {
        let mut attrs = vec!["\\HasNoChildren".to_string()];
        if q.special_use {
            if let Some(su) = f.special_use {
                attrs.push(su.to_string());
            }
        }
        out.push_str(&format!(
            "* LIST ({}) \"{}\" \"{}\"\r\n",
            attrs.join(" "),
            q.delimiter,
            f.name
        ));
    }
    out.push_str(&format!("{tag} OK LIST completed\r\n"));
    Reply::text(out)
}

fn do_select(state: &Shared, c: &mut Conn, tag: &str, rest: &str, examine: bool) -> Reply {
    let name = rest.trim().trim_matches('"').to_string();
    let s = state.lock().unwrap();
    let Some(key) = s.resolve(&name) else {
        return Reply::text(format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n"));
    };
    let mb = s.folder(&key).expect("resolved");
    let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft";
    let body = format!(
        "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS ({flags})\r\n\
         * OK [PERMANENTFLAGS ({flags} \\*)] limited\r\n\
         * OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] predicted next UID\r\n\
         {tag} OK [{}] {} completed\r\n",
        mb.messages.len(),
        mb.uidvalidity,
        mb.uidnext,
        if examine { "READ-ONLY" } else { "READ-WRITE" },
        if examine { "EXAMINE" } else { "SELECT" },
    );
    drop(s);
    c.selected = Some(key);
    c.read_only = examine;
    Reply::text(body)
}

fn do_create(state: &Shared, tag: &str, rest: &str) -> Reply {
    let name = rest.trim().trim_matches('"').to_string();
    let mut s = state.lock().unwrap();
    if s.resolve(&name).is_some() {
        return Reply::text(format!("{tag} NO [ALREADYEXISTS] Mailbox exists\r\n"));
    }
    s.quirks
        .folders
        .push(crate::quirks::SimFolder::new(name.clone(), None));
    s.append(&name, Vec::new(), Vec::new()); // creates the mailbox entry
    if let Some(mb) = s.folder_mut(&name) {
        mb.messages.clear();
        mb.uidnext = 1;
    }
    Reply::text(format!("{tag} OK CREATE completed\r\n"))
}

fn do_status(state: &Shared, tag: &str, rest: &str) -> Reply {
    let name = rest
        .split('(')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_string();
    let s = state.lock().unwrap();
    let Some(mb) = s.folder(&name) else {
        return Reply::text(format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n"));
    };
    let unseen = mb.messages.iter().filter(|m| !m.has_flag("\\Seen")).count();
    Reply::text(format!(
        "* STATUS \"{name}\" (MESSAGES {} UNSEEN {unseen} UIDNEXT {} UIDVALIDITY {})\r\n\
         {tag} OK STATUS completed\r\n",
        mb.messages.len(),
        mb.uidnext,
        mb.uidvalidity
    ))
}

/// `APPEND folder (flags) {len}` followed by the literal.
async fn do_append(
    state: &Shared,
    tag: &str,
    rest: &str,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    lines: &mut tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
) -> Result<Reply, ()> {
    let folder = first_astring(rest);
    let flags: Vec<String> = match (rest.find('('), rest.find(')')) {
        (Some(a), Some(b)) if b > a => rest[a + 1..b]
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    let len: usize = rest
        .rsplit_once('{')
        .and_then(|(_, n)| n.trim_end_matches('}').trim_end_matches('+').parse().ok())
        .unwrap_or(0);

    {
        let s = state.lock().unwrap();
        if s.resolve(&folder).is_none() {
            return Ok(Reply::text(format!(
                "{tag} NO [TRYCREATE] Mailbox does not exist\r\n"
            )));
        }
    }
    if wr.write_all(b"+ ready for literal data\r\n").await.is_err() {
        return Err(());
    }
    // Read exactly `len` bytes of literal, then the CRLF that ends the command line. The
    // reader is line-based, so re-join the lines it gives back.
    let mut raw = Vec::with_capacity(len);
    while raw.len() < len {
        match lines.next_line().await {
            Ok(Some(l)) => {
                // The reader is line-based, so the CRLF it stripped goes back on; the final
                // truncate below drops any that ran past the declared length.
                raw.extend_from_slice(l.as_bytes());
                raw.extend_from_slice(b"\r\n");
            }
            _ => return Err(()),
        }
    }
    raw.truncate(len);
    let mut s = state.lock().unwrap();
    let uid = s.append(&folder, raw, flags).unwrap_or(0);
    let uidvalidity = s.folder(&folder).map_or(0, |m| m.uidvalidity);
    let uidplus = s.quirks.has_uidplus;
    Ok(Reply::text(if uidplus {
        format!("{tag} OK [APPENDUID {uidvalidity} {uid}] APPEND completed\r\n")
    } else {
        format!("{tag} OK APPEND completed\r\n")
    }))
}

fn do_expunge(state: &Shared, c: &Conn, tag: &str, only: Option<Vec<u32>>) -> Reply {
    let Some(folder) = c.selected.clone() else {
        return Reply::text(format!("{tag} BAD No mailbox selected\r\n"));
    };
    if c.read_only {
        return Reply::text(format!("{tag} NO Mailbox is read-only\r\n"));
    }
    let mut s = state.lock().unwrap();
    if only.is_some() && !s.quirks.has_uidplus {
        return Reply::text(format!("{tag} BAD UID EXPUNGE needs UIDPLUS\r\n"));
    }
    // Sequence numbers, highest first, as RFC 3501 requires for untagged EXPUNGE.
    let before = s.folder(&folder).map(|m| m.uids()).unwrap_or_default();
    let gone = s.expunge(&folder, only.as_deref());
    let mut seqs: Vec<usize> = gone
        .iter()
        .filter_map(|uid| before.iter().position(|u| u == uid).map(|i| i + 1))
        .collect();
    seqs.sort_unstable_by(|a, b| b.cmp(a));
    let mut out = String::new();
    for seq in seqs {
        out.push_str(&format!("* {seq} EXPUNGE\r\n"));
    }
    out.push_str(&format!("{tag} OK EXPUNGE completed\r\n"));
    Reply::text(out)
}

/// Every `UID …` subcommand: SEARCH, FETCH, STORE, COPY, MOVE, EXPUNGE.
fn do_uid(state: &Shared, c: &mut Conn, tag: &str, rest: &str) -> Reply {
    let mut it = rest.splitn(2, ' ');
    let sub = it.next().unwrap_or("").to_ascii_uppercase();
    let args = it.next().unwrap_or("").to_string();
    let Some(folder) = c.selected.clone() else {
        return Reply::text(format!("{tag} BAD No mailbox selected\r\n"));
    };
    match sub.as_str() {
        "SEARCH" => uid_search(state, tag, &folder, &args),
        "FETCH" => uid_fetch(state, tag, &folder, &args),
        "STORE" => uid_store(state, c, tag, &folder, &args),
        "COPY" => uid_copy(state, tag, &folder, &args, false),
        "MOVE" => {
            let has_move = state.lock().unwrap().quirks.has_move;
            if !has_move {
                // What a server without RFC 6851 says, and the reason the client has to fall
                // back to COPY + STORE + EXPUNGE.
                Reply::text(format!("{tag} BAD Unknown command UID MOVE\r\n"))
            } else {
                uid_copy(state, tag, &folder, &args, true)
            }
        }
        "EXPUNGE" => {
            let max = state
                .lock()
                .unwrap()
                .folder(&folder)
                .and_then(|m| m.uids().last().copied())
                .unwrap_or(0);
            do_expunge(state, c, tag, Some(parse_uid_set(&args, max)))
        }
        other => Reply::text(format!("{tag} BAD unimplemented UID {other}\r\n")),
    }
}

fn uid_search(state: &Shared, tag: &str, folder: &str, args: &str) -> Reply {
    let s = state.lock().unwrap();
    let Some(mb) = s.folder(folder) else {
        return Reply::text(format!("{tag} NO [NONEXISTENT] Mailbox gone\r\n"));
    };
    let all = mb.uids();
    let max = all.last().copied().unwrap_or(0);
    let up = args.trim().to_ascii_uppercase();
    let hits: Vec<u32> = if let Some(set) = up.strip_prefix("UID ") {
        let wanted = parse_uid_set(set, max);
        let mut hits: Vec<u32> = all.iter().copied().filter(|u| wanted.contains(u)).collect();
        // RFC 3501's `n:*` quirk: when nothing is at or above `n`, the highest UID matches,
        // because `*` is the highest UID and a range is inclusive of both ends.
        if hits.is_empty() && set.trim().ends_with(":*") {
            hits.extend(all.last().copied());
        }
        hits
    } else if up == "ALL" || up.is_empty() {
        all.clone()
    } else if up == "UNSEEN" {
        mb.messages
            .iter()
            .filter(|m| !m.has_flag("\\Seen"))
            .map(|m| m.uid)
            .collect()
    } else if let Some(hdr) = up
        .strip_prefix("HEADER ")
        .filter(|_| s.quirks.header_search)
    {
        // `HEADER Message-ID "<...>"` — how the send path checks whether submission already
        // filed its own Sent copy before appending one. Case-insensitive substring match on the
        // named header's line, as RFC 3501 §6.4.4 specifies.
        let mut it = hdr.splitn(2, ' ');
        let field = it.next().unwrap_or("").to_string();
        // Take the value from the original, not the upper-cased copy, then compare case-folded.
        let value = args
            .trim()
            .splitn(3, ' ')
            .nth(2)
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase();
        mb.messages
            .iter()
            .filter(|m| {
                let text = String::from_utf8_lossy(&m.raw).to_ascii_lowercase();
                let prefix = format!("{}:", field.to_ascii_lowercase());
                text.split("\r\n\r\n")
                    .next()
                    .unwrap_or("")
                    .lines()
                    .any(|l| l.starts_with(&prefix) && l.contains(&value))
            })
            .map(|m| m.uid)
            .collect()
    } else {
        // Be honest about what is not implemented rather than answering "nothing matched",
        // which a client cannot tell from a real empty result.
        return Reply::text(format!("{tag} BAD unimplemented SEARCH key {up}\r\n"));
    };
    let list: Vec<String> = hits.iter().map(u32::to_string).collect();
    Reply::text(format!(
        "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
        list.join(" ")
    ))
}

fn uid_fetch(state: &Shared, tag: &str, folder: &str, args: &str) -> Reply {
    let (set, items) = args.split_once(' ').unwrap_or((args, ""));
    let up = items.to_ascii_uppercase();
    let want_body = up.contains("BODY") || up.contains("RFC822") && !up.contains("RFC822.SIZE");
    let want_size = up.contains("RFC822.SIZE");
    let want_flags = up.contains("FLAGS");
    let s = state.lock().unwrap();
    let Some(mb) = s.folder(folder) else {
        return Reply::text(format!("{tag} NO [NONEXISTENT] Mailbox gone\r\n"));
    };
    let max = mb.uids().last().copied().unwrap_or(0);
    let mut uids = parse_uid_set(set, max);
    if let Some(limit) = s.quirks.fetch_chunk_limit {
        // The quirk: answer a prefix and a tagged OK, leaving the client to notice and ask
        // again. A client that assumes a complete answer silently loses the rest.
        uids.truncate(limit);
    }
    let mut out = String::new();
    for uid in uids {
        let Some((seq, msg)) = mb
            .messages
            .iter()
            .enumerate()
            .find(|(_, m)| m.uid == uid)
            .map(|(i, m)| (i + 1, m))
        else {
            continue;
        };
        let mut fields = vec![format!("UID {uid}")];
        if want_flags {
            fields.push(format!("FLAGS ({})", msg.flags.join(" ")));
        }
        if want_size {
            fields.push(format!("RFC822.SIZE {}", msg.raw.len()));
        }
        if want_body {
            // The closing paren goes *after* the literal, not on the line that declares its
            // length: `… BODY[] {227}\r\n<227 bytes>)\r\n`. Closing it early produces a
            // response async-imap rejects with a nom TakeWhile1 error rather than a clear
            // message, which is how this was found.
            out.push_str(&format!(
                "* {seq} FETCH ({} BODY[] {{{}}}\r\n",
                fields.join(" "),
                msg.raw.len()
            ));
            out.push_str(&String::from_utf8_lossy(&msg.raw));
            out.push_str(")\r\n");
            continue;
        }
        out.push_str(&format!("* {seq} FETCH ({})\r\n", fields.join(" ")));
    }
    out.push_str(&format!("{tag} OK FETCH completed\r\n"));
    Reply::text(out)
}

fn uid_store(state: &Shared, c: &Conn, tag: &str, folder: &str, args: &str) -> Reply {
    if c.read_only {
        return Reply::text(format!("{tag} NO Mailbox is read-only\r\n"));
    }
    let mut it = args.splitn(2, ' ');
    let set = it.next().unwrap_or("").to_string();
    let rest = it.next().unwrap_or("").to_string();
    let op = rest.split_whitespace().next().unwrap_or("").to_string();
    let flags: Vec<String> = match (rest.find('('), rest.rfind(')')) {
        (Some(a), Some(b)) if b > a => rest[a + 1..b]
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    let silent = op.to_ascii_uppercase().contains("SILENT");
    let mut s = state.lock().unwrap();
    let max = s
        .folder(folder)
        .and_then(|m| m.uids().last().copied())
        .unwrap_or(0);
    let uids = parse_uid_set(&set, max);
    let mut out = String::new();
    for uid in uids {
        let Some(mb) = s.folder_mut(folder) else {
            break;
        };
        let Some(msg) = mb.get_mut(uid) else { continue };
        if op.starts_with('+') {
            for f in &flags {
                if !msg.has_flag(f) {
                    msg.flags.push(f.clone());
                }
            }
        } else if op.starts_with('-') {
            msg.flags
                .retain(|f| !flags.iter().any(|g| g.eq_ignore_ascii_case(f)));
        } else {
            msg.flags = flags.clone();
        }
        if !silent {
            let now = msg.flags.join(" ");
            let seq = mb.messages.iter().position(|m| m.uid == uid).unwrap_or(0) + 1;
            out.push_str(&format!("* {seq} FETCH (UID {uid} FLAGS ({now}))\r\n"));
        }
    }
    out.push_str(&format!("{tag} OK STORE completed\r\n"));
    Reply::text(out)
}

/// `UID COPY set dest` and `UID MOVE set dest`. Under label semantics a copy adds a label, so
/// the message is in both folders at once — which is exactly what the engine has to cope with.
fn uid_copy(state: &Shared, tag: &str, folder: &str, args: &str, move_it: bool) -> Reply {
    let (set, dest) = args.split_once(' ').unwrap_or((args, ""));
    let dest = dest.trim().trim_matches('"').to_string();
    let mut s = state.lock().unwrap();
    if s.resolve(&dest).is_none() {
        return Reply::text(format!("{tag} NO [TRYCREATE] Mailbox does not exist\r\n"));
    }
    let max = s
        .folder(folder)
        .and_then(|m| m.uids().last().copied())
        .unwrap_or(0);
    let uids = parse_uid_set(set, max);
    let mut copied = Vec::new();
    for uid in &uids {
        if let Some(new_uid) = s.copy(folder, *uid, &dest) {
            copied.push((*uid, new_uid));
        }
    }
    if move_it {
        for (uid, _) in &copied {
            if let Some(mb) = s.folder_mut(folder) {
                mb.messages.retain(|m| m.uid != *uid);
            }
        }
    }
    let uidvalidity = s.folder(&dest).map_or(0, |m| m.uidvalidity);
    let srcs: Vec<String> = copied.iter().map(|(a, _)| a.to_string()).collect();
    let dsts: Vec<String> = copied.iter().map(|(_, b)| b.to_string()).collect();
    let verb = if move_it { "MOVE" } else { "COPY" };
    Reply::text(if s.quirks.has_uidplus && !copied.is_empty() {
        format!(
            "{tag} OK [COPYUID {uidvalidity} {} {}] {verb} completed\r\n",
            srcs.join(","),
            dsts.join(",")
        )
    } else {
        format!("{tag} OK {verb} completed\r\n")
    })
}

/// The first IMAP astring of `s`: a quoted string, or the next whitespace-delimited word.
///
/// Splitting on whitespace alone is wrong and was a real bug here: `APPEND "Sent Items" …`
/// yielded `Sent`, which no Outlook, iCloud or Gmail mailbox is called, so every APPEND was
/// answered `TRYCREATE` and silently stored nothing. The engine test for duplicate Sent copies
/// is what caught it.
fn first_astring(s: &str) -> String {
    let t = s.trim_start();
    match t.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or("").to_string(),
        None => t.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// `"a" "b"` or `a b`.
fn split_two(s: &str) -> (String, String) {
    let mut it = s.split_whitespace();
    let a = it.next().unwrap_or("").trim_matches('"').to_string();
    let b = it.next().unwrap_or("").trim_matches('"').to_string();
    (a, b)
}

/// A token the fake IdP would have issued, for tests that do not run the OAuth flow.
pub fn grant_token(state: &Shared, token: &str) {
    state.lock().unwrap().live_tokens.push(token.to_string());
}

/// Convenience for tests: a shared state for one provider.
pub fn shared(quirks: crate::quirks::Quirks) -> Shared {
    Arc::new(Mutex::new(crate::state::SimState::new(quirks)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_folder_name_with_spaces_survives_parsing() {
        assert_eq!(first_astring(r#""Sent Items" (\Seen) {913}"#), "Sent Items");
        assert_eq!(
            first_astring(r#""[Gmail]/All Mail" {12}"#),
            "[Gmail]/All Mail"
        );
        assert_eq!(first_astring("INBOX {5}"), "INBOX");
        assert_eq!(first_astring("  Drafts"), "Drafts");
        assert_eq!(first_astring(""), "");
    }

    #[test]
    fn xoauth2_fields_are_read_out_of_the_sasl_payload() {
        let payload = "user=a@b.test\x01auth=Bearer tok-1\x01\x01";
        assert_eq!(xoauth2_field(payload, "user="), "a@b.test");
        assert_eq!(xoauth2_field(payload, "auth=Bearer "), "tok-1");
        assert_eq!(xoauth2_field(payload, "nope="), "");
    }
}
