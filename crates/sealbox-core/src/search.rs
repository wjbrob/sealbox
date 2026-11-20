//! Message search (engine half): a full-text index over subject, sender, recipients and the
//! decrypted body, queried by [`Engine::search`].
//!
//! **Same protection level as the bodies.** `message_blobs.text_body/html_body/raw` are sealed at
//! rest (G27, `vault.rs`) while subjects and addresses stay plaintext, so an index holding
//! body tokens must never be written to `sealbox.db`. It is an FTS5 table in an in-memory
//! database ATTACHed to the store's connection as `sbx_search`: built lazily by the first
//! search (or [`Engine::rebuild_search_index`]) from the decrypted bodies and then kept
//! current on every path that changes the message rows:
//!
//! * **insert** — `Store::insert_message` calls [`index_inserted`] inside its transaction;
//! * **delete** — a TEMP trigger on `messages` drops the index row, so `delete_message`,
//!   `reset_folder`, the account cascade and raw `DELETE`s elsewhere (recovery) are covered;
//! * **move** — in place (`relocate_message`) only `folder_id`/`uid` change and the folder is
//!   joined at query time; a server-side move is a delete now and an insert at the next sync;
//! * **content update** — TEMP triggers on `messages` (subject, addresses) and on
//!   `message_blobs` (bodies) mark the row dirty, the next search re-indexes it (today only
//!   the vault re-encoding the same plaintext on rewrap does this);
//! * **another connection** (the CLI next to the app) — `PRAGMA data_version` changes and
//!   the next search rebuilds.
//!
//! Plaintext never reaches a sorter or a temp file: the ranking query sorts message ids and
//! scores only, snippets are computed per hit afterwards, and an in-memory database keeps
//! its journal in memory. Memory: [`SearchIndexStats::memory_bytes`] (about 1 KiB per
//! message of typical mail plus the indexed text; see `docs/ARCHITECTURE.md`).
//!
//! Matching: unicode61 tokens, case- and diacritic-insensitive; CJK runs (Han, kana, Hangul)
//! are segmented per character with a zero-width space at index and query time, so a word
//! inside `来週の会議は日本語で` is found as the phrase of its characters (`segment_cjk`). Every word the user typed is
//! a quoted FTS5 phrase (operators and punctuation are literal; `bob@example.org` is the
//! phrase *bob example org*), the last one also matches as a prefix unless the text ends
//! with whitespace, and all words must match. Ranking: bm25 with column weights subject 3,
//! sender 2, recipients 1.5, body 1; equal ranks newest first.

use std::collections::HashMap;

use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::Result;
use crate::store::{NewMessage, Store};
use crate::types::{Address, MessageSummary};

/// Opens a matched term in [`SearchHit::snippet`] (U+E000, private use: never in real text).
pub const MATCH_START: char = '\u{E000}';
/// Closes a matched term in [`SearchHit::snippet`] (U+E001).
pub const MATCH_END: char = '\u{E001}';
/// Body text indexed per message, in bytes (cut at a character boundary). Bounds the memory
/// of the index; words beyond it are not found.
pub const MAX_INDEXED_BODY_BYTES: usize = 32 * 1024;

/// The last word matches as a prefix only when its last token has at least this many
/// characters: shorter prefixes match most of the mailbox and cost a scan of it.
pub const MIN_PREFIX_CHARS: usize = 3;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 500;
const SNIPPET_TOKENS: i64 = 16;
const SCHEMA_NAME: &str = "sbx_search";
/// Column weights, in FTS5 column order (subject, sender, recipients, body).
const RANK_EXPR: &str = "bm25(sbx_search_fts, 3.0, 2.0, 1.5, 1.0)";

const FTS_CREATE: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS sbx_search.sbx_search_fts USING \
     fts5(subject, sender, recipients, body, tokenize = 'unicode61 remove_diacritics 2');";

/// The index database, created right after the ATTACH. The triggers are TEMP (per
/// connection, allowed to reach an attached database) and use unqualified names, which
/// SQLite requires inside trigger bodies; the `sbx_search_` names exist nowhere else.
const INDEX_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sbx_search.sbx_search_dirty (id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS sbx_search.sbx_search_meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TEMP TRIGGER IF NOT EXISTS sbx_search_deleted AFTER DELETE ON main.messages BEGIN
    DELETE FROM sbx_search_fts WHERE rowid = old.id;
    DELETE FROM sbx_search_dirty WHERE id = old.id;
END;
CREATE TEMP TRIGGER IF NOT EXISTS sbx_search_changed
AFTER UPDATE OF subject, from_name, from_addr, to_json, cc_json
ON main.messages BEGIN
    INSERT OR IGNORE INTO sbx_search_dirty (id) VALUES (new.id);
END;
CREATE TEMP TRIGGER IF NOT EXISTS sbx_search_body_changed
AFTER UPDATE OF text_body, html_body
ON main.message_blobs BEGIN
    INSERT OR IGNORE INTO sbx_search_dirty (id) VALUES (new.message_id);
END;
"#;

/// Input of [`Engine::search`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Account address; `None` = every account.
    #[serde(default)]
    pub account: Option<String>,
    /// What the user typed.
    pub text: String,
    /// Folder name (case-insensitive); `None` or `"*"` = every folder.
    #[serde(default)]
    pub folder: Option<String>,
    /// 0 = default (50); at most 500.
    #[serde(default)]
    pub limit: usize,
}

/// One result of [`Engine::search`]; results come best first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    #[serde(flatten)]
    pub summary: MessageSummary,
    /// About 16 words of the body around the best match, whitespace collapsed, matched terms
    /// wrapped in [`MATCH_START`] … [`MATCH_END`]; the start of the body when only the
    /// subject or an address matched; empty when there is no readable body.
    pub snippet: String,
    /// Relevance, higher is better (the negated FTS5 bm25 score). Comparable only within one
    /// result list.
    pub rank: f64,
}

/// The in-memory index after [`Engine::rebuild_search_index`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndexStats {
    /// Messages in the index.
    pub documents: u64,
    /// Size of the in-memory index database (page count × page size).
    pub memory_bytes: u64,
}

// ----- query text ------------------------------------------------------------------------

/// The FTS5 `MATCH` expression for what the user typed, or `None` when no word has a letter
/// or digit. Each word becomes a quoted phrase (FTS5 tokenizes it, so `bob@example.org` is a
/// phrase and `AND`/`NEAR`/`*` are literal), phrases are ANDed, and the last one gets `*`
/// (prefix on its last token) unless the text ends with whitespace or that token is shorter
/// than [`MIN_PREFIX_CHARS`].
pub(crate) fn match_expression(text: &str) -> Option<String> {
    // CJK runs are segmented exactly like the indexed text, so `日本語` becomes the phrase
    // of its three characters (its last token is one character: never a prefix).
    let words: Vec<String> = text
        .split_whitespace()
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .map(|w| segment_cjk(w).into_owned())
        .collect();
    let last = words.len().checked_sub(1)?;
    let last_token_chars = words[last]
        .chars()
        .rev()
        .skip_while(|c| !c.is_alphanumeric())
        .take_while(|c| c.is_alphanumeric())
        .count();
    let prefix = !text.ends_with(char::is_whitespace) && last_token_chars >= MIN_PREFIX_CHARS;
    let mut out = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('"');
        out.push_str(&w.replace('"', "\"\""));
        out.push('"');
        if i == last && prefix {
            out.push('*');
        }
    }
    Some(out)
}

// ----- document text ---------------------------------------------------------------------

/// Runs of whitespace (including newlines and no-break spaces) collapsed to one space.
fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for w in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out
}

/// A character of a script that writes words without spaces (Han, kana, Hangul, bopomofo,
/// the CJK radicals and compatibility blocks). FTS5's `unicode61` tokenizer makes one token
/// of a whole run of them, so a word inside the run could never be found on its own.
pub(crate) fn is_cjk(c: char) -> bool {
    matches!(
        u32::from(c),
        0x1100..=0x11FF
            | 0x2E80..=0x2FDF
            | 0x3040..=0x30FF
            | 0x3100..=0x31FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA960..=0xA97F
            | 0xAC00..=0xD7FF
            | 0xF900..=0xFAFF
            | 0xFF66..=0xFF9F
            | 0x20000..=0x2FA1F
    )
}

/// The separator put between the characters of a CJK run: a zero-width space, which
/// `unicode61` treats as a token boundary (category Cf), renders as nothing, and does not
/// occur in real mail. Real spaces stay real, so Korean word boundaries survive in snippets.
pub(crate) const CJK_SEPARATOR: char = '\u{200B}';

/// `s` with every CJK character made its own token: [`CJK_SEPARATOR`] between two CJK
/// characters and between a CJK character and an adjacent letter or digit (`東京2024`).
/// A phrase query of consecutive characters then finds a word inside a run. Text without
/// CJK characters is returned untouched.
pub(crate) fn segment_cjk(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(is_cjk) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() * 2);
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if let Some(p) = prev {
            let boundary = (is_cjk(c) && p.is_alphanumeric()) || (is_cjk(p) && c.is_alphanumeric());
            if boundary {
                out.push(CJK_SEPARATOR);
            }
        }
        out.push(c);
        prev = Some(c);
    }
    std::borrow::Cow::Owned(out)
}

/// The longest prefix of `s` of at most `max` bytes that ends on a character boundary.
fn prefix_at_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn decode_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let num = name.strip_prefix('#')?;
            let code = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse::<u32>().ok()?,
            };
            char::from_u32(code)
        }
    }
}

/// Searchable text of an HTML body: tags become spaces, `script`/`style` content and
/// comments are dropped, `&amp; &lt; &gt; &quot; &apos; &nbsp;` and numeric references are
/// decoded (other named entities stay as written). Deliberately simple: this is an index,
/// not a renderer.
pub(crate) fn html_to_index_text(html: &str) -> String {
    // ASCII lower-casing keeps every byte offset (and so every char boundary) of `html`.
    let lower = html.to_ascii_lowercase();
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => {
                if lower[i..].starts_with("<!--") {
                    i = lower[i + 4..]
                        .find("-->")
                        .map_or(bytes.len(), |p| i + 4 + p + 3);
                    out.push(' ');
                    continue;
                }
                // `inner_end` is the `>` or the end of input: always a char boundary.
                let (end, inner_end) = match html[i..].find('>') {
                    Some(p) => (i + p + 1, i + p),
                    None => (bytes.len(), bytes.len()),
                };
                let tag = &lower[i + 1..inner_end];
                let name: String = tag
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                i = end;
                if name == "script" || name == "style" {
                    let close = format!("</{name}");
                    i = match lower[end..].find(&close) {
                        Some(p) => {
                            let s = end + p;
                            lower[s..].find('>').map_or(bytes.len(), |q| s + q + 1)
                        }
                        None => bytes.len(),
                    };
                }
                out.push(' ');
            }
            b'&' => {
                let decoded = html[i + 1..]
                    .find(';')
                    .filter(|&p| p <= 10)
                    .and_then(|p| decode_entity(&html[i + 1..i + 1 + p]).map(|c| (c, p)));
                match decoded {
                    Some((c, p)) => {
                        out.push(c);
                        i += p + 2;
                    }
                    None => {
                        out.push('&');
                        i += 1;
                    }
                }
            }
            _ => match html[i..].chars().next() {
                Some(c) => {
                    out.push(c);
                    i += c.len_utf8();
                }
                None => break,
            },
        }
    }
    out
}

/// The body text that goes into the index: the text part, else the stripped HTML part,
/// whitespace collapsed and capped at [`MAX_INDEXED_BODY_BYTES`].
fn index_body(text: Option<&str>, html: Option<&str>) -> String {
    let body = match (text.filter(|t| !t.trim().is_empty()), html) {
        (Some(t), _) => collapse_ws(prefix_at_boundary(t, 2 * MAX_INDEXED_BODY_BYTES)),
        (None, Some(h)) => collapse_ws(&html_to_index_text(prefix_at_boundary(
            h,
            8 * MAX_INDEXED_BODY_BYTES,
        ))),
        (None, None) => String::new(),
    };
    prefix_at_boundary(&body, MAX_INDEXED_BODY_BYTES).to_string()
}

fn person(a: &Address) -> String {
    match a.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => format!("{n} {}", a.address),
        None => a.address.clone(),
    }
}

/// One row of the index.
struct Doc {
    subject: String,
    sender: String,
    recipients: String,
    body: String,
}

impl Doc {
    fn new(
        subject: Option<&str>,
        from: &Address,
        to: &[Address],
        cc: &[Address],
        body: String,
    ) -> Self {
        let recipients = to
            .iter()
            .chain(cc)
            .map(person)
            .collect::<Vec<_>>()
            .join(" ");
        Self {
            subject: segment_cjk(subject.unwrap_or_default()).into_owned(),
            sender: segment_cjk(&person(from)).into_owned(),
            recipients: segment_cjk(&recipients).into_owned(),
            body: segment_cjk(&body).into_owned(),
        }
    }
}

/// Columns an index row is made of, in [`RawDoc::from_row`] order: the message row `m` and
/// its bodies `b` ([`DOC_FROM`]).
const DOC_COLUMNS: &str =
    "m.id, m.subject, m.from_name, m.from_addr, m.to_json, m.cc_json, b.text_body, b.html_body";

/// The rows [`DOC_COLUMNS`] are read from (the bodies live in `message_blobs`, `raw` after
/// them in the same row, so reading them stops before the raw MIME).
const DOC_FROM: &str = "FROM messages m LEFT JOIN message_blobs b ON b.message_id = m.id";

/// Saved drafts' server copies (`draft_copies`) are never indexed: the draft is searched as
/// a draft, not as a message.
const NOT_A_DRAFT_COPY: &str =
    "NOT EXISTS (SELECT 1 FROM draft_copies c WHERE c.message_id = m.id)";

/// A `messages` row as read for the index, bodies still wrapped.
struct RawDoc {
    id: i64,
    subject: Option<String>,
    from_name: Option<String>,
    from_addr: String,
    to_json: String,
    cc_json: String,
    text: Value,
    html: Value,
}

impl RawDoc {
    fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            subject: r.get(1)?,
            from_name: r.get(2)?,
            from_addr: r.get(3)?,
            to_json: r.get(4)?,
            cc_json: r.get(5)?,
            text: r.get(6)?,
            html: r.get(7)?,
        })
    }
}

fn put_doc(conn: &Connection, id: i64, d: &Doc) -> Result<()> {
    // Row ids are reused after deletes (`MAX(id) + 1`): replace, never append.
    conn.prepare_cached("DELETE FROM sbx_search.sbx_search_fts WHERE rowid = ?1")?
        .execute(params![id])?;
    conn.prepare_cached(
        "INSERT INTO sbx_search.sbx_search_fts (rowid, subject, sender, recipients, body) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?
    .execute(params![id, d.subject, d.sender, d.recipients, d.body])?;
    Ok(())
}

// ----- index lifecycle --------------------------------------------------------------------

fn attached(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_database_list WHERE name = ?1)",
        params![SCHEMA_NAME],
        |r| r.get(0),
    )?)
}

/// Commits by *other* connections since this one last looked (`PRAGMA data_version`).
fn data_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA main.data_version", [], |r| r.get(0))?)
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT value FROM sbx_search.sbx_search_meta WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .optional()?)
}

fn meta_set(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO sbx_search.sbx_search_meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Called by `Store::insert_message` (inside its transaction) for the message it just
/// stored as `id`. A no-op until the index exists: the first search indexes everything that
/// is stored by then, this message included.
///
/// Best effort: the index is derived data and must never cost a message. When the row
/// cannot be indexed (say the in-memory database ran out of memory) the failure is logged
/// and the recorded `data_version` dropped, so the next search rebuilds the index.
pub(crate) fn index_inserted(conn: &Connection, id: i64, m: &NewMessage) -> Result<()> {
    if !attached(conn)? {
        return Ok(());
    }
    let body = index_body(m.text.as_deref(), m.html.as_deref());
    let doc = Doc::new(m.subject.as_deref(), &m.from, &m.to, &m.cc, body);
    if let Err(e) = put_doc(conn, id, &doc) {
        tracing::warn!(
            id,
            "search index: message {id} not indexed ({e}); rebuilding at the next search"
        );
        let _ = conn.execute(
            "DELETE FROM sbx_search.sbx_search_meta WHERE key = 'data_version'",
            [],
        );
    }
    Ok(())
}

impl Store {
    /// ATTACH the in-memory index database (idempotent) and create its tables + triggers.
    fn attach_search_index(&self) -> Result<()> {
        let conn = self.conn();
        if !attached(conn)? {
            conn.execute_batch("ATTACH DATABASE ':memory:' AS sbx_search;")?;
        }
        conn.execute_batch(FTS_CREATE)?;
        conn.execute_batch(INDEX_SCHEMA)?;
        Ok(())
    }

    /// The index row of a stored message read with [`DOC_COLUMNS`], bodies decrypted. A body
    /// that does not open (tampered row) is logged and left out; the rest stays searchable.
    fn finish_doc(&self, raw: RawDoc) -> Doc {
        let from = Address {
            name: raw.from_name,
            address: raw.from_addr,
        };
        let to: Vec<Address> = serde_json::from_str(&raw.to_json).unwrap_or_default();
        let cc: Vec<Address> = serde_json::from_str(&raw.cc_json).unwrap_or_default();
        let id = raw.id;
        let rid = id.to_string();
        let v = self.vault();
        let html = raw.html;
        let body = v
            .open_opt_text("messages", "text_body", &rid, raw.text)
            .and_then(|text| match text.filter(|t| !t.trim().is_empty()) {
                Some(t) => Ok(index_body(Some(&t), None)),
                None => v
                    .open_opt_text("messages", "html_body", &rid, html)
                    .map(|h| index_body(None, h.as_deref())),
            })
            .unwrap_or_else(|e| {
                tracing::warn!(id, "search index: body of message {id} left out: {e}");
                String::new()
            });
        Doc::new(raw.subject.as_deref(), &from, &to, &cc, body)
    }

    /// The index row of stored message `id`, `None` when it is gone.
    fn stored_doc(&self, id: i64) -> Result<Option<Doc>> {
        let raw = self
            .conn()
            .prepare_cached(&format!(
                "SELECT {DOC_COLUMNS} {DOC_FROM} WHERE m.id = ?1 AND {NOT_A_DRAFT_COPY}"
            ))?
            .query_row(params![id], RawDoc::from_row)
            .optional()?;
        Ok(raw.map(|r| self.finish_doc(r)))
    }

    /// Rebuild the in-memory index from every stored message (decrypting the bodies), in one
    /// transaction and one pass over `messages` joined with their `message_blobs`.
    pub(crate) fn rebuild_search_index(&self) -> Result<SearchIndexStats> {
        self.attach_search_index()?;
        // Read before the rows: a commit racing the rebuild then only causes another one.
        let version = data_version(self.conn())?;
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch("DROP TABLE IF EXISTS sbx_search.sbx_search_fts;")?;
        tx.execute_batch(FTS_CREATE)?;
        tx.execute("DELETE FROM sbx_search.sbx_search_dirty", [])?;
        let mut documents = 0u64;
        {
            let mut insert = tx.prepare(
                "INSERT INTO sbx_search.sbx_search_fts (rowid, subject, sender, recipients, body) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            let mut stmt = tx.prepare(&format!(
                "SELECT {DOC_COLUMNS} {DOC_FROM} WHERE {NOT_A_DRAFT_COPY}"
            ))?;
            let rows = stmt.query_map([], RawDoc::from_row)?;
            for raw in rows {
                let raw = raw?;
                let id = raw.id;
                let d = self.finish_doc(raw);
                insert.execute(params![id, d.subject, d.sender, d.recipients, d.body])?;
                documents += 1;
            }
        }
        meta_set(&tx, "data_version", version)?;
        tx.commit()?;
        tracing::debug!(documents, "search index rebuilt");
        self.search_index_stats(documents)
    }

    fn search_index_stats(&self, documents: u64) -> Result<SearchIndexStats> {
        let conn = self.conn();
        let pages: i64 = conn.query_row("PRAGMA sbx_search.page_count", [], |r| r.get(0))?;
        let size: i64 = conn.query_row("PRAGMA sbx_search.page_size", [], |r| r.get(0))?;
        Ok(SearchIndexStats {
            documents,
            memory_bytes: u64::try_from(pages.saturating_mul(size)).unwrap_or(0),
        })
    }

    /// Make the index current: build it when missing, rebuild it after another connection
    /// committed or when it is empty while messages exist, re-index dirty rows.
    fn ensure_search_index(&self) -> Result<()> {
        let conn = self.conn();
        if !attached(conn)? {
            self.rebuild_search_index()?;
            return Ok(());
        }
        // Idempotent: re-creates whatever an earlier failure left missing.
        self.attach_search_index()?;
        if meta_get(conn, "data_version")? != Some(data_version(conn)?) {
            tracing::debug!("search index: another connection changed the store; rebuilding");
            self.rebuild_search_index()?;
            return Ok(());
        }
        let indexed: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sbx_search.sbx_search_fts)",
            [],
            |r| r.get(0),
        )?;
        let stored: bool =
            conn.query_row("SELECT EXISTS (SELECT 1 FROM messages)", [], |r| r.get(0))?;
        if !indexed && stored {
            self.rebuild_search_index()?;
            return Ok(());
        }
        let dirty: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT id FROM sbx_search.sbx_search_dirty")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        if dirty.is_empty() {
            return Ok(());
        }
        // Most rows changed (a profile rewrap re-encodes every body): one pass is cheaper.
        let total: i64 = conn.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        if i64::try_from(dirty.len())
            .unwrap_or(i64::MAX)
            .saturating_mul(2)
            > total
        {
            self.rebuild_search_index()?;
            return Ok(());
        }
        let tx = conn.unchecked_transaction()?;
        for id in dirty {
            match self.stored_doc(id)? {
                Some(doc) => put_doc(&tx, id, &doc)?,
                None => {
                    tx.execute(
                        "DELETE FROM sbx_search.sbx_search_fts WHERE rowid = ?1",
                        params![id],
                    )?;
                }
            }
        }
        tx.execute("DELETE FROM sbx_search.sbx_search_dirty", [])?;
        tx.commit()?;
        Ok(())
    }

    /// The search behind [`Engine::search`] (without the G30 decoration).
    pub(crate) fn search_messages(&self, q: &SearchQuery) -> Result<Vec<SearchHit>> {
        let Some(expr) = match_expression(&q.text) else {
            return Ok(Vec::new());
        };
        self.ensure_search_index()?;
        let limit = match q.limit {
            0 => DEFAULT_LIMIT,
            n => n.min(MAX_LIMIT),
        };
        // Only ids and scores are sorted: no plaintext ever sits in a sorter.
        let mut sql = format!(
            "SELECT m.id, {RANK_EXPR} AS score FROM sbx_search.sbx_search_fts \
             JOIN messages m ON m.id = sbx_search_fts.rowid \
             JOIN accounts a ON a.id = m.account_id JOIN folders f ON f.id = m.folder_id \
             WHERE sbx_search_fts MATCH ?"
        );
        let mut args: Vec<Value> = vec![Value::Text(expr.clone())];
        if let Some(acct) = q
            .account
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            sql.push_str(" AND a.email = ? COLLATE NOCASE");
            args.push(Value::Text(acct.to_string()));
        }
        if let Some(folder) = q
            .folder
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty() && *f != "*")
        {
            sql.push_str(" AND f.name = ? COLLATE NOCASE");
            args.push(Value::Text(folder.to_string()));
        }
        sql.push_str(" ORDER BY score, COALESCE(m.date, m.received_at) DESC, m.id DESC LIMIT ?");
        args.push(Value::Integer(i64::try_from(limit).unwrap_or(50)));
        let ranked: Vec<(i64, f64)> = {
            let mut stmt = self.conn().prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        if ranked.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i64> = ranked.iter().map(|(id, _)| *id).collect();
        let mut summaries: HashMap<i64, MessageSummary> = self
            .summaries_by_ids(&ids)?
            .into_iter()
            .map(|s| (s.id, s))
            .collect();
        let mut snippet = self.conn().prepare_cached(
            "SELECT snippet(sbx_search_fts, 3, ?3, ?4, '…', ?5) FROM sbx_search.sbx_search_fts \
             WHERE sbx_search_fts MATCH ?1 AND rowid = ?2",
        )?;
        let (start, end) = (MATCH_START.to_string(), MATCH_END.to_string());
        let mut out = Vec::with_capacity(ranked.len());
        for (id, score) in ranked {
            let Some(summary) = summaries.remove(&id) else {
                continue;
            };
            let text: Option<String> = snippet
                .query_row(params![expr, id, start, end, SNIPPET_TOKENS], |r| r.get(0))
                .optional()?;
            out.push(SearchHit {
                summary,
                snippet: collapse_ws(&text.unwrap_or_default()).replace(CJK_SEPARATOR, ""),
                rank: -score,
            });
        }
        Ok(out)
    }
}

impl Engine {
    /// Search the stored mail: subject, sender and recipient names and addresses, and the
    /// decrypted body (HTML-only bodies tag-stripped). Case- and diacritic-insensitive, every
    /// word must match, the last word also as a prefix; CJK text (Han, kana, Hangul) is found
    /// by any run of consecutive characters; best match first, equal ranks newest first. An unknown `q.account` is [`crate::Error::AccountNotFound`]; text without a
    /// letter or digit returns no hits. The first search of a process builds the in-memory
    /// index (module docs); nothing is sent over the network.
    pub fn search(&self, q: SearchQuery) -> Result<Vec<SearchHit>> {
        if let Some(a) = q.account.as_deref().filter(|a| !a.trim().is_empty()) {
            self.account_row(a)?;
        }
        let mut hits = self.store().search_messages(&q)?;
        self.identity_decorate_messages(hits.iter_mut().map(|h| &mut h.summary)); // G30
        Ok(hits)
    }

    /// Drop and rebuild the in-memory search index from every stored message. Never needed
    /// for correctness (the index follows every change, and the first search builds it);
    /// useful to measure it or to warm it up before the first search.
    pub fn rebuild_search_index(&self) -> Result<SearchIndexStats> {
        self.store().rebuild_search_index()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::store::NewAccount;
    use crate::types::{AuthKind, SignatureSummary};
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn account(store: &Store, email: &str) -> i64 {
        let ep = Endpoint::new("127.0.0.1", 3143, Security::Plain);
        store
            .insert_account(&NewAccount {
                email,
                display_name: "",
                imap: &ep,
                smtp: &ep,
                auth_kind: AuthKind::Password,
                login: email,
                credential: "pw",
            })
            .unwrap()
    }

    fn addr(name: Option<&str>, address: &str) -> Address {
        Address {
            name: name.map(str::to_owned),
            address: address.into(),
        }
    }

    struct Mail<'a> {
        uid: u32,
        subject: &'a str,
        from: Address,
        to: Vec<Address>,
        text: Option<&'a str>,
        html: Option<&'a str>,
        date: i64,
    }

    fn mail<'a>(uid: u32, subject: &'a str, from: &str, text: &'a str) -> Mail<'a> {
        Mail {
            uid,
            subject,
            from: addr(None, from),
            to: vec![addr(Some("Alice Liddell"), "alice@example.org")],
            text: Some(text),
            html: None,
            date: 1_700_000_000 + i64::from(uid),
        }
    }

    fn insert(store: &mut Store, account_id: i64, folder: &str, m: Mail<'_>) -> i64 {
        let folder_id = store.folder(account_id, folder).unwrap().id;
        store
            .insert_message(&NewMessage {
                account_id,
                folder_id,
                uid: m.uid,
                message_id: Some(format!("{}.{}@example.org", m.uid, folder_id)),
                from: m.from,
                to: m.to,
                cc: vec![addr(None, "carol@example.net")],
                subject: Some(m.subject.into()),
                protected_subject: false,
                date: Some(m.date),
                received_at: m.date,
                flags: vec![],
                was_encrypted: true,
                decrypted: true,
                was_signed: false,
                signature: SignatureSummary::default(),
                signatures_json: "[]".into(),
                text: m.text.map(str::to_owned),
                html: m.html.map(str::to_owned),
                in_reply_to: vec![],
                references: vec![],
                decrypt_error: None,
                raw: b"raw".to_vec(),
                attachments: vec![],
            })
            .unwrap()
            .unwrap()
    }

    fn q(text: &str) -> SearchQuery {
        SearchQuery {
            text: text.into(),
            ..Default::default()
        }
    }

    fn ids(store: &Store, query: SearchQuery) -> Vec<i64> {
        store
            .search_messages(&query)
            .unwrap()
            .iter()
            .map(|h| h.summary.id)
            .collect()
    }

    fn keyed() -> (Store, i64) {
        let store = Store::open_in_memory_keyed(&[4u8; 32]).unwrap();
        let a = account(&store, "alice@example.org");
        (store, a)
    }

    #[test]
    fn cjk_text_is_found_by_consecutive_characters_and_snippets_stay_clean() {
        assert_eq!(segment_cjk("plain ascii"), "plain ascii");
        assert_eq!(
            segment_cjk("東京2024年 会議"),
            "東\u{200B}京\u{200B}2024\u{200B}年 会\u{200B}議"
        );
        let (mut store, a) = keyed();
        let jp = insert(
            &mut store,
            a,
            "INBOX",
            mail(
                31,
                "東京2024年の予定",
                "ken@example.jp",
                "来週の会議は日本語で行います。資料は添付します。",
            ),
        );
        let ko = insert(
            &mut store,
            a,
            "INBOX",
            mail(
                32,
                "서울 회의",
                "min@example.kr",
                "다음 주 회의 자료를 보냅니다.",
            ),
        );
        assert_eq!(ids(&store, q("日本語")), vec![jp], "a word inside a run");
        assert_eq!(ids(&store, q("会議")), vec![jp], "two characters of a run");
        assert_eq!(ids(&store, q("東京")), vec![jp], "subject");
        assert_eq!(ids(&store, q("2024")), vec![jp], "a number glued to CJK");
        assert_eq!(ids(&store, q("予定 日本語")), vec![jp], "subject AND body");
        assert!(ids(&store, q("日語")).is_empty(), "not consecutive");
        assert_eq!(ids(&store, q("회의")), vec![ko], "Hangul syllables");
        assert_eq!(ids(&store, q("회의 자료")), vec![ko], "two Korean words");
        assert_eq!(ids(&store, q("자료 회의")), vec![ko], "AND is order-free");
        // Snippets: separators never leak, the matched run is highlighted as one term or
        // character by character, and the real Korean spaces survive.
        let hit = &store.search_messages(&q("日本語")).unwrap()[0];
        assert!(!hit.snippet.contains(CJK_SEPARATOR), "{:?}", hit.snippet);
        let whole = format!("{MATCH_START}日本語{MATCH_END}");
        let each = format!(
            "{MATCH_START}日{MATCH_END}{MATCH_START}本{MATCH_END}{MATCH_START}語{MATCH_END}"
        );
        assert!(
            hit.snippet.contains(&whole) || hit.snippet.contains(&each),
            "{:?}",
            hit.snippet
        );
        assert!(hit.snippet.contains("来週の会議は"), "{:?}", hit.snippet);
        let hit = &store.search_messages(&q("회의")).unwrap()[0];
        assert!(!hit.snippet.contains(CJK_SEPARATOR), "{:?}", hit.snippet);
        assert!(hit.snippet.contains("다음 주 "), "{:?}", hit.snippet);
        assert!(hit.snippet.contains(" 자료를"), "{:?}", hit.snippet);
    }

    #[test]
    fn fts5_is_compiled_into_the_bundled_sqlite() {
        let store = Store::open_in_memory().unwrap();
        let on: i64 = store
            .conn()
            .query_row("SELECT sqlite_compileoption_used('ENABLE_FTS5')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(on, 1);
    }

    #[test]
    fn query_words_become_quoted_phrases_and_the_last_a_prefix() {
        assert_eq!(match_expression("budget").as_deref(), Some("\"budget\"*"));
        assert_eq!(
            match_expression("  Quarterly   budget ").as_deref(),
            Some("\"Quarterly\" \"budget\""),
            "a trailing space ends the last word"
        );
        assert_eq!(
            match_expression("bob@example.org").as_deref(),
            Some("\"bob@example.org\"*")
        );
        assert_eq!(
            match_expression("say \"hi\" AND NEAR(xyz)").as_deref(),
            Some("\"say\" \"\"\"hi\"\"\" \"AND\" \"NEAR(xyz)\"*")
        );
        assert_eq!(match_expression("-- ... !!").as_deref(), None);
        assert_eq!(match_expression("").as_deref(), None);
        assert_eq!(
            match_expression("x -- yes").as_deref(),
            Some("\"x\" \"yes\"*"),
            "punctuation-only words are dropped"
        );
        // A prefix needs MIN_PREFIX_CHARS in the last token of the last word.
        assert_eq!(match_expression("ka").as_deref(), Some("\"ka\""));
        assert_eq!(match_expression("kal").as_deref(), Some("\"kal\"*"));
        assert_eq!(match_expression("bob@ex").as_deref(), Some("\"bob@ex\""));
        assert_eq!(match_expression("bob@exa").as_deref(), Some("\"bob@exa\"*"));
        assert_eq!(match_expression("end.").as_deref(), Some("\"end.\"*"));
    }

    #[test]
    fn html_is_stripped_for_the_index() {
        let t = html_to_index_text(
            "<html><head><style>p{color:red}</style><title>T</title></head>\
             <body><p>Caf&eacute; &amp; <b>bar</b>&nbsp;&#233;t&#xE9;</p><!-- hidden -->\
             <script>var secret = 1;</script><div>end</DIV></body></html>",
        );
        let t = collapse_ws(&t);
        assert_eq!(t, "T Caf&eacute; & bar été end");
        assert!(!t.contains("color") && !t.contains("secret") && !t.contains("hidden"));
        // Broken markup never panics and never loses the text before it.
        assert_eq!(collapse_ws(&html_to_index_text("a <b")), "a");
        assert_eq!(collapse_ws(&html_to_index_text("a <bü")), "a");
        assert_eq!(collapse_ws(&html_to_index_text("a <script>x")), "a");
        assert_eq!(
            collapse_ws(&html_to_index_text("x &#99999999; y &")),
            "x &#99999999; y &"
        );
        assert_eq!(
            collapse_ws(&html_to_index_text("ünï <i>cödé</i>")),
            "ünï cödé"
        );
        assert_eq!(
            index_body(Some("   "), Some("<p>from html</p>")),
            "from html"
        );
        let long = "wörd ".repeat(20_000);
        let cut = index_body(Some(&long), None);
        assert!(cut.len() <= MAX_INDEXED_BODY_BYTES && cut.starts_with("wörd wörd"));
    }

    #[test]
    fn finds_subject_sender_recipients_and_body_case_and_accent_insensitively() {
        let (mut store, a) = keyed();
        let budget = insert(
            &mut store,
            a,
            "INBOX",
            Mail {
                from: addr(Some("Bob Builder"), "bob@example.org"),
                ..mail(
                    1,
                    "Quarterly numbers",
                    "",
                    "The zanzibar budget is due on Friday. Café later?",
                )
            },
        );
        let html = insert(
            &mut store,
            a,
            "INBOX",
            Mail {
                text: None,
                html: Some("<p>Meet at the <b>lighthouse</b></p><script>tracker()</script>"),
                ..mail(2, "Plans", "dave@example.com", "")
            },
        );
        let other = insert(
            &mut store,
            a,
            "INBOX",
            mail(3, "Lunch", "erin@example.com", "pizza today"),
        );
        assert_eq!(ids(&store, q("zanzibar")), vec![budget], "body word");
        assert_eq!(ids(&store, q("ZANZIBAR")), vec![budget], "case");
        assert_eq!(ids(&store, q("cafe")), vec![budget], "diacritics");
        assert_eq!(ids(&store, q("quarterly")), vec![budget], "subject");
        assert_eq!(ids(&store, q("Builder")), vec![budget], "sender name");
        assert_eq!(ids(&store, q("bob@example.org")), vec![budget], "address");
        assert_eq!(ids(&store, q("lighthouse")), vec![html], "stripped HTML");
        assert!(ids(&store, q("tracker")).is_empty(), "script content");
        assert_eq!(
            ids(&store, q("zanzi")),
            vec![budget],
            "prefix on the last word"
        );
        assert!(
            ids(&store, q("zanzi ")).is_empty(),
            "no prefix after a space"
        );
        assert!(
            ids(&store, q("zanzi budget")).is_empty(),
            "only the last word is a prefix"
        );
        assert_eq!(ids(&store, q("budget friday")), vec![budget], "AND");
        assert!(
            ids(&store, q("budget pizza")).is_empty(),
            "every word must match"
        );
        // Recipients: every message is to Alice and cc Carol.
        assert_eq!(ids(&store, q("liddell")).len(), 3);
        assert_eq!(ids(&store, q("carol@example.net")).len(), 3);
        assert_eq!(ids(&store, q("pizza")), vec![other]);
        // FTS5 syntax is literal, never an error.
        for t in [
            "\"", "AND", "NEAR(", "a OR b", "x*", "(", "^budget", "col:x",
        ] {
            store.search_messages(&q(t)).unwrap();
        }
        assert!(store.search_messages(&q("  ... ")).unwrap().is_empty());
        // Snippet: the matched term highlighted, whitespace collapsed.
        let hit = &store.search_messages(&q("friday")).unwrap()[0];
        assert!(
            hit.snippet
                .contains(&format!("{MATCH_START}Friday{MATCH_END}")),
            "{:?}",
            hit.snippet
        );
        assert!(hit.rank > 0.0);
        // Only the subject matched: the snippet is the start of the body.
        let hit = &store.search_messages(&q("lunch")).unwrap()[0];
        assert_eq!(hit.snippet, "pizza today");
    }

    #[test]
    fn ranking_prefers_the_subject_and_ties_are_newest_first() {
        let (mut store, a) = keyed();
        let body_only = insert(
            &mut store,
            a,
            "INBOX",
            mail(1, "hello", "x@example.org", "the meteor shower tonight"),
        );
        let in_subject = insert(
            &mut store,
            a,
            "INBOX",
            mail(2, "meteor shower", "x@example.org", "see subject"),
        );
        assert_eq!(ids(&store, q("meteor")), vec![in_subject, body_only]);
        // Identical documents: newest first, then the higher id.
        let older = insert(&mut store, a, "INBOX", mail(10, "same", "y@x.org", "same"));
        let newer = insert(&mut store, a, "INBOX", mail(20, "same", "y@x.org", "same"));
        let mut tied = mail(30, "same", "y@x.org", "same");
        tied.date = 1_700_000_020; // same date as `newer`
        let tied = insert(&mut store, a, "INBOX", tied);
        assert_eq!(ids(&store, q("same")), vec![tied, newer, older]);
        let hits = store.search_messages(&q("same")).unwrap();
        assert_eq!(hits[0].rank, hits[2].rank);
        // Limit: 0 = default, otherwise honoured.
        let mut lim = q("same");
        lim.limit = 2;
        assert_eq!(ids(&store, lim), vec![tied, newer]);
    }

    #[test]
    fn filters_by_account_and_folder() {
        let (mut store, a) = keyed();
        let b = account(&store, "bob@example.org");
        let a_inbox = insert(&mut store, a, "INBOX", mail(1, "kiwi", "x@y.org", "fruit"));
        let a_sent = insert(&mut store, a, "Sent", mail(1, "kiwi", "x@y.org", "fruit"));
        let b_inbox = insert(&mut store, b, "INBOX", mail(1, "kiwi", "x@y.org", "fruit"));
        let mut all = ids(&store, q("kiwi"));
        all.sort();
        assert_eq!(all, vec![a_inbox, a_sent, b_inbox]);
        let by = |account: Option<&str>, folder: Option<&str>| {
            let mut v = ids(
                &store,
                SearchQuery {
                    account: account.map(str::to_owned),
                    folder: folder.map(str::to_owned),
                    ..q("kiwi")
                },
            );
            v.sort();
            v
        };
        assert_eq!(by(Some("ALICE@example.org"), None), vec![a_inbox, a_sent]);
        assert_eq!(by(None, Some("inbox")), vec![a_inbox, b_inbox]);
        assert_eq!(by(Some("bob@example.org"), Some("Sent")), Vec::<i64>::new());
        assert_eq!(by(None, Some("*")), vec![a_inbox, a_sent, b_inbox]);
    }

    #[test]
    fn index_follows_inserts_deletes_moves_cascades_and_row_id_reuse() {
        let (mut store, a) = keyed();
        let first = insert(&mut store, a, "INBOX", mail(1, "alpha", "x@y.org", "one"));
        assert_eq!(ids(&store, q("alpha")), vec![first]); // builds the index
                                                          // Insert after the build: indexed by the hook in `insert_message`.
        let second = insert(&mut store, a, "INBOX", mail(2, "beta", "x@y.org", "two"));
        assert_eq!(ids(&store, q("beta")), vec![second]);
        // A move in place (spam.rs): the folder is joined at query time.
        let junk = store.folder(a, "Junk").unwrap().id;
        store.relocate_message(second, junk, 7, &[]).unwrap();
        let in_folder = |store: &Store, f: &str| {
            ids(
                store,
                SearchQuery {
                    folder: Some(f.into()),
                    ..q("beta")
                },
            )
        };
        assert_eq!(in_folder(&store, "Junk"), vec![second]);
        assert!(in_folder(&store, "INBOX").is_empty());
        // Delete, then reuse of the row id (`MAX(id) + 1`) by an unrelated message.
        store.delete_message(second).unwrap();
        assert!(ids(&store, q("beta")).is_empty());
        let reused = insert(&mut store, a, "INBOX", mail(3, "gamma", "x@y.org", "three"));
        assert_eq!(reused, second, "the store reuses the highest row id");
        assert!(ids(&store, q("beta")).is_empty(), "no stale document");
        assert_eq!(ids(&store, q("gamma")), vec![reused]);
        // Raw DELETE from another module (recovery.rs) and a UIDVALIDITY reset.
        store
            .conn()
            .execute("DELETE FROM messages WHERE id = ?1", params![reused])
            .unwrap();
        let count = |store: &Store| -> i64 {
            store
                .conn()
                .query_row("SELECT count(*) FROM sbx_search.sbx_search_fts", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_eq!(count(&store), 1);
        let inbox = store.folder(a, "INBOX").unwrap();
        store.reset_folder(inbox.id, 99).unwrap();
        assert_eq!(count(&store), 0);
        assert!(ids(&store, q("alpha")).is_empty());
        // Removing the account cascades through the trigger too.
        let kept = insert(&mut store, a, "INBOX", mail(4, "delta", "x@y.org", "four"));
        assert_eq!(ids(&store, q("delta")), vec![kept]);
        store.delete_account(a).unwrap();
        assert_eq!(count(&store), 0);
    }

    #[test]
    fn changed_rows_are_reindexed_and_tampered_bodies_left_out() {
        let (mut store, a) = keyed();
        let id = insert(
            &mut store,
            a,
            "INBOX",
            mail(1, "old title", "x@y.org", "body"),
        );
        let other = insert(
            &mut store,
            a,
            "INBOX",
            mail(2, "other", "x@y.org", "corpus"),
        );
        assert_eq!(ids(&store, q("old")), vec![id]);
        store
            .conn()
            .execute(
                "UPDATE messages SET subject = 'new title' WHERE id = ?1",
                params![id],
            )
            .unwrap();
        assert!(ids(&store, q("old")).is_empty());
        assert_eq!(ids(&store, q("new")), vec![id]);
        // A body that no longer opens (moved ciphertext) does not break search.
        store
            .conn()
            .execute(
                "UPDATE message_blobs SET text_body = \
                 (SELECT text_body FROM message_blobs WHERE message_id = ?1) WHERE message_id = ?2",
                params![id, other],
            )
            .unwrap();
        assert!(ids(&store, q("corpus")).is_empty());
        assert_eq!(ids(&store, q("other")), vec![other]);
        assert_eq!(ids(&store, q("body")), vec![id]);
    }

    #[test]
    fn search_survives_a_profile_rewrap() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |k: u8| crate::engine::EngineConfig {
            profile_key: crate::vault::ProfileKeySource::Raw(vec![k; 32]),
            ..crate::engine::EngineConfig::default()
        };
        let engine = Engine::open_with(dir.path(), cfg(1)).unwrap();
        let ids: Vec<i64> = {
            let mut store = engine.store();
            let a = account(&store, "alice@example.org");
            (1..=3)
                .map(|uid| insert(&mut store, a, "INBOX", mail(uid, "s", "x@y.org", "orchid")))
                .collect()
        };
        let found = |e: &Engine| -> Vec<i64> {
            let mut v: Vec<i64> = e
                .search(q("orchid"))
                .unwrap()
                .iter()
                .map(|h| h.summary.id)
                .collect();
            v.sort();
            v
        };
        assert_eq!(found(&engine), ids);
        // Every body is re-encrypted under the new key: all rows dirty, rebuilt in one pass
        // with the new key.
        engine
            .rewrap_profile(crate::vault::ProfileKeySource::Raw(vec![2; 32]))
            .unwrap();
        let dirty: i64 = engine
            .store()
            .conn()
            .query_row(
                "SELECT count(*) FROM sbx_search.sbx_search_dirty",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dirty, 3, "the content trigger saw the re-encryption");
        assert_eq!(found(&engine), ids);
        drop(engine);
        assert_eq!(found(&Engine::open_with(dir.path(), cfg(2)).unwrap()), ids);
    }

    /// The index is a cache: failing to index a new message never fails storing it, and the
    /// next search rebuilds what is missing.
    #[test]
    fn an_indexing_failure_never_costs_the_message() {
        let (mut store, a) = keyed();
        insert(&mut store, a, "INBOX", mail(1, "first", "x@y.org", "one"));
        assert_eq!(ids(&store, q("first")).len(), 1);
        store
            .conn()
            .execute_batch("DROP TABLE sbx_search.sbx_search_fts;")
            .unwrap();
        let second = insert(&mut store, a, "INBOX", mail(2, "second", "x@y.org", "two"));
        assert_eq!(ids(&store, q("second")), vec![second], "rebuilt");
        assert_eq!(ids(&store, q("first")).len(), 1);
    }

    #[test]
    fn another_connection_commit_triggers_a_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.db");
        let mut writer = Store::open(&path).unwrap();
        let reader = Store::open(&path).unwrap();
        let a = account(&writer, "alice@example.org");
        let first = insert(&mut writer, a, "INBOX", mail(1, "alpha", "x@y.org", "one"));
        assert_eq!(ids(&reader, q("alpha")), vec![first]);
        let second = insert(&mut writer, a, "INBOX", mail(2, "beta", "x@y.org", "two"));
        assert_eq!(
            ids(&reader, q("beta")),
            vec![second],
            "rebuilt after data_version"
        );
        writer.delete_message(first).unwrap();
        assert!(ids(&reader, q("alpha")).is_empty());
    }

    #[test]
    fn the_index_is_in_memory_and_body_words_never_reach_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealbox.db");
        let mut store = Store::open(&path).unwrap();
        store.set_vault(crate::vault::Vault::with_master(&[8u8; 32]).unwrap());
        let a = account(&store, "alice@example.org");
        let word = "xylophonequartz";
        insert(
            &mut store,
            a,
            "INBOX",
            mail(1, "subject", "x@y.org", &format!("a {word} b")),
        );
        let hits = store.search_messages(&q(word)).unwrap();
        assert_eq!(hits.len(), 1);
        // A word only in the index (inserted after the build) as well.
        let late = "zebrafinchmarble";
        insert(
            &mut store,
            a,
            "INBOX",
            mail(2, "later", "x@y.org", &format!("c {late} d")),
        );
        assert_eq!(store.search_messages(&q(late)).unwrap().len(), 1);
        let file: String = store
            .conn()
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name = 'sbx_search'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(file, "", "sbx_search must be an in-memory database");
        store
            .conn()
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .unwrap();
        let mut on_disk = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            on_disk.extend(std::fs::read(entry.unwrap().path()).unwrap());
        }
        assert!(!on_disk.is_empty());
        for needle in [word, late] {
            assert!(
                !on_disk
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes()),
                "{needle} found on disk"
            );
        }
        // Positive control: the plaintext subject is found by the same scan.
        assert!(on_disk.windows(5).any(|w| w == b"later"));
    }

    #[test]
    fn engine_search_checks_the_account_and_rebuild_reports_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), crate::engine::EngineConfig::default()).unwrap();
        let id = {
            let mut store = engine.store();
            let a = account(&store, "alice@example.org");
            insert(&mut store, a, "INBOX", mail(1, "hello", "x@y.org", "world"))
        };
        let hits = engine.search(q("world")).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].summary.id, id);
        assert_eq!(hits[0].summary.account, "alice@example.org");
        let err = engine
            .search(SearchQuery {
                account: Some("nobody@example.org".into()),
                ..q("world")
            })
            .unwrap_err();
        assert!(matches!(err, crate::Error::AccountNotFound(_)), "{err}");
        let stats = engine.rebuild_search_index().unwrap();
        assert_eq!(stats.documents, 1);
        assert!(stats.memory_bytes > 0);
        // JSON: the summary is flattened like `MessageDetail`.
        let v = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(v["id"], id);
        assert!(v["snippet"].is_string() && v["rank"].is_number());
    }

    /// 10 000 synthetic messages with Zipf-ish bodies (60–180 words), written straight into
    /// `messages` with sealed bodies (`insert_message` per row costs ~25 s in a debug build:
    /// its thread lookup scans every stored row). Times the first search, which builds the
    /// index from the sealed bodies, and warm queries; the assertion is the < 1 s bound.
    /// `--nocapture` prints the numbers.
    #[test]
    fn ten_thousand_messages_are_searched_in_under_a_second() {
        const N: i64 = 10_000;
        let (mut store, a) = keyed();
        let folder_id = store.folder(a, "INBOX").unwrap().id;
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let syll = ["ka", "lo", "mi", "ne", "su", "ta", "ri", "po", "de", "fu"];
        let vocab: Vec<String> = (1..=3000usize)
            .map(|mut n| {
                let mut w = String::new();
                while n > 0 {
                    w.push_str(syll[n % 10]);
                    n /= 10;
                }
                w
            })
            .collect();
        let started = Instant::now();
        let mut body_bytes = 0usize;
        {
            let tx = store.conn().unchecked_transaction().unwrap();
            for id in 1..=N {
                let words = 60 + (rnd() % 121) as usize;
                let mut body = String::new();
                for _ in 0..words {
                    // Squaring skews towards the head of the vocabulary (frequent words).
                    let r = (rnd() % 1000) as usize;
                    body.push_str(&vocab[r * r * vocab.len() / 1_000_000]);
                    body.push(' ');
                }
                if id == N / 2 {
                    body.push_str("needleword");
                }
                body_bytes += body.len();
                let rid = id.to_string();
                let text = store
                    .vault()
                    .seal_text("messages", "text_body", &rid, &body)
                    .unwrap();
                let raw = store
                    .vault()
                    .seal_blob("messages", "raw", &rid, b"r")
                    .unwrap();
                tx.execute(
                    "INSERT INTO messages (id, account_id, folder_id, uid, message_id, from_name, \
                     from_addr, to_json, subject, date, received_at, raw_size, thread_id) \
                     VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?7, ?8, ?9, ?9, 1, ?4)",
                    params![
                        id,
                        a,
                        folder_id,
                        format!("{id}@synthetic"),
                        format!("User {}", rnd() % 200),
                        format!("user{}@example.org", rnd() % 200),
                        "[{\"address\":\"alice@example.org\"}]",
                        format!("{} {id}", vocab[(rnd() % 3000) as usize]),
                        1_700_000_000 + id,
                    ],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO message_blobs (message_id, text_body, raw) VALUES (?1, ?2, ?3)",
                    params![id, text, raw],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let setup = started.elapsed();
        let t = Instant::now();
        let hits = store.search_messages(&q("needleword")).unwrap();
        let cold = t.elapsed();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].summary.id, N / 2);
        let stats = store.search_index_stats(N as u64).unwrap();
        let common = vocab[0].clone(); // the most frequent word, two letters: exact match
        let mut timings = Vec::new();
        for text in [
            "needleword",
            common.as_str(),
            "kalo",
            "kal",
            "ka",
            "lo mine",
        ] {
            let t = Instant::now();
            let hits = store.search_messages(&q(text)).unwrap();
            timings.push((text.to_string(), hits.len(), t.elapsed()));
        }
        eprintln!(
            "search 10k: setup {setup:?}; first search incl. index build {cold:?}; index \
             {} documents, {:.1} MiB in memory ({} bytes per message, {:.2} bytes per byte of \
             body text); warm: {timings:?}",
            stats.documents,
            stats.memory_bytes as f64 / (1024.0 * 1024.0),
            stats.memory_bytes / N as u64,
            stats.memory_bytes as f64 / body_bytes as f64
        );
        for (text, _, took) in &timings {
            assert!(*took < Duration::from_secs(1), "{text}: {took:?}");
        }
        assert_eq!(timings[1].1, 50, "the common word fills a page of results");
        // Inserted after the build: the hook keeps a 10k index current.
        let late = insert(
            &mut store,
            a,
            "INBOX",
            mail(20_000, "late arrival", "z@example.org", "afterthought"),
        );
        assert_eq!(ids(&store, q("afterthought")), vec![late]);
    }
}
