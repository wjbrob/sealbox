//! `sealbox search "<text>"` — full-text search of the stored mail (engine: `search.rs`).
//! `--json` prints the engine's `SearchHit` list (the summary fields flattened, plus
//! `snippet` with the matched terms between U+E000 and U+E001, and `rank`, higher = better).

use std::path::Path;

use clap::Args;
use sealbox_core::{Engine, SearchHit, SearchQuery, MATCH_END, MATCH_START};

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// What to look for. Every word must match (subject, sender and recipient names and
    /// addresses, decrypted body), case- and accent-insensitive; the last word also matches
    /// as a prefix when it has 3+ characters and the text does not end with a space
    pub text: String,
    /// Only this account (default: every account)
    #[arg(long)]
    pub account: Option<String>,
    /// Only this folder name (default: every folder)
    #[arg(long)]
    pub folder: Option<String>,
    /// At most this many results, best first (max 500)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

/// The snippet as plain text: matched terms in `[…]`.
fn plain_snippet(s: &str) -> String {
    s.replace(MATCH_START, "[").replace(MATCH_END, "]")
}

fn print_hits(hits: &[SearchHit]) {
    if hits.is_empty() {
        println!("(no matches)");
        return;
    }
    for h in hits {
        let m = &h.summary;
        let from = m
            .from
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&m.from.address);
        println!(
            "{:>5} {:<4} {}  {:<24} {:<12} {}",
            m.id,
            crate::status_icons(m),
            crate::fmt_date(m.date),
            crate::truncate(from, 24),
            crate::truncate(&m.folder, 12),
            m.subject.as_deref().unwrap_or("(no subject)")
        );
        if !h.snippet.is_empty() {
            println!("        {}", plain_snippet(&h.snippet));
        }
    }
}

pub fn run(profile: &Path, json: bool, a: SearchArgs) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let hits = engine.search(SearchQuery {
        account: a.account,
        text: a.text,
        folder: a.folder,
        limit: a.limit,
    })?;
    if json {
        return crate::print_json(&hits);
    }
    print_hits(&hits);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_markers_become_brackets() {
        let s = format!("the {MATCH_START}budget{MATCH_END} is due");
        assert_eq!(plain_snippet(&s), "the [budget] is due");
    }
}
