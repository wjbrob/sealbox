//! User filter rules (gate G25): storage per account, the engine API the CLI / UI use, and
//! the application of a [`FilterOutcome`] on the server (flags, move). Matching semantics are
//! in `sealbox_spam::filters`; the hook in `spam.rs` runs the rules after classification
//! (spam first — user rules never see spam).

use rusqlite::{params, OptionalExtension};
use sealbox_mail::imap::{FlagOp as ImapFlagOp, ImapClient};
use sealbox_spam::features;
use sealbox_spam::filters::{
    apply_rules, rule_matches, FilterAction, FilterField, FilterOutcome, FilterRule, MessageFacts,
};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::{now, AccountRow, FolderRow, MessageRow, Store};

/// What `apply_filter_outcome` did on the server.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterApplied {
    pub moved_to: Option<String>,
    pub flags_added: Vec<String>,
}

/// Result of [`Engine::test_filter_rules`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterTestReport {
    pub message_id: i64,
    pub outcome: FilterOutcome,
    /// `(rule id, description, matched)` for every enabled rule, in evaluation order.
    pub rules: Vec<(i64, String, bool)>,
}

fn map_err(e: sealbox_spam::Error) -> Error {
    Error::InvalidInput(e.to_string())
}

/// [`FilterRule::validate`] plus the checks `sealbox filter add` applies while parsing typed
/// input: a `header:` field needs a header name and an `AddFlag` flag must be a plain IMAP
/// flag (no spaces, parentheses, quotes, wildcards). A rule assembled field by field — the
/// Flutter bridge — must not store what the CLI would refuse (the flag ends up in a `STORE`).
fn validate_rule(rule: &FilterRule) -> Result<()> {
    rule.validate().map_err(map_err)?;
    rule.matcher
        .field
        .to_string()
        .parse::<FilterField>()
        .map_err(map_err)?;
    rule.action
        .to_string()
        .parse::<FilterAction>()
        .map_err(map_err)?;
    Ok(())
}

impl Store {
    pub(crate) fn list_filter_rules(&self, account_id: i64) -> Result<Vec<FilterRule>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, ord, enabled, json FROM filter_rules WHERE account_id = ?1 ORDER BY ord, id",
        )?;
        let rows = stmt.query_map(params![account_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, ord, enabled, json) = r?;
            match serde_json::from_str::<FilterRule>(&json) {
                Ok(mut rule) => {
                    rule.id = id;
                    rule.order = i32::try_from(ord).unwrap_or(0);
                    rule.enabled = enabled;
                    out.push(rule);
                }
                Err(e) => tracing::warn!(id, "unreadable filter rule skipped: {e}"),
            }
        }
        Ok(out)
    }

    pub(crate) fn insert_filter_rule(&self, account_id: i64, rule: &FilterRule) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO filter_rules (account_id, ord, enabled, json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account_id,
                i64::from(rule.order),
                rule.enabled,
                serde_json::to_string(rule)?,
                now()
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub(crate) fn update_filter_rule(&self, account_id: i64, rule: &FilterRule) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE filter_rules SET ord = ?1, enabled = ?2, json = ?3 WHERE id = ?4 AND account_id = ?5",
            params![
                i64::from(rule.order),
                rule.enabled,
                serde_json::to_string(rule)?,
                rule.id,
                account_id
            ],
        )?;
        Ok(n > 0)
    }

    pub(crate) fn delete_filter_rule(&self, account_id: i64, id: i64) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM filter_rules WHERE id = ?1 AND account_id = ?2",
            params![id, account_id],
        )?;
        Ok(n > 0)
    }

    fn max_filter_order(&self, account_id: i64) -> Result<i32> {
        let m: Option<i64> = self
            .conn()
            .query_row(
                "SELECT MAX(ord) FROM filter_rules WHERE account_id = ?1",
                params![account_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        Ok(m.and_then(|v| i32::try_from(v).ok()).unwrap_or(0))
    }
}

impl Engine {
    /// The account's filter rules in evaluation order.
    pub fn filter_rules(&self, email: &str) -> Result<Vec<FilterRule>> {
        let acct = self.account_row(email)?;
        self.store().list_filter_rules(acct.id)
    }

    /// Validate and store a rule. `order == 0` appends it after the existing rules.
    pub fn add_filter_rule(&self, email: &str, mut rule: FilterRule) -> Result<FilterRule> {
        let acct = self.account_row(email)?;
        validate_rule(&rule)?;
        let store = self.store();
        if rule.order == 0 {
            rule.order = store.max_filter_order(acct.id)?.saturating_add(10);
        }
        rule.id = store.insert_filter_rule(acct.id, &rule)?;
        Ok(rule)
    }

    /// Replace every rule of the account with `rules`, in the order given (a rules editor
    /// saving its whole list). All rules are validated first; nothing changes when one is
    /// invalid. Ids are reassigned and `order` becomes 10, 20, … by position. Returns the
    /// stored rules.
    pub fn set_filter_rules(&self, email: &str, rules: Vec<FilterRule>) -> Result<Vec<FilterRule>> {
        let acct = self.account_row(email)?;
        for r in &rules {
            validate_rule(r)?;
        }
        let store = self.store();
        let tx = store.conn().unchecked_transaction()?;
        tx.execute(
            "DELETE FROM filter_rules WHERE account_id = ?1",
            params![acct.id],
        )?;
        let created = now();
        let mut out = Vec::with_capacity(rules.len());
        for (i, mut rule) in rules.into_iter().enumerate() {
            rule.order = i32::try_from((i + 1) * 10).unwrap_or(i32::MAX);
            tx.execute(
                "INSERT INTO filter_rules (account_id, ord, enabled, json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    acct.id,
                    i64::from(rule.order),
                    rule.enabled,
                    serde_json::to_string(&rule)?,
                    created
                ],
            )?;
            rule.id = tx.last_insert_rowid();
            out.push(rule);
        }
        tx.commit()?;
        Ok(out)
    }

    /// Replace a stored rule (same id).
    pub fn update_filter_rule(&self, email: &str, rule: FilterRule) -> Result<FilterRule> {
        let acct = self.account_row(email)?;
        validate_rule(&rule)?;
        if !self.store().update_filter_rule(acct.id, &rule)? {
            return Err(Error::InvalidInput(format!(
                "no filter rule {} for {email}",
                rule.id
            )));
        }
        Ok(rule)
    }

    /// Delete a rule; `Ok(false)` when there was none.
    pub fn remove_filter_rule(&self, email: &str, id: i64) -> Result<bool> {
        let acct = self.account_row(email)?;
        self.store().delete_filter_rule(acct.id, id)
    }

    /// Enable / disable a rule.
    pub fn set_filter_rule_enabled(
        &self,
        email: &str,
        id: i64,
        enabled: bool,
    ) -> Result<FilterRule> {
        let acct = self.account_row(email)?;
        let mut rule = self
            .store()
            .list_filter_rules(acct.id)?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| Error::InvalidInput(format!("no filter rule {id} for {email}")))?;
        rule.enabled = enabled;
        self.store().update_filter_rule(acct.id, &rule)?;
        Ok(rule)
    }

    /// Dry run of the account's rules against a stored message (nothing is changed).
    pub fn test_filter_rules(&self, email: &str, message_id: i64) -> Result<FilterTestReport> {
        let acct = self.account_row(email)?;
        let (rules, raw) = {
            let store = self.store();
            let row = store.message(message_id)?;
            if row.account_id != acct.id {
                return Err(Error::InvalidInput(format!(
                    "message {message_id} does not belong to {email}"
                )));
            }
            (
                store.list_filter_rules(acct.id)?,
                store.message_raw(message_id)?,
            )
        };
        let f = features::extract(&raw).map_err(map_err)?;
        let facts = MessageFacts::from_features(&f);
        let outcome = apply_rules(&rules, &facts);
        let mut sorted: Vec<&FilterRule> = rules.iter().filter(|r| r.enabled).collect();
        sorted.sort_by_key(|r| (r.order, r.id));
        let report_rules = sorted
            .into_iter()
            .map(|r| (r.id, r.describe(), rule_matches(r, &facts).unwrap_or(false)))
            .collect();
        Ok(FilterTestReport {
            message_id,
            outcome,
            rules: report_rules,
        })
    }

    /// Dry run of the account's rules against raw bytes (for `filter test --file`).
    pub fn test_filter_rules_raw(&self, email: &str, raw: &[u8]) -> Result<FilterOutcome> {
        let acct = self.account_row(email)?;
        let rules = self.store().list_filter_rules(acct.id)?;
        let f = features::extract(raw).map_err(map_err)?;
        Ok(apply_rules(&rules, &MessageFacts::from_features(&f)))
    }

    /// Perform a [`FilterOutcome`] on an open session: flags first (`\Seen` for mark-read,
    /// `\Flagged` for star, custom flags), then the move (creating the folder when missing).
    pub(crate) async fn apply_filter_outcome(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        row: &MessageRow,
        folder: &FolderRow,
        outcome: &FilterOutcome,
    ) -> Result<FilterApplied> {
        let mut applied = FilterApplied::default();
        let mut flags: Vec<String> = outcome.add_flags.clone();
        if outcome.mark_read && !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")) {
            flags.push("\\Seen".into());
        }
        if outcome.star && !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")) {
            flags.push("\\Flagged".into());
        }
        flags.retain(|f| !row.summary.flags.iter().any(|x| x.eq_ignore_ascii_case(f)));
        match &outcome.move_to {
            Some(dest) => {
                if client.ensure_folder(dest).await? {
                    tracing::info!(email = %acct.email, folder = %dest, "created folder for filter rule");
                    let _ = client.subscribe(dest).await;
                }
                // `spam_move` sets the flags before moving so the copy carries them.
                self.spam_move(acct, client, row, folder, dest, &flags)
                    .await?;
                applied.moved_to = Some(dest.clone());
            }
            None if !flags.is_empty() => {
                if client.selected().map(|m| m.name.as_str()) != Some(folder.name.as_str()) {
                    client.select(&folder.name).await?;
                }
                let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
                client
                    .set_flags(&[row.summary.uid], ImapFlagOp::Add, &refs)
                    .await?;
                let mut all = row.summary.flags.clone();
                all.extend(flags.iter().cloned());
                self.store().update_flags(row.summary.id, &all)?;
            }
            None => {}
        }
        applied.flags_added = flags;
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;
    use sealbox_spam::filters::FilterMatch;
    use sealbox_spam::filters::FilterOp;

    fn engine_with_account() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        engine
            .store()
            .insert_account(&NewAccount {
                email: "alice@example.org",
                display_name: "Alice",
                imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "alice",
                credential: "pw",
            })
            .unwrap();
        (dir, engine)
    }

    fn rule(field: FilterField, op: FilterOp, value: &str, action: FilterAction) -> FilterRule {
        FilterRule {
            id: 0,
            order: 0,
            enabled: true,
            name: String::new(),
            matcher: FilterMatch {
                field,
                op,
                value: value.into(),
                case_insensitive: true,
            },
            action,
            stop: false,
        }
    }

    #[test]
    fn rules_roundtrip_through_the_store() {
        let (_dir, engine) = engine_with_account();
        let r1 = engine
            .add_filter_rule(
                "alice@example.org",
                rule(
                    FilterField::Subject,
                    FilterOp::Contains,
                    "[newsletter]",
                    FilterAction::MoveTo {
                        folder: "Newsletters".into(),
                    },
                ),
            )
            .unwrap();
        assert!(r1.id > 0);
        assert_eq!(r1.order, 10);
        let r2 = engine
            .add_filter_rule(
                "alice@example.org",
                rule(
                    FilterField::From,
                    FilterOp::Domain,
                    "example.com",
                    FilterAction::Star,
                ),
            )
            .unwrap();
        assert_eq!(r2.order, 20);
        let list = engine.filter_rules("alice@example.org").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, r1.id);
        let off = engine
            .set_filter_rule_enabled("alice@example.org", r2.id, false)
            .unwrap();
        assert!(!off.enabled);
        assert!(!engine.filter_rules("alice@example.org").unwrap()[1].enabled);
        assert!(engine
            .remove_filter_rule("alice@example.org", r2.id)
            .unwrap());
        assert!(!engine
            .remove_filter_rule("alice@example.org", r2.id)
            .unwrap());
        assert_eq!(engine.filter_rules("alice@example.org").unwrap().len(), 1);
        // Invalid rules are refused.
        let bad = rule(
            FilterField::Subject,
            FilterOp::Regex,
            "(",
            FilterAction::MarkRead,
        );
        assert!(matches!(
            engine.add_filter_rule("alice@example.org", bad),
            Err(Error::InvalidInput(_))
        ));
        assert!(engine.filter_rules("nobody@example.org").is_err());
        // Dry run against raw bytes.
        let out = engine
            .test_filter_rules_raw(
                "alice@example.org",
                b"From: x@y.example\r\nSubject: [Newsletter] hi\r\n\r\nbody\r\n",
            )
            .unwrap();
        assert_eq!(out.move_to.as_deref(), Some("Newsletters"));
        assert_eq!(out.matched, vec![r1.id]);
    }

    #[test]
    fn set_filter_rules_replaces_the_list_in_order() {
        let (_dir, engine) = engine_with_account();
        engine
            .add_filter_rule(
                "alice@example.org",
                rule(
                    FilterField::Subject,
                    FilterOp::Contains,
                    "old",
                    FilterAction::Star,
                ),
            )
            .unwrap();
        let stored = engine
            .set_filter_rules(
                "alice@example.org",
                vec![
                    rule(
                        FilterField::From,
                        FilterOp::Domain,
                        "example.com",
                        FilterAction::MoveTo {
                            folder: "Lists".into(),
                        },
                    ),
                    rule(
                        FilterField::Subject,
                        FilterOp::Contains,
                        "[ci]",
                        FilterAction::MarkRead,
                    ),
                ],
            )
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!((stored[0].order, stored[1].order), (10, 20));
        assert!(stored[0].id > 0 && stored[1].id > stored[0].id);
        let listed = engine.filter_rules("alice@example.org").unwrap();
        assert_eq!(listed, stored);
        // An invalid rule leaves the stored list untouched.
        let bad = engine.set_filter_rules(
            "alice@example.org",
            vec![rule(
                FilterField::Subject,
                FilterOp::Regex,
                "(",
                FilterAction::Star,
            )],
        );
        assert!(bad.is_err());
        assert_eq!(engine.filter_rules("alice@example.org").unwrap(), stored);
        // An empty list clears everything.
        assert!(engine
            .set_filter_rules("alice@example.org", Vec::new())
            .unwrap()
            .is_empty());
        assert!(engine.filter_rules("alice@example.org").unwrap().is_empty());
    }

    #[test]
    fn rules_built_field_by_field_are_validated_like_typed_ones() {
        let (_dir, engine) = engine_with_account();
        let a = "alice@example.org";
        let bad_flag = |flag: &str| {
            rule(
                FilterField::Subject,
                FilterOp::Contains,
                "x",
                FilterAction::AddFlag { flag: flag.into() },
            )
        };
        for flag in ["", "two words", "x) (\\Deleted", "\"quoted\"", "*"] {
            assert!(
                matches!(
                    engine.add_filter_rule(a, bad_flag(flag)),
                    Err(Error::InvalidInput(_))
                ),
                "flag {flag:?} must be refused"
            );
        }
        let no_header = rule(
            FilterField::AnyHeader("  ".into()),
            FilterOp::Contains,
            "x",
            FilterAction::Star,
        );
        assert!(matches!(
            engine.add_filter_rule(a, no_header.clone()),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            engine.set_filter_rules(a, vec![no_header]),
            Err(Error::InvalidInput(_))
        ));
        assert!(
            engine.filter_rules(a).unwrap().is_empty(),
            "nothing was stored"
        );
        // The same shapes with valid contents are fine, and an update is checked too.
        let ok = engine
            .add_filter_rule(
                a,
                rule(
                    FilterField::AnyHeader("X-Mailer".into()),
                    FilterOp::Contains,
                    "bulk",
                    FilterAction::AddFlag {
                        flag: "$Bulk".into(),
                    },
                ),
            )
            .unwrap();
        let mut broken = ok.clone();
        broken.action = FilterAction::AddFlag { flag: "a b".into() };
        assert!(matches!(
            engine.update_filter_rule(a, broken),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(engine.filter_rules(a).unwrap(), vec![ok]);
    }
}
