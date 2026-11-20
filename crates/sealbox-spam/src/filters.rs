//! User filter rules: `field op value → action`, evaluated in order after spam
//! classification. Pure matching lives here; `sealbox-core` stores the rules and performs the
//! actions on the server.
//!
//! Semantics: rules run in `order`; every enabled rule that matches contributes its action
//! (flags / read / star accumulate, the **first** `MoveTo` wins because a message can only be
//! in one folder); a matching rule with `stop = true` ends the evaluation. `Delete` is not an
//! action — it is parsed as `MoveTo("Trash")` so a filter can never destroy mail.

use std::fmt;
use std::str::FromStr;

use crate::features::Features;
use crate::util::{address_domain, url_host};
use crate::{Error, Result};

/// Which part of the message a rule looks at.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterField {
    From,
    To,
    Cc,
    Subject,
    ListId,
    /// Any header by name (case-insensitive), e.g. `X-Mailer`.
    AnyHeader(String),
    Body,
}

impl fmt::Display for FilterField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterField::From => f.write_str("from"),
            FilterField::To => f.write_str("to"),
            FilterField::Cc => f.write_str("cc"),
            FilterField::Subject => f.write_str("subject"),
            FilterField::ListId => f.write_str("list-id"),
            FilterField::AnyHeader(h) => write!(f, "header:{h}"),
            FilterField::Body => f.write_str("body"),
        }
    }
}

impl FromStr for FilterField {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let l = s.trim().to_ascii_lowercase();
        Ok(match l.as_str() {
            "from" => FilterField::From,
            "to" => FilterField::To,
            "cc" => FilterField::Cc,
            "subject" => FilterField::Subject,
            "list-id" | "list_id" | "listid" | "list" => FilterField::ListId,
            "body" => FilterField::Body,
            _ => {
                if let Some(h) = l.strip_prefix("header:") {
                    let h = h.trim();
                    if h.is_empty() {
                        return Err(Error::InvalidFilter("header: needs a header name".into()));
                    }
                    FilterField::AnyHeader(h.to_string())
                } else {
                    return Err(Error::InvalidFilter(format!(
                        "unknown field `{s}` (from|to|cc|subject|list-id|header:NAME|body)"
                    )));
                }
            }
        })
    }
}

/// How the value is compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Contains,
    Equals,
    Regex,
    /// For address fields: the address domain equals the value or is a sub-domain of it.
    /// For other fields: a `@value` suffix / `.value` suffix match on each word.
    Domain,
}

impl fmt::Display for FilterOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FilterOp::Contains => "contains",
            FilterOp::Equals => "equals",
            FilterOp::Regex => "regex",
            FilterOp::Domain => "domain",
        })
    }
}

impl FromStr for FilterOp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "contains" | "has" => FilterOp::Contains,
            "equals" | "is" | "eq" => FilterOp::Equals,
            "regex" | "matches" | "re" => FilterOp::Regex,
            "domain" => FilterOp::Domain,
            other => {
                return Err(Error::InvalidFilter(format!(
                    "unknown op `{other}` (contains|equals|regex|domain)"
                )))
            }
        })
    }
}

/// The condition.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterMatch {
    pub field: FilterField,
    pub op: FilterOp,
    pub value: String,
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
}

fn default_true() -> bool {
    true
}

/// What to do. There is deliberately no delete.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    MoveTo { folder: String },
    AddFlag { flag: String },
    MarkRead,
    Star,
}

impl fmt::Display for FilterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterAction::MoveTo { folder } => write!(f, "move:{folder}"),
            FilterAction::AddFlag { flag } => write!(f, "flag:{flag}"),
            FilterAction::MarkRead => f.write_str("read"),
            FilterAction::Star => f.write_str("star"),
        }
    }
}

impl FromStr for FilterAction {
    type Err = Error;
    /// `move:FOLDER` · `flag:NAME` · `read` · `star` · `delete` (= `move:Trash`).
    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim();
        let lower = t.to_ascii_lowercase();
        if let Some(folder) = t.get(5..).filter(|_| lower.starts_with("move:")) {
            let folder = folder.trim();
            if folder.is_empty() {
                return Err(Error::InvalidFilter("move: needs a folder name".into()));
            }
            return Ok(FilterAction::MoveTo {
                folder: folder.to_string(),
            });
        }
        if let Some(flag) = t.get(5..).filter(|_| lower.starts_with("flag:")) {
            let flag = flag.trim();
            if flag.is_empty()
                || flag.contains(char::is_whitespace)
                || flag.contains(['(', ')', '{', '}', '"', '%', '*'])
            {
                return Err(Error::InvalidFilter(format!(
                    "`{flag}` is not a valid IMAP flag"
                )));
            }
            return Ok(FilterAction::AddFlag {
                flag: flag.to_string(),
            });
        }
        match lower.as_str() {
            "read" | "mark-read" | "markread" | "seen" => Ok(FilterAction::MarkRead),
            "star" | "flagged" => Ok(FilterAction::Star),
            "delete" | "trash" => Ok(FilterAction::MoveTo {
                folder: "Trash".into(),
            }),
            other => Err(Error::InvalidFilter(format!(
                "unknown action `{other}` (move:FOLDER|flag:NAME|read|star|delete)"
            ))),
        }
    }
}

/// One stored rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterRule {
    /// Store id (0 before it is saved).
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub order: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: FilterMatch,
    pub action: FilterAction,
    /// Stop evaluating further rules when this one matches.
    #[serde(default)]
    pub stop: bool,
}

impl FilterRule {
    /// Validate (regex compiles, value non-empty).
    pub fn validate(&self) -> Result<()> {
        if self.matcher.value.trim().is_empty() {
            return Err(Error::InvalidFilter("the value must not be empty".into()));
        }
        if self.matcher.op == FilterOp::Regex {
            compile_regex(&self.matcher.value, self.matcher.case_insensitive)?;
        }
        if let FilterAction::MoveTo { folder } = &self.action {
            if folder.trim().is_empty() {
                return Err(Error::InvalidFilter(
                    "the target folder must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// `subject contains "[newsletter]" → move:Newsletters`
    pub fn describe(&self) -> String {
        format!(
            "{} {} {:?}{} → {}{}",
            self.matcher.field,
            self.matcher.op,
            self.matcher.value,
            if self.matcher.case_insensitive {
                ""
            } else {
                " (case-sensitive)"
            },
            self.action,
            if self.stop { " [stop]" } else { "" }
        )
    }
}

fn compile_regex(pattern: &str, case_insensitive: bool) -> Result<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| Error::Regex(e.to_string()))
}

/// The parts of a message that filters can look at.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageFacts {
    /// `Name <addr>` display forms.
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub list_id: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl MessageFacts {
    pub fn from_features(f: &Features) -> Self {
        let from = match (&f.from_name, &f.from_address) {
            (Some(n), Some(a)) => vec![format!("{n} <{a}>")],
            (None, Some(a)) => vec![a.clone()],
            _ => Vec::new(),
        };
        MessageFacts {
            from,
            to: f.to.clone(),
            cc: f.cc.clone(),
            subject: f.subject.clone(),
            list_id: f.list_id.clone(),
            headers: f.headers.clone(),
            body: f.text.clone(),
        }
    }
}

/// Bare address inside `Name <addr>` (or the string itself).
fn bare_address(display: &str) -> String {
    match (display.rfind('<'), display.rfind('>')) {
        (Some(a), Some(b)) if b > a => display[a + 1..b].trim().to_string(),
        _ => display.trim().to_string(),
    }
}

fn text_matches(m: &FilterMatch, candidates: &[String], is_address: bool) -> Result<bool> {
    let value = m.value.trim();
    let fold = |s: &str| {
        if m.case_insensitive {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let v = fold(value);
    match m.op {
        FilterOp::Contains => Ok(candidates.iter().any(|c| fold(c).contains(&v))),
        FilterOp::Equals => Ok(candidates.iter().any(|c| {
            let c = if is_address {
                bare_address(c)
            } else {
                c.trim().to_string()
            };
            fold(&c) == v
        })),
        FilterOp::Regex => {
            let re = compile_regex(value, m.case_insensitive)?;
            Ok(candidates.iter().any(|c| re.is_match(c)))
        }
        FilterOp::Domain => {
            let want = value
                .trim_start_matches('@')
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if want.is_empty() {
                return Ok(false);
            }
            Ok(candidates.iter().any(|c| {
                let hosts: Vec<String> = if is_address {
                    address_domain(&bare_address(c)).into_iter().collect()
                } else {
                    c.split(|ch: char| {
                        ch.is_whitespace() || matches!(ch, '<' | '>' | ',' | ';' | '(' | ')')
                    })
                    .filter_map(|w| {
                        let w = w.trim().to_ascii_lowercase();
                        if let Some(d) = address_domain(&w) {
                            Some(d)
                        } else if w.contains("://") || w.starts_with("www.") {
                            url_host(&w)
                        } else if w.contains('.') {
                            Some(w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
                };
                hosts
                    .iter()
                    .any(|h| h == &want || h.ends_with(&format!(".{want}")))
            }))
        }
    }
}

/// Does this rule match the message? (`Err` only for an invalid regex.)
pub fn rule_matches(rule: &FilterRule, facts: &MessageFacts) -> Result<bool> {
    let m = &rule.matcher;
    match &m.field {
        FilterField::From => text_matches(m, &facts.from, true),
        FilterField::To => text_matches(m, &facts.to, true),
        FilterField::Cc => text_matches(m, &facts.cc, true),
        FilterField::Subject => text_matches(m, std::slice::from_ref(&facts.subject), false),
        FilterField::ListId => match &facts.list_id {
            Some(l) => text_matches(m, std::slice::from_ref(l), false),
            None => Ok(false),
        },
        FilterField::AnyHeader(name) => {
            let values: Vec<String> = facts
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .collect();
            if values.is_empty() {
                return Ok(false);
            }
            let is_addr = matches!(
                name.to_ascii_lowercase().as_str(),
                "from"
                    | "to"
                    | "cc"
                    | "bcc"
                    | "reply-to"
                    | "sender"
                    | "return-path"
                    | "delivered-to"
            );
            text_matches(m, &values, is_addr)
        }
        FilterField::Body => text_matches(m, std::slice::from_ref(&facts.body), false),
    }
}

/// Combined effect of the matching rules.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterOutcome {
    /// Ids of the rules that matched, in evaluation order.
    pub matched: Vec<i64>,
    pub move_to: Option<String>,
    pub add_flags: Vec<String>,
    pub mark_read: bool,
    pub star: bool,
    /// Rules skipped because their regex is invalid (id, error).
    pub errors: Vec<(i64, String)>,
}

impl FilterOutcome {
    pub fn is_noop(&self) -> bool {
        self.move_to.is_none() && self.add_flags.is_empty() && !self.mark_read && !self.star
    }
}

/// Evaluate the rules (sorted by `order`, then id) against the message.
pub fn apply_rules(rules: &[FilterRule], facts: &MessageFacts) -> FilterOutcome {
    let mut sorted: Vec<&FilterRule> = rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| (r.order, r.id));
    let mut out = FilterOutcome::default();
    for r in sorted {
        match rule_matches(r, facts) {
            Ok(true) => {
                out.matched.push(r.id);
                match &r.action {
                    FilterAction::MoveTo { folder } => {
                        if out.move_to.is_none() {
                            out.move_to = Some(folder.clone());
                        }
                    }
                    FilterAction::AddFlag { flag } => {
                        if !out.add_flags.iter().any(|f| f.eq_ignore_ascii_case(flag)) {
                            out.add_flags.push(flag.clone());
                        }
                    }
                    FilterAction::MarkRead => out.mark_read = true,
                    FilterAction::Star => out.star = true,
                }
                if r.stop {
                    break;
                }
            }
            Ok(false) => {}
            Err(e) => out.errors.push((r.id, e.to_string())),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, field: &str, op: &str, value: &str, action: &str) -> FilterRule {
        FilterRule {
            id,
            order: id as i32,
            enabled: true,
            name: String::new(),
            matcher: FilterMatch {
                field: field.parse().unwrap(),
                op: op.parse().unwrap(),
                value: value.into(),
                case_insensitive: true,
            },
            action: action.parse().unwrap(),
            stop: false,
        }
    }

    fn facts() -> MessageFacts {
        MessageFacts {
            from: vec!["News Team <news@mail.Example.COM>".into()],
            to: vec!["me@sealbox.test".into()],
            cc: vec![],
            subject: "[Newsletter] October issue".into(),
            list_id: Some("News <news.example.com>".into()),
            headers: vec![
                ("X-Mailer".into(), "Mailchimp 7".into()),
                ("From".into(), "News Team <news@mail.Example.COM>".into()),
            ],
            body: "Read the issue at https://example.com/october".into(),
        }
    }

    #[test]
    fn parsing() {
        assert_eq!(
            "header:X-Mailer".parse::<FilterField>().unwrap(),
            FilterField::AnyHeader("x-mailer".into())
        );
        assert!("nope".parse::<FilterField>().is_err());
        assert!("header:".parse::<FilterField>().is_err());
        assert_eq!(
            "delete".parse::<FilterAction>().unwrap(),
            FilterAction::MoveTo {
                folder: "Trash".into()
            }
        );
        assert_eq!(
            "move:News Letters".parse::<FilterAction>().unwrap(),
            FilterAction::MoveTo {
                folder: "News Letters".into()
            }
        );
        assert_eq!(
            "flag:$Label1".parse::<FilterAction>().unwrap(),
            FilterAction::AddFlag {
                flag: "$Label1".into()
            }
        );
        assert!("flag:bad flag".parse::<FilterAction>().is_err());
        assert!("move:".parse::<FilterAction>().is_err());
        assert_eq!("matches".parse::<FilterOp>().unwrap(), FilterOp::Regex);
    }

    #[test]
    fn matching_ops() {
        let f = facts();
        assert!(rule_matches(&rule(1, "subject", "contains", "[newsletter]", "read"), &f).unwrap());
        assert!(!rule_matches(&rule(1, "subject", "equals", "[newsletter]", "read"), &f).unwrap());
        assert!(rule_matches(
            &rule(1, "from", "equals", "NEWS@mail.example.com", "read"),
            &f
        )
        .unwrap());
        assert!(rule_matches(&rule(1, "from", "domain", "example.com", "read"), &f).unwrap());
        assert!(rule_matches(&rule(1, "from", "domain", "@mail.example.com", "read"), &f).unwrap());
        assert!(!rule_matches(&rule(1, "from", "domain", "ample.com", "read"), &f).unwrap());
        assert!(rule_matches(&rule(1, "from", "regex", r"^news\s+team", "read"), &f).unwrap());
        assert!(rule_matches(
            &rule(1, "list-id", "contains", "news.example.com", "read"),
            &f
        )
        .unwrap());
        assert!(rule_matches(
            &rule(1, "header:x-mailer", "contains", "mailchimp", "read"),
            &f
        )
        .unwrap());
        assert!(!rule_matches(&rule(1, "header:x-nothing", "contains", "x", "read"), &f).unwrap());
        assert!(rule_matches(&rule(1, "body", "domain", "example.com", "read"), &f).unwrap());
        assert!(rule_matches(&rule(1, "to", "equals", "me@sealbox.test", "read"), &f).unwrap());
        let mut cs = rule(1, "subject", "contains", "newsletter", "read");
        cs.matcher.case_insensitive = false;
        assert!(!rule_matches(&cs, &f).unwrap());
        assert!(rule_matches(&rule(1, "subject", "regex", "(", "read"), &f).is_err());
        assert!(rule(1, "subject", "regex", "(", "read").validate().is_err());
        assert!(rule(1, "subject", "contains", "  ", "read")
            .validate()
            .is_err());
    }

    #[test]
    fn apply_order_stop_and_first_move_wins() {
        let f = facts();
        let mut r1 = rule(1, "subject", "contains", "[newsletter]", "move:Newsletters");
        let mut r2 = rule(2, "from", "domain", "example.com", "star");
        let r3 = rule(3, "subject", "contains", "october", "move:Archive");
        let r4 = rule(4, "subject", "contains", "october", "flag:$Seen2");
        let mut r5 = rule(5, "body", "contains", "issue", "read");
        r5.enabled = false;
        // r2 runs first by order, r1 stops the chain after it.
        r2.order = 0;
        r1.stop = true;
        let out = apply_rules(
            &[r1.clone(), r2.clone(), r3.clone(), r4.clone(), r5.clone()],
            &f,
        );
        assert_eq!(out.matched, vec![2, 1]);
        assert_eq!(out.move_to.as_deref(), Some("Newsletters"));
        assert!(out.star && !out.mark_read && out.add_flags.is_empty());
        r1.stop = false;
        let out = apply_rules(&[r1, r2, r3, r4, r5], &f);
        assert_eq!(out.matched, vec![2, 1, 3, 4]);
        assert_eq!(
            out.move_to.as_deref(),
            Some("Newsletters"),
            "first move wins"
        );
        assert_eq!(out.add_flags, vec!["$Seen2".to_string()]);
        assert!(out.errors.is_empty());
        let bad = rule(9, "subject", "regex", "(", "read");
        let out = apply_rules(&[bad], &f);
        assert_eq!(out.errors.len(), 1);
        assert!(out.is_noop());
    }

    #[test]
    fn json_shape_is_stable() {
        let r = rule(1, "header:X-Mailer", "contains", "mailchimp", "move:Lists");
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(
            json["match"]["field"],
            serde_json::json!({"any_header": "x-mailer"})
        );
        assert_eq!(json["match"]["op"], "contains");
        assert_eq!(
            json["action"],
            serde_json::json!({"move_to": {"folder": "Lists"}})
        );
        let back: FilterRule = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
        assert_eq!(
            r.describe(),
            "header:x-mailer contains \"mailchimp\" → move:Lists"
        );
    }
}
