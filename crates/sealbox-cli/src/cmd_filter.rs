//! `sealbox filter …` — user filter rules (gate G25): add, list, rm, enable, test.
//! Thin shell over `sealbox_core::filters`; `--json` prints `FilterRule` / `FilterTestReport`.

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};
use sealbox_core::{Engine, FilterAction, FilterField, FilterMatch, FilterOp, FilterRule};

#[derive(Subcommand, Debug)]
pub enum FilterCmd {
    /// Add a rule: --field from|to|cc|subject|list-id|header:NAME|body --op contains|equals|regex|domain
    /// --value V --action move:FOLDER|flag:NAME|read|star|delete (delete = move:Trash)
    Add(FilterAddArgs),
    /// List the rules of an account in evaluation order
    List {
        #[arg(long)]
        account: String,
    },
    /// Remove a rule
    #[command(visible_alias = "remove")]
    Rm {
        id: i64,
        #[arg(long)]
        account: String,
    },
    /// Enable a rule (or disable it with --off)
    Enable {
        id: i64,
        #[arg(long)]
        account: String,
        #[arg(long)]
        off: bool,
    },
    /// Dry run: what the rules would do with stored message ID (or a raw file via --file)
    Test {
        /// Local message id (from `list`)
        id: Option<i64>,
        #[arg(long)]
        account: String,
        /// Raw RFC 5322 file instead of a stored message
        #[arg(long, conflicts_with = "id")]
        file: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct FilterAddArgs {
    #[arg(long)]
    account: String,
    /// from | to | cc | subject | list-id | header:NAME | body
    #[arg(long)]
    field: String,
    /// contains | equals | regex | domain
    #[arg(long)]
    op: String,
    #[arg(long)]
    value: String,
    /// move:FOLDER | flag:NAME | read | star | delete (= move:Trash; nothing is ever deleted)
    #[arg(long)]
    action: String,
    /// Match case-sensitively (default: case-insensitive)
    #[arg(long)]
    case_sensitive: bool,
    /// Stop evaluating further rules when this one matches
    #[arg(long)]
    stop: bool,
    /// Optional label shown in `list`
    #[arg(long)]
    name: Option<String>,
    /// Position (lower runs first; 0 = after the existing rules)
    #[arg(long, default_value_t = 0)]
    order: i32,
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_rule(r: &FilterRule) {
    println!(
        "{:>4} {:>5} {} {}{}",
        r.id,
        r.order,
        if r.enabled { "on " } else { "off" },
        r.describe(),
        if r.name.is_empty() {
            String::new()
        } else {
            format!("  ({})", r.name)
        }
    );
}

pub async fn run(profile: &Path, json: bool, cmd: FilterCmd) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    match cmd {
        FilterCmd::Add(a) => {
            let field: FilterField = a.field.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let op: FilterOp = a.op.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let action: FilterAction = a.action.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let rule = FilterRule {
                id: 0,
                order: a.order,
                enabled: true,
                name: a.name.unwrap_or_default(),
                matcher: FilterMatch {
                    field,
                    op,
                    value: a.value,
                    case_insensitive: !a.case_sensitive,
                },
                action,
                stop: a.stop,
            };
            let rule = engine.add_filter_rule(&a.account, rule)?;
            if json {
                return print_json(&rule);
            }
            println!("added rule {}: {}", rule.id, rule.describe());
            Ok(())
        }
        FilterCmd::List { account } => {
            let rules = engine.filter_rules(&account)?;
            if json {
                return print_json(&rules);
            }
            if rules.is_empty() {
                println!("(no filter rules for {account})");
            } else {
                println!("  id order  on  rule");
                for r in &rules {
                    print_rule(r);
                }
            }
            Ok(())
        }
        FilterCmd::Rm { id, account } => {
            let removed = engine.remove_filter_rule(&account, id)?;
            if json {
                return print_json(&serde_json::json!({"id": id, "removed": removed}));
            }
            if removed {
                println!("removed rule {id}");
            } else {
                anyhow::bail!("no rule {id} for {account}");
            }
            Ok(())
        }
        FilterCmd::Enable { id, account, off } => {
            let rule = engine.set_filter_rule_enabled(&account, id, !off)?;
            if json {
                return print_json(&rule);
            }
            print_rule(&rule);
            Ok(())
        }
        FilterCmd::Test { id, account, file } => match (id, file) {
            (Some(id), None) => {
                let report = engine.test_filter_rules(&account, id)?;
                if json {
                    return print_json(&report);
                }
                for (rid, desc, matched) in &report.rules {
                    println!(
                        "{} {rid:>4} {desc}",
                        if *matched { "MATCH" } else { "  -  " }
                    );
                }
                print_outcome(&report.outcome);
                Ok(())
            }
            (None, Some(f)) => {
                let raw = std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?;
                let outcome = engine.test_filter_rules_raw(&account, &raw)?;
                if json {
                    return print_json(&outcome);
                }
                print_outcome(&outcome);
                Ok(())
            }
            _ => {
                let err = clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "give a message ID or --file FILE\n",
                );
                err.exit();
            }
        },
    }
}

fn print_outcome(o: &sealbox_core::FilterOutcome) {
    if o.is_noop() {
        println!("outcome: nothing to do");
        return;
    }
    println!(
        "outcome: matched {:?}{}{}{}{}",
        o.matched,
        o.move_to
            .as_deref()
            .map(|f| format!(" → move to {f}"))
            .unwrap_or_default(),
        if o.mark_read { " → mark read" } else { "" },
        if o.star { " → star" } else { "" },
        if o.add_flags.is_empty() {
            String::new()
        } else {
            format!(" → flags {}", o.add_flags.join(" "))
        }
    );
    for (id, e) in &o.errors {
        println!("  rule {id} skipped: {e}");
    }
}
