//! Corpus evaluation without the full CLI:
//! `cargo run -p sealbox-spam --example eval -- --corpus DIR [--dev] [--seed N] [--train 0.7] [--max N] [--json]`
//! Exits 1 when the G25 targets (precision ≥ 0.98, recall ≥ 0.85) are not met on a held-out run.

use std::path::PathBuf;

use sealbox_spam::eval::{evaluate, summary, EvalOptions};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut corpus: Option<PathBuf> = None;
    let mut opts = EvalOptions::default();
    let mut json = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--corpus" => corpus = args.next().map(PathBuf::from),
            "--dev" => opts.dev = true,
            "--json" => json = true,
            "--seed" => {
                opts.seed = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(opts.seed)
            }
            "--train" => {
                opts.train_fraction = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(opts.train_fraction)
            }
            "--max" => opts.max_per_class = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--spam-threshold" => {
                opts.thresholds.spam = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(opts.thresholds.spam)
            }
            "--list" => opts.list_errors = args.next().and_then(|v| v.parse().ok()).unwrap_or(20),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(corpus) = corpus else {
        eprintln!("usage: eval --corpus DIR [--dev] [--seed N] [--train F] [--max N] [--json]");
        std::process::exit(2);
    };
    match evaluate(&corpus, &opts) {
        Ok(r) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            } else {
                println!("{}", summary(&r));
                if !r.false_positives.is_empty() {
                    println!("false positives (ham labelled spam):");
                    for p in &r.false_positives {
                        println!("  {p}");
                    }
                }
                if !r.false_negatives.is_empty() {
                    println!("false negatives (spam not labelled spam):");
                    for p in &r.false_negatives {
                        println!("  {p}");
                    }
                }
            }
            if !r.dev && !r.meets(0.98, 0.85) {
                eprintln!("G25 target not met (precision >= 0.98 and recall >= 0.85)");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
