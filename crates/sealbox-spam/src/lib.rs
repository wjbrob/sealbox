//! sealbox-spam — spam detection and filtering for Sealbox.
//!
//! Pipeline (all pure and synchronous except the optional DNSBL step):
//!
//! ```text
//! raw RFC 5322 bytes ──► features::extract ──► Features
//!                                           ├──► rules::evaluate   ──► Vec<RuleHit>   (explainable, weighted)
//!                                           ├──► BayesModel::log_odds (per-user, hashed tokens)
//!                                           └──► dnsbl::check       ──► Vec<RuleHit>   (optional, async, off by default)
//!                                                       │
//!                     Classifier::classify ◄────────────┘ ──► Verdict { spam_probability, label, reasons }
//! ```
//!
//! * [`features`] turns a message into tokens and structural attributes (URLs, attachments,
//!   Received chain, Authentication-Results, HTML tricks …).
//! * [`rules`] are hand-written, explainable checks with log-odds weights (dangerous
//!   attachments, lookalike domains of the user's contacts, phishing language, SPF/DKIM/DMARC
//!   failures, …).
//! * [`bayes`] is a multinomial naive-Bayes model with Laplace smoothing over FNV-hashed tokens;
//!   it learns from the user's `spam` / `ham` feedback and is persisted by `sealbox-core`.
//! * [`classifier`] combines a spam prior, the (clamped) Bayes log-odds and the rule weights into
//!   a probability and a label with configurable thresholds.
//! * [`dnsbl`] queries Spamhaus ZEN (last external relay IP) and DBL (URL domains) through a
//!   pluggable resolver. **Off by default**: it reveals sender IPs / URL domains to the resolver.
//! * [`filters`] is the user filter-rule engine (field/op/value → move/flag/read/star).
//! * [`eval`] trains on a labelled corpus split and reports precision / recall / F1.
//!
//! See `docs/SPAM.md` for design notes, thresholds, privacy and evaluation numbers.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod bayes;
pub mod classifier;
pub mod dnsbl;
pub mod eval;
pub mod features;
pub mod filters;
pub mod rules;
pub mod util;

pub use bayes::{BayesModel, TokenExplanation};
pub use classifier::{Classifier, Reason, SpamLabel, Thresholds, Verdict};
pub use dnsbl::{DnsblConfig, HickoryResolver, Resolver, StaticResolver};
pub use eval::{EvalOptions, EvalReport};
pub use features::{AttachmentMeta, AuthResult, AuthResults, Features, HtmlTricks, UrlInfo};
pub use filters::{
    FilterAction, FilterField, FilterMatch, FilterOp, FilterOutcome, FilterRule, MessageFacts,
};
pub use rules::{RuleContext, RuleHit};

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("message could not be parsed")]
    Unparseable,
    #[error("invalid filter rule: {0}")]
    InvalidFilter(String),
    #[error("regex: {0}")]
    Regex(String),
    #[error("corpus: {0}")]
    Corpus(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
