//! Per-user multinomial naive Bayes over hashed tokens, Laplace-smoothed, with
//! `learn` / `unlearn` feedback. The model is a plain serde struct so `sealbox-core` can
//! persist it as JSON (one row per profile).
//!
//! Each message contributes its *distinct* tokens once (the "boolean multinomial" variant,
//! which is robust to long or repetitive messages). Tokens never seen in either class carry
//! no information and are skipped; otherwise every unknown word would push the score toward
//! the class with the larger vocabulary.

use std::collections::{BTreeSet, HashMap};

use crate::util::fnv1a64;

/// Laplace smoothing constant.
const ALPHA: f64 = 1.0;

/// Spam / ham occurrence counts of one hashed token.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenCount {
    pub spam: u32,
    pub ham: u32,
}

/// The persisted model.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BayesModel {
    /// Format version (for future migrations).
    #[serde(default)]
    pub version: u32,
    pub spam_messages: u32,
    pub ham_messages: u32,
    /// Sum of distinct-token occurrences over all spam messages.
    pub spam_tokens: u64,
    pub ham_tokens: u64,
    /// `fnv1a64(token)` → counts.
    #[serde(default)]
    pub counts: HashMap<u64, TokenCount>,
}

/// One token's contribution, for `explain`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TokenExplanation {
    pub token: String,
    pub spam: u32,
    pub ham: u32,
    pub log_odds: f64,
}

/// Summary numbers for `spam status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelStats {
    pub spam_messages: u32,
    pub ham_messages: u32,
    pub tokens: usize,
}

impl BayesModel {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            ..Default::default()
        }
    }

    fn distinct(tokens: &[String]) -> BTreeSet<u64> {
        tokens.iter().map(|t| fnv1a64(t)).collect()
    }

    /// Add one message to the model.
    pub fn learn(&mut self, tokens: &[String], is_spam: bool) {
        let distinct = Self::distinct(tokens);
        for h in &distinct {
            let c = self.counts.entry(*h).or_default();
            if is_spam {
                c.spam = c.spam.saturating_add(1);
            } else {
                c.ham = c.ham.saturating_add(1);
            }
        }
        let n = distinct.len() as u64;
        if is_spam {
            self.spam_messages = self.spam_messages.saturating_add(1);
            self.spam_tokens = self.spam_tokens.saturating_add(n);
        } else {
            self.ham_messages = self.ham_messages.saturating_add(1);
            self.ham_tokens = self.ham_tokens.saturating_add(n);
        }
    }

    /// Remove a message previously learned as `is_spam` (saturating; safe to over-call).
    pub fn unlearn(&mut self, tokens: &[String], is_spam: bool) {
        let distinct = Self::distinct(tokens);
        let mut removed = 0u64;
        for h in &distinct {
            if let Some(c) = self.counts.get_mut(h) {
                let slot = if is_spam { &mut c.spam } else { &mut c.ham };
                if *slot > 0 {
                    *slot -= 1;
                    removed += 1;
                }
                if c.spam == 0 && c.ham == 0 {
                    self.counts.remove(h);
                }
            }
        }
        if is_spam {
            self.spam_messages = self.spam_messages.saturating_sub(1);
            self.spam_tokens = self.spam_tokens.saturating_sub(removed);
        } else {
            self.ham_messages = self.ham_messages.saturating_sub(1);
            self.ham_tokens = self.ham_tokens.saturating_sub(removed);
        }
    }

    /// How much to trust the model: ramps from 0 (no messages of one class) to 1 once at
    /// least `min_trained` messages of *each* class were learned.
    pub fn confidence(&self, min_trained: u32) -> f64 {
        if min_trained == 0 {
            return 1.0;
        }
        let m = self.spam_messages.min(self.ham_messages);
        (f64::from(m) / f64::from(min_trained)).min(1.0)
    }

    pub fn is_empty(&self) -> bool {
        self.spam_messages == 0 && self.ham_messages == 0
    }

    pub fn stats(&self) -> ModelStats {
        ModelStats {
            spam_messages: self.spam_messages,
            ham_messages: self.ham_messages,
            tokens: self.counts.len(),
        }
    }

    fn vocab(&self) -> f64 {
        (self.counts.len() as f64).max(1.0)
    }

    /// `ln P(token|spam) − ln P(token|ham)` with Laplace smoothing; `None` if unseen.
    fn token_log_odds(&self, c: &TokenCount) -> f64 {
        let v = self.vocab();
        let ps = (f64::from(c.spam) + ALPHA) / (self.spam_tokens as f64 + ALPHA * v);
        let ph = (f64::from(c.ham) + ALPHA) / (self.ham_tokens as f64 + ALPHA * v);
        ps.ln() - ph.ln()
    }

    /// Sum of per-token log-odds over the message's distinct, known tokens (class prior
    /// excluded: the classifier supplies its own).
    pub fn log_odds(&self, tokens: &[String]) -> f64 {
        if self.is_empty() {
            return 0.0;
        }
        let mut sum = 0.0;
        for h in Self::distinct(tokens) {
            if let Some(c) = self.counts.get(&h) {
                sum += self.token_log_odds(c);
            }
        }
        sum
    }

    /// The `n` tokens with the largest absolute contribution.
    pub fn explain(&self, tokens: &[String], n: usize) -> Vec<TokenExplanation> {
        let mut seen = BTreeSet::new();
        let mut out: Vec<TokenExplanation> = Vec::new();
        for t in tokens {
            let h = fnv1a64(t);
            if !seen.insert(h) {
                continue;
            }
            if let Some(c) = self.counts.get(&h) {
                out.push(TokenExplanation {
                    token: t.clone(),
                    spam: c.spam,
                    ham: c.ham,
                    log_odds: self.token_log_odds(c),
                });
            }
        }
        out.sort_by(|a, b| {
            b.log_odds
                .abs()
                .partial_cmp(&a.log_odds.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(n);
        out
    }

    /// Drop tokens seen fewer than `min_total` times in total (keeps the model small).
    pub fn prune(&mut self, min_total: u32) -> usize {
        let before = self.counts.len();
        self.counts
            .retain(|_, c| c.spam.saturating_add(c.ham) >= min_total);
        before - self.counts.len()
    }

    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(s: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn learns_and_scores() {
        let mut m = BayesModel::new();
        assert_eq!(m.log_odds(&toks("anything")), 0.0);
        for _ in 0..5 {
            m.learn(&toks("win free money now"), true);
            m.learn(&toks("meeting notes attached thanks"), false);
        }
        assert_eq!(m.spam_messages, 5);
        assert_eq!(m.ham_messages, 5);
        assert!(m.log_odds(&toks("free money")) > 2.0);
        assert!(m.log_odds(&toks("meeting notes")) < -2.0);
        // Unknown tokens carry no information.
        assert_eq!(m.log_odds(&toks("zebra quantum")), 0.0);
        // Repeated tokens count once.
        assert_eq!(
            m.log_odds(&toks("free free free")),
            m.log_odds(&toks("free"))
        );
        let ex = m.explain(&toks("free meeting zebra"), 5);
        assert_eq!(ex.len(), 2);
        assert_eq!(ex[0].token, "free");
        assert!(ex[0].log_odds > 0.0);
    }

    #[test]
    fn unlearn_restores_counts() {
        let mut m = BayesModel::new();
        m.learn(&toks("a b c"), true);
        m.learn(&toks("c d"), false);
        let snapshot = m.clone();
        m.learn(&toks("x y"), true);
        m.unlearn(&toks("x y"), true);
        assert_eq!(m.spam_messages, snapshot.spam_messages);
        assert_eq!(m.spam_tokens, snapshot.spam_tokens);
        assert_eq!(m.counts.len(), snapshot.counts.len());
        // Over-unlearning never underflows.
        m.unlearn(&toks("nothing here"), false);
        m.unlearn(&toks("nothing here"), false);
        assert_eq!(m.ham_messages, 0);
    }

    #[test]
    fn confidence_ramps_with_both_classes() {
        let mut m = BayesModel::new();
        assert_eq!(m.confidence(10), 0.0);
        for _ in 0..10 {
            m.learn(&toks("s"), true);
        }
        assert_eq!(m.confidence(10), 0.0, "spam only is not enough");
        for _ in 0..5 {
            m.learn(&toks("h"), false);
        }
        assert!((m.confidence(10) - 0.5).abs() < 1e-9);
        for _ in 0..5 {
            m.learn(&toks("h"), false);
        }
        assert_eq!(m.confidence(10), 1.0);
        assert_eq!(m.confidence(0), 1.0);
    }

    #[test]
    fn json_roundtrip_and_prune() {
        let mut m = BayesModel::new();
        m.learn(&toks("a b"), true);
        m.learn(&toks("a c"), false);
        let json = m.to_json().unwrap();
        let back = BayesModel::from_json(&json).unwrap();
        assert_eq!(back.counts, m.counts);
        assert_eq!(back.spam_tokens, 2);
        assert_eq!(m.prune(2), 2);
        assert_eq!(m.counts.len(), 1);
        assert_eq!(m.stats().tokens, 1);
    }
}
