//! Combine prior + Bayes + rules into a probability, a label and the list of reasons.
//!
//! ```text
//! log-odds = logit(prior_spam) + clamp(bayes_log_odds, ±bayes_clamp) · confidence + Σ rule weights
//! p        = sigmoid(log-odds)
//! label    = Spam  if p ≥ spam_threshold
//!            Unsure if p ≥ unsure_threshold
//!            Ham   otherwise
//! ```

use std::fmt;
use std::str::FromStr;

use crate::bayes::BayesModel;
use crate::features::Features;
use crate::rules::{self, RuleContext, RuleHit};

/// Tunables (all stored in the account's `SpamSettings`).
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Thresholds {
    /// Probability from which a message is `Unsure`.
    pub unsure: f64,
    /// Probability from which a message is `Spam` (and moved).
    pub spam: f64,
    /// Prior probability of spam before looking at the message.
    pub prior_spam: f64,
    /// The Bayes log-odds are clamped to ±this before being combined with the rules.
    pub bayes_clamp: f64,
    /// Messages of *each* class the model needs before it is trusted fully.
    pub min_trained: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            unsure: 0.5,
            spam: 0.9,
            prior_spam: 0.1,
            bayes_clamp: 12.0,
            min_trained: 10,
        }
    }
}

impl Thresholds {
    /// Clamp everything into a usable range (`unsure ≤ spam`, probabilities strictly inside 0..1).
    pub fn sanitized(self) -> Self {
        let clamp01 = |v: f64| {
            if v.is_finite() {
                v.clamp(0.01, 0.999)
            } else {
                0.5
            }
        };
        let spam = clamp01(self.spam);
        let unsure = clamp01(self.unsure).min(spam);
        Self {
            unsure,
            spam,
            prior_spam: clamp01(self.prior_spam),
            bayes_clamp: if self.bayes_clamp.is_finite() {
                self.bayes_clamp.clamp(1.0, 50.0)
            } else {
                12.0
            },
            min_trained: self.min_trained,
        }
    }
}

/// The label.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SpamLabel {
    #[default]
    Ham,
    Unsure,
    Spam,
}

impl SpamLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            SpamLabel::Ham => "ham",
            SpamLabel::Unsure => "unsure",
            SpamLabel::Spam => "spam",
        }
    }
}

impl fmt::Display for SpamLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SpamLabel {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ham" => Ok(SpamLabel::Ham),
            "unsure" => Ok(SpamLabel::Unsure),
            "spam" => Ok(SpamLabel::Spam),
            other => Err(format!("unknown spam label `{other}`")),
        }
    }
}

/// One line of the explanation.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Reason {
    pub code: String,
    pub weight: f64,
    pub detail: String,
}

impl From<RuleHit> for Reason {
    fn from(h: RuleHit) -> Self {
        Reason {
            code: h.code,
            weight: h.weight,
            detail: h.detail,
        }
    }
}

/// The classifier's answer.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub spam_probability: f64,
    pub label: SpamLabel,
    pub reasons: Vec<Reason>,
    /// Raw Bayes log-odds before clamping / confidence scaling.
    pub bayes_log_odds: f64,
    /// 0..1 — how much the Bayes model was trusted.
    pub bayes_confidence: f64,
    /// Sum of the rule weights.
    pub rules_score: f64,
    /// Final log-odds the probability was derived from.
    pub log_odds: f64,
}

impl Verdict {
    /// A verdict that forces a label without evaluating anything (allowlist / blocklist /
    /// signed mail from a known contact). `code` and `detail` become the single reason.
    pub fn forced(label: SpamLabel, code: &str, detail: impl Into<String>) -> Self {
        let p = match label {
            SpamLabel::Ham => 0.0,
            SpamLabel::Unsure => 0.5,
            SpamLabel::Spam => 1.0,
        };
        Verdict {
            spam_probability: p,
            label,
            reasons: vec![Reason {
                code: code.to_string(),
                weight: 0.0,
                detail: detail.into(),
            }],
            bayes_log_odds: 0.0,
            bayes_confidence: 0.0,
            rules_score: 0.0,
            log_odds: 0.0,
        }
    }
}

fn logit(p: f64) -> f64 {
    (p / (1.0 - p)).ln()
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Rules + Bayes → verdict.
#[derive(Clone, Copy, Debug)]
pub struct Classifier<'a> {
    pub model: &'a BayesModel,
    pub thresholds: Thresholds,
}

impl<'a> Classifier<'a> {
    pub fn new(model: &'a BayesModel, thresholds: Thresholds) -> Self {
        Self {
            model,
            thresholds: thresholds.sanitized(),
        }
    }

    /// Label for a probability under the configured thresholds.
    pub fn label_for(&self, p: f64) -> SpamLabel {
        if p >= self.thresholds.spam {
            SpamLabel::Spam
        } else if p >= self.thresholds.unsure {
            SpamLabel::Unsure
        } else {
            SpamLabel::Ham
        }
    }

    /// Run the rules, add `extra_hits` (e.g. DNSBL results obtained asynchronously) and the
    /// Bayes model, and produce the verdict.
    pub fn classify(&self, f: &Features, ctx: &RuleContext<'_>, extra_hits: &[RuleHit]) -> Verdict {
        let mut hits = rules::evaluate(f, ctx);
        hits.extend(extra_hits.iter().cloned());
        self.verdict_from(f, hits)
    }

    /// Verdict from already-evaluated rule hits.
    pub fn verdict_from(&self, f: &Features, hits: Vec<RuleHit>) -> Verdict {
        let t = self.thresholds;
        let rules_score: f64 = hits.iter().map(|h| h.weight).sum();
        let raw_bayes = self.model.log_odds(&f.tokens);
        let confidence = self.model.confidence(t.min_trained);
        let bayes = raw_bayes.clamp(-t.bayes_clamp, t.bayes_clamp) * confidence;
        let log_odds = logit(t.prior_spam) + bayes + rules_score;
        let p = sigmoid(log_odds);
        let mut reasons: Vec<Reason> = hits.into_iter().map(Reason::from).collect();
        if confidence > 0.0 {
            let top = self.model.explain(&f.tokens, 6);
            let tokens = top
                .iter()
                .map(|e| format!("{}({:+.1})", e.token, e.log_odds))
                .collect::<Vec<_>>()
                .join(" ");
            reasons.push(Reason {
                code: "bayes".into(),
                weight: bayes,
                detail: format!(
                    "learned from {} spam / {} ham (confidence {:.0} %), raw log-odds {:+.1}; strongest tokens: {}",
                    self.model.spam_messages,
                    self.model.ham_messages,
                    confidence * 100.0,
                    raw_bayes,
                    if tokens.is_empty() { "(none known)".to_string() } else { tokens }
                ),
            });
        }
        reasons.sort_by(|a, b| {
            b.weight
                .abs()
                .partial_cmp(&a.weight.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Verdict {
            spam_probability: p,
            label: self.label_for(p),
            reasons,
            bayes_log_odds: raw_bayes,
            bayes_confidence: confidence,
            rules_score,
            log_odds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::extract;

    #[test]
    fn thresholds_are_sanitized() {
        let t = Thresholds {
            unsure: 0.95,
            spam: 0.8,
            prior_spam: 2.0,
            bayes_clamp: f64::NAN,
            min_trained: 3,
        }
        .sanitized();
        assert_eq!(t.spam, 0.8);
        assert_eq!(t.unsure, 0.8);
        assert_eq!(t.prior_spam, 0.999);
        assert_eq!(t.bayes_clamp, 12.0);
    }

    #[test]
    fn untrained_model_relies_on_rules_and_prior() {
        let model = BayesModel::new();
        let c = Classifier::new(&model, Thresholds::default());
        let ham = extract(b"From: a@b.example\r\nTo: x@y.example\r\nSubject: hi\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <1@b.example>\r\n\r\nhello\r\n").unwrap();
        let v = c.classify(&ham, &RuleContext::default(), &[]);
        assert_eq!(v.label, SpamLabel::Ham);
        assert!((v.spam_probability - 0.1).abs() < 1e-9, "{v:?}");
        assert!(v.reasons.is_empty());

        let spam = extract(b"From: \"x@bank.example\" <x@evil.example>\r\nSubject: You have won the lottery!!!\r\n\r\nDear winner, verify your account at http://1.2.3.4/login now\r\n").unwrap();
        let v = c.classify(&spam, &RuleContext::default(), &[]);
        assert_eq!(v.label, SpamLabel::Spam, "{v:?}");
        assert!(v.spam_probability > 0.99);
        assert!(v.reasons.iter().any(|r| r.code == "phish_language"));
        // Extra (DNSBL) hits are merged in and sorted by magnitude.
        let v2 = c.classify(
            &spam,
            &RuleContext::default(),
            &[RuleHit::new("dnsbl_zen", 3.0, "listed")],
        );
        assert!(v2.log_odds > v.log_odds);
        assert!(v2.reasons.iter().any(|r| r.code == "dnsbl_zen"));
    }

    #[test]
    fn trained_model_adds_bayes_reason_and_respects_confidence() {
        let mut model = BayesModel::new();
        let spam = extract(b"From: a@b.example\r\nSubject: cheap meds\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <1@b.example>\r\n\r\ncheap meds online pharmacy discount\r\n").unwrap();
        let ham = extract(b"From: a@b.example\r\nSubject: project update\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <2@b.example>\r\n\r\nproject update meeting agenda minutes\r\n").unwrap();
        for _ in 0..3 {
            model.learn(&spam.tokens, true);
            model.learn(&ham.tokens, false);
        }
        let c = Classifier::new(
            &model,
            Thresholds {
                min_trained: 3,
                ..Default::default()
            },
        );
        let v = c.classify(&spam, &RuleContext::default(), &[]);
        assert_eq!(v.bayes_confidence, 1.0);
        assert_eq!(v.label, SpamLabel::Spam, "{v:?}");
        assert!(v
            .reasons
            .iter()
            .any(|r| r.code == "bayes" && r.weight > 0.0));
        let v = c.classify(&ham, &RuleContext::default(), &[]);
        assert_eq!(v.label, SpamLabel::Ham);
        // With a higher requirement the same model is only partially trusted.
        let c = Classifier::new(
            &model,
            Thresholds {
                min_trained: 30,
                ..Default::default()
            },
        );
        let v = c.classify(&spam, &RuleContext::default(), &[]);
        assert!((v.bayes_confidence - 0.1).abs() < 1e-9);
    }

    #[test]
    fn forced_verdicts_and_label_parsing() {
        let v = Verdict::forced(SpamLabel::Ham, "allowlist", "sender allowlisted");
        assert_eq!(v.spam_probability, 0.0);
        assert_eq!(v.reasons[0].code, "allowlist");
        assert_eq!("Spam".parse::<SpamLabel>(), Ok(SpamLabel::Spam));
        assert!("maybe".parse::<SpamLabel>().is_err());
        assert_eq!(SpamLabel::Unsure.to_string(), "unsure");
    }
}
