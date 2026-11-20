//! Evaluation harness: load a labelled corpus (`DIR/ham/**`, `DIR/spam/**`, one message per
//! file), split it deterministically (seeded, stratified) into train / held-out, train the
//! Bayes model on the training part and score the held-out part with the *production*
//! pipeline (rules + Bayes, default thresholds, no DNSBL).
//!
//! Honesty rules baked in:
//! * the split depends only on the seed and the sorted file names, never on the content;
//! * `dev = true` runs k-fold cross-validation **inside the training part** — that is what
//!   feature work iterates on; the held-out part is only touched by the final run;
//! * a message counts as spam only when the label is `Spam` (what would actually be moved);
//!   `lenient_*` additionally counts `Unsure`, for information.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::bayes::BayesModel;
use crate::classifier::{Classifier, SpamLabel, Thresholds};
use crate::features::{extract, Features};
use crate::rules::RuleContext;
use crate::{Error, Result};

/// Options of one evaluation.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvalOptions {
    pub seed: u64,
    /// Share of each class used for training (the rest is held out).
    pub train_fraction: f64,
    pub thresholds: Thresholds,
    /// Cross-validate inside the training split instead of touching the held-out part.
    pub dev: bool,
    /// Folds for `dev`.
    pub folds: usize,
    /// Cap on messages per class (0 = all), for quick runs.
    pub max_per_class: usize,
    /// How many misclassified paths to list.
    pub list_errors: usize,
}

impl Default for EvalOptions {
    fn default() -> Self {
        Self {
            seed: 42,
            train_fraction: 0.7,
            thresholds: Thresholds::default(),
            dev: false,
            folds: 5,
            max_per_class: 0,
            list_errors: 20,
        }
    }
}

/// The numbers.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvalReport {
    pub corpus: String,
    pub seed: u64,
    pub train_fraction: f64,
    pub dev: bool,
    pub n_ham: usize,
    pub n_spam: usize,
    pub n_train_ham: usize,
    pub n_train_spam: usize,
    pub n_test_ham: usize,
    pub n_test_spam: usize,
    /// Spam labelled spam.
    pub tp: usize,
    /// Ham labelled spam.
    pub fp: usize,
    /// Ham labelled ham or unsure.
    pub tn: usize,
    /// Spam labelled ham or unsure.
    pub fn_: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub accuracy: f64,
    /// Held-out messages labelled `Unsure`, by true class.
    pub unsure_ham: usize,
    pub unsure_spam: usize,
    /// Counting `Unsure` as spam.
    pub lenient_precision: f64,
    pub lenient_recall: f64,
    pub false_positives: Vec<String>,
    pub false_negatives: Vec<String>,
    pub thresholds: Thresholds,
    pub elapsed_ms: u128,
    pub unparseable: usize,
}

impl EvalReport {
    /// `precision ≥ p && recall ≥ r`.
    pub fn meets(&self, precision: f64, recall: f64) -> bool {
        self.precision >= precision && self.recall >= recall
    }
}

/// One corpus message.
#[derive(Clone, Debug)]
pub struct Sample {
    pub path: PathBuf,
    pub is_spam: bool,
    pub features: Features,
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name == "cmds" {
            continue;
        }
        if p.is_dir() {
            walk(&p, out)?;
        } else if p.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// Load `DIR/ham/**` and `DIR/spam/**`, extracting features. Unparseable files are counted
/// and skipped.
pub fn load_corpus(dir: &Path, max_per_class: usize) -> Result<(Vec<Sample>, usize)> {
    let mut samples = Vec::new();
    let mut unparseable = 0;
    for (label, is_spam) in [("ham", false), ("spam", true)] {
        let sub = dir.join(label);
        if !sub.is_dir() {
            return Err(Error::Corpus(format!(
                "{} has no `{label}/` directory",
                dir.display()
            )));
        }
        let mut files = Vec::new();
        walk(&sub, &mut files)?;
        if max_per_class > 0 {
            files.truncate(max_per_class);
        }
        for path in files {
            let raw = std::fs::read(&path)?;
            match extract(&raw) {
                Ok(features) => samples.push(Sample {
                    path,
                    is_spam,
                    features,
                }),
                Err(_) => unparseable += 1,
            }
        }
    }
    if samples.is_empty() {
        return Err(Error::Corpus(format!(
            "no messages under {}",
            dir.display()
        )));
    }
    Ok((samples, unparseable))
}

/// splitmix64 — tiny, seedable, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}

/// Stratified, seeded split into (train, test) index lists.
fn split(samples: &[Sample], seed: u64, train_fraction: f64) -> (Vec<usize>, Vec<usize>) {
    let mut rng = Rng(seed);
    let mut train = Vec::new();
    let mut test = Vec::new();
    for is_spam in [false, true] {
        let mut idx: Vec<usize> = samples
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_spam == is_spam)
            .map(|(i, _)| i)
            .collect();
        rng.shuffle(&mut idx);
        let n_train = ((idx.len() as f64) * train_fraction).round() as usize;
        train.extend_from_slice(&idx[..n_train.min(idx.len())]);
        test.extend_from_slice(&idx[n_train.min(idx.len())..]);
    }
    (train, test)
}

struct Counts {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_: usize,
    unsure_ham: usize,
    unsure_spam: usize,
    fps: Vec<String>,
    fns: Vec<String>,
}

fn score(
    samples: &[Sample],
    train: &[usize],
    test: &[usize],
    thresholds: Thresholds,
    list: usize,
) -> Counts {
    let mut model = BayesModel::new();
    for &i in train {
        model.learn(&samples[i].features.tokens, samples[i].is_spam);
    }
    let classifier = Classifier::new(&model, thresholds);
    let ctx = RuleContext::default();
    let mut c = Counts {
        tp: 0,
        fp: 0,
        tn: 0,
        fn_: 0,
        unsure_ham: 0,
        unsure_spam: 0,
        fps: Vec::new(),
        fns: Vec::new(),
    };
    for &i in test {
        let s = &samples[i];
        let v = classifier.classify(&s.features, &ctx, &[]);
        let path = s.path.display().to_string();
        match (s.is_spam, v.label) {
            (true, SpamLabel::Spam) => c.tp += 1,
            (true, l) => {
                c.fn_ += 1;
                if l == SpamLabel::Unsure {
                    c.unsure_spam += 1;
                }
                if c.fns.len() < list {
                    c.fns.push(format!("{path} (p={:.3})", v.spam_probability));
                }
            }
            (false, SpamLabel::Spam) => {
                c.fp += 1;
                if c.fps.len() < list {
                    c.fps.push(format!("{path} (p={:.3})", v.spam_probability));
                }
            }
            (false, l) => {
                c.tn += 1;
                if l == SpamLabel::Unsure {
                    c.unsure_ham += 1;
                }
            }
        }
    }
    c
}

fn ratio(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 / b as f64
    }
}

/// Run the evaluation.
pub fn evaluate(dir: &Path, opts: &EvalOptions) -> Result<EvalReport> {
    let started = Instant::now();
    let (samples, unparseable) = load_corpus(dir, opts.max_per_class)?;
    let thresholds = opts.thresholds.sanitized();
    let (train, test) = split(&samples, opts.seed, opts.train_fraction.clamp(0.1, 0.95));
    let mut report = EvalReport {
        corpus: dir.display().to_string(),
        seed: opts.seed,
        train_fraction: opts.train_fraction,
        dev: opts.dev,
        n_ham: samples.iter().filter(|s| !s.is_spam).count(),
        n_spam: samples.iter().filter(|s| s.is_spam).count(),
        n_train_ham: train.iter().filter(|&&i| !samples[i].is_spam).count(),
        n_train_spam: train.iter().filter(|&&i| samples[i].is_spam).count(),
        n_test_ham: test.iter().filter(|&&i| !samples[i].is_spam).count(),
        n_test_spam: test.iter().filter(|&&i| samples[i].is_spam).count(),
        thresholds,
        unparseable,
        ..Default::default()
    };
    let counts = if opts.dev {
        // k-fold inside the training split; the held-out indices are never scored.
        let folds = opts.folds.max(2);
        let mut rng = Rng(opts.seed ^ 0xD3);
        let mut order = train.clone();
        rng.shuffle(&mut order);
        let mut total = Counts {
            tp: 0,
            fp: 0,
            tn: 0,
            fn_: 0,
            unsure_ham: 0,
            unsure_spam: 0,
            fps: Vec::new(),
            fns: Vec::new(),
        };
        for k in 0..folds {
            let fold_test: Vec<usize> = order
                .iter()
                .enumerate()
                .filter(|(j, _)| j % folds == k)
                .map(|(_, &i)| i)
                .collect();
            let fold_train: Vec<usize> = order
                .iter()
                .enumerate()
                .filter(|(j, _)| j % folds != k)
                .map(|(_, &i)| i)
                .collect();
            let c = score(
                &samples,
                &fold_train,
                &fold_test,
                thresholds,
                opts.list_errors,
            );
            total.tp += c.tp;
            total.fp += c.fp;
            total.tn += c.tn;
            total.fn_ += c.fn_;
            total.unsure_ham += c.unsure_ham;
            total.unsure_spam += c.unsure_spam;
            total.fps.extend(c.fps);
            total.fns.extend(c.fns);
        }
        total.fps.truncate(opts.list_errors);
        total.fns.truncate(opts.list_errors);
        report.n_test_ham = report.n_train_ham;
        report.n_test_spam = report.n_train_spam;
        total
    } else {
        score(&samples, &train, &test, thresholds, opts.list_errors)
    };
    report.tp = counts.tp;
    report.fp = counts.fp;
    report.tn = counts.tn;
    report.fn_ = counts.fn_;
    report.unsure_ham = counts.unsure_ham;
    report.unsure_spam = counts.unsure_spam;
    report.precision = ratio(counts.tp, counts.tp + counts.fp);
    report.recall = ratio(counts.tp, counts.tp + counts.fn_);
    report.f1 = if report.precision + report.recall > 0.0 {
        2.0 * report.precision * report.recall / (report.precision + report.recall)
    } else {
        0.0
    };
    report.accuracy = ratio(
        counts.tp + counts.tn,
        counts.tp + counts.tn + counts.fp + counts.fn_,
    );
    let l_tp = counts.tp + counts.unsure_spam;
    let l_fp = counts.fp + counts.unsure_ham;
    report.lenient_precision = ratio(l_tp, l_tp + l_fp);
    report.lenient_recall = ratio(l_tp, counts.tp + counts.fn_);
    report.false_positives = counts.fps;
    report.false_negatives = counts.fns;
    report.elapsed_ms = started.elapsed().as_millis();
    Ok(report)
}

/// Human-readable summary (what the gate greps for).
pub fn summary(r: &EvalReport) -> String {
    format!(
        "spam eval{}: corpus {} ham / {} spam; train {} ham / {} spam; test {} ham / {} spam\n\
         precision={:.4} recall={:.4} f1={:.4} accuracy={:.4}\n\
         confusion: tp={} fp={} tn={} fn={} (unsure: {} ham, {} spam; lenient precision={:.4} recall={:.4})\n\
         thresholds: spam>={:.2} unsure>={:.2} prior={:.2} clamp={:.0} min_trained={}; seed={} train_fraction={:.2}; {} ms{}",
        if r.dev { " [dev: k-fold inside the training split]" } else { " [held-out]" },
        r.n_ham,
        r.n_spam,
        r.n_train_ham,
        r.n_train_spam,
        r.n_test_ham,
        r.n_test_spam,
        r.precision,
        r.recall,
        r.f1,
        r.accuracy,
        r.tp,
        r.fp,
        r.tn,
        r.fn_,
        r.unsure_ham,
        r.unsure_spam,
        r.lenient_precision,
        r.lenient_recall,
        r.thresholds.spam,
        r.thresholds.unsure,
        r.thresholds.prior_spam,
        r.thresholds.bayes_clamp,
        r.thresholds.min_trained,
        r.seed,
        r.train_fraction,
        r.elapsed_ms,
        if r.unparseable > 0 { format!("; {} unparseable skipped", r.unparseable) } else { String::new() }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_corpus(dir: &Path) {
        std::fs::create_dir_all(dir.join("ham/set")).unwrap();
        std::fs::create_dir_all(dir.join("spam/set")).unwrap();
        const HAM_WORDS: &[&str] = &[
            "meeting", "agenda", "minutes", "project", "deadline", "report", "review", "lunch",
            "invoice", "thanks",
        ];
        const SPAM_WORDS: &[&str] = &[
            "viagra",
            "casino",
            "lottery",
            "pills",
            "cheap",
            "winner",
            "mortgage",
            "refinance",
            "unsubscribe",
            "offer",
        ];
        let ham_words = HAM_WORDS;
        let spam_words = SPAM_WORDS;
        for i in 0..40 {
            let w = |src: &'static [&'static str], k: usize| -> &'static str {
                src[(i + k) % src.len()]
            };
            let ham = format!(
                "From: colleague{i}@work.example\r\nTo: me@work.example\r\nSubject: {} {}\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <h{i}@work.example>\r\n\r\n{} {} {} tomorrow\r\n",
                w(ham_words, 0), w(ham_words, 1), w(ham_words, 2), w(ham_words, 3), w(ham_words, 4)
            );
            let spam = format!(
                "From: promo{i}@deals.example\r\nTo: me@work.example\r\nSubject: {} {}\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <s{i}@deals.example>\r\n\r\n{} {} {} http://deals.example/x\r\n",
                w(spam_words, 0), w(spam_words, 1), w(spam_words, 2), w(spam_words, 3), w(spam_words, 4)
            );
            std::fs::write(dir.join(format!("ham/set/{i:04}.txt")), ham).unwrap();
            std::fs::write(dir.join(format!("spam/set/{i:04}.txt")), spam).unwrap();
        }
        std::fs::write(dir.join("ham/set/cmds"), "ignored").unwrap();
    }

    #[test]
    fn synthetic_corpus_is_separable_and_split_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        write_corpus(dir.path());
        let opts = EvalOptions {
            thresholds: Thresholds {
                min_trained: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let r = evaluate(dir.path(), &opts).unwrap();
        assert_eq!((r.n_ham, r.n_spam), (40, 40));
        assert_eq!(
            (r.n_train_ham, r.n_train_spam, r.n_test_ham, r.n_test_spam),
            (28, 28, 12, 12)
        );
        assert!(r.meets(0.98, 0.85), "{}", summary(&r));
        assert_eq!(r.fp, 0);
        let again = evaluate(dir.path(), &opts).unwrap();
        assert_eq!(
            (again.tp, again.fp, again.tn, again.fn_),
            (r.tp, r.fp, r.tn, r.fn_)
        );
        let dev = evaluate(
            dir.path(),
            &EvalOptions {
                dev: true,
                ..opts.clone()
            },
        )
        .unwrap();
        assert!(dev.dev);
        assert_eq!(
            dev.n_test_ham + dev.n_test_spam,
            56,
            "dev scores only the training split"
        );
        assert!(summary(&dev).contains("[dev"));
        // A different seed yields a different split but the same sizes.
        let other = evaluate(dir.path(), &EvalOptions { seed: 7, ..opts }).unwrap();
        assert_eq!(other.n_test_ham, r.n_test_ham);
    }

    #[test]
    fn missing_corpus_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            evaluate(dir.path(), &EvalOptions::default()),
            Err(Error::Corpus(_))
        ));
    }
}
