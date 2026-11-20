//! Explainable rules with log-odds weights. Every hit carries a stable `code`, its weight and
//! a human-readable `detail`; the classifier adds the weights to the Bayes log-odds.
//!
//! Weights are in natural-log odds units: +4 means "this alone multiplies the spam odds by
//! e⁴ ≈ 55". With the default prior (10 % spam) a message needs a total of about +4.4 to be
//! labelled spam when the Bayes model has nothing to say (see `docs/SPAM.md`).

use crate::features::{AuthResult, Features, DANGEROUS_EXTENSIONS};
use crate::util::{address_domain, is_lookalike_domain, registrable_domain};

/// One rule that fired.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuleHit {
    /// Stable identifier (documented in `docs/SPAM.md`).
    pub code: String,
    /// Log-odds contribution (negative = evidence of ham).
    pub weight: f64,
    /// What exactly was seen.
    pub detail: String,
}

impl RuleHit {
    pub fn new(code: &str, weight: f64, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            weight,
            detail: detail.into(),
        }
    }
}

/// What the rules know about the user.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleContext<'a> {
    /// Addresses of known correspondents (lower-cased).
    pub contacts: &'a [String],
    /// The user's own addresses (lower-cased).
    pub own_addresses: &'a [String],
}

pub const W_DANGEROUS_ATTACHMENT: f64 = 4.0;
pub const W_DOUBLE_EXTENSION: f64 = 1.5;
pub const W_LOOKALIKE_SENDER: f64 = 3.5;
pub const W_LOOKALIKE_URL: f64 = 2.5;
pub const W_DISPLAY_NAME_SPOOF: f64 = 2.5;
pub const W_PHISH_LANGUAGE: f64 = 2.5;
pub const W_PHISH_LANGUAGE_NO_LINK: f64 = 1.0;
pub const W_SCAM_LANGUAGE: f64 = 1.5;
pub const W_SCAM_LANGUAGE_MANY: f64 = 2.5;
pub const W_DMARC_FAIL: f64 = 2.0;
pub const W_DKIM_FAIL: f64 = 1.5;
pub const W_SPF_FAIL: f64 = 1.0;
pub const W_MAJOR_DOMAIN_BONUS: f64 = 1.0;
pub const W_AUTH_MISSING_MAJOR: f64 = 1.5;
pub const W_REPLY_TO_MISMATCH: f64 = 0.6;
pub const W_REPLY_TO_FREEMAIL: f64 = 0.8;
pub const W_RAW_IP_URL: f64 = 1.5;
pub const W_RAW_IP_FROM: f64 = 2.0;
pub const W_HTML_ONLY: f64 = 0.3;
pub const W_HIDDEN_TEXT: f64 = 1.5;
pub const W_TINY_FONT: f64 = 1.0;
pub const W_COMMENT_OBFUSCATION: f64 = 1.5;
pub const W_IMAGE_ONLY: f64 = 1.0;
pub const W_MISSING_MESSAGE_ID: f64 = 1.0;
pub const W_MISSING_DATE: f64 = 0.5;
pub const W_EMPTY_SUBJECT: f64 = 0.5;
pub const W_LINK_ONLY_BODY: f64 = 1.5;
pub const W_EMPTY_SUBJECT_LINK_ONLY: f64 = 1.0;
pub const W_SHOUTING: f64 = 0.5;
pub const W_EXCESSIVE_PUNCTUATION: f64 = 0.5;
pub const W_KNOWN_SENDER: f64 = -2.0;

/// Domains whose mail is virtually always authenticated; a failure or absence of
/// SPF/DKIM/DMARC on these is a strong phishing signal.
pub const MAJOR_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "google.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "microsoft.com",
    "office.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "apple.com",
    "paypal.com",
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "ebay.com",
    "facebook.com",
    "facebookmail.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "netflix.com",
    "dropbox.com",
    "docusign.com",
    "docusign.net",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "hsbc.com",
    "barclays.co.uk",
    "lloydsbank.com",
    "natwest.com",
    "santander.co.uk",
    "dhl.com",
    "fedex.com",
    "ups.com",
    "usps.com",
    "irs.gov",
    "gov.uk",
    "hmrc.gov.uk",
    "proton.me",
    "protonmail.com",
    "coinbase.com",
    "binance.com",
    "stripe.com",
    "shopify.com",
    "adobe.com",
    "zoom.us",
    "whatsapp.com",
];

const FREEMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "gmx.de",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "qq.com",
    "163.com",
    "126.com",
];

const PHISH_PHRASES: &[&str] = &[
    "verify your account",
    "verify your identity",
    "verify your email",
    "verify your e-mail",
    "confirm your account",
    "confirm your identity",
    "confirm your password",
    "confirm your email",
    "update your account",
    "update your password",
    "update your billing",
    "update your payment",
    "account has been suspended",
    "account will be suspended",
    "account has been limited",
    "account has been locked",
    "account will be closed",
    "account has been compromised",
    "unusual activity",
    "unusual sign-in",
    "unusual login",
    "suspicious activity",
    "suspicious sign-in",
    "click here to verify",
    "click below to verify",
    "password has expired",
    "password will expire",
    "security alert",
    "validate your account",
    "re-activate your",
    "reactivate your",
    "restore your account",
    "unlock your account",
    "mailbox is full",
    "mailbox storage",
    "login to your account",
    "log in to your account",
    "sign in to your account",
    "verify now",
    "confirm now",
    "verification required",
    "action required",
    "your account will be",
    "failure to verify",
    "within 24 hours",
    "within 48 hours",
];

const SCAM_PHRASES: &[&str] = &[
    "lottery",
    "lotto",
    "you have won",
    "you've won",
    "you have been selected",
    "you have been chosen",
    "winning notification",
    "winner",
    "claim your prize",
    "claim your reward",
    "prize money",
    "beneficiary",
    "next of kin",
    "unclaimed",
    "million dollars",
    "million us dollars",
    "million usd",
    "million pounds",
    "million euros",
    "wire transfer",
    "western union",
    "moneygram",
    "100% guaranteed",
    "risk free",
    "risk-free",
    "act now",
    "limited time offer",
    "congratulations",
    "dear friend",
    "dear winner",
    "dear beneficiary",
    "business proposal",
    "transfer of funds",
    "investment opportunity",
    "work from home",
    "earn extra income",
    "no obligation",
    "cash bonus",
    "free money",
    "bank account details",
    "atm card",
    "fund transfer",
    "consignment",
    "diplomatic",
    "inheritance",
    "compensation fund",
    "casino",
    "bitcoin investment",
    "crypto investment",
    "double your",
    "make money fast",
    "get rich",
];

fn phrase_hits<'p>(text: &str, phrases: &[&'p str]) -> Vec<&'p str> {
    let mut out = Vec::new();
    for p in phrases {
        if text.contains(p) {
            out.push(*p);
        }
    }
    out
}

fn is_major(domain: &str) -> bool {
    let r = registrable_domain(domain);
    MAJOR_DOMAINS.iter().any(|m| *m == r) || r.ends_with(".gov") || r.ends_with(".gov.uk")
}

fn is_freemail(domain: &str) -> bool {
    let r = registrable_domain(domain);
    FREEMAIL_DOMAINS.iter().any(|m| *m == r)
}

/// Addresses embedded in a display name (`"bob@bank.com" <x@evil.com>`).
fn addresses_in(name: &str) -> Vec<String> {
    name.split(|c: char| {
        c.is_whitespace() || matches!(c, '<' | '>' | '"' | '(' | ')' | ',' | ';' | '\'')
    })
    .filter(|w| w.contains('@') && w.len() > 3)
    .map(|w| {
        w.trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase()
    })
    .filter(|w| address_domain(w).is_some())
    .collect()
}

/// Run every rule over the features.
pub fn evaluate(f: &Features, ctx: &RuleContext<'_>) -> Vec<RuleHit> {
    let mut hits: Vec<RuleHit> = Vec::new();
    let from_addr = f.from_address.as_deref().map(str::to_ascii_lowercase);
    let from_domain = f.from_domain.as_deref().map(registrable_domain);
    let text_lower = {
        let mut s = f.subject.to_lowercase();
        s.push(' ');
        s.push_str(&f.text.to_lowercase());
        s
    };

    // ---- attachments ------------------------------------------------------------------------
    let dangerous: Vec<&str> = f
        .attachments
        .iter()
        .filter(|a| DANGEROUS_EXTENSIONS.contains(&a.extension.as_str()))
        .map(|a| a.filename.as_str())
        .collect();
    if !dangerous.is_empty() {
        hits.push(RuleHit::new(
            "dangerous_attachment",
            W_DANGEROUS_ATTACHMENT,
            format!("executable attachment: {}", dangerous.join(", ")),
        ));
    }
    let doubles: Vec<&str> = f
        .attachments
        .iter()
        .filter(|a| {
            a.double_extension
                && !matches!(
                    a.extension.as_str(),
                    "gz" | "bz2" | "xz" | "zst" | "asc" | "sig" | "gpg" | "pgp"
                )
        })
        .map(|a| a.filename.as_str())
        .collect();
    if !doubles.is_empty() {
        hits.push(RuleHit::new(
            "double_extension",
            W_DOUBLE_EXTENSION,
            format!("double file extension: {}", doubles.join(", ")),
        ));
    }

    // ---- lookalikes of the user's contacts / own domains ----------------------------------------
    let mut genuine_domains: Vec<String> = ctx
        .contacts
        .iter()
        .chain(ctx.own_addresses.iter())
        .filter_map(|a| address_domain(a))
        .map(|d| registrable_domain(&d))
        .collect();
    genuine_domains.sort();
    genuine_domains.dedup();
    let known_sender = from_addr
        .as_deref()
        .is_some_and(|a| ctx.contacts.iter().any(|c| c.eq_ignore_ascii_case(a)));
    if let Some(fd) = &from_domain {
        if let Some(g) = genuine_domains.iter().find(|g| is_lookalike_domain(fd, g)) {
            hits.push(RuleHit::new(
                "lookalike_sender",
                W_LOOKALIKE_SENDER,
                format!("sender domain {fd} imitates {g}"),
            ));
        }
    }
    let mut url_lookalike: Option<String> = None;
    for u in &f.urls {
        if u.raw_ip {
            continue;
        }
        // Both the full host (`sealbox.test.evil.example`) and the registrable domain
        // (`sea1box.test`) can imitate a genuine domain.
        if let Some(g) = genuine_domains
            .iter()
            .find(|g| is_lookalike_domain(&u.host, g) || is_lookalike_domain(&u.domain, g))
        {
            url_lookalike = Some(format!("link domain {} imitates {g}", u.host));
            break;
        }
    }
    if let Some(d) = url_lookalike {
        hits.push(RuleHit::new("lookalike_url", W_LOOKALIKE_URL, d));
    }

    // ---- display name carrying somebody else's address ---------------------------------------
    if let Some(name) = &f.from_name {
        let lname = name.to_ascii_lowercase();
        let mut spoof: Option<String> = None;
        for a in addresses_in(&lname) {
            let ad = address_domain(&a).map(|d| registrable_domain(&d));
            if ad.is_some() && ad != from_domain {
                spoof = Some(format!(
                    "display name shows {a} but the sender is {}",
                    from_addr.as_deref().unwrap_or("?")
                ));
                break;
            }
        }
        if spoof.is_none() {
            for c in ctx.contacts.iter().chain(ctx.own_addresses.iter()) {
                let c = c.to_ascii_lowercase();
                if Some(c.as_str()) == from_addr.as_deref() {
                    continue;
                }
                let cd = address_domain(&c).map(|d| registrable_domain(&d));
                let names_contact = lname.contains(&c)
                    || cd
                        .as_deref()
                        .is_some_and(|d| d.len() >= 6 && lname.contains(d));
                if names_contact && cd != from_domain {
                    spoof = Some(format!(
                        "display name names {c} but the sender is {}",
                        from_addr.as_deref().unwrap_or("?")
                    ));
                    break;
                }
            }
        }
        if let Some(d) = spoof {
            hits.push(RuleHit::new("display_name_spoof", W_DISPLAY_NAME_SPOOF, d));
        }
    }

    // ---- language -----------------------------------------------------------------------------
    let phish = phrase_hits(&text_lower, PHISH_PHRASES);
    if !phish.is_empty() {
        let has_link = !f.urls.is_empty() || f.html_tricks.links > 0;
        let credential = f.urls.iter().any(|u| u.credential_path);
        if has_link {
            let mut w = W_PHISH_LANGUAGE;
            if credential {
                w += 0.5;
            }
            hits.push(RuleHit::new(
                "phish_language",
                w,
                format!(
                    "credential phishing phrase(s) with a link{}: {}",
                    if credential {
                        " to a login/verify page"
                    } else {
                        ""
                    },
                    phish.iter().take(3).copied().collect::<Vec<_>>().join("; ")
                ),
            ));
        } else {
            hits.push(RuleHit::new(
                "phish_language_no_link",
                W_PHISH_LANGUAGE_NO_LINK,
                format!(
                    "credential phishing phrase(s): {}",
                    phish.iter().take(3).copied().collect::<Vec<_>>().join("; ")
                ),
            ));
        }
    }
    let scam = phrase_hits(&text_lower, SCAM_PHRASES);
    if !scam.is_empty() {
        let w = if scam.len() >= 2 {
            W_SCAM_LANGUAGE_MANY
        } else {
            W_SCAM_LANGUAGE
        };
        hits.push(RuleHit::new(
            "scam_language",
            w,
            format!(
                "advance-fee / lottery phrase(s): {}",
                scam.iter().take(4).copied().collect::<Vec<_>>().join("; ")
            ),
        ));
    }

    // ---- authentication results -------------------------------------------------------------------
    if f.auth.present {
        let major = from_domain.as_deref().is_some_and(is_major);
        let bonus = if major { W_MAJOR_DOMAIN_BONUS } else { 0.0 };
        let fd = from_domain.as_deref().unwrap_or("?");
        if f.auth.dmarc == Some(AuthResult::Fail) {
            hits.push(RuleHit::new(
                "dmarc_fail",
                W_DMARC_FAIL + bonus,
                format!("DMARC failed for {fd}"),
            ));
        } else if f.auth.dkim == Some(AuthResult::Fail) && f.auth.spf != Some(AuthResult::Pass) {
            hits.push(RuleHit::new(
                "dkim_fail",
                W_DKIM_FAIL + bonus,
                format!("DKIM failed for {fd} (no SPF pass)"),
            ));
        } else if f.auth.spf == Some(AuthResult::Fail) {
            hits.push(RuleHit::new(
                "spf_fail",
                W_SPF_FAIL + bonus,
                format!("SPF failed for {fd}"),
            ));
        } else if major && !f.auth.any_pass() {
            hits.push(RuleHit::new(
                "auth_missing_major",
                W_AUTH_MISSING_MAJOR,
                format!("{fd} mail normally passes SPF/DKIM/DMARC; none did"),
            ));
        }
    }
    let auth_failed = hits
        .iter()
        .any(|h| matches!(h.code.as_str(), "dmarc_fail" | "dkim_fail" | "spf_fail"));

    // ---- Reply-To ------------------------------------------------------------------------------
    if let (Some(fd), Some(rd)) = (
        &from_domain,
        f.reply_to_domain.as_deref().map(registrable_domain),
    ) {
        if *fd != rd && f.list_id.is_none() {
            let freemail = is_freemail(&rd) && !is_freemail(fd);
            let w = if freemail {
                W_REPLY_TO_MISMATCH + W_REPLY_TO_FREEMAIL
            } else {
                W_REPLY_TO_MISMATCH
            };
            hits.push(RuleHit::new(
                "reply_to_mismatch",
                w,
                format!(
                    "replies go to {rd}, not to the sender's {fd}{}",
                    if freemail { " (free webmail)" } else { "" }
                ),
            ));
        }
    }

    // ---- raw IPs -------------------------------------------------------------------------------
    if let Some(u) = f.urls.iter().find(|u| u.raw_ip) {
        hits.push(RuleHit::new(
            "raw_ip_url",
            W_RAW_IP_URL,
            format!("link to a bare IP address: {}", u.host),
        ));
    }
    if f.from_raw_ip {
        hits.push(RuleHit::new(
            "raw_ip_from",
            W_RAW_IP_FROM,
            "sender address uses a bare IP address",
        ));
    }

    // ---- HTML -----------------------------------------------------------------------------------
    if f.html_only {
        hits.push(RuleHit::new(
            "html_only",
            W_HTML_ONLY,
            "HTML body without a text alternative",
        ));
    }
    if f.html_tricks.hidden_text {
        hits.push(RuleHit::new(
            "hidden_text",
            W_HIDDEN_TEXT,
            "hidden text (display:none / invisible colour)",
        ));
    }
    if f.html_tricks.tiny_font {
        hits.push(RuleHit::new(
            "tiny_font",
            W_TINY_FONT,
            "zero / one-pixel font size",
        ));
    }
    if f.html_tricks.comment_obfuscation >= 2 {
        hits.push(RuleHit::new(
            "comment_obfuscation",
            W_COMMENT_OBFUSCATION,
            format!(
                "{} HTML comments splitting words",
                f.html_tricks.comment_obfuscation
            ),
        ));
    }
    if f.html_tricks.image_only {
        hits.push(RuleHit::new(
            "image_only",
            W_IMAGE_ONLY,
            "image with (almost) no text",
        ));
    }

    // ---- structure ------------------------------------------------------------------------------
    if f.message_id.is_none() {
        hits.push(RuleHit::new(
            "missing_message_id",
            W_MISSING_MESSAGE_ID,
            "no Message-ID header",
        ));
    }
    if f.date.is_none() {
        hits.push(RuleHit::new(
            "missing_date",
            W_MISSING_DATE,
            "no (parseable) Date header",
        ));
    }
    let empty_subject = f.subject.trim().is_empty();
    if empty_subject {
        hits.push(RuleHit::new(
            "empty_subject",
            W_EMPTY_SUBJECT,
            "empty subject",
        ));
    }
    let words = f
        .text
        .split_whitespace()
        .filter(|w| !w.contains("://") && !w.starts_with("www."))
        .count();
    if !f.urls.is_empty() && words <= 3 {
        let w = if empty_subject {
            W_LINK_ONLY_BODY + W_EMPTY_SUBJECT_LINK_ONLY
        } else {
            W_LINK_ONLY_BODY
        };
        hits.push(RuleHit::new("link_only_body", w, "body is just a link"));
    }
    let subject_letters = f.subject.chars().filter(|c| c.is_alphabetic()).count();
    let subject_upper = f.subject.chars().filter(|c| c.is_uppercase()).count();
    if f.caps_ratio > 0.6 || (subject_letters >= 10 && subject_upper * 10 > subject_letters * 7) {
        hits.push(RuleHit::new(
            "shouting",
            W_SHOUTING,
            "mostly upper-case text",
        ));
    }
    if f.exclamations >= 3 || f.subject.contains("!!") || f.subject.contains("$$") {
        hits.push(RuleHit::new(
            "excessive_punctuation",
            W_EXCESSIVE_PUNCTUATION,
            "excessive !!! / $$$",
        ));
    }

    // ---- known correspondent ------------------------------------------------------------------
    if known_sender && !auth_failed {
        hits.push(RuleHit::new(
            "known_sender",
            W_KNOWN_SENDER,
            format!(
                "{} is a known correspondent",
                from_addr.as_deref().unwrap_or("?")
            ),
        ));
    }
    hits
}

/// Sum of the weights.
pub fn total_weight(hits: &[RuleHit]) -> f64 {
    hits.iter().map(|h| h.weight).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::extract;

    fn codes(hits: &[RuleHit]) -> Vec<&str> {
        hits.iter().map(|h| h.code.as_str()).collect()
    }

    #[test]
    fn clean_mail_from_a_contact_only_hits_known_sender() {
        let raw = "From: Bob <bob@example.org>\r\nTo: alice@example.org\r\nSubject: Lunch?\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <a@example.org>\r\n\r\nSee you at 12.\r\n";
        let f = extract(raw.as_bytes()).unwrap();
        let contacts = vec!["bob@example.org".to_string()];
        let hits = evaluate(
            &f,
            &RuleContext {
                contacts: &contacts,
                own_addresses: &[],
            },
        );
        assert_eq!(codes(&hits), vec!["known_sender"]);
        assert!(total_weight(&hits) < 0.0);
        let hits = evaluate(&f, &RuleContext::default());
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn obvious_phish_fires_many_rules() {
        let raw = "From: \"bob@example.org\" <bob@examp1e.org>\r\nReply-To: claims@gmail.com\r\nSubject: CONGRATULATIONS!!! YOU HAVE WON THE LOTTERY\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nDear winner, verify your account at http://10.0.0.1/secure/login to claim your prize of 1 million dollars.\r\n--b\r\nContent-Type: application/octet-stream; name=\"prize.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"prize.pdf.exe\"\r\n\r\nMZ\r\n--b--\r\n";
        let f = extract(raw.as_bytes()).unwrap();
        let contacts = vec!["bob@example.org".to_string()];
        let hits = evaluate(
            &f,
            &RuleContext {
                contacts: &contacts,
                own_addresses: &[],
            },
        );
        let c = codes(&hits);
        for expected in [
            "dangerous_attachment",
            "double_extension",
            "lookalike_sender",
            "display_name_spoof",
            "phish_language",
            "scam_language",
            "reply_to_mismatch",
            "raw_ip_url",
            "missing_message_id",
            "missing_date",
            "shouting",
            "excessive_punctuation",
        ] {
            assert!(c.contains(&expected), "missing {expected} in {c:?}");
        }
        assert!(!c.contains(&"known_sender"));
        assert!(total_weight(&hits) > 15.0, "{}", total_weight(&hits));
    }

    #[test]
    fn auth_rules() {
        let base = "From: PayPal <service@paypal.com>\r\nTo: a@b.c\r\nSubject: hi\r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <x@paypal.com>\r\n";
        let mk = |ar: &str| {
            let raw = format!("Authentication-Results: mx; {ar}\r\n{base}\r\nhello\r\n");
            let f = extract(raw.as_bytes()).unwrap();
            evaluate(&f, &RuleContext::default())
        };
        let h = mk("dmarc=fail header.from=paypal.com");
        assert_eq!(codes(&h), vec!["dmarc_fail"]);
        assert_eq!(h[0].weight, W_DMARC_FAIL + W_MAJOR_DOMAIN_BONUS);
        let h = mk("spf=none; dkim=none");
        assert_eq!(codes(&h), vec!["auth_missing_major"]);
        let h = mk("spf=pass; dkim=pass; dmarc=pass");
        assert!(h.is_empty(), "{h:?}");
        let h = mk("dkim=fail; spf=softfail");
        assert_eq!(codes(&h), vec!["dkim_fail"]);
        // Unknown small domain: fail still counts, without the bonus; no "missing" rule.
        let raw = format!(
            "Authentication-Results: mx; spf=fail\r\n{}\r\nhello\r\n",
            base.replace("paypal.com", "tiny.example")
        );
        let f = extract(raw.as_bytes()).unwrap();
        let h = evaluate(&f, &RuleContext::default());
        assert_eq!(codes(&h), vec!["spf_fail"]);
        assert_eq!(h[0].weight, W_SPF_FAIL);
        let raw = format!(
            "Authentication-Results: mx; spf=none\r\n{}\r\nhello\r\n",
            base.replace("paypal.com", "tiny.example")
        );
        let f = extract(raw.as_bytes()).unwrap();
        assert!(evaluate(&f, &RuleContext::default()).is_empty());
    }

    #[test]
    fn link_only_and_lookalike_url() {
        let raw = "From: x@y.example\r\nSubject: \r\nDate: Thu, 22 Aug 2002 06:18:18 -0600\r\nMessage-ID: <x@y.example>\r\n\r\nhttp://sealb0x.test/login\r\n";
        let f = extract(raw.as_bytes()).unwrap();
        let own = vec!["me@sealbox.test".to_string()];
        let hits = evaluate(
            &f,
            &RuleContext {
                contacts: &[],
                own_addresses: &own,
            },
        );
        let c = codes(&hits);
        assert!(c.contains(&"lookalike_url"), "{c:?}");
        assert!(c.contains(&"empty_subject"));
        assert!(c.contains(&"link_only_body"));
        assert_eq!(
            hits.iter()
                .find(|h| h.code == "link_only_body")
                .map(|h| h.weight),
            Some(W_LINK_ONLY_BODY + W_EMPTY_SUBJECT_LINK_ONLY)
        );
    }

    #[test]
    fn display_name_address_spoof() {
        assert_eq!(
            addresses_in("\"bob@bank.com\" via mail"),
            vec!["bob@bank.com"]
        );
        assert!(addresses_in("Bob Example").is_empty());
    }
}
