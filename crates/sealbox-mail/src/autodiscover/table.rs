//! Built-in provider table (works offline). Sources: provider documentation
//! and the Mozilla ISPDB as of 2026; see `docs/PROVIDERS.md`.

use super::{AuthHint, ConfigSource, Endpoint, OAuthProvider, ServerConfig, UsernameForm};
use crate::Security;

#[derive(Clone, Copy, Debug)]
enum AuthKind {
    OAuthGoogle,
    OAuthMicrosoft,
    AppPassword(&'static str),
    Password,
}

#[derive(Clone, Copy, Debug)]
struct Provider {
    /// Exact domains, or `label.*` to match any TLD (e.g. `yahoo.*`).
    domains: &'static [&'static str],
    display_name: &'static str,
    imap: (&'static str, u16, Security),
    smtp: (&'static str, u16, Security),
    auth: AuthKind,
    username: UsernameForm,
}

const GOOGLE: Provider = Provider {
    domains: &["gmail.com", "googlemail.com", "google.com"],
    display_name: "Gmail",
    imap: ("imap.gmail.com", 993, Security::Tls),
    smtp: ("smtp.gmail.com", 465, Security::Tls),
    auth: AuthKind::OAuthGoogle,
    username: UsernameForm::FullAddress,
};

const MICROSOFT: Provider = Provider {
    domains: &[
        "outlook.com",
        "outlook.*",
        "hotmail.com",
        "hotmail.*",
        "live.com",
        "live.*",
        "msn.com",
        "office365.com",
        "onmicrosoft.com",
        "windowslive.com",
        "passport.com",
    ],
    display_name: "Outlook.com / Microsoft 365",
    imap: ("outlook.office365.com", 993, Security::Tls),
    smtp: ("smtp.office365.com", 587, Security::StartTls),
    auth: AuthKind::OAuthMicrosoft,
    username: UsernameForm::FullAddress,
};

const YAHOO: Provider = Provider {
    domains: &[
        "yahoo.com",
        "yahoo.*",
        "ymail.com",
        "rocketmail.com",
        "yahoodns.net",
    ],
    display_name: "Yahoo Mail",
    imap: ("imap.mail.yahoo.com", 993, Security::Tls),
    smtp: ("smtp.mail.yahoo.com", 465, Security::Tls),
    auth: AuthKind::AppPassword("https://help.yahoo.com/kb/SLN15241.html"),
    username: UsernameForm::FullAddress,
};

const AOL: Provider = Provider {
    domains: &["aol.com", "aol.*", "aim.com"],
    display_name: "AOL Mail",
    imap: ("imap.aol.com", 993, Security::Tls),
    smtp: ("smtp.aol.com", 465, Security::Tls),
    auth: AuthKind::AppPassword("https://help.aol.com/articles/Create-and-manage-app-password"),
    username: UsernameForm::FullAddress,
};

const ICLOUD: Provider = Provider {
    domains: &["icloud.com", "me.com", "mac.com"],
    display_name: "iCloud Mail",
    imap: ("imap.mail.me.com", 993, Security::Tls),
    smtp: ("smtp.mail.me.com", 587, Security::StartTls),
    auth: AuthKind::AppPassword("https://support.apple.com/102654"),
    username: UsernameForm::FullAddress,
};

const FASTMAIL: Provider = Provider {
    domains: &[
        "fastmail.com",
        "fastmail.fm",
        "fastmail.*",
        "messagingengine.com",
        "sent.com",
    ],
    display_name: "Fastmail",
    imap: ("imap.fastmail.com", 993, Security::Tls),
    smtp: ("smtp.fastmail.com", 465, Security::Tls),
    auth: AuthKind::AppPassword("https://www.fastmail.help/hc/en-us/articles/360058752854"),
    username: UsernameForm::FullAddress,
};

const ZOHO: Provider = Provider {
    domains: &["zoho.com", "zohomail.com"],
    display_name: "Zoho Mail",
    imap: ("imap.zoho.com", 993, Security::Tls),
    smtp: ("smtp.zoho.com", 465, Security::Tls),
    auth: AuthKind::AppPassword(
        "https://www.zoho.com/mail/help/adminconsole/two-factor-authentication.html#alink5",
    ),
    username: UsernameForm::FullAddress,
};

const ZOHO_EU: Provider = Provider {
    domains: &["zoho.eu", "zohomail.eu"],
    display_name: "Zoho Mail (EU)",
    imap: ("imap.zoho.eu", 993, Security::Tls),
    smtp: ("smtp.zoho.eu", 465, Security::Tls),
    auth: AuthKind::AppPassword(
        "https://www.zoho.com/mail/help/adminconsole/two-factor-authentication.html#alink5",
    ),
    username: UsernameForm::FullAddress,
};

const GMX: Provider = Provider {
    domains: &["gmx.net", "gmx.de", "gmx.com", "gmx.*"],
    display_name: "GMX",
    imap: ("imap.gmx.net", 993, Security::Tls),
    smtp: ("mail.gmx.net", 465, Security::Tls),
    auth: AuthKind::Password,
    username: UsernameForm::FullAddress,
};

const WEB_DE: Provider = Provider {
    domains: &["web.de"],
    display_name: "WEB.DE",
    imap: ("imap.web.de", 993, Security::Tls),
    smtp: ("smtp.web.de", 587, Security::StartTls),
    auth: AuthKind::Password,
    username: UsernameForm::FullAddress,
};

const POSTEO: Provider = Provider {
    domains: &["posteo.de", "posteo.net", "posteo.*"],
    display_name: "Posteo",
    imap: ("posteo.de", 993, Security::Tls),
    smtp: ("posteo.de", 465, Security::Tls),
    auth: AuthKind::Password,
    username: UsernameForm::FullAddress,
};

const MAILBOX_ORG: Provider = Provider {
    domains: &["mailbox.org"],
    display_name: "mailbox.org",
    imap: ("imap.mailbox.org", 993, Security::Tls),
    smtp: ("smtp.mailbox.org", 465, Security::Tls),
    auth: AuthKind::Password,
    username: UsernameForm::FullAddress,
};

const YANDEX: Provider = Provider {
    domains: &["yandex.ru", "yandex.com", "yandex.*", "ya.ru", "narod.ru"],
    display_name: "Yandex Mail",
    imap: ("imap.yandex.com", 993, Security::Tls),
    smtp: ("smtp.yandex.com", 465, Security::Tls),
    auth: AuthKind::AppPassword("https://yandex.com/support/id/authorization/app-passwords.html"),
    username: UsernameForm::FullAddress,
};

const MAIL_RU: Provider = Provider {
    domains: &["mail.ru", "inbox.ru", "list.ru", "bk.ru", "internet.ru"],
    display_name: "Mail.ru",
    imap: ("imap.mail.ru", 993, Security::Tls),
    smtp: ("smtp.mail.ru", 465, Security::Tls),
    auth: AuthKind::AppPassword("https://help.mail.ru/mail/security/protection/external"),
    username: UsernameForm::FullAddress,
};

const PROTON_BRIDGE: Provider = Provider {
    domains: &["protonmail.com", "protonmail.ch", "proton.me", "pm.me"],
    display_name: "Proton Mail (via Proton Mail Bridge on this device)",
    imap: ("127.0.0.1", 1143, Security::StartTls),
    smtp: ("127.0.0.1", 1025, Security::StartTls),
    auth: AuthKind::AppPassword("https://proton.me/support/protonmail-bridge-clients"),
    username: UsernameForm::FullAddress,
};

const PROVIDERS: &[Provider] = &[
    GOOGLE,
    MICROSOFT,
    YAHOO,
    AOL,
    ICLOUD,
    FASTMAIL,
    ZOHO,
    ZOHO_EU,
    GMX,
    WEB_DE,
    POSTEO,
    MAILBOX_ORG,
    YANDEX,
    MAIL_RU,
    PROTON_BRIDGE,
];

fn pattern_matches(pattern: &str, domain: &str) -> bool {
    if let Some(label) = pattern.strip_suffix(".*") {
        domain == label || domain.starts_with(&format!("{label}."))
    } else {
        domain == pattern
    }
}

fn to_config(p: &Provider) -> ServerConfig {
    ServerConfig {
        imap: Endpoint::new(p.imap.0, p.imap.1, p.imap.2),
        smtp: Endpoint::new(p.smtp.0, p.smtp.1, p.smtp.2),
        auth_hint: match p.auth {
            AuthKind::OAuthGoogle => AuthHint::OAuth2(OAuthProvider::Google),
            AuthKind::OAuthMicrosoft => AuthHint::OAuth2(OAuthProvider::Microsoft),
            AuthKind::AppPassword(url) => AuthHint::AppPassword {
                help_url: url.to_owned(),
            },
            AuthKind::Password => AuthHint::Password,
        },
        display_name: p.display_name.to_owned(),
        source: ConfigSource::BuiltIn,
        username: p.username,
    }
}

/// Look up a (lower-cased) domain in the built-in table.
pub fn lookup(domain: &str) -> Option<ServerConfig> {
    let domain = domain.to_ascii_lowercase();
    PROVIDERS
        .iter()
        .find(|p| p.domains.iter().any(|d| pattern_matches(d, &domain)))
        .map(to_config)
}

/// Infer a provider from an MX exchange host name (e.g. `aspmx.l.google.com`
/// ⇒ Gmail / Google Workspace, `*.mail.protection.outlook.com` ⇒ Microsoft 365).
pub fn provider_for_mx(mx_host: &str) -> Option<ServerConfig> {
    let mx = mx_host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = |s: &str| mx == s || mx.ends_with(&format!(".{s}"));
    let mut cfg = if suffix("google.com") || suffix("googlemail.com") {
        let mut c = to_config(&GOOGLE);
        c.display_name = "Google Workspace".to_owned();
        c
    } else if suffix("outlook.com") || suffix("office365.us") {
        let mut c = to_config(&MICROSOFT);
        c.display_name = "Microsoft 365".to_owned();
        c
    } else if suffix("yahoodns.net") {
        to_config(&YAHOO)
    } else if suffix("icloud.com") || suffix("me.com") {
        to_config(&ICLOUD)
    } else if suffix("messagingengine.com") {
        to_config(&FASTMAIL)
    } else if suffix("zoho.com") {
        to_config(&ZOHO)
    } else if suffix("zoho.eu") {
        to_config(&ZOHO_EU)
    } else if suffix("mail.ru") {
        to_config(&MAIL_RU)
    } else if suffix("yandex.net") || suffix("yandex.ru") {
        to_config(&YANDEX)
    } else if suffix("mailbox.org") {
        to_config(&MAILBOX_ORG)
    } else if suffix("gmx.net") {
        to_config(&GMX)
    } else if suffix("protonmail.ch") || suffix("proton.me") {
        to_config(&PROTON_BRIDGE)
    } else {
        return None;
    };
    cfg.source = ConfigSource::Mx;
    Some(cfg)
}

/// Every domain pattern in the table (for diagnostics / tests).
pub fn known_patterns() -> impl Iterator<Item = &'static str> {
    PROVIDERS.iter().flat_map(|p| p.domains.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_patterns() {
        assert!(pattern_matches("yahoo.*", "yahoo.co.uk"));
        assert!(pattern_matches("yahoo.*", "yahoo.de"));
        assert!(!pattern_matches("yahoo.*", "notyahoo.com"));
        assert!(pattern_matches("gmail.com", "gmail.com"));
        assert!(!pattern_matches("gmail.com", "mail.gmail.com"));
    }
}
