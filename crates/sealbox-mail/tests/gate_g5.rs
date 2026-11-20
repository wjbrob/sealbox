//! Gate G5 — autodiscover: the built-in table offline, the Mozilla autoconfig
//! XML parser offline, and (network permitting) ISPDB, RFC 6186 SRV and MX
//! inference for domains outside the table.

use std::time::Duration;

use sealbox_mail::autodiscover::{
    discover_offline, discover_with, domain_of, ispdb_lookup, mx_hosts, parse_autoconfig_xml,
    srv_endpoints, table, AuthHint, ConfigSource, DiscoverOptions, Endpoint, OAuthProvider,
    ServerConfig, UsernameForm,
};
use sealbox_mail::Security;

fn ep(host: &str, port: u16, security: Security) -> Endpoint {
    Endpoint::new(host, port, security)
}

fn offline(email: &str) -> ServerConfig {
    let cfg =
        discover_offline(email).unwrap_or_else(|| panic!("{email} must be in the built-in table"));
    assert_eq!(cfg.source, ConfigSource::BuiltIn);
    cfg
}

#[test]
fn gmail_offline() {
    for email in ["alice@gmail.com", "Alice@GoogleMail.com"] {
        let cfg = offline(email);
        assert_eq!(cfg.imap, ep("imap.gmail.com", 993, Security::Tls));
        assert_eq!(cfg.smtp, ep("smtp.gmail.com", 465, Security::Tls));
        assert_eq!(cfg.auth_hint, AuthHint::OAuth2(OAuthProvider::Google));
        assert_eq!(cfg.username, UsernameForm::FullAddress);
        assert_eq!(cfg.login_name(email), email);
    }
}

#[test]
fn outlook_hotmail_live_offline() {
    for email in [
        "a@outlook.com",
        "a@hotmail.com",
        "a@live.com",
        "a@msn.com",
        "a@hotmail.co.uk",
        "a@outlook.de",
        "a@live.fr",
    ] {
        let cfg = offline(email);
        assert_eq!(
            cfg.imap,
            ep("outlook.office365.com", 993, Security::Tls),
            "{email}"
        );
        assert_eq!(
            cfg.smtp,
            ep("smtp.office365.com", 587, Security::StartTls),
            "{email}"
        );
        assert_eq!(
            cfg.auth_hint,
            AuthHint::OAuth2(OAuthProvider::Microsoft),
            "{email}"
        );
    }
}

#[test]
fn yahoo_aol_offline() {
    for email in ["a@yahoo.com", "a@yahoo.co.uk", "a@yahoo.de", "a@ymail.com"] {
        let cfg = offline(email);
        assert_eq!(
            cfg.imap,
            ep("imap.mail.yahoo.com", 993, Security::Tls),
            "{email}"
        );
        assert_eq!(
            cfg.smtp,
            ep("smtp.mail.yahoo.com", 465, Security::Tls),
            "{email}"
        );
        assert!(
            matches!(cfg.auth_hint, AuthHint::AppPassword { ref help_url } if help_url.starts_with("https://")),
            "{email}"
        );
    }
    let cfg = offline("a@aol.com");
    assert_eq!(cfg.imap, ep("imap.aol.com", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.aol.com", 465, Security::Tls));
}

#[test]
fn icloud_offline() {
    for email in ["a@icloud.com", "a@me.com", "a@mac.com"] {
        let cfg = offline(email);
        assert_eq!(
            cfg.imap,
            ep("imap.mail.me.com", 993, Security::Tls),
            "{email}"
        );
        assert_eq!(
            cfg.smtp,
            ep("smtp.mail.me.com", 587, Security::StartTls),
            "{email}"
        );
        assert!(
            matches!(cfg.auth_hint, AuthHint::AppPassword { .. }),
            "{email}"
        );
    }
}

#[test]
fn fastmail_zoho_gmx_and_friends_offline() {
    let cfg = offline("a@fastmail.com");
    assert_eq!(cfg.imap, ep("imap.fastmail.com", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.fastmail.com", 465, Security::Tls));
    assert!(matches!(cfg.auth_hint, AuthHint::AppPassword { .. }));

    let cfg = offline("a@zoho.com");
    assert_eq!(cfg.imap, ep("imap.zoho.com", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.zoho.com", 465, Security::Tls));
    let cfg = offline("a@zoho.eu");
    assert_eq!(cfg.imap.host, "imap.zoho.eu");

    for email in ["a@gmx.de", "a@gmx.net", "a@gmx.at", "a@gmx.com"] {
        let cfg = offline(email);
        assert_eq!(cfg.imap, ep("imap.gmx.net", 993, Security::Tls), "{email}");
        assert_eq!(cfg.smtp, ep("mail.gmx.net", 465, Security::Tls), "{email}");
    }
    let cfg = offline("a@web.de");
    assert_eq!(cfg.imap, ep("imap.web.de", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.web.de", 587, Security::StartTls));
    let cfg = offline("a@posteo.de");
    assert_eq!(cfg.imap, ep("posteo.de", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("posteo.de", 465, Security::Tls));
    let cfg = offline("a@mailbox.org");
    assert_eq!(cfg.imap, ep("imap.mailbox.org", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.mailbox.org", 465, Security::Tls));
    let cfg = offline("a@yandex.ru");
    assert_eq!(cfg.imap, ep("imap.yandex.com", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.yandex.com", 465, Security::Tls));
    let cfg = offline("a@mail.ru");
    assert_eq!(cfg.imap, ep("imap.mail.ru", 993, Security::Tls));
    assert_eq!(cfg.smtp, ep("smtp.mail.ru", 465, Security::Tls));
    let cfg = offline("a@proton.me");
    assert_eq!(cfg.imap, ep("127.0.0.1", 1143, Security::StartTls));
    assert_eq!(cfg.smtp, ep("127.0.0.1", 1025, Security::StartTls));
}

#[tokio::test]
async fn offline_mode_never_touches_the_network() {
    let opts = DiscoverOptions {
        allow_network: false,
        timeout: Duration::from_millis(1),
    };
    let cfg = discover_with("someone@hotmail.com", &opts).await.unwrap();
    assert_eq!(cfg.source, ConfigSource::BuiltIn);
    let err = discover_with("someone@no-such-provider-sealbox.invalid", &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(err, sealbox_mail::DiscoverError::NotFound(_)),
        "{err:?}"
    );
    assert!(discover_offline("someone@no-such-provider-sealbox.invalid").is_none());
    assert!(discover_offline("not-an-email").is_none());
    assert_eq!(domain_of("A@Example.COM.").unwrap(), "example.com");
    assert!(domain_of("@example.com").is_err());
    assert!(table::known_patterns().any(|p| p == "gmail.com"));
}

#[test]
fn mx_inference_table() {
    let cfg = table::provider_for_mx("aspmx.l.google.com.").expect("google mx");
    assert_eq!(cfg.imap.host, "imap.gmail.com");
    assert_eq!(cfg.auth_hint, AuthHint::OAuth2(OAuthProvider::Google));
    assert_eq!(cfg.source, ConfigSource::Mx);
    let cfg = table::provider_for_mx("contoso-com.mail.protection.outlook.com").expect("ms mx");
    assert_eq!(cfg.imap.host, "outlook.office365.com");
    assert_eq!(cfg.auth_hint, AuthHint::OAuth2(OAuthProvider::Microsoft));
    assert!(table::provider_for_mx("mx1.example.org").is_none());
}

const T_ONLINE_XML: &str = r#"<clientConfig version="1.1">
  <emailProvider id="t-online.de">
    <domain>t-online.de</domain>
    <domain>magenta.de</domain>
    <displayName>t-online</displayName>
    <displayShortName>t-online</displayShortName>
    <incomingServer type="imap">
      <hostname>secureimap.t-online.de</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>securepop.t-online.de</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>securesmtp.t-online.de</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>securesmtp.t-online.de</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
    <enable visiturl="https://www.telekom.de/hilfe/apps-dienste/e-mail/programme/passwort-verwalten">
      <instruction>You need to set up an E-Mail-Password.</instruction>
      <instruction lang="de">Sie m&#252;ssen ein E-Mail-Passwort einrichten.</instruction>
    </enable>
    <documentation url="https://www.telekom.de/hilfe"/>
  </emailProvider>
  <webMail>
    <loginPage url="https://email.t-online.de"/>
  </webMail>
</clientConfig>"#;

#[test]
fn autoconfig_xml_parser_offline() {
    let cfg = parse_autoconfig_xml(T_ONLINE_XML, "t-online.de").expect("parse");
    assert_eq!(cfg.display_name, "t-online");
    assert_eq!(cfg.imap, ep("secureimap.t-online.de", 993, Security::Tls));
    assert_eq!(
        cfg.smtp,
        ep("securesmtp.t-online.de", 465, Security::Tls),
        "SSL preferred over STARTTLS"
    );
    assert_eq!(cfg.username, UsernameForm::FullAddress);
    assert!(
        matches!(cfg.auth_hint, AuthHint::AppPassword { ref help_url } if help_url.contains("telekom.de"))
    );

    // Gmail-style entry with OAuth2 and a local-part username.
    let gmail = r#"<clientConfig version="1.1"><emailProvider id="g"><displayName>G</displayName>
      <incomingServer type="imap"><hostname>imap.gmail.com</hostname><port>993</port><socketType>SSL</socketType>
        <username>%EMAILLOCALPART%</username><authentication>OAuth2</authentication><authentication>password-cleartext</authentication></incomingServer>
      <outgoingServer type="smtp"><hostname>smtp.gmail.com</hostname><port>465</port><socketType>SSL</socketType>
        <username>%EMAILADDRESS%</username><authentication>OAuth2</authentication></outgoingServer>
      </emailProvider></clientConfig>"#;
    let cfg = parse_autoconfig_xml(gmail, "g.example").unwrap();
    assert_eq!(cfg.auth_hint, AuthHint::OAuth2(OAuthProvider::Google));
    assert_eq!(cfg.username, UsernameForm::LocalPart);
    assert_eq!(cfg.login_name("alice@g.example"), "alice");

    assert!(parse_autoconfig_xml("<clientConfig/>", "x").is_err());
    assert!(parse_autoconfig_xml("not xml at all <", "x").is_err());
}

async fn network_available() -> bool {
    tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::TcpStream::connect(("autoconfig.thunderbird.net", 443)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

#[tokio::test]
async fn ispdb_resolves_a_domain_outside_the_table() {
    if !network_available().await {
        eprintln!("SKIP: no network for ISPDB test");
        return;
    }
    // None of these are in the built-in table; the first that answers wins.
    let candidates = [
        "t-online.de",
        "orange.fr",
        "comcast.net",
        "btinternet.com",
        "seznam.cz",
    ];
    let mut last_err = None;
    for domain in candidates {
        assert!(
            discover_offline(&format!("x@{domain}")).is_none(),
            "{domain} must not be in the table"
        );
        match ispdb_lookup(domain, Duration::from_secs(10)).await {
            Ok(cfg) => {
                assert_eq!(cfg.source, ConfigSource::Ispdb);
                assert!(cfg.imap.port == 993 || cfg.imap.port == 143, "{cfg:?}");
                assert!(cfg.smtp.port == 465 || cfg.smtp.port == 587, "{cfg:?}");
                assert!(!cfg.imap.host.is_empty() && !cfg.smtp.host.is_empty());
                assert_ne!(cfg.imap.security, Security::Plain);
                if domain == "t-online.de" {
                    assert_eq!(cfg.imap.host, "secureimap.t-online.de");
                }
                // The full chain lands on the same answer.
                let full = discover_with(&format!("user@{domain}"), &DiscoverOptions::default())
                    .await
                    .expect("discover");
                assert_eq!(full.imap, cfg.imap);
                assert_eq!(full.source, ConfigSource::Ispdb);
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    panic!("no ISPDB candidate resolved: {last_err:?}");
}

#[tokio::test]
async fn srv_records_resolve_for_rfc6186_domain() {
    if !network_available().await {
        eprintln!("SKIP: no network for SRV test");
        return;
    }
    // fastmail.com publishes _imaps._tcp and _submissions._tcp (RFC 6186).
    let (imap, smtp) = match srv_endpoints("fastmail.com", Duration::from_secs(8)).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("SKIP: DNS not usable here: {e}");
            return;
        }
    };
    let imap = imap.expect("_imaps._tcp.fastmail.com SRV");
    assert_eq!(imap, ep("imap.fastmail.com", 993, Security::Tls));
    let smtp = smtp.expect("_submissions._tcp.fastmail.com SRV");
    assert_eq!(smtp, ep("smtp.fastmail.com", 465, Security::Tls));
}

#[tokio::test]
async fn mx_inference_for_google_hosted_domain() {
    if !network_available().await {
        eprintln!("SKIP: no network for MX test");
        return;
    }
    let hosts = match mx_hosts("mozilla.com", Duration::from_secs(8)).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP: DNS not usable here: {e}");
            return;
        }
    };
    assert!(
        hosts
            .iter()
            .any(|h| h.ends_with("google.com") || h.ends_with("googlemail.com")),
        "{hosts:?}"
    );
    let cfg = hosts
        .iter()
        .find_map(|h| table::provider_for_mx(h))
        .expect("google workspace inferred");
    assert_eq!(cfg.imap.host, "imap.gmail.com");
    assert_eq!(cfg.auth_hint, AuthHint::OAuth2(OAuthProvider::Google));
}
