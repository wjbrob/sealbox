//! Mozilla ISPDB / domain autoconfig (`config-v1.1.xml`) lookup and parsing.

use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;

use super::{AuthHint, ConfigSource, Endpoint, OAuthProvider, ServerConfig, UsernameForm};
use crate::error::DiscoverError;
use crate::Security;

const ISPDB_BASE: &str = "https://autoconfig.thunderbird.net/v1.1/";
const MAX_BODY: usize = 256 * 1024;

/// `https://autoconfig.thunderbird.net/v1.1/{domain}`.
pub async fn ispdb_lookup(domain: &str, timeout: Duration) -> Result<ServerConfig, DiscoverError> {
    let url = format!("{ISPDB_BASE}{domain}");
    let xml = fetch(&url, timeout).await?;
    let mut cfg = parse_autoconfig_xml(&xml, domain)?;
    cfg.source = ConfigSource::Ispdb;
    Ok(cfg)
}

/// `https://autoconfig.{domain}/mail/config-v1.1.xml` then
/// `https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml` (HTTPS only).
pub async fn domain_autoconfig_lookup(
    domain: &str,
    email: &str,
    timeout: Duration,
) -> Result<ServerConfig, DiscoverError> {
    let email_q: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
    let urls = [
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email_q}"),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
    ];
    let mut last = DiscoverError::NotFound(domain.to_owned());
    for url in urls {
        match fetch(&url, timeout).await {
            Ok(xml) => match parse_autoconfig_xml(&xml, domain) {
                Ok(mut cfg) => {
                    cfg.source = ConfigSource::DomainAutoconfig;
                    return Ok(cfg);
                }
                Err(e) => last = e,
            },
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn fetch(url: &str, timeout: Duration) -> Result<String, DiscoverError> {
    crate::tls::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .https_only(true)
        .user_agent("sealbox-mail/0.1 (autodiscover)")
        .build()
        .map_err(|e| DiscoverError::Http(e.to_string()))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| DiscoverError::Http(format!("{url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(DiscoverError::Http(format!(
            "{url}: HTTP {}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DiscoverError::Http(e.to_string()))?;
    if bytes.len() > MAX_BODY {
        return Err(DiscoverError::Http(format!("{url}: response too large")));
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| DiscoverError::Xml(e.to_string()))
}

#[derive(Debug, Default, Clone)]
struct Server {
    kind: String,
    hostname: String,
    port: u16,
    socket_type: String,
    authentication: Vec<String>,
    username: String,
}

impl Server {
    fn endpoint(&self) -> Option<Endpoint> {
        if self.hostname.is_empty() || self.port == 0 {
            return None;
        }
        let security = match self.socket_type.to_ascii_uppercase().as_str() {
            "SSL" | "TLS" => Security::Tls,
            "STARTTLS" => Security::StartTls,
            "PLAIN" => Security::Plain,
            _ => return None,
        };
        Some(Endpoint::new(self.hostname.clone(), self.port, security))
    }

    fn rank(&self) -> u8 {
        match self.socket_type.to_ascii_uppercase().as_str() {
            "SSL" | "TLS" => 0,
            "STARTTLS" => 1,
            _ => 9,
        }
    }
}

/// Parse a Mozilla `clientConfig` version 1.1 document.
pub fn parse_autoconfig_xml(xml: &str, domain: &str) -> Result<ServerConfig, DiscoverError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut servers: Vec<Server> = Vec::new();
    let mut current: Option<Server> = None;
    let mut display_name = String::new();
    let mut enable_url: Option<String> = None;
    let mut in_provider_display_name = false;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| DiscoverError::Xml(format!("{e} at {}", reader.error_position())))?;
        match event {
            Event::Eof => break,
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_owned();
                let type_attr = e
                    .attributes()
                    .flatten()
                    .find(|a| a.key.local_name().as_ref() == "type")
                    .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok())
                    .map(|v| v.into_owned())
                    .unwrap_or_default();
                match name.as_str() {
                    "incomingServer" | "outgoingServer" => {
                        current = Some(Server {
                            kind: type_attr.to_ascii_lowercase(),
                            ..Default::default()
                        });
                    }
                    "displayName" => {
                        in_provider_display_name =
                            stack.last().is_some_and(|p| p == "emailProvider");
                    }
                    "enable" => {
                        enable_url = e
                            .attributes()
                            .flatten()
                            .find(|a| a.key.local_name().as_ref() == "visiturl")
                            .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok())
                            .map(|v| v.into_owned());
                    }
                    _ => {}
                }
                stack.push(name);
            }
            Event::Empty(e) => {
                let name = e.local_name().as_ref().to_owned();
                if name == "enable" {
                    enable_url = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == "visiturl")
                        .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok())
                        .map(|v| v.into_owned());
                }
            }
            Event::End(e) => {
                let name = e.local_name().as_ref().to_owned();
                if (name == "incomingServer" || name == "outgoingServer") && current.is_some() {
                    if let Some(s) = current.take() {
                        servers.push(s);
                    }
                }
                if name == "displayName" {
                    in_provider_display_name = false;
                }
                stack.pop();
            }
            Event::Text(t) => {
                let text = t.xml_content(XmlVersion::Implicit1_0).trim().to_owned();
                if text.is_empty() {
                    continue;
                }
                let Some(elem) = stack.last() else { continue };
                if let Some(s) = current.as_mut() {
                    match elem.as_str() {
                        "hostname" => s.hostname = text,
                        "port" => s.port = text.parse().unwrap_or(0),
                        "socketType" => s.socket_type = text,
                        "authentication" => s.authentication.push(text),
                        "username" => s.username = text,
                        _ => {}
                    }
                } else if elem == "displayName"
                    && in_provider_display_name
                    && display_name.is_empty()
                {
                    display_name = text;
                }
            }
            _ => {}
        }
    }

    let pick = |kind: &str| -> Option<Server> {
        let mut candidates: Vec<&Server> = servers
            .iter()
            .filter(|s| s.kind == kind && s.endpoint().is_some())
            .collect();
        candidates.sort_by_key(|s| s.rank());
        candidates.first().map(|s| (*s).clone())
    };
    let imap =
        pick("imap").ok_or_else(|| DiscoverError::Xml(format!("no IMAP server for {domain}")))?;
    let smtp =
        pick("smtp").ok_or_else(|| DiscoverError::Xml(format!("no SMTP server for {domain}")))?;

    let username = if imap.username.contains("%EMAILLOCALPART%") {
        UsernameForm::LocalPart
    } else {
        UsernameForm::FullAddress
    };

    let oauth_only = !imap.authentication.is_empty()
        && imap
            .authentication
            .iter()
            .all(|a| a.eq_ignore_ascii_case("OAuth2"));
    let has_oauth = imap
        .authentication
        .iter()
        .any(|a| a.eq_ignore_ascii_case("OAuth2"));
    let provider = oauth_provider_for_host(&imap.hostname);
    let auth_hint = match (provider, has_oauth, oauth_only) {
        (Some(p), true, _) => AuthHint::OAuth2(p),
        (Some(p), false, _) if matches!(p, OAuthProvider::Microsoft) => AuthHint::OAuth2(p),
        _ => match &enable_url {
            Some(url) => AuthHint::AppPassword {
                help_url: url.clone(),
            },
            None => AuthHint::Password,
        },
    };

    let imap_ep = imap
        .endpoint()
        .ok_or_else(|| DiscoverError::Xml("bad IMAP endpoint".into()))?;
    let smtp_ep = smtp
        .endpoint()
        .ok_or_else(|| DiscoverError::Xml("bad SMTP endpoint".into()))?;
    Ok(ServerConfig {
        imap: imap_ep,
        smtp: smtp_ep,
        auth_hint,
        display_name: if display_name.is_empty() {
            domain.to_owned()
        } else {
            display_name
        },
        source: ConfigSource::Ispdb,
        username,
    })
}

/// The OAuth identity provider that owns `host`, matched on a domain boundary (the same rule
/// as `table::provider_for_mx`). A bare `ends_with` would treat `imap.evilgmail.com` as Gmail:
/// an autoconfig document naming such a host would be offered "Sign in with Google", and the
/// XOAUTH2 bearer token would then be handed to that host (docs/THREAT_MODEL.md, T20).
fn oauth_provider_for_host(host: &str) -> Option<OAuthProvider> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let under = |domain: &str| h == domain || h.ends_with(&format!(".{domain}"));
    if under("gmail.com") || under("googlemail.com") || under("google.com") {
        Some(OAuthProvider::Google)
    } else if under("office365.com") || under("outlook.com") || under("hotmail.com") {
        Some(OAuthProvider::Microsoft)
    } else if under("yahoo.com") || under("aol.com") {
        Some(OAuthProvider::Yahoo)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_provider_needs_a_domain_boundary() {
        for (host, want) in [
            ("imap.gmail.com", Some(OAuthProvider::Google)),
            ("IMAP.GMAIL.COM.", Some(OAuthProvider::Google)),
            ("gmail.com", Some(OAuthProvider::Google)),
            ("imap.googlemail.com", Some(OAuthProvider::Google)),
            ("outlook.office365.com", Some(OAuthProvider::Microsoft)),
            ("imap-mail.outlook.com", Some(OAuthProvider::Microsoft)),
            ("imap.mail.yahoo.com", Some(OAuthProvider::Yahoo)),
            ("imap.aol.com", Some(OAuthProvider::Yahoo)),
            ("imap.evilgmail.com", None),
            ("gmail.com.evil.example", None),
            ("notoutlook.com", None),
            ("fakeyahoo.com", None),
            ("imap.example.com", None),
        ] {
            assert_eq!(oauth_provider_for_host(host), want, "{host}");
        }
    }

    /// R12 at the autodiscover boundary: an autoconfig document that only offers `plain` for a
    /// public host is parsed, but `discover_with` refuses it through the transport policy;
    /// when TLS is offered too, TLS wins and the policy has nothing to object to.
    #[test]
    fn plaintext_autoconfig_for_a_public_host_is_refused_by_the_policy() {
        let plain_only = r#"<clientConfig version="1.1"><emailProvider id="x">
          <incomingServer type="imap"><hostname>imap.victim.example</hostname><port>143</port>
            <socketType>plain</socketType><authentication>password-cleartext</authentication></incomingServer>
          <outgoingServer type="smtp"><hostname>smtp.victim.example</hostname><port>25</port>
            <socketType>plain</socketType></outgoingServer>
          </emailProvider></clientConfig>"#;
        let cfg = parse_autoconfig_xml(plain_only, "victim.example").unwrap();
        assert_eq!(cfg.imap.security, Security::Plain);
        let err = crate::net_policy::check_server_config(&cfg).unwrap_err();
        assert_eq!(
            err,
            crate::TransportPolicyError::InsecureTransportRefused {
                host: "imap.victim.example".into(),
                port: 143
            }
        );
        assert!(
            err.to_string().contains("SEALBOX_ALLOW_PLAIN_HOSTS"),
            "{err}"
        );
        // The same through the error type `discover_with` returns.
        let wrapped: DiscoverError = err.into();
        assert!(
            wrapped
                .to_string()
                .starts_with("plaintext connection to imap.victim.example:143 refused"),
            "{wrapped}"
        );

        let mixed = r#"<clientConfig version="1.1"><emailProvider id="x">
          <incomingServer type="imap"><hostname>imap.victim.example</hostname><port>143</port>
            <socketType>plain</socketType></incomingServer>
          <incomingServer type="imap"><hostname>imap.victim.example</hostname><port>993</port>
            <socketType>SSL</socketType></incomingServer>
          <outgoingServer type="smtp"><hostname>smtp.victim.example</hostname><port>25</port>
            <socketType>plain</socketType></outgoingServer>
          <outgoingServer type="smtp"><hostname>smtp.victim.example</hostname><port>587</port>
            <socketType>STARTTLS</socketType></outgoingServer>
          </emailProvider></clientConfig>"#;
        let cfg = parse_autoconfig_xml(mixed, "victim.example").unwrap();
        assert_eq!(cfg.imap.security, Security::Tls);
        assert_eq!(cfg.smtp.security, Security::StartTls);
        crate::net_policy::check_server_config(&cfg).expect("TLS preferred");

        // A plaintext test server in a special-use zone is fine.
        let local = plain_only
            .replace("imap.victim.example", "imap.sealbox.test")
            .replace("smtp.victim.example", "smtp.sealbox.test");
        let cfg = parse_autoconfig_xml(&local, "sealbox.test").unwrap();
        crate::net_policy::check_server_config(&cfg).expect("special-use zone");
    }

    #[test]
    fn hostile_autoconfig_lookalike_host_gets_no_oauth_hint() {
        let xml = r#"<clientConfig version="1.1"><emailProvider id="x">
          <incomingServer type="imap"><hostname>imap.evilgmail.com</hostname><port>993</port>
            <socketType>SSL</socketType><authentication>OAuth2</authentication></incomingServer>
          <outgoingServer type="smtp"><hostname>smtp.evilgmail.com</hostname><port>465</port>
            <socketType>SSL</socketType><authentication>OAuth2</authentication></outgoingServer>
          </emailProvider></clientConfig>"#;
        let cfg = parse_autoconfig_xml(xml, "victim.example").unwrap();
        assert!(
            !matches!(cfg.auth_hint, AuthHint::OAuth2(_)),
            "{:?}",
            cfg.auth_hint
        );
    }
}
