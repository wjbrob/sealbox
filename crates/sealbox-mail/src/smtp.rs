//! SMTP submission (lettre, tokio + rustls), including XOAUTH2.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::AsyncSmtpTransportBuilder;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::error::SmtpError;
use crate::net_policy::{self, ConnectOptions};
use crate::{Auth, Security};

/// Default command timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Server reply to a successful `DATA`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpResponse {
    pub code: String,
    pub message: String,
}

/// Which SASL mechanism family the client was configured with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpAuth {
    /// No credentials (local relays).
    None,
    /// `PLAIN`, falling back to `LOGIN`.
    PlainOrLogin,
    /// `XOAUTH2` with a bearer token.
    XOAuth2,
}

/// An SMTP submission client. Connections are opened lazily on first send.
///
/// When credentials are given but the server advertises no `AUTH` mechanism we
/// can use, the client logs one warning and continues **without**
/// authentication (local relays and test servers often work that way); see
/// [`auth_skipped`](Self::auth_skipped).
#[derive(Clone)]
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    /// Same transport without credentials, used once the server turned out to
    /// offer no usable `AUTH`.
    unauthenticated: Option<AsyncSmtpTransport<Tokio1Executor>>,
    auth_skipped: Arc<AtomicBool>,
    auth: SmtpAuth,
    host: String,
    port: u16,
}

impl std::fmt::Debug for SmtpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth)
            .field("auth_skipped", &self.auth_skipped())
            .finish()
    }
}

fn builder(
    host: &str,
    port: u16,
    security: Security,
    timeout: Duration,
) -> Result<AsyncSmtpTransportBuilder, SmtpError> {
    let builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .port(port)
        .timeout(Some(timeout));
    Ok(match security {
        Security::Tls => builder.tls(Tls::Wrapper(tls_params(host)?)),
        Security::StartTls => builder.tls(Tls::Required(tls_params(host)?)),
        Security::Plain => builder.tls(Tls::None),
    })
}

fn is_no_auth_mechanism(e: &lettre::transport::smtp::Error) -> bool {
    e.is_client()
        && e.to_string()
            .to_ascii_lowercase()
            .contains("no compatible authentication mechanism")
}

impl SmtpClient {
    /// Build a client. `auth = None` means no authentication (local test servers). An OAuth
    /// token passed here has no [`BearerScope`](crate::BearerScope): it is only sent to a
    /// Google or Microsoft host (see [`connect_with`](Self::connect_with)).
    pub fn connect(
        host: &str,
        port: u16,
        security: Security,
        auth: Option<Auth>,
    ) -> Result<Self, SmtpError> {
        Self::connect_with_timeout(host, port, security, auth, DEFAULT_TIMEOUT)
    }

    /// Like [`connect`](Self::connect) with an explicit command timeout.
    pub fn connect_with_timeout(
        host: &str,
        port: u16,
        security: Security,
        auth: Option<Auth>,
        timeout: Duration,
    ) -> Result<Self, SmtpError> {
        Self::connect_with(host, port, security, auth, &ConnectOptions::new(timeout))
    }

    /// Build a client with explicit [`ConnectOptions`]. Nothing is sent yet (connections open
    /// lazily), and the transport policy is applied here, before any network write:
    /// `Security::Plain` only towards local/private hosts or `SEALBOX_ALLOW_PLAIN_HOSTS`, and
    /// an XOAUTH2 token only towards its provider's mail hosts per `opts.bearer`
    /// ([`SmtpError::Policy`]). An XOAUTH2 token is only ever offered through lettre's
    /// `XOAUTH2` mechanism, never through `PLAIN` / `LOGIN`; a server without `AUTH XOAUTH2`
    /// gets no `AUTH` command at all.
    pub fn connect_with(
        host: &str,
        port: u16,
        security: Security,
        auth: Option<Auth>,
        opts: &ConnectOptions,
    ) -> Result<Self, SmtpError> {
        net_policy::check_transport(host, port, security)?;
        if matches!(auth, Some(Auth::XOAuth2 { .. })) {
            net_policy::check_bearer_host(opts.bearer, host)?;
        }
        let timeout = opts.timeout;
        crate::tls::ensure_crypto_provider();
        let mut b = builder(host, port, security, timeout)?;
        let (kind, unauthenticated) = match auth {
            None => (SmtpAuth::None, None),
            Some(Auth::Password { user, pass }) => {
                b = b
                    .credentials(Credentials::new(user, pass))
                    .authentication(vec![Mechanism::Plain, Mechanism::Login]);
                (
                    SmtpAuth::PlainOrLogin,
                    Some(builder(host, port, security, timeout)?.build()),
                )
            }
            Some(Auth::XOAuth2 { user, access_token }) => {
                // XOAUTH2 is the only mechanism this credential may use: lettre picks from
                // this list only, so a server offering just PLAIN/LOGIN never sees the token
                // (it gets no AUTH at all, see `auth_skipped`).
                b = b
                    .credentials(Credentials::new(user, access_token))
                    .authentication(vec![Mechanism::Xoauth2]);
                (
                    SmtpAuth::XOAuth2,
                    Some(builder(host, port, security, timeout)?.build()),
                )
            }
        };
        Ok(Self {
            transport: b.build(),
            unauthenticated,
            auth_skipped: Arc::new(AtomicBool::new(false)),
            auth: kind,
            host: host.to_owned(),
            port,
        })
    }

    /// The mechanism family this client was configured with.
    pub fn auth(&self) -> SmtpAuth {
        self.auth
    }

    /// True once a connection found that the server offers no usable `AUTH`
    /// and the client continued unauthenticated.
    pub fn auth_skipped(&self) -> bool {
        self.auth_skipped.load(Ordering::Relaxed)
    }

    /// Human-readable mechanism description for diagnostics
    /// (`XOAUTH2`, `PLAIN/LOGIN`, `none`, or `… (skipped: server offers no AUTH)`).
    pub fn auth_mechanism(&self) -> String {
        let base = match self.auth {
            SmtpAuth::None => "none",
            SmtpAuth::PlainOrLogin => "PLAIN/LOGIN",
            SmtpAuth::XOAuth2 => "XOAUTH2",
        };
        if self.auth_skipped() {
            format!("{base} (skipped: server offers no AUTH)")
        } else {
            base.to_owned()
        }
    }

    fn note_auth_skipped(&self) {
        if self
            .auth_skipped
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(
                host = %self.host,
                port = self.port,
                "SMTP server advertises no AUTH mechanism we support; continuing without \
                 authentication (credentials were given but cannot be used)"
            );
        }
    }

    fn active(&self) -> &AsyncSmtpTransport<Tokio1Executor> {
        match (&self.unauthenticated, self.auth_skipped()) {
            (Some(t), true) => t,
            _ => &self.transport,
        }
    }

    /// Open a connection, EHLO (and authenticate) without sending; `Ok(true)`
    /// when the server is reachable and accepted the credentials.
    pub async fn test_connection(&self) -> Result<bool, SmtpError> {
        match self.active().test_connection().await {
            Err(e) if is_no_auth_mechanism(&e) && self.unauthenticated.is_some() => {
                self.note_auth_skipped();
                Ok(self.active().test_connection().await?)
            }
            other => Ok(other?),
        }
    }

    /// Submit a raw RFC 5322 message. `raw` must use CRLF line endings
    /// (lettre performs dot-stuffing). `rcpts` is the full envelope recipient
    /// list, i.e. To + Cc + Bcc.
    pub async fn send_raw(
        &self,
        envelope_from: &str,
        rcpts: &[String],
        raw: &[u8],
    ) -> Result<SmtpResponse, SmtpError> {
        let from = parse_address(envelope_from)?;
        let to = rcpts
            .iter()
            .map(|r| parse_address(r))
            .collect::<Result<Vec<_>, _>>()?;
        let envelope =
            Envelope::new(Some(from), to).map_err(|e| SmtpError::Envelope(e.to_string()))?;
        let response = match self.active().send_raw(&envelope, raw).await {
            Err(e) if is_no_auth_mechanism(&e) && self.unauthenticated.is_some() => {
                self.note_auth_skipped();
                self.active().send_raw(&envelope, raw).await?
            }
            other => other?,
        };
        Ok(SmtpResponse {
            code: response.code().to_string(),
            message: response.message().collect::<Vec<_>>().join("\n"),
        })
    }

    /// Close pooled connections.
    pub async fn shutdown(&self) {
        self.transport.shutdown().await;
        if let Some(t) = &self.unauthenticated {
            t.shutdown().await;
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

fn tls_params(host: &str) -> Result<TlsParameters, SmtpError> {
    TlsParameters::new_rustls(host.to_owned()).map_err(|e| SmtpError::Tls(e.to_string()))
}

fn parse_address(s: &str) -> Result<Address, SmtpError> {
    s.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .parse::<Address>()
        .map_err(|e| SmtpError::Address(s.to_owned(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_policy::BearerScope;
    use crate::oauth::Provider;
    use crate::TransportPolicyError;
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// A minimal SMTP server that records every line it received. `auth` is the EHLO `AUTH`
    /// capability it advertises (`None` = no AUTH at all); any `AUTH` command is refused.
    /// Handles any number of sequential connections.
    async fn fake_server(auth: Option<&'static str>) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let log = log2.clone();
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut lines = BufReader::new(r).lines();
                    let _ = w.write_all(b"220 fake.test ESMTP\r\n").await;
                    let mut in_data = false;
                    while let Ok(Some(line)) = lines.next_line().await {
                        log.lock().unwrap().push(line.clone());
                        if in_data {
                            if line == "." {
                                in_data = false;
                                let _ = w.write_all(b"250 2.0.0 queued\r\n").await;
                            }
                            continue;
                        }
                        let upper = line.to_ascii_uppercase();
                        let ehlo = match auth {
                            Some(mechs) => {
                                format!("250-fake.test\r\n250-8BITMIME\r\n250-AUTH {mechs}\r\n250 SIZE 1000000\r\n")
                            }
                            None => {
                                "250-fake.test\r\n250-8BITMIME\r\n250 SIZE 1000000\r\n".to_owned()
                            }
                        };
                        let reply: Vec<u8> = if upper.starts_with("EHLO") {
                            ehlo.into_bytes()
                        } else if upper.starts_with("HELO") {
                            b"250 fake.test\r\n".to_vec()
                        } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                            b"250 2.1.0 OK\r\n".to_vec()
                        } else if upper.starts_with("DATA") {
                            in_data = true;
                            b"354 go ahead\r\n".to_vec()
                        } else if upper.starts_with("NOOP") {
                            b"250 OK\r\n".to_vec()
                        } else if upper.starts_with("QUIT") {
                            let _ = w.write_all(b"221 bye\r\n").await;
                            break;
                        } else if upper.starts_with("AUTH") {
                            b"535 5.7.8 not accepted here\r\n".to_vec()
                        } else {
                            b"500 5.5.2 unknown\r\n".to_vec()
                        };
                        if w.write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (port, log)
    }

    /// The scope of a token issued by a loopback mock IdP (tests): local hosts are fine.
    fn dev_scope() -> ConnectOptions {
        ConnectOptions::new(DEFAULT_TIMEOUT).with_bearer(Some(BearerScope {
            provider: Provider::Google,
            dev_idp: true,
        }))
    }

    #[tokio::test]
    async fn credentials_are_skipped_when_server_offers_no_auth() {
        let (port, log) = fake_server(None).await;
        let client = SmtpClient::connect(
            "127.0.0.1",
            port,
            Security::Plain,
            Some(Auth::Password {
                user: "someone".into(),
                pass: "secret".into(),
            }),
        )
        .unwrap();
        assert_eq!(client.auth(), SmtpAuth::PlainOrLogin);
        assert!(!client.auth_skipped());
        assert!(client.test_connection().await.unwrap());
        assert!(client.auth_skipped(), "the fallback must have been taken");
        let resp = client
            .send_raw(
                "a@fake.test",
                &["b@fake.test".to_string()],
                b"Subject: x\r\n\r\nbody\r\n",
            )
            .await
            .unwrap();
        assert!(resp.code.starts_with('2'), "{resp:?}");
        assert!(client.auth_mechanism().contains("skipped"));
        let seen = log.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|l| l.to_ascii_uppercase().starts_with("AUTH")),
            "client must not attempt AUTH: {seen:?}"
        );
        assert!(seen
            .iter()
            .any(|l| l.to_ascii_uppercase().starts_with("MAIL FROM")));
        client.shutdown().await;

        // XOAUTH2 credentials (from a loopback test IdP) take the same path.
        let client = SmtpClient::connect_with(
            "127.0.0.1",
            port,
            Security::Plain,
            Some(Auth::XOAuth2 {
                user: "someone".into(),
                access_token: "tok".into(),
            }),
            &dev_scope(),
        )
        .unwrap();
        let resp = client
            .send_raw(
                "a@fake.test",
                &["b@fake.test".to_string()],
                b"Subject: y\r\n\r\nbody\r\n",
            )
            .await
            .unwrap();
        assert!(resp.code.starts_with('2'));
        assert!(client.auth_skipped());
        client.shutdown().await;
    }

    /// R14: a server that offers only PLAIN / LOGIN never receives the bearer token — not as a
    /// PLAIN/LOGIN password and not at all (no AUTH command is sent).
    #[tokio::test]
    async fn xoauth2_token_never_goes_through_plain_or_login() {
        // Built at run time so the source carries no token-shaped literal (gitleaks, G13).
        let token = ["never", "on", "the", "wire", "7f3a"].join("-");
        let token = token.as_str();
        let (port, log) = fake_server(Some("PLAIN LOGIN")).await;
        let client = SmtpClient::connect_with(
            "127.0.0.1",
            port,
            Security::Plain,
            Some(Auth::XOAuth2 {
                user: "someone@sealbox.test".into(),
                access_token: token.into(),
            }),
            &dev_scope(),
        )
        .unwrap();
        assert_eq!(client.auth(), SmtpAuth::XOAuth2);
        let _ = client.test_connection().await;
        let _ = client
            .send_raw(
                "someone@sealbox.test",
                &["b@sealbox.test".to_string()],
                b"Subject: z\r\n\r\nbody\r\n",
            )
            .await;
        client.shutdown().await;
        let seen = log.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|l| l.to_ascii_uppercase().starts_with("EHLO")),
            "the server was reached: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|l| l.to_ascii_uppercase().starts_with("AUTH")),
            "no AUTH may be attempted without XOAUTH2: {seen:?}"
        );
        let wire = seen.join("\n");
        let b64 = |s: &str| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s);
        assert!(!wire.contains(token), "token on the wire: {wire}");
        assert!(
            !wire.contains(&b64(&format!("\0someone@sealbox.test\0{token}"))),
            "token sent as AUTH PLAIN: {wire}"
        );
        assert!(
            !wire.contains(&b64(token)),
            "token sent as AUTH LOGIN: {wire}"
        );
    }

    #[tokio::test]
    async fn policy_refuses_before_any_connection() {
        // Plaintext towards a public host: refused at construction, nothing is dialled.
        let err = SmtpClient::connect("smtp.example.com", 25, Security::Plain, None)
            .expect_err("public plaintext");
        assert!(
            matches!(
                &err,
                SmtpError::Policy(TransportPolicyError::InsecureTransportRefused { host, port: 25 })
                    if host == "smtp.example.com"
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("SEALBOX_ALLOW_PLAIN_HOSTS"),
            "{err}"
        );
        // TLS towards the same host is fine (still lazy: no connection is made here).
        SmtpClient::connect("smtp.example.com", 465, Security::Tls, None).expect("tls");

        // A Google token for a foreign host, and an unscoped token for a local host.
        let tok = || {
            Some(Auth::XOAuth2 {
                user: "u".into(),
                access_token: "t".into(),
            })
        };
        let google =
            ConnectOptions::default().with_bearer(Some(BearerScope::new(Provider::Google)));
        let err = SmtpClient::connect_with("smtp.example.com", 465, Security::Tls, tok(), &google)
            .expect_err("foreign host");
        assert!(
            matches!(
                &err,
                SmtpError::Policy(TransportPolicyError::OAuthHostMismatch {
                    provider: Some(Provider::Google),
                    host
                }) if host == "smtp.example.com"
            ),
            "{err:?}"
        );
        SmtpClient::connect_with("smtp.gmail.com", 465, Security::Tls, tok(), &google)
            .expect("gmail host");
        let err = SmtpClient::connect("127.0.0.1", 3025, Security::Plain, tok())
            .expect_err("unscoped token to a local host");
        assert!(
            matches!(
                &err,
                SmtpError::Policy(TransportPolicyError::OAuthHostMismatch { provider: None, .. })
            ),
            "{err:?}"
        );
        // Password logins are not subject to the bearer rule.
        SmtpClient::connect(
            "smtp.example.com",
            587,
            Security::StartTls,
            Some(Auth::Password {
                user: "u".into(),
                pass: "p".into(),
            }),
        )
        .expect("password over starttls");
    }

    #[test]
    fn address_parsing_tolerates_angle_brackets() {
        assert_eq!(
            parse_address("<alice@example.org>").unwrap().to_string(),
            "alice@example.org"
        );
        assert!(parse_address("not an address").is_err());
    }
}
