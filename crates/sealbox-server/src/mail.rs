//! Outgoing mail (address-verification challenges only).
//!
//! [`MailSender`] is object-safe so the router can hold `Arc<dyn MailSender>`: an SMTP
//! implementation for production, an in-memory sink for tests, and a logging null sender used
//! when no SMTP relay is configured.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{authentication::Credentials, client::Tls},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::config::SmtpTlsMode;

/// Boxed future used by the object-safe [`MailSender`] trait.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A plain-text e-mail to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("invalid e-mail address: {0}")]
    Address(String),
    #[error("could not build message: {0}")]
    Build(String),
    #[error("SMTP transport error: {0}")]
    Transport(String),
}

/// Something that can deliver an [`OutgoingMail`].
pub trait MailSender: Send + Sync {
    /// Deliver `mail`. Implementations must not log the body (it carries a secret link).
    fn send(&self, mail: OutgoingMail) -> BoxFuture<'_, Result<(), MailError>>;

    /// Short human-readable name for the startup log line.
    fn describe(&self) -> String;
}

/// SMTP settings for [`SmtpMailSender`].
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub from: String,
    pub tls: SmtpTlsMode,
}

/// Sends through an SMTP relay with `lettre` (rustls, async).
pub struct SmtpMailSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    description: String,
}

impl SmtpMailSender {
    pub fn new(cfg: &SmtpConfig) -> Result<Self, MailError> {
        let from: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| MailError::Address(format!("SMTP from address: {e}")))?;
        let builder = match cfg.tls {
            SmtpTlsMode::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                    .map_err(|e| MailError::Transport(e.to_string()))?
            }
            SmtpTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                .map_err(|e| MailError::Transport(e.to_string()))?,
            SmtpTlsMode::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host).tls(Tls::None)
            }
        };
        let mut builder = builder.port(cfg.port);
        if let (Some(user), Some(pass)) = (&cfg.user, &cfg.pass) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }
        Ok(Self {
            transport: builder.build(),
            from,
            description: format!("smtp://{}:{} ({:?})", cfg.host, cfg.port, cfg.tls),
        })
    }
}

impl MailSender for SmtpMailSender {
    fn send(&self, mail: OutgoingMail) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            let to: Mailbox = mail
                .to
                .parse()
                .map_err(|e| MailError::Address(format!("{e}")))?;
            let message = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(mail.subject)
                .header(ContentType::TEXT_PLAIN)
                .body(mail.body)
                .map_err(|e| MailError::Build(e.to_string()))?;
            self.transport
                .send(message)
                .await
                .map(|_| ())
                .map_err(|e| MailError::Transport(e.to_string()))
        })
    }

    fn describe(&self) -> String {
        self.description.clone()
    }
}

/// Keeps every mail in memory so tests can read the challenge link.
#[derive(Default)]
pub struct MemoryMailSink {
    inner: Mutex<Vec<OutgoingMail>>,
}

impl MemoryMailSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Copy of everything sent so far.
    pub fn messages(&self) -> Vec<OutgoingMail> {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Remove and return everything sent so far.
    pub fn take(&self) -> Vec<OutgoingMail> {
        match self.inner.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(p) => std::mem::take(&mut *p.into_inner()),
        }
    }
}

impl MailSender for MemoryMailSink {
    fn send(&self, mail: OutgoingMail) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            match self.inner.lock() {
                Ok(mut g) => g.push(mail),
                Err(p) => p.into_inner().push(mail),
            }
            Ok(())
        })
    }

    fn describe(&self) -> String {
        "in-memory sink".to_owned()
    }
}

/// No relay configured: log that a mail was dropped (recipient only, never the body).
pub struct NullMailSender;

impl MailSender for NullMailSender {
    fn send(&self, mail: OutgoingMail) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            tracing::warn!(to = %mail.to, "no SMTP relay configured; challenge mail dropped");
            Err(MailError::Transport("no SMTP relay configured".to_owned()))
        })
    }

    fn describe(&self) -> String {
        "disabled (set SEALBOX_SMTP_HOST)".to_owned()
    }
}
