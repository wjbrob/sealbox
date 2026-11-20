//! Connection helpers around `sealbox-mail`: IMAP/SMTP clients for a stored account and the
//! Sent-folder pick. These take the credential exactly as stored; the OAuth refresh hook sits
//! one level up (`Engine::imap_for` / `Engine::smtp_for` in `oauth.rs`), which every network
//! path goes through. Folder creation is `ImapClient::create_folder` / `ensure_folder` now.
//!
//! The transport policy (`sealbox_mail::net_policy`, docs/THREAT_MODEL.md R12/R14) is applied
//! inside `sealbox-mail` before any network write; these helpers only supply the OAuth token's
//! [`BearerScope`] so a token is pinned to the provider that issued it.

use std::time::Duration;

use sealbox_mail::imap::{pick_role_folder, Folder, FolderRole, ImapClient};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{BearerScope, ConnectOptions, ImapError};

use crate::error::Result;
use crate::store::AccountRow;

/// Default per-operation network timeout.
pub(crate) const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

/// IMAP session for `acct`, with the token scope taken from the stored credential.
pub(crate) async fn connect_imap(acct: &AccountRow, timeout: Duration) -> Result<ImapClient> {
    connect_imap_scoped(
        acct,
        acct.bearer_scope(),
        timeout,
        &TRANSIENT_LOGIN_RETRY_DELAYS,
    )
    .await
}

/// Like [`connect_imap`] with an explicit token scope (the `oauth_tokens` row knows whether
/// the token came from a loopback mock IdP; `None` falls back to the stored credential) and
/// explicit pauses before retrying a login refusal that may clear
/// ([`ImapError::may_clear_on_retry`]): [`TRANSIENT_LOGIN_RETRY_DELAYS`] for an account
/// already known to log in, [`NO_LOGIN_RETRY`] for a probe of login candidates (there a
/// refusal is far more likely to mean "wrong login" than "busy", and the next candidate is
/// the better retry).
pub(crate) async fn connect_imap_scoped(
    acct: &AccountRow,
    bearer: Option<BearerScope>,
    timeout: Duration,
    retry_delays: &[Duration],
) -> Result<ImapClient> {
    let opts = ConnectOptions::new(timeout).with_bearer(bearer.or_else(|| acct.bearer_scope()));
    let client = retry_transient_login(&acct.imap.host, retry_delays, || {
        ImapClient::connect_with(
            &acct.imap.host,
            acct.imap.port,
            acct.imap.security,
            acct.mail_auth(),
            &opts,
        )
    })
    .await?;
    Ok(client)
}

/// No retry: one login attempt, its refusal returned as it is.
pub(crate) const NO_LOGIN_RETRY: [Duration; 0] = [];

/// Pauses before the retries of a login refusal that may clear
/// ([`ImapError::may_clear_on_retry`]): three more attempts, 5 + 10 + 20 s. Exchange Online
/// answers a burst of new logins with a code-less `NO User is authenticated but not
/// connected.` and accepts the same token seconds later (G21 Outlook, 2026-11-17); it sends
/// the same text for failures that never clear, so the retry is bounded and the last refusal
/// is returned unchanged (no temporary code: it reads as a rejected login).
pub(crate) const TRANSIENT_LOGIN_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
];

/// Run `attempt` (one IMAP connect + login) and, while it fails with a login refusal that
/// may clear ([`ImapError::may_clear_on_retry`]), run it again after each of `delays` in
/// turn. Any other error, or that one once `delays` are used up, is returned as it is:
/// rejected credentials are never retried.
pub(crate) async fn retry_transient_login<T, F, Fut>(
    host: &str,
    delays: &[Duration],
    mut attempt: F,
) -> std::result::Result<T, ImapError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, ImapError>>,
{
    let mut pauses = delays.iter();
    loop {
        match attempt().await {
            Err(e) if e.may_clear_on_retry() => match pauses.next() {
                Some(pause) => {
                    tracing::warn!(
                        host,
                        retry_in_ms = pause.as_millis() as u64,
                        "IMAP login refused for now ({e}); retrying"
                    );
                    tokio::time::sleep(*pause).await;
                }
                None => return Err(e),
            },
            r => return r,
        }
    }
}

/// SMTP client for `acct`, with the token scope taken from the stored credential.
pub(crate) fn smtp_client(acct: &AccountRow, timeout: Duration) -> Result<SmtpClient> {
    smtp_client_scoped(acct, acct.bearer_scope(), timeout)
}

/// Like [`smtp_client`] with an explicit token scope.
pub(crate) fn smtp_client_scoped(
    acct: &AccountRow,
    bearer: Option<BearerScope>,
    timeout: Duration,
) -> Result<SmtpClient> {
    let opts = ConnectOptions::new(timeout).with_bearer(bearer.or_else(|| acct.bearer_scope()));
    Ok(SmtpClient::connect_with(
        &acct.smtp.host,
        acct.smtp.port,
        acct.smtp.security,
        Some(acct.mail_auth()),
        &opts,
    )?)
}

/// Pick the Sent folder from a `LIST` result: the `\Sent` special-use attribute wins, then
/// the usual names (`Sent`, `Sent Items`, `Sent Messages`, `[Gmail]/Sent Mail`, …).
pub(crate) fn find_sent_folder(folders: &[Folder]) -> Option<String> {
    pick_role_folder(FolderRole::Sent, folders).map(|(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbox_mail::imap::LoginCode;

    fn folder(name: &str, attrs: &[&str]) -> Folder {
        Folder {
            name: name.into(),
            delimiter: Some("/".into()),
            attributes: attrs.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn refusal(reply: &str, code: Option<LoginCode>) -> ImapError {
        ImapError::LoginRejected {
            host: "h".into(),
            mechanism: sealbox_mail::imap::AUTH_XOAUTH2,
            code,
            reply: reply.into(),
        }
    }

    /// Runs `retry_transient_login` over scripted outcomes (`None` = success); returns the
    /// result and how many attempts were made.
    async fn run_script(
        script: Vec<Option<ImapError>>,
    ) -> (std::result::Result<u32, ImapError>, u32) {
        run_script_with(&[Duration::ZERO; 3], script).await
    }

    async fn run_script_with(
        delays: &[Duration],
        mut script: Vec<Option<ImapError>>,
    ) -> (std::result::Result<u32, ImapError>, u32) {
        script.reverse();
        let mut calls = 0u32;
        let r = retry_transient_login("h", delays, || {
            calls += 1;
            let next = script.pop().expect("an outcome per attempt");
            let n = calls;
            async move { next.map_or(Ok(n), Err) }
        })
        .await;
        (r, calls)
    }

    /// Exchange's code-less refusal as `sealbox-mail` reports it: no response code.
    fn not_connected() -> ImapError {
        refusal("NO User is authenticated but not connected.", None)
    }

    #[tokio::test]
    async fn a_transient_login_refusal_is_retried_until_it_succeeds() {
        let (r, calls) = run_script(vec![Some(not_connected()), Some(not_connected()), None]).await;
        assert_eq!(r.expect("third attempt succeeds"), 3);
        assert_eq!(calls, 3);
    }

    /// A persistent `not connected` (a `user=` that is not the token's mailbox, IMAP
    /// disabled): retried a bounded number of times, then returned as the code-less
    /// rejection it is - never turned into a temporary one.
    #[tokio::test]
    async fn a_persistent_not_connected_refusal_stands_after_the_retries() {
        let t = || Some(not_connected());
        let (r, calls) = run_script(vec![t(), t(), t(), t()]).await;
        let err = r.expect_err("still refused");
        assert!(
            matches!(&err, ImapError::LoginRejected { code: None, .. }),
            "{err:?}"
        );
        assert!(!err.is_transient_login());
        assert_eq!(calls, 4, "one attempt + one per pause");
    }

    /// The OAuth candidate probe passes [`NO_LOGIN_RETRY`]: one attempt per candidate.
    #[tokio::test]
    async fn no_login_retry_means_one_attempt() {
        let (r, calls) = run_script_with(&NO_LOGIN_RETRY, vec![Some(not_connected())]).await;
        assert!(matches!(
            r,
            Err(ImapError::LoginRejected { code: None, .. })
        ));
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn a_transient_refusal_gives_up_after_the_last_pause() {
        let t = || {
            Some(refusal(
                "NO [UNAVAILABLE] later",
                Some(LoginCode::Unavailable),
            ))
        };
        let (r, calls) = run_script(vec![t(), t(), t(), t()]).await;
        assert!(r.expect_err("still refused").is_transient_login());
        assert_eq!(calls, 4, "one attempt + one per pause");
    }

    #[tokio::test]
    async fn rejected_credentials_and_other_errors_are_not_retried() {
        let (r, calls) = run_script(vec![Some(refusal(
            "NO [AUTHENTICATIONFAILED] bad",
            Some(LoginCode::AuthenticationFailed),
        ))])
        .await;
        assert!(matches!(r, Err(ImapError::LoginRejected { .. })));
        assert_eq!(calls, 1);
        let (r, calls) = run_script(vec![Some(ImapError::Auth("BYE".into()))]).await;
        assert!(matches!(r, Err(ImapError::Auth(_))));
        assert_eq!(calls, 1);
        let (r, calls) = run_script(vec![None]).await;
        assert_eq!((r.expect("ok"), calls), (1, 1));
    }

    #[test]
    fn transient_retry_pauses_are_5_10_20_seconds() {
        assert_eq!(
            TRANSIENT_LOGIN_RETRY_DELAYS.map(|d| d.as_secs()),
            [5, 10, 20]
        );
    }

    #[test]
    fn sent_folder_detection() {
        assert_eq!(find_sent_folder(&[folder("INBOX", &[])]), None);
        assert_eq!(
            find_sent_folder(&[folder("INBOX", &[]), folder("sent", &[])]).as_deref(),
            Some("sent")
        );
        assert_eq!(
            find_sent_folder(&[
                folder("INBOX", &[]),
                folder("Sent Items", &[]),
                folder("[Gmail]/Sent Mail", &["Extension(\"\\\\Sent\")"])
            ])
            .as_deref(),
            Some("[Gmail]/Sent Mail")
        );
    }
}
