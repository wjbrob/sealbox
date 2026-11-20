//! Publishing the account key to the Sealbox key directory (the VKS-compatible subset
//! served by `sealbox-server`) and completing the address verification from the mailbox.
//!
//! The directory publishes an address only after its owner opened a challenge link that the
//! directory mailed to that address. [`Engine::publish_key`] uploads the key and asks for
//! the challenge; [`Engine::complete_directory_verification`] syncs the mailbox, finds the
//! challenge mail and follows its link — but only a link whose origin (scheme, host, port)
//! is the configured directory's, never an arbitrary URL from an inbound mail;
//! [`Engine::directory_status`] reports what the directory holds for the address.

use sealbox_mail::imap::FolderRole;

use crate::directory::{self, VerifyLinkOutcome};
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::types::{DirectoryStatus, ListQuery, PublishReport};

/// Newest stored messages of the account scanned for a challenge link.
const SCAN_LIMIT: usize = 100;
/// Distinct challenge links followed (newest mail first) before giving up.
const MAX_LINKS_TRIED: usize = 5;

impl Engine {
    /// Base URL of the key directory, or [`Error::ServerNotConfigured`].
    pub(crate) fn directory_base(&self) -> Result<String> {
        self.directory_url().ok_or_else(|| {
            Error::ServerNotConfigured(
                "no key directory: run `sealbox server set-url <url>` or set \
                 SEALBOX_SERVER_URL / SEALBOX_DIRECTORY_URL"
                    .into(),
            )
        })
    }

    /// Upload the account's public key to the directory and, unless the address is already
    /// published, request the verification challenge (the directory mails a link to the
    /// address; [`Engine::complete_directory_verification`] follows it).
    pub async fn publish_key(&self, email: &str) -> Result<PublishReport> {
        let acct = self.account_row(email)?;
        let (identity_row, _identity) = self.identity_for(&acct)?;
        let base = self.directory_base()?;
        let uploaded =
            directory::vks_upload(self.http(), &base, &identity_row.public_armored).await?;
        let state = uploaded
            .status
            .iter()
            .find(|(addr, _)| addr.eq_ignore_ascii_case(acct.email.trim()))
            .map(|(_, s)| s.clone())
            .ok_or_else(|| {
                Error::Directory(format!(
                    "the directory did not associate {} with key {} (addresses on the key: {})",
                    acct.email,
                    uploaded.key_fpr,
                    if uploaded.status.is_empty() {
                        "none".to_string()
                    } else {
                        uploaded
                            .status
                            .keys()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ))
            })?;
        if state == "published" {
            tracing::info!(email = %acct.email, fpr = %uploaded.key_fpr, "key already published");
            return Ok(PublishReport {
                fingerprint: uploaded.key_fpr,
                server_url: base,
                status: uploaded.status,
                token_issued: false,
            });
        }
        let requested = directory::vks_request_verify(
            self.http(),
            &base,
            &uploaded.token,
            std::slice::from_ref(&acct.email),
        )
        .await?;
        tracing::info!(email = %acct.email, fpr = %requested.key_fpr, "verification challenge requested");
        Ok(PublishReport {
            fingerprint: requested.key_fpr,
            server_url: base,
            status: requested.status,
            token_issued: true,
        })
    }

    /// What the directory holds for the account's address: nothing, our current key, or
    /// another key.
    pub async fn directory_status(&self, email: &str) -> Result<DirectoryStatus> {
        let acct = self.account_row(email)?;
        let (identity_row, _identity) = self.identity_for(&acct)?;
        let base = self.directory_base()?;
        self.directory_status_at(&base, &acct.email, &identity_row.fingerprint)
            .await
    }

    async fn directory_status_at(
        &self,
        base: &str,
        email: &str,
        own_fingerprint: &str,
    ) -> Result<DirectoryStatus> {
        Ok(
            match directory::vks_by_email(self.http(), base, email).await? {
                Some(key) => {
                    let matches = key.fingerprint().eq_ignore_ascii_case(own_fingerprint);
                    DirectoryStatus {
                        server_url: base.to_string(),
                        published: true,
                        fingerprint_matches: Some(matches),
                        state: if matches { "published" } else { "other_key" }.to_string(),
                    }
                }
                None => DirectoryStatus {
                    server_url: base.to_string(),
                    published: false,
                    fingerprint_matches: None,
                    state: "unpublished".to_string(),
                },
            },
        )
    }

    /// Finish publishing: sync INBOX, find the directory's challenge mail (newest first)
    /// and follow its link, then report the directory's state. Only links whose origin is
    /// the configured directory are followed. When the directory already publishes our key
    /// nothing is fetched. `state` is `awaiting_verification` when no challenge mail has
    /// arrived yet and `verification_failed` when every link found was refused (expired
    /// or already used): run [`Engine::publish_key`] again for a fresh challenge.
    pub async fn complete_directory_verification(&self, email: &str) -> Result<DirectoryStatus> {
        let acct = self.account_row(email)?;
        let (identity_row, _identity) = self.identity_for(&acct)?;
        let base = self.directory_base()?;
        let current = self
            .directory_status_at(&base, &acct.email, &identity_row.fingerprint)
            .await?;
        if current.fingerprint_matches == Some(true) {
            return Ok(current);
        }
        self.sync_folder_role(&acct.email, FolderRole::Inbox)
            .await?;
        let mut links = self.challenge_links(&acct.email, &base)?;
        if links.is_empty() {
            // The spam pass may have moved the challenge to the junk folder.
            self.sync_folder_role(&acct.email, FolderRole::Junk).await?;
            links = self.challenge_links(&acct.email, &base)?;
        }
        let mut tried = 0usize;
        for link in links.into_iter().take(MAX_LINKS_TRIED) {
            tried += 1;
            match directory::follow_verify_link(self.http(), &link).await? {
                VerifyLinkOutcome::Accepted => {
                    tracing::info!(email = %acct.email, "directory address verified");
                    break;
                }
                VerifyLinkOutcome::Refused => {
                    tracing::debug!(email = %acct.email, "challenge link refused (expired or used)");
                }
            }
        }
        let mut status = self
            .directory_status_at(&base, &acct.email, &identity_row.fingerprint)
            .await?;
        if !status.published {
            status.state = if tried == 0 {
                "awaiting_verification"
            } else {
                "verification_failed"
            }
            .to_string();
        }
        Ok(status)
    }

    /// Challenge links of the configured directory in the account's stored mail, newest
    /// message first, deduplicated.
    fn challenge_links(&self, email: &str, base: &str) -> Result<Vec<String>> {
        let rows = self.store().list_messages(&ListQuery {
            account: Some(email.to_string()),
            folder: Some("*".to_string()),
            folder_role: None,
            limit: SCAN_LIMIT,
        })?;
        let mut out: Vec<String> = Vec::new();
        for m in rows {
            let detail = match self.store().message_detail(m.id) {
                Ok(d) => d,
                Err(Error::MessageNotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            for body in [detail.text.as_deref(), detail.html.as_deref()]
                .into_iter()
                .flatten()
            {
                for link in directory::verify_links_in(body, base) {
                    if !out.contains(&link) {
                        out.push(link);
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use sealbox_crypto::Identity;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn engine_with_account(config: EngineConfig) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), config).unwrap();
        let id = engine
            .store()
            .insert_account(&NewAccount {
                email: "alice@example.org",
                display_name: "Alice",
                imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "alice",
                credential: "pw",
            })
            .unwrap();
        let identity = Identity::generate("Alice", "alice@example.org").unwrap();
        engine
            .store()
            .insert_identity(
                id,
                &identity.fingerprint(),
                "alice@example.org",
                &identity.to_armored_secret(None).unwrap(),
                &identity.public().to_armored().unwrap(),
            )
            .unwrap();
        (dir, engine)
    }

    #[tokio::test]
    async fn refuses_without_a_directory_and_without_an_account() {
        let (_dir, engine) = engine_with_account(EngineConfig::default());
        assert!(matches!(
            engine.publish_key("alice@example.org").await,
            Err(Error::ServerNotConfigured(_))
        ));
        assert!(matches!(
            engine.directory_status("alice@example.org").await,
            Err(Error::ServerNotConfigured(_))
        ));
        assert!(matches!(
            engine
                .complete_directory_verification("alice@example.org")
                .await,
            Err(Error::ServerNotConfigured(_))
        ));
        assert!(matches!(
            engine.publish_key("nobody@example.org").await,
            Err(Error::AccountNotFound(_))
        ));
        // The runtime server setting makes the directory known without any environment.
        engine
            .set_server_url(Some("http://127.0.0.1:1/".into()))
            .unwrap();
        assert_eq!(engine.directory_base().unwrap(), "http://127.0.0.1:1");
        // Nothing listens there: a directory error, not a silent "unpublished".
        assert!(matches!(
            engine.directory_status("alice@example.org").await,
            Err(Error::Directory(_))
        ));
    }

    #[test]
    fn challenge_links_come_from_stored_mail_only() {
        let (_dir, engine) = engine_with_account(EngineConfig::default());
        // No mail stored: nothing to follow, nothing fetched.
        assert!(engine
            .challenge_links("alice@example.org", "http://127.0.0.1:8787")
            .unwrap()
            .is_empty());
    }
}
