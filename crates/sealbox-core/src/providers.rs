//! Provider quirk profiles and the special-use folder mapping that the send (Sent-copy
//! policy), delete (Trash), spam (Junk) and conformance paths share.
//!
//! Two layers:
//! * [`ProviderProfile`] — static facts per provider (default folder names, whether SMTP
//!   submission already saves to Sent, connection caps, label semantics, IDLE timeout, size
//!   limit, required auth, help URL). [`folder_for`] answers from this table alone.
//! * `folder_roles` — what the server's `LIST` actually said (RFC 6154 attributes or name
//!   heuristics, see `sealbox_mail::imap::SpecialFolders`), remembered on every sync and
//!   preferred by [`Engine::special_folder`] / `Engine::folder_for_role`. Gmail localises its
//!   folder names (`[Gmail]/Gesendet`), so the live mapping wins over the static defaults.

use std::time::Duration;

use rusqlite::{params, OptionalExtension};
use sealbox_mail::imap::FlagOp as ImapFlagOp;
use sealbox_mail::imap::{
    pick_role_folder, Folder, FolderRole, ImapClient, MoveMethod, SpecialFolders,
};
use sealbox_mail::oauth::Provider;

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::{now, AccountRow};
use crate::types::{AccountInfo, FolderRoleEntry};

/// Migration for this module (applied by `Store::open`).
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS folder_roles (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'list',
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, role)
);
"#;

/// Known providers (plus the local test server and a generic fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    Gmail,
    Outlook,
    Yahoo,
    Icloud,
    Fastmail,
    Zoho,
    Gmx,
    /// The local GreenMail docker server (`testing/mail_up.sh`).
    Greenmail,
    Generic,
}

impl ProviderId {
    /// Stable lower-case name, also used in evidence file names.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderId::Gmail => "gmail",
            ProviderId::Outlook => "outlook",
            ProviderId::Yahoo => "yahoo",
            ProviderId::Icloud => "icloud",
            ProviderId::Fastmail => "fastmail",
            ProviderId::Zoho => "zoho",
            ProviderId::Gmx => "gmx",
            ProviderId::Greenmail => "greenmail",
            ProviderId::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "gmail" | "google" | "workspace" => ProviderId::Gmail,
            "outlook" | "hotmail" | "live" | "microsoft" | "m365" | "office365" => {
                ProviderId::Outlook
            }
            "yahoo" | "aol" => ProviderId::Yahoo,
            "icloud" | "apple" | "me" | "mac" => ProviderId::Icloud,
            "fastmail" => ProviderId::Fastmail,
            "zoho" => ProviderId::Zoho,
            "gmx" | "web.de" | "webde" => ProviderId::Gmx,
            "greenmail" | "local" | "test" => ProviderId::Greenmail,
            "generic" | "imap" | "other" => ProviderId::Generic,
            _ => return None,
        })
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a third-party client must present to log in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    /// XOAUTH2 only (`sealbox account add --oauth …`).
    OAuth2,
    /// An app-specific password generated in the provider's security settings.
    AppPassword,
    /// The regular mailbox password works.
    Password,
}

/// Default special-use folder names (the live `LIST` mapping overrides them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProfileFolders {
    pub sent: &'static str,
    pub drafts: &'static str,
    pub trash: &'static str,
    pub junk: &'static str,
    pub archive: Option<&'static str>,
}

/// Everything Sealbox knows about one provider's behaviour.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProviderProfile {
    pub id: ProviderId,
    pub display_name: &'static str,
    /// IMAP host names (exact, or a suffix after a dot) that select this profile.
    pub imap_hosts: &'static [&'static str],
    pub folders: ProfileFolders,
    /// SMTP submission stores a copy in Sent by itself: never `APPEND` a second one. The
    /// send path verifies by Message-ID either way, so a wrong value costs a short wait,
    /// never a duplicate.
    pub smtp_saves_sent: bool,
    /// IMAP connections per account we may hold at once (`1` = strictly serial).
    pub max_connections: u8,
    /// Whether folders may be fetched on parallel connections.
    pub parallel_fetch: bool,
    /// Gmail: folders are labels. `COPY` adds a label, a message can be in several folders at
    /// once, expunging from INBOX only archives (the message stays in All Mail); moving to
    /// Trash is the real delete.
    pub label_semantics: bool,
    /// Re-issue `IDLE` before this many seconds (RFC 2177 says 29 min; servers differ).
    pub idle_timeout_secs: u64,
    /// Largest message the submission server accepts, when documented.
    pub max_message_bytes: Option<u64>,
    pub auth: AuthRequirement,
    /// OAuth identity provider, when `auth` is [`AuthRequirement::OAuth2`].
    pub oauth: Option<Provider>,
    /// Where the user generates an app password / what to read first.
    pub help_url: &'static str,
    pub notes: &'static str,
}

impl ProviderProfile {
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    /// Default folder name for a role from this profile (always a name, never `None`).
    pub fn folder(&self, role: FolderRole) -> String {
        match role {
            FolderRole::Inbox => "INBOX",
            FolderRole::Sent => self.folders.sent,
            FolderRole::Drafts => self.folders.drafts,
            FolderRole::Trash => self.folders.trash,
            FolderRole::Junk => self.folders.junk,
            FolderRole::Archive => self.folders.archive.unwrap_or("Archive"),
            FolderRole::All => {
                if self.id == ProviderId::Gmail {
                    "[Gmail]/All Mail"
                } else {
                    self.folders.archive.unwrap_or("Archive")
                }
            }
            FolderRole::Flagged => {
                if self.id == ProviderId::Gmail {
                    "[Gmail]/Starred"
                } else {
                    "Flagged"
                }
            }
        }
        .to_owned()
    }
}

const MB: u64 = 1024 * 1024;

/// The profile table. Order matters only for host matching (first match wins).
pub const PROFILES: &[ProviderProfile] = &[
    ProviderProfile {
        id: ProviderId::Gmail,
        display_name: "Gmail / Google Workspace",
        imap_hosts: &["imap.gmail.com", "imap.googlemail.com", "gmail.com", "google.com"],
        folders: ProfileFolders {
            sent: "[Gmail]/Sent Mail",
            drafts: "[Gmail]/Drafts",
            trash: "[Gmail]/Trash",
            junk: "[Gmail]/Spam",
            archive: Some("[Gmail]/All Mail"),
        },
        smtp_saves_sent: true,
        max_connections: 10,
        parallel_fetch: true,
        label_semantics: true,
        idle_timeout_secs: 24 * 60,
        max_message_bytes: Some(25 * MB),
        auth: AuthRequirement::OAuth2,
        oauth: Some(Provider::Google),
        help_url: "https://support.google.com/mail/answer/7126229",
        notes: "SMTP keeps a copy in [Gmail]/Sent Mail (no APPEND). Folder names are \
                localised per account language; the \\Sent/\\Trash/\\Junk attributes from LIST \
                are authoritative. 15 simultaneous IMAP connections per account max. App \
                passwords need 2-Step Verification; OAuth needs the client in Testing mode or \
                Google verification.",
    },
    ProviderProfile {
        id: ProviderId::Outlook,
        display_name: "Outlook.com / Hotmail / Microsoft 365",
        imap_hosts: &[
            "outlook.office365.com",
            "imap-mail.outlook.com",
            "outlook.office.com",
            "office365.com",
            "outlook.com",
        ],
        folders: ProfileFolders {
            sent: "Sent Items",
            drafts: "Drafts",
            trash: "Deleted Items",
            junk: "Junk Email",
            archive: Some("Archive"),
        },
        smtp_saves_sent: true,
        max_connections: 8,
        parallel_fetch: true,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(20 * MB),
        auth: AuthRequirement::OAuth2,
        oauth: Some(Provider::Microsoft),
        help_url: "https://support.microsoft.com/office/pop-imap-and-smtp-settings-8361e398-8af4-4e97-b147-6c6c4ac95353",
        notes: "Basic auth is gone for consumer accounts (Sept 2024): XOAUTH2 only. SMTP AUTH \
                submission stores a copy in Sent Items (clients that APPEND get duplicates; we \
                verify by Message-ID). Exchange drops IDLE sessions after ~30 min.",
    },
    ProviderProfile {
        id: ProviderId::Yahoo,
        display_name: "Yahoo Mail / AOL",
        imap_hosts: &[
            "imap.mail.yahoo.com",
            "imap.aol.com",
            "yahoo.com",
            "aol.com",
            "mail.yahoo.com",
        ],
        folders: ProfileFolders {
            sent: "Sent",
            drafts: "Draft",
            trash: "Trash",
            junk: "Bulk Mail",
            archive: Some("Archive"),
        },
        smtp_saves_sent: false,
        max_connections: 1,
        parallel_fetch: false,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(25 * MB),
        auth: AuthRequirement::AppPassword,
        oauth: None,
        help_url: "https://help.yahoo.com/kb/SLN15241.html",
        notes: "App password required (OAuth needs Yahoo partner approval). Connection cap: \
                keep one IMAP session per account, no parallel fetch. Spam folder is 'Bulk Mail' \
                (\\Junk attribute present).",
    },
    ProviderProfile {
        id: ProviderId::Icloud,
        display_name: "iCloud Mail",
        imap_hosts: &["imap.mail.me.com", "mail.me.com", "icloud.com", "me.com"],
        folders: ProfileFolders {
            sent: "Sent Messages",
            drafts: "Drafts",
            trash: "Deleted Messages",
            junk: "Junk",
            archive: Some("Archive"),
        },
        smtp_saves_sent: false,
        max_connections: 1,
        parallel_fetch: false,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(20 * MB),
        auth: AuthRequirement::AppPassword,
        oauth: None,
        help_url: "https://support.apple.com/102654",
        notes: "App-specific password (Apple ID with 2FA). Few simultaneous connections are \
                tolerated: single session, serial folders. SMTP is STARTTLS on 587 and expects \
                the full address as login.",
    },
    ProviderProfile {
        id: ProviderId::Fastmail,
        display_name: "Fastmail",
        imap_hosts: &["imap.fastmail.com", "fastmail.com", "messagingengine.com"],
        folders: ProfileFolders {
            sent: "Sent",
            drafts: "Drafts",
            trash: "Trash",
            junk: "Spam",
            archive: Some("Archive"),
        },
        smtp_saves_sent: false,
        max_connections: 8,
        parallel_fetch: true,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(50 * MB),
        auth: AuthRequirement::AppPassword,
        oauth: None,
        help_url: "https://www.fastmail.help/hc/en-us/articles/360058752854",
        notes: "App password with IMAP+SMTP access scope. Full SPECIAL-USE support.",
    },
    ProviderProfile {
        id: ProviderId::Zoho,
        display_name: "Zoho Mail",
        imap_hosts: &["imap.zoho.com", "imap.zoho.eu", "zoho.com", "zoho.eu"],
        folders: ProfileFolders {
            sent: "Sent",
            drafts: "Drafts",
            trash: "Trash",
            junk: "Spam",
            archive: None,
        },
        smtp_saves_sent: false,
        max_connections: 4,
        parallel_fetch: true,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(20 * MB),
        auth: AuthRequirement::AppPassword,
        oauth: None,
        help_url: "https://www.zoho.com/mail/help/adminconsole/two-factor-authentication.html#alink5",
        notes: "IMAP must be enabled in Settings → Mail accounts; app password when 2FA is on.",
    },
    ProviderProfile {
        id: ProviderId::Gmx,
        display_name: "GMX / WEB.DE",
        imap_hosts: &["imap.gmx.net", "imap.gmx.com", "imap.web.de", "gmx.net", "web.de"],
        folders: ProfileFolders {
            sent: "Gesendet",
            drafts: "Entwürfe",
            trash: "Gelöscht",
            junk: "Spamverdacht",
            archive: Some("Archiv"),
        },
        smtp_saves_sent: false,
        max_connections: 2,
        parallel_fetch: false,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: Some(50 * MB),
        auth: AuthRequirement::Password,
        oauth: None,
        help_url: "https://hilfe.gmx.net/pop-imap/einschalten.html",
        notes: "IMAP access must be switched on in the web settings first. Folder names are \
                German (SPECIAL-USE attributes are sent, so the live mapping is correct). Strict \
                connection limit.",
    },
    ProviderProfile {
        id: ProviderId::Greenmail,
        display_name: "GreenMail (local test server)",
        imap_hosts: &["127.0.0.1", "localhost", "::1", "sealbox-mail"],
        folders: ProfileFolders {
            sent: "Sent",
            drafts: "Drafts",
            trash: "Trash",
            junk: "Junk",
            archive: Some("Archive"),
        },
        smtp_saves_sent: false,
        max_connections: 10,
        parallel_fetch: true,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: None,
        auth: AuthRequirement::Password,
        oauth: None,
        help_url: "testing/mail_up.sh",
        notes: "No SPECIAL-USE, no XOAUTH2 on IMAP (SMTP accepts XOAUTH2 when the bearer token \
                equals the password), so an OAuth account cannot sign in to its IMAP: the token is \
                never sent as a password (the G21 local test uses an XOAUTH2 front). Users start \
                with INBOX only; special folders are created on first use.",
    },
    ProviderProfile {
        id: ProviderId::Generic,
        display_name: "IMAP / SMTP (generic)",
        imap_hosts: &[],
        folders: ProfileFolders {
            sent: "Sent",
            drafts: "Drafts",
            trash: "Trash",
            junk: "Junk",
            archive: Some("Archive"),
        },
        smtp_saves_sent: false,
        max_connections: 2,
        parallel_fetch: false,
        label_semantics: false,
        idle_timeout_secs: 25 * 60,
        max_message_bytes: None,
        auth: AuthRequirement::Password,
        oauth: None,
        help_url: "docs/PROVIDERS.md",
        notes: "Conservative defaults; the live LIST mapping decides the folders.",
    },
];

/// The profile for an IMAP host name (exact or suffix match; `Generic` otherwise).
pub fn profile_for_host(imap_host: &str) -> &'static ProviderProfile {
    let host = imap_host.trim().trim_end_matches('.').to_ascii_lowercase();
    PROFILES
        .iter()
        .find(|p| {
            p.imap_hosts
                .iter()
                .any(|h| host == *h || host.ends_with(&format!(".{h}")))
        })
        .unwrap_or(&PROFILES[PROFILES.len() - 1])
}

/// The profile by id.
pub fn profile(id: ProviderId) -> &'static ProviderProfile {
    PROFILES
        .iter()
        .find(|p| p.id == id)
        .unwrap_or(&PROFILES[PROFILES.len() - 1])
}

/// The profile for a stored account: the provider the **owner stated** if there is one, else a
/// guess from the IMAP host.
///
/// The host guess is right for `imap.gmail.com` and wrong twice over without this: a company
/// domain on Microsoft 365 or Google Workspace has its own IMAP host, so it reads as `Generic`
/// and loses the quirks it really has; and a provider simulator on `127.0.0.1` reads as
/// `Greenmail`, which is why the conformance suite could not be pointed at one.
/// `sealbox account set-provider` writes the stated id.
pub(crate) fn profile_of(acct: &AccountRow) -> &'static ProviderProfile {
    match acct.provider {
        Some(id) => profile(id),
        None => profile_for_host(&acct.imap.host),
    }
}

/// The profile for a stored account (by its IMAP host). Prefers nothing the owner stated —
/// inside the engine use [`profile_of`], which does.
pub fn profile_for(account: &AccountInfo) -> &'static ProviderProfile {
    profile_for_host(&account.imap.host)
}

/// The folder name for a role on this account, from the static profile (no store, no
/// network). Prefer [`Engine::special_folder`], which also knows what the server's `LIST`
/// said; this is the fallback that function uses.
pub fn folder_for(role: FolderRole, account: &AccountInfo) -> String {
    profile_for(account).folder(role)
}

/// Pick the folder for a role from a live `LIST`: attributes/heuristics first, then the
/// profile's default name if such a folder exists in the list.
pub fn resolve_from_list(
    role: FolderRole,
    profile: &ProviderProfile,
    folders: &[Folder],
) -> Option<String> {
    if let Some((name, _)) = pick_role_folder(role, folders) {
        return Some(name);
    }
    let want = profile.folder(role);
    folders
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(&want) && !f.is_noselect())
        .map(|f| f.name.clone())
}

/// Outcome of [`Engine::move_message`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MoveReport {
    pub id: i64,
    pub from_folder: String,
    pub to_folder: String,
    /// `None` when the message already was in the destination.
    pub method: Option<MoveMethod>,
}

/// Local sync state of a folder (what the engine remembers between syncs).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderSyncState {
    pub name: String,
    pub uidvalidity: u32,
    pub last_uid: u32,
}

impl Engine {
    /// The provider profile of an account.
    pub fn provider_profile(&self, email: &str) -> Result<&'static ProviderProfile> {
        let acct = self.account_row(email)?;
        Ok(profile_of(&acct))
    }

    /// State which provider an account really is, overriding the guess from its IMAP host, or
    /// clear it with `None` to go back to guessing. Takes effect at once for folder roles,
    /// send quirks and the conformance suite; nothing is re-synced.
    pub fn set_account_provider(&self, email: &str, provider: Option<ProviderId>) -> Result<()> {
        let acct = self.account_row(email)?;
        self.store().set_account_provider(acct.id, provider)
    }

    /// The provider stated for an account, if any (`None` = guessed from the host).
    pub fn account_provider(&self, email: &str) -> Result<Option<ProviderId>> {
        Ok(self.account_row(email)?.provider)
    }

    /// Roles learned from the server's `LIST` (empty until the first sync).
    pub fn folder_roles(&self, email: &str) -> Result<Vec<(FolderRole, String)>> {
        let acct = self.account_row(email)?;
        self.learned_roles(acct.id)
    }

    fn learned_roles(&self, account_id: i64) -> Result<Vec<(FolderRole, String)>> {
        let store = self.store();
        let mut stmt = store
            .conn()
            .prepare("SELECT role, name FROM folder_roles WHERE account_id = ?1 ORDER BY role")?;
        let rows = stmt.query_map(params![account_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (role, name) = r?;
            if let Some(role) = FolderRole::parse(&role) {
                out.push((role, name));
            }
        }
        Ok(out)
    }

    fn learned_role(&self, account_id: i64, role: FolderRole) -> Result<Option<String>> {
        Ok(self
            .learned_roles(account_id)?
            .into_iter()
            .find(|(r, _)| *r == role)
            .map(|(_, n)| n))
    }

    /// The folder for a role: what the server's `LIST` said (remembered on sync), else the
    /// provider profile's default. Never touches the network.
    pub fn special_folder(&self, email: &str, role: FolderRole) -> Result<String> {
        let acct = self.account_row(email)?;
        Ok(self.folder_for_role(&acct, role))
    }

    /// In-crate form of [`Engine::special_folder`] for callers holding an `AccountRow`
    /// (send, delete, spam, auto-reply).
    pub(crate) fn folder_for_role(&self, acct: &AccountRow, role: FolderRole) -> String {
        match self.learned_role(acct.id, role) {
            Ok(Some(name)) => name,
            _ => profile_of(acct).folder(role),
        }
    }

    /// Remember the special-use mapping derived from a `LIST` result (called by sync).
    pub(crate) fn remember_folder_roles(
        &self,
        acct: &AccountRow,
        folders: &[Folder],
    ) -> Result<SpecialFolders> {
        let profile = profile_of(acct);
        let mut su = SpecialFolders::from_folders(folders);
        for role in FolderRole::ALL {
            if su.get(role).is_none() {
                if let Some(name) = resolve_from_list(role, profile, folders) {
                    su.set(role, Some(name));
                }
            }
        }
        let store = self.store();
        for (role, name) in su.mapped() {
            store.conn().execute(
                "INSERT INTO folder_roles (account_id, role, name, source, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(account_id, role) DO UPDATE SET \
                 name = excluded.name, source = excluded.source, updated_at = excluded.updated_at",
                params![
                    acct.id,
                    role.as_str(),
                    name,
                    format!("{:?}", su.source).to_ascii_lowercase(),
                    now()
                ],
            )?;
        }
        Ok(su)
    }

    /// Resolve a role on an open session: `LIST`, remember, pick; when nothing matches and
    /// `create` is set, create the profile's default folder. Returns the folder name.
    pub(crate) async fn resolve_folder_live(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        role: FolderRole,
        create: bool,
    ) -> Result<String> {
        let folders = client.list_folders().await?;
        let su = self.remember_folder_roles(acct, &folders)?;
        if let Some(name) = su.get(role) {
            return Ok(name.to_owned());
        }
        let name = profile_of(acct).folder(role);
        if !create {
            return Err(Error::InvalidInput(format!(
                "no {role} folder on the server for {}",
                acct.email
            )));
        }
        if client.ensure_folder(&name).await? {
            tracing::info!(email = %acct.email, folder = %name, role = %role, "created folder");
            let _ = client.subscribe(&name).await;
        }
        let folders = client.list_folders().await?;
        let _ = self.remember_folder_roles(acct, &folders)?;
        Ok(name)
    }

    /// What the engine remembers about a folder's UIDVALIDITY / last synced UID.
    pub fn folder_sync_state(&self, email: &str, folder: &str) -> Result<Option<FolderSyncState>> {
        let acct = self.account_row(email)?;
        let store = self.store();
        let row = store
            .conn()
            .query_row(
                "SELECT name, uidvalidity, last_uid FROM folders WHERE account_id = ?1 AND name = ?2",
                params![acct.id, folder],
                |r| {
                    Ok(FolderSyncState {
                        name: r.get(0)?,
                        uidvalidity: u32::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        last_uid: u32::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Every special-use role with the folder it maps to on this account: what the server's
    /// `LIST` said on a sync (`learned`), else the provider profile's default (not yet
    /// confirmed). Never touches the network; the UI can show role chips from this alone.
    pub fn folder_role_entries(&self, email: &str) -> Result<Vec<FolderRoleEntry>> {
        let acct = self.account_row(email)?;
        let learned = self.learned_roles(acct.id)?;
        let profile = profile_of(&acct);
        Ok(FolderRole::ALL
            .iter()
            .map(|&role| match learned.iter().find(|(r, _)| *r == role) {
                Some((_, name)) => FolderRoleEntry {
                    role,
                    folder: name.clone(),
                    learned: true,
                },
                None => FolderRoleEntry {
                    role,
                    folder: profile.folder(role),
                    learned: false,
                },
            })
            .collect())
    }

    /// Move a stored message to the folder playing `role` (Trash, Junk, Archive, Inbox, …),
    /// creating the folder when the server has none. The local row is dropped; the next
    /// sync of the destination folder (when synced) stores it again under its new UID.
    /// Takes the account's mailbox lock.
    pub async fn move_message(&self, id: i64, role: FolderRole) -> Result<MoveReport> {
        let account_id = self.store().message(id)?.account_id;
        let _guard = self.account_lock(account_id).await;
        self.move_message_locked(id, role).await
    }

    /// [`Engine::move_message`] for callers that already hold the account's mailbox lock.
    async fn move_message_locked(&self, id: i64, role: FolderRole) -> Result<MoveReport> {
        let (row, acct, folder) = {
            let store = self.store();
            let row = store.message(id)?;
            let acct = store
                .account_by_id(row.account_id)?
                .ok_or_else(|| Error::AccountNotFound(row.summary.account.clone()))?;
            let folder = store
                .folder_by_id(row.folder_id)?
                .ok_or_else(|| Error::MessageNotFound(id))?;
            (row, acct, folder)
        };
        let mut client = self.imap_for(&acct).await?;
        let dest = self
            .resolve_folder_live(&acct, &mut client, role, true)
            .await?;
        if dest.eq_ignore_ascii_case(&folder.name) {
            let _ = client.logout().await;
            return Ok(MoveReport {
                id,
                from_folder: folder.name,
                to_folder: dest,
                method: None,
            });
        }
        client.select(&folder.name).await?;
        let method = client.r#move(&[row.summary.uid], &dest).await?;
        let _ = client.logout().await;
        self.store().delete_message(id)?;
        Ok(MoveReport {
            id,
            from_folder: folder.name,
            to_folder: dest,
            method: Some(method),
        })
    }

    /// The delete path: a message outside Trash is moved to Trash; a message already in
    /// Trash is flagged `\Deleted` and expunged (gone for good). Gmail's label semantics make
    /// the move the only real delete. Takes the account's mailbox lock.
    pub(crate) async fn delete_to_trash(&self, id: i64) -> Result<()> {
        let (row, acct, folder) = {
            let store = self.store();
            let row = store.message(id)?;
            let acct = store
                .account_by_id(row.account_id)?
                .ok_or_else(|| Error::AccountNotFound(row.summary.account.clone()))?;
            let folder = store
                .folder_by_id(row.folder_id)?
                .ok_or_else(|| Error::MessageNotFound(id))?;
            (row, acct, folder)
        };
        let _guard = self.account_lock(acct.id).await;
        let trash = self.folder_for_role(&acct, FolderRole::Trash);
        if !folder.name.eq_ignore_ascii_case(&trash) {
            self.move_message_locked(id, FolderRole::Trash).await?;
            return Ok(());
        }
        let mut client = self.imap_for(&acct).await?;
        client.select(&folder.name).await?;
        client
            .set_flags(&[row.summary.uid], ImapFlagOp::Add, &["\\Deleted"])
            .await?;
        if client.has_capability("UIDPLUS") {
            client.uid_expunge(&[row.summary.uid]).await?;
        } else {
            client.expunge().await?;
        }
        let _ = client.logout().await;
        self.store().delete_message(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn info(host: &str) -> AccountInfo {
        AccountInfo {
            id: 1,
            email: "x@example.org".into(),
            display_name: String::new(),
            imap: Endpoint::new(host, 993, Security::Tls),
            smtp: Endpoint::new(host, 465, Security::Tls),
            auth_kind: AuthKind::Password,
            login: "x".into(),
            fingerprint: None,
            created_at: 0,
        }
    }

    #[test]
    fn hosts_select_profiles() {
        assert_eq!(profile_for_host("imap.gmail.com").id, ProviderId::Gmail);
        assert_eq!(profile_for_host("IMAP.GMAIL.COM.").id, ProviderId::Gmail);
        assert_eq!(
            profile_for_host("outlook.office365.com").id,
            ProviderId::Outlook
        );
        assert_eq!(
            profile_for_host("imap.mail.yahoo.com").id,
            ProviderId::Yahoo
        );
        assert_eq!(profile_for_host("imap.aol.com").id, ProviderId::Yahoo);
        assert_eq!(profile_for_host("imap.mail.me.com").id, ProviderId::Icloud);
        assert_eq!(
            profile_for_host("imap.fastmail.com").id,
            ProviderId::Fastmail
        );
        assert_eq!(profile_for_host("imap.zoho.eu").id, ProviderId::Zoho);
        assert_eq!(profile_for_host("imap.gmx.net").id, ProviderId::Gmx);
        assert_eq!(profile_for_host("127.0.0.1").id, ProviderId::Greenmail);
        assert_eq!(profile_for_host("mail.example.org").id, ProviderId::Generic);
        assert_eq!(
            profile_for_host("notgmail.com").id,
            ProviderId::Generic,
            "suffix match must respect the dot boundary"
        );
        for p in PROFILES {
            assert_eq!(profile(p.id).id, p.id);
            assert_eq!(ProviderId::parse(p.id.as_str()), Some(p.id));
        }
    }

    #[test]
    fn folder_for_uses_profile_defaults() {
        let g = info("imap.gmail.com");
        assert_eq!(folder_for(FolderRole::Sent, &g), "[Gmail]/Sent Mail");
        assert_eq!(folder_for(FolderRole::Junk, &g), "[Gmail]/Spam");
        assert_eq!(folder_for(FolderRole::Trash, &g), "[Gmail]/Trash");
        assert_eq!(folder_for(FolderRole::All, &g), "[Gmail]/All Mail");
        assert_eq!(folder_for(FolderRole::Inbox, &g), "INBOX");
        let o = info("outlook.office365.com");
        assert_eq!(folder_for(FolderRole::Sent, &o), "Sent Items");
        assert_eq!(folder_for(FolderRole::Trash, &o), "Deleted Items");
        assert_eq!(folder_for(FolderRole::Junk, &o), "Junk Email");
        let i = info("imap.mail.me.com");
        assert_eq!(folder_for(FolderRole::Sent, &i), "Sent Messages");
        assert_eq!(folder_for(FolderRole::Trash, &i), "Deleted Messages");
        let y = info("imap.mail.yahoo.com");
        assert_eq!(folder_for(FolderRole::Junk, &y), "Bulk Mail");
        assert_eq!(profile_for(&y).max_connections, 1);
        assert!(!profile_for(&y).parallel_fetch);
        assert!(profile_for(&g).smtp_saves_sent && profile_for(&o).smtp_saves_sent);
        assert!(!profile_for(&i).smtp_saves_sent);
        assert!(profile_for(&g).label_semantics);
        assert_eq!(profile_for(&g).oauth, Some(Provider::Google));
        assert_eq!(profile_for(&o).auth, AuthRequirement::OAuth2);
        assert_eq!(profile_for(&i).auth, AuthRequirement::AppPassword);
    }

    #[test]
    fn resolve_from_list_prefers_attributes_then_profile_names() {
        let f = |name: &str, attrs: &[&str]| Folder {
            name: name.into(),
            delimiter: Some("/".into()),
            attributes: attrs.iter().map(|a| a.to_string()).collect(),
        };
        let gmail = profile(ProviderId::Gmail);
        // Localised Gmail: the attribute wins over the (English) default name.
        let list = vec![
            f("INBOX", &[]),
            f("[Gmail]/Gesendet", &["Extension(\"\\\\Sent\")"]),
            f("[Gmail]/Papierkorb", &["Extension(\"\\\\Trash\")"]),
        ];
        assert_eq!(
            resolve_from_list(FolderRole::Sent, gmail, &list).as_deref(),
            Some("[Gmail]/Gesendet")
        );
        assert_eq!(
            resolve_from_list(FolderRole::Trash, gmail, &list).as_deref(),
            Some("[Gmail]/Papierkorb")
        );
        assert_eq!(resolve_from_list(FolderRole::Junk, gmail, &list), None);
        // Profile default present without attribute and outside the heuristics.
        let gmx = profile(ProviderId::Gmx);
        let list = vec![f("INBOX", &[]), f("Spamverdacht", &[])];
        assert_eq!(
            resolve_from_list(FolderRole::Junk, gmx, &list).as_deref(),
            Some("Spamverdacht")
        );
    }

    /// An account on a loopback host reads as `Greenmail` from its host alone, and a company
    /// domain on Microsoft 365 reads as `Generic` — both wrong, and the first is why the
    /// conformance suite could not be pointed at a provider simulator at all. A stated
    /// provider overrides the guess, survives a reopen, and changes real behaviour (the folder
    /// a role resolves to), not just a reported label.
    #[test]
    fn a_stated_provider_overrides_the_host_guess_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        const EMAIL: &str = "staff@acme-corp.example";
        {
            let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
            engine
                .store()
                .insert_account(&NewAccount {
                    email: EMAIL,
                    display_name: "",
                    // A company domain's own host: nothing in it says Microsoft.
                    imap: &Endpoint::new("mail.acme-corp.example", 993, Security::Tls),
                    smtp: &Endpoint::new("smtp.acme-corp.example", 465, Security::Tls),
                    auth_kind: AuthKind::Password,
                    login: EMAIL,
                    credential: "pw",
                })
                .unwrap();

            // Guessed: Generic, and the generic Junk folder with it.
            assert_eq!(
                engine.provider_profile(EMAIL).unwrap().id,
                ProviderId::Generic
            );
            assert_eq!(engine.account_provider(EMAIL).unwrap(), None);
            let guessed_junk = engine.special_folder(EMAIL, FolderRole::Junk).unwrap();

            engine
                .set_account_provider(EMAIL, Some(ProviderId::Outlook))
                .unwrap();
            assert_eq!(
                engine.provider_profile(EMAIL).unwrap().id,
                ProviderId::Outlook
            );
            assert_eq!(
                engine.account_provider(EMAIL).unwrap(),
                Some(ProviderId::Outlook)
            );
            let stated_junk = engine.special_folder(EMAIL, FolderRole::Junk).unwrap();
            assert_eq!(
                stated_junk, "Junk Email",
                "Outlook's name, not the generic one"
            );
            assert_ne!(
                stated_junk, guessed_junk,
                "it changed behaviour, not a label"
            );
        }

        // Reopened: it is stored, not held in memory.
        {
            let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
            assert_eq!(
                engine.account_provider(EMAIL).unwrap(),
                Some(ProviderId::Outlook)
            );
            assert_eq!(
                engine.provider_profile(EMAIL).unwrap().id,
                ProviderId::Outlook
            );

            // And it can be taken back off, returning to the host guess.
            engine.set_account_provider(EMAIL, None).unwrap();
            assert_eq!(engine.account_provider(EMAIL).unwrap(), None);
            assert_eq!(
                engine.provider_profile(EMAIL).unwrap().id,
                ProviderId::Generic
            );
        }
    }

    /// The case Phase 2 is built on: a provider simulator listening on loopback must be
    /// testable as the provider it imitates, and by host alone it is `Greenmail`.
    #[test]
    fn a_simulator_on_loopback_can_be_stated_as_the_provider_it_imitates() {
        let dir = tempfile::tempdir().unwrap();
        const EMAIL: &str = "sim@sealbox.test";
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        engine
            .store()
            .insert_account(&NewAccount {
                email: EMAIL,
                display_name: "",
                imap: &Endpoint::new("127.0.0.1", 3143, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 3025, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "sim",
                credential: "pw",
            })
            .unwrap();
        assert_eq!(
            engine.provider_profile(EMAIL).unwrap().id,
            ProviderId::Greenmail,
            "by host alone, any loopback IMAP is GreenMail"
        );
        for id in [ProviderId::Gmail, ProviderId::Yahoo, ProviderId::Icloud] {
            engine.set_account_provider(EMAIL, Some(id)).unwrap();
            assert_eq!(engine.provider_profile(EMAIL).unwrap().id, id);
        }
    }

    #[test]
    fn learned_roles_beat_profile_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let acct = {
            let store = engine.store();
            let id = store
                .insert_account(&NewAccount {
                    email: "a@gmail.com",
                    display_name: "",
                    imap: &Endpoint::new("imap.gmail.com", 993, Security::Tls),
                    smtp: &Endpoint::new("smtp.gmail.com", 465, Security::Tls),
                    auth_kind: AuthKind::Password,
                    login: "a@gmail.com",
                    credential: "pw",
                })
                .unwrap();
            store.account_by_id(id).unwrap().unwrap()
        };
        assert_eq!(
            engine
                .special_folder("a@gmail.com", FolderRole::Junk)
                .unwrap(),
            "[Gmail]/Spam"
        );
        assert!(engine.folder_roles("a@gmail.com").unwrap().is_empty());
        let folders = vec![
            Folder {
                name: "INBOX".into(),
                delimiter: Some("/".into()),
                attributes: vec![],
            },
            Folder {
                name: "[Gmail]/Spamordner".into(),
                delimiter: Some("/".into()),
                attributes: vec!["Extension(\"\\\\Junk\")".into()],
            },
        ];
        let su = engine.remember_folder_roles(&acct, &folders).unwrap();
        assert_eq!(su.junk.as_deref(), Some("[Gmail]/Spamordner"));
        assert_eq!(
            engine
                .special_folder("a@gmail.com", FolderRole::Junk)
                .unwrap(),
            "[Gmail]/Spamordner"
        );
        // Unmapped roles still fall back to the profile.
        assert_eq!(
            engine
                .special_folder("a@gmail.com", FolderRole::Trash)
                .unwrap(),
            "[Gmail]/Trash"
        );
        assert_eq!(engine.folder_roles("a@gmail.com").unwrap().len(), 2);
        assert!(engine
            .folder_sync_state("a@gmail.com", "INBOX")
            .unwrap()
            .is_none());
        // Every role is reported, learned ones flagged, the rest from the profile.
        let entries = engine.folder_role_entries("a@gmail.com").unwrap();
        assert_eq!(entries.len(), FolderRole::ALL.len());
        let junk = entries.iter().find(|e| e.role == FolderRole::Junk).unwrap();
        assert_eq!(
            (junk.folder.as_str(), junk.learned),
            ("[Gmail]/Spamordner", true)
        );
        let trash = entries
            .iter()
            .find(|e| e.role == FolderRole::Trash)
            .unwrap();
        assert_eq!(
            (trash.folder.as_str(), trash.learned),
            ("[Gmail]/Trash", false)
        );
        assert!(engine.folder_role_entries("nobody@gmail.com").is_err());
    }
}
