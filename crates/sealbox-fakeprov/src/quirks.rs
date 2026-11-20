//! What makes one provider behave unlike another, as knobs a fake server can honour.
//!
//! **The defaults come from `PROFILES`.** `providers.rs` is a table of claims about Gmail,
//! Outlook, Yahoo, iCloud, Fastmail, Zoho, GMX — folder names, whether submission files a Sent
//! copy by itself, how many IMAP connections an account may hold, whether folders are labels,
//! the submission size limit, what authentication is accepted. Nothing executed any of it. By
//! deriving the fake's behaviour from the same table, editing a profile changes the fake, and a
//! conformance run against the fake is a test of what we *believe* rather than of a second,
//! separately-maintained copy of those beliefs.
//!
//! That is also the honest limit of the whole exercise, and it belongs here rather than in a
//! README nobody reads: **a simulator that matches the belief proves the engine handles the
//! belief, not that the belief is right.** Only a real account can do the latter.

use sealbox_core::providers::{profile, AuthRequirement, ProviderId, ProviderProfile};

/// The mailbox address every fake serves unless a test says otherwise.
pub const DEFAULT_ACCOUNT: &str = "you@fakeprov.test";

/// How an account authenticates to the fake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimAuth {
    /// `LOGIN` / `AUTHENTICATE PLAIN` with this password.
    Password(String),
    /// `AUTHENTICATE XOAUTH2` only; the bearer must be a token the bundled IdP issued.
    XOAuth2,
}

/// One provider's behaviour, as a fake server can act it out.
///
/// Construct with [`Quirks::for_provider`] and then change only what a test is about, so every
/// other dimension stays at what we believe the real provider does.
#[derive(Clone, Debug)]
pub struct Quirks {
    pub id: ProviderId,
    /// The address this mailbox belongs to. Submission delivers to `INBOX` when a recipient
    /// matches it, which is what makes a send-to-self conformance check possible against a
    /// fake: a real provider's MX would do it, and without it the engine submits into a void.
    pub account: String,
    /// Folder names in the order a `LIST` reports them, each with its special-use attribute.
    pub folders: Vec<SimFolder>,
    /// Hierarchy delimiter in `LIST` replies.
    pub delimiter: char,
    /// Advertise `SPECIAL-USE` and the `\Sent` / `\Drafts` / `\Trash` / `\Junk` / `\Archive`
    /// attributes. Without it a client must fall back to matching names, which is the case
    /// that breaks on a localised mailbox (GMX's `Gesendet`).
    pub special_use: bool,
    /// Gmail: folders are labels. `COPY` adds one, a message can be in several folders at
    /// once, and expunging from INBOX only archives it — it stays in All Mail.
    pub label_semantics: bool,
    /// Submission files its own copy in Sent: a client that `APPEND`s as well gets two.
    pub smtp_saves_sent: bool,
    /// The profile's `max_connections`, carried so a test can read it. **The fake does not
    /// enforce it**, because it is not a server limit: the table's notes say "keep one IMAP
    /// session per account" — our own client-side budget — and no provider documents the number
    /// of sessions it will actually refuse. Enforcing a budget as a refusal would manufacture
    /// failures that say nothing about any real server.
    pub max_connections: u8,
    /// Sessions this server really refuses beyond, when a test wants to exercise a refusal.
    /// `None` (the default) accepts as many as the client opens.
    pub connection_hard_limit: Option<u8>,
    /// Largest message submission accepts, advertised as `SIZE` and enforced.
    pub max_message_bytes: Option<u64>,
    /// `IDLE` is terminated by the server after this long.
    pub idle_timeout_secs: u64,
    /// Answer at most this many UIDs per `UID FETCH`, whatever was asked for — the quirk that
    /// makes a client's batching matter.
    pub fetch_chunk_limit: Option<usize>,
    /// `MOVE` (RFC 6851) is not implemented, so a client must `COPY` + `STORE \Deleted` +
    /// `EXPUNGE`.
    pub has_move: bool,
    /// `SEARCH HEADER <field> <value>` is supported. Turning it off is not a hypothetical: the
    /// send path uses it to check whether submission already filed a Sent copy, and
    /// `an_unimplemented_search_key_is_a_bad_on_the_wire_and_invisible_to_the_client` shows the
    /// client cannot tell a refusal from "no match" — so a provider that refuses it gets a
    /// duplicate Sent copy. See the test of that name in `engine_against_the_fake`.
    pub header_search: bool,
    /// `UIDPLUS`, hence `UID EXPUNGE`. Without it `EXPUNGE` removes every `\Deleted` message
    /// in the mailbox, not only the named ones.
    pub has_uidplus: bool,
    /// Accept this many commands per connection, then answer the rest with a temporary
    /// failure until the connection is reopened (`None` = never throttle).
    pub throttle_after: Option<u32>,
    /// How the account authenticates.
    pub auth: SimAuth,
    /// `XOAUTH2` is not offered at all, whatever the profile says.
    pub no_xoauth2: bool,
    /// The one login XOAUTH2 is accepted for. Outlook rejects XOAUTH2 under an alias of the
    /// mailbox even when the token is perfectly good, which cost a day of the owner's time to
    /// diagnose on a real account; with this set, logging in as anything else after a
    /// successful token exchange fails with `AUTHENTICATIONFAILED`.
    pub primary_login: Option<String>,
    /// Access-token lifetime the IdP reports.
    pub token_ttl_secs: u64,
    /// The IdP issues a fresh refresh token on every refresh and invalidates the old one.
    pub rotate_refresh_tokens: bool,
    /// Fail exactly one refresh with `invalid_grant` before succeeding again — Google's
    /// seven-day expiry for a project still in Testing, which is how the owner's own Gmail
    /// token will fail.
    pub one_invalid_grant: bool,
}

/// One mailbox as `LIST` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimFolder {
    pub name: String,
    /// `\Sent`, `\Drafts`, `\Trash`, `\Junk`, `\All`, `\Archive`, or none for INBOX and the
    /// rest. Only sent when [`Quirks::special_use`].
    pub special_use: Option<&'static str>,
}

impl SimFolder {
    pub fn new(name: impl Into<String>, special_use: Option<&'static str>) -> Self {
        Self {
            name: name.into(),
            special_use,
        }
    }
}

impl Quirks {
    /// The quirks of a named provider, every value taken from its [`ProviderProfile`].
    pub fn for_provider(id: ProviderId) -> Self {
        Self::from_profile(profile(id))
    }

    /// As [`Quirks::for_provider`], from a profile reference.
    pub fn from_profile(p: &'static ProviderProfile) -> Self {
        let f = &p.folders;
        let mut folders = vec![SimFolder::new("INBOX", None)];
        folders.push(SimFolder::new(f.sent, Some("\\Sent")));
        folders.push(SimFolder::new(f.drafts, Some("\\Drafts")));
        folders.push(SimFolder::new(f.trash, Some("\\Trash")));
        folders.push(SimFolder::new(f.junk, Some("\\Junk")));
        if let Some(a) = f.archive {
            // Gmail's archive *is* All Mail, and it is the `\All` mailbox, not `\Archive`.
            let attr = if p.label_semantics {
                "\\All"
            } else {
                "\\Archive"
            };
            folders.push(SimFolder::new(a, Some(attr)));
        }
        if p.label_semantics {
            folders.push(SimFolder::new("[Gmail]/Starred", Some("\\Flagged")));
        }
        Self {
            id: p.id,
            account: DEFAULT_ACCOUNT.to_string(),
            folders,
            delimiter: '/',
            // Every provider in the table advertises SPECIAL-USE today; a test turns it off to
            // exercise the name-matching fallback.
            special_use: true,
            label_semantics: p.label_semantics,
            smtp_saves_sent: p.smtp_saves_sent,
            max_connections: p.max_connections,
            connection_hard_limit: None,
            max_message_bytes: p.max_message_bytes,
            idle_timeout_secs: p.idle_timeout_secs,
            fetch_chunk_limit: None,
            header_search: true,
            has_move: true,
            has_uidplus: true,
            throttle_after: None,
            auth: match p.auth {
                AuthRequirement::OAuth2 => SimAuth::XOAuth2,
                // An app password and a mailbox password are the same wire protocol; what
                // differs is where the user gets the string, which no server can tell.
                AuthRequirement::AppPassword | AuthRequirement::Password => {
                    SimAuth::Password(format!("{}-app-pw", p.id.as_str()))
                }
            },
            no_xoauth2: false,
            primary_login: None,
            token_ttl_secs: 3600,
            rotate_refresh_tokens: false,
            one_invalid_grant: false,
        }
    }

    /// The folder playing a special-use role, by its attribute (`"\\Sent"`).
    pub fn folder_with(&self, attr: &str) -> Option<&SimFolder> {
        self.folders.iter().find(|f| f.special_use == Some(attr))
    }

    /// The name of the Sent folder, which submission files into when
    /// [`Quirks::smtp_saves_sent`].
    pub fn sent_folder(&self) -> String {
        self.folder_with("\\Sent")
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Sent".to_string())
    }

    pub fn trash_folder(&self) -> String {
        self.folder_with("\\Trash")
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Trash".to_string())
    }

    /// `All Mail` under label semantics: expunging elsewhere leaves the message here.
    pub fn all_mail(&self) -> Option<String> {
        self.label_semantics
            .then(|| self.folder_with("\\All").map(|f| f.name.clone()))
            .flatten()
    }

    /// Whether `addr` is this mailbox's own address, so submission should deliver to `INBOX`.
    pub fn is_own_address(&self, addr: &str) -> bool {
        addr.trim()
            .trim_matches(|c| c == '<' || c == '>')
            .eq_ignore_ascii_case(&self.account)
    }

    /// Whether this provider wants XOAUTH2 on the wire.
    pub fn wants_xoauth2(&self) -> bool {
        !self.no_xoauth2 && matches!(self.auth, SimAuth::XOAuth2)
    }

    /// The IMAP `CAPABILITY` line this provider answers with.
    pub fn capabilities(&self) -> String {
        let mut caps = vec!["IMAP4rev1".to_string(), "IDLE".to_string()];
        if self.has_uidplus {
            caps.push("UIDPLUS".into());
        }
        if self.has_move {
            caps.push("MOVE".into());
        }
        if self.special_use {
            caps.push("SPECIAL-USE".into());
            caps.push("LIST-EXTENDED".into());
        }
        match (&self.auth, self.no_xoauth2) {
            (SimAuth::XOAuth2, false) => caps.push("AUTH=XOAUTH2".into()),
            (SimAuth::XOAuth2, true) => {} // offers nothing it can accept: the hostile case
            (SimAuth::Password(_), _) => {
                caps.push("AUTH=PLAIN".into());
                if !self.no_xoauth2 {
                    caps.push("AUTH=XOAUTH2".into());
                }
            }
        }
        caps.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_profile_table_rather_than_a_second_copy_of_it() {
        for p in sealbox_core::providers::PROFILES {
            let q = Quirks::from_profile(p);
            assert_eq!(q.id, p.id);
            assert_eq!(q.smtp_saves_sent, p.smtp_saves_sent);
            assert_eq!(q.max_connections, p.max_connections);
            assert_eq!(q.label_semantics, p.label_semantics);
            assert_eq!(q.max_message_bytes, p.max_message_bytes);
            assert_eq!(q.idle_timeout_secs, p.idle_timeout_secs);
            assert_eq!(q.sent_folder(), p.folders.sent, "{} Sent", p.id.as_str());
            assert_eq!(q.trash_folder(), p.folders.trash, "{} Trash", p.id.as_str());
            assert!(
                q.folders.iter().any(|f| f.name == "INBOX"),
                "every provider has an INBOX"
            );
            assert_eq!(
                q.wants_xoauth2(),
                p.auth == AuthRequirement::OAuth2,
                "{} auth",
                p.id.as_str()
            );
        }
    }

    #[test]
    fn gmails_archive_is_all_mail_and_it_has_a_starred_folder() {
        let g = Quirks::for_provider(ProviderId::Gmail);
        assert!(g.label_semantics);
        assert_eq!(g.all_mail().as_deref(), Some("[Gmail]/All Mail"));
        assert_eq!(
            g.folder_with("\\All").map(|f| f.name.as_str()),
            Some("[Gmail]/All Mail"),
            "All Mail is \\All, not \\Archive"
        );
        assert_eq!(
            g.folder_with("\\Flagged").map(|f| f.name.as_str()),
            Some("[Gmail]/Starred")
        );

        // Nobody else has label semantics or an All-Mail folder.
        let o = Quirks::for_provider(ProviderId::Outlook);
        assert!(!o.label_semantics);
        assert_eq!(o.all_mail(), None);
        assert_eq!(
            o.folder_with("\\Archive").map(|f| f.name.as_str()),
            Some("Archive")
        );
    }

    #[test]
    fn zoho_has_no_archive_folder_at_all() {
        // The one profile with `archive: None`: the fake must not invent one, because the
        // engine's fallback for a missing Archive is a real code path.
        let z = Quirks::for_provider(ProviderId::Zoho);
        assert_eq!(z.folder_with("\\Archive"), None);
        assert!(z.folders.iter().all(|f| f.name != "Archive"));
    }

    #[test]
    fn gmx_keeps_its_localised_folder_names() {
        let g = Quirks::for_provider(ProviderId::Gmx);
        assert_eq!(g.sent_folder(), "Gesendet");
        assert_eq!(g.trash_folder(), "Gelöscht");
        assert_eq!(
            g.folder_with("\\Junk").map(|f| f.name.as_str()),
            Some("Spamverdacht"),
            "a client that matches on the English name finds nothing"
        );
    }

    #[test]
    fn capabilities_say_what_the_provider_will_accept() {
        let gmail = Quirks::for_provider(ProviderId::Gmail);
        assert!(gmail.capabilities().contains("AUTH=XOAUTH2"));
        assert!(!gmail.capabilities().contains("AUTH=PLAIN"), "OAuth only");

        let yahoo = Quirks::for_provider(ProviderId::Yahoo);
        assert!(yahoo.capabilities().contains("AUTH=PLAIN"));

        let mut hostile = Quirks::for_provider(ProviderId::Gmail);
        hostile.no_xoauth2 = true;
        let caps = hostile.capabilities();
        assert!(
            !caps.contains("XOAUTH2") && !caps.contains("AUTH=PLAIN"),
            "a server offering no mechanism it accepts: {caps}"
        );

        let mut no_move = Quirks::for_provider(ProviderId::Outlook);
        no_move.has_move = false;
        no_move.has_uidplus = false;
        let caps = no_move.capabilities();
        assert!(
            !caps.contains("MOVE") && !caps.contains("UIDPLUS"),
            "{caps}"
        );
    }
}
