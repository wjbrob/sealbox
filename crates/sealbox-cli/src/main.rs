//! `sealbox` — command-line client for Sealbox: the e2e harness and the first desktop client.
//! See `crates/sealbox-cli/README.md` for usage and the JSON output contract.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sealbox_core::providers::ProviderId;
use sealbox_core::{
    AccountInfo, AddAccount, AttachmentData, AuthHint, AuthSpec, ComposeKind, ComposeOptions,
    ConfigSource, DirectoryStatus, Draft, Endpoint, Engine, EngineConfig, FlagOp, FolderRole,
    ListQuery, MessageSummary, Security, SendMode, SendPolicy, ServerConfig, SigState, SyncPhase,
    SyncProgress, SyncReport, UsernameForm, WatchEvent,
};

mod cmd_hosted;
mod cmd_settings;

mod cmd_oauth;
mod cmd_provider_test;

mod cmd_draft;
mod cmd_filter;
mod cmd_guest;
mod cmd_identity;
mod cmd_profile;
mod cmd_read;
mod cmd_recovery;
mod cmd_search;
mod cmd_spam;

/// Exit code for usage errors (also what clap uses).
const EXIT_USAGE: i32 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "sealbox",
    version,
    about = "End-to-end encrypted e-mail on top of the mailbox you already have",
    propagate_version = true
)]
struct Cli {
    /// Profile directory (accounts, keys, local store). Default: $SEALBOX_HOME or
    /// ~/.local/share/sealbox
    #[arg(long, global = true, env = "SEALBOX_HOME")]
    profile: Option<PathBuf>,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,
    #[command(flatten)]
    key: cmd_profile::KeyArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Secrets at rest: key status, rewrap to another key source (G27)
    Profile(cmd_profile::ProfileArgs),
    /// Manage accounts
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Fetch new mail (INBOX + Sent) for one or all accounts; --role syncs one special-use
    /// folder (trash|junk|archive|…) of one account instead. A folder's first sync fetches
    /// only its newest messages (--window); later syncs also fetch older mail, a batch at a
    /// time, and --backfill fetches all of it now. A progress line per stored batch goes to
    /// stderr (a JSON object per line with --json); stdout gets the report
    Sync {
        #[arg(long)]
        account: Option<String>,
        /// Sync only the folder playing this role (inbox|sent|drafts|trash|junk|archive|all|
        /// flagged) for --account (or the only account)
        #[arg(long)]
        role: Option<String>,
        /// First sync of a folder: fetch only its newest N messages, newest first (default
        /// 500 or $SEALBOX_SYNC_WINDOW; 0 = the whole folder at once)
        #[arg(long, value_name = "N")]
        window: Option<usize>,
        /// Then fetch all older mail still missing below the window, down to the first message
        #[arg(long)]
        backfill: bool,
    },
    /// Converge one folder with the server without fetching any new mail: drop the messages
    /// that are gone from the server (deleted in webmail or on the phone) and follow the flags
    /// that changed there. A `sync` does this for the folders it visits; this is for catching
    /// up with other clients on its own
    Reconcile {
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value = "INBOX")]
        folder: String,
    },
    /// Special-use folders of an account: role → folder name, learned from the server or the
    /// provider default
    Folders {
        #[arg(long)]
        account: Option<String>,
    },
    /// Move a message to the folder playing a role (inbox|trash|junk|archive|…); the local
    /// copy is dropped until that folder is synced
    Move {
        id: i64,
        /// Destination role
        #[arg(long)]
        to: String,
    },
    /// The Sealbox server (key directory, guest links, backups): show or set its URL
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Wait for new mail with IMAP IDLE and sync as it arrives
    Watch {
        #[arg(long)]
        account: String,
        /// Stop after this many seconds (default: run until interrupted)
        #[arg(long)]
        timeout: Option<u64>,
        /// Stop after the first batch of new mail
        #[arg(long)]
        once: bool,
    },
    /// List stored messages (newest first); all accounts unless --account is given
    List {
        #[arg(long)]
        account: Option<String>,
        /// Folder name; "*" for every folder
        #[arg(long, default_value = "INBOX")]
        folder: String,
        /// Pick the folder by special-use role instead (inbox|sent|drafts|trash|junk|archive|
        /// all|flagged), resolved per account to what the server calls it; overrides --folder
        #[arg(long)]
        role: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one message (marks it \Seen on the server unless --no-mark)
    Read {
        id: i64,
        /// Print the raw RFC 822 bytes as fetched
        #[arg(long)]
        raw: bool,
        /// Do not set the \Seen flag
        #[arg(long)]
        no_mark: bool,
        /// Print the sanitized HTML part instead of the text view (docs/HTML_MAIL.md)
        #[arg(long)]
        html: bool,
        /// Keep the URLs of remote images instead of blocking them (the sender's server
        /// learns that the message was opened)
        #[arg(long)]
        load_images: bool,
    },
    /// Send a message
    Send(SendArgs),
    /// Known correspondents: recommendation, key changes (⚠), verification (✓); ack/verify
    Contacts {
        #[command(subcommand)]
        cmd: Option<cmd_identity::ContactsCmd>,
    },
    /// Key transparency: audit the directory's log, list entries (G30)
    Kt {
        #[command(subcommand)]
        cmd: cmd_identity::KtCmd,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Attachments
    Attachment {
        #[command(subcommand)]
        cmd: AttachmentCmd,
    },
    /// Add or remove IMAP flags on a message
    Flag {
        id: i64,
        #[arg(long, value_delimiter = ',')]
        add: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        remove: Vec<String>,
    },
    /// Delete a message (moved to the provider's Trash; expunged when already there) and locally
    Delete { id: i64 },
    /// Provider conformance suite (G21): login, folders, encrypted send-to-self, IDLE, Sent
    /// copy, flags, Trash, spam folder, large attachment, connections, header preservation
    ProviderTest(cmd_provider_test::ProviderTestArgs),
    /// Spam detection: status, learn, explain, check, eval, settings, allow/block (G25)
    Spam {
        #[command(subcommand)]
        cmd: cmd_spam::SpamCmd,
    },
    /// Filter rules: add, list, rm, enable, test (G25)
    #[command(visible_alias = "filters")]
    Filter {
        #[command(subcommand)]
        cmd: cmd_filter::FilterCmd,
    },
    /// Per-account settings: signature, holiday auto-reply
    Settings {
        #[command(subcommand)]
        cmd: cmd_settings::SettingsCmd,
    },
    /// Guest links: resend a notification (G29)
    Guest {
        #[command(subcommand)]
        cmd: cmd_guest::GuestCmd,
    },
    /// Recovery phrase, encrypted server backup, restore, Autocrypt Setup Message (G15)
    Recovery {
        #[command(subcommand)]
        cmd: cmd_recovery::RecoveryCmd,
    },
    /// Full-text search of the stored mail (subject, sender, recipients, decrypted body):
    /// every word must match, the last one also as a prefix (3+ characters); best first
    Search(cmd_search::SearchArgs),
    /// Saved drafts: save, list, show, delete, send (kept in this profile only; not synced to
    /// the server's Drafts folder)
    Draft {
        #[command(subcommand)]
        cmd: cmd_draft::DraftCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ServerCmd {
    /// Store the server URL in the profile (wins over SEALBOX_SERVER_URL); --clear removes it
    SetUrl {
        /// http(s)://host[:port]
        #[arg(required_unless_present = "clear", conflicts_with = "clear")]
        url: Option<String>,
        #[arg(long)]
        clear: bool,
    },
    /// The effective server URL and where it comes from (settings | environment | none)
    Show,
}

#[derive(Subcommand, Debug)]
enum AccountCmd {
    /// Add an account (autodiscovers servers unless --imap/--smtp are given)
    Add(AddArgs),
    /// Create a new hosted Sealbox address on a server and add it (docs/HOSTED_MAILBOX.md)
    CreateHosted(cmd_hosted::CreateHostedArgs),
    /// Show a server's hosted-address offer; --check NAME tests availability
    HostedInfo(cmd_hosted::HostedInfoArgs),
    /// List accounts
    List,
    /// State which provider an account really is, when its IMAP host does not say (a company
    /// domain hosted on Microsoft 365 or Google Workspace, a simulator on loopback). Takes
    /// effect at once for folder roles, send quirks and the conformance suite; nothing is
    /// re-synced. `--provider generic` pins the neutral profile, `--clear` goes back to
    /// guessing from the host
    SetProvider {
        #[arg(long)]
        account: Option<String>,
        /// gmail|outlook|yahoo|icloud|fastmail|zoho|gmx|greenmail|generic
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        provider: Option<String>,
        /// Forget the stated provider and guess from the IMAP host again
        #[arg(long)]
        clear: bool,
    },
    /// Remove an account and everything stored for it
    Remove {
        #[arg(long)]
        email: String,
    },
}

#[derive(Args, Debug)]
struct AddArgs {
    #[arg(long)]
    email: String,
    /// Password / app password (prefer --password-env)
    #[arg(long, conflicts_with = "password_env")]
    password: Option<String>,
    /// Name of an environment variable holding the password
    #[arg(long)]
    password_env: Option<String>,
    /// Display name
    #[arg(long)]
    name: Option<String>,
    /// Login name override (default: what the provider wants, usually the full address)
    #[arg(long)]
    user: Option<String>,
    /// Manual IMAP server as host:port:plain|tls|starttls (requires --smtp). `plain` (no TLS)
    /// only for loopback, private-network and .test/.local/.localhost/.internal/.lan/.home/
    /// .invalid hosts, or exact hosts listed in SEALBOX_ALLOW_PLAIN_HOSTS
    #[arg(long, requires = "smtp")]
    imap: Option<String>,
    /// Manual SMTP server as host:port:plain|tls|starttls (requires --imap); `plain` as for
    /// --imap
    #[arg(long, requires = "imap")]
    smtp: Option<String>,
    /// Only detect and print the server configuration; do not connect or store anything
    #[arg(long)]
    dry_run: bool,
    /// Sign in with OAuth2 instead of a password (loopback PKCE flow; prints the URL)
    #[arg(long, value_enum, conflicts_with_all = ["password", "password_env"])]
    oauth: Option<cmd_oauth::OAuthArg>,
    /// OAuth client id (default: $GOOGLE_OAUTH_CLIENT_ID / $MS_OAUTH_CLIENT_ID)
    #[arg(long, requires = "oauth", conflicts_with = "client_id_env")]
    client_id: Option<String>,
    /// Name of an environment variable holding the OAuth client id
    #[arg(long, requires = "oauth")]
    client_id_env: Option<String>,
    /// Name of an environment variable holding the OAuth client secret
    /// (Google "Desktop app" clients have one; default $GOOGLE_OAUTH_CLIENT_SECRET)
    #[arg(long, requires = "oauth")]
    client_secret_env: Option<String>,
    /// Open the authorization URL with xdg-open (otherwise it is only printed)
    #[arg(long, requires = "oauth")]
    open_browser: bool,
    /// Seconds to wait for the browser redirect
    #[arg(long, requires = "oauth", default_value_t = 300)]
    oauth_timeout: u64,
    /// Which provider this really is (gmail|outlook|yahoo|icloud|fastmail|zoho|gmx|greenmail|
    /// generic), when the IMAP host does not say: a company domain on Microsoft 365 or Google
    /// Workspace, or a provider simulator on loopback. Default: guessed from the host
    #[arg(long)]
    provider: Option<String>,
}

#[derive(Args, Debug)]
struct SendArgs {
    /// Sending account
    #[arg(long)]
    from: String,
    #[arg(long, value_delimiter = ',', required = true)]
    to: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    cc: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    bcc: Vec<String>,
    #[arg(long)]
    subject: String,
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// Read the body from a file ("-" for stdin)
    #[arg(long)]
    body_file: Option<PathBuf>,
    /// Attach a file (repeatable)
    #[arg(long = "attach")]
    attachments: Vec<PathBuf>,
    #[arg(long, value_enum, default_value_t = PolicyArg::Auto)]
    policy: PolicyArg,
    /// Local message id (from `list`) or a Message-ID to reply to
    #[arg(long)]
    in_reply_to: Option<String>,
    /// Quote the replied-to message below the text (`On <date>, <from> wrote:` + `> `)
    #[arg(long)]
    quote: bool,
    /// Forward a stored message (local id or Message-ID): its headers, text and attachments
    /// are included
    #[arg(long, conflicts_with = "in_reply_to")]
    forward: Option<String>,
    /// Do not add the account signature
    #[arg(long)]
    no_signature: bool,
    /// How a guest link (`--policy guest`) is protected; see docs/GUEST_LINKS.md
    #[arg(long, value_enum, default_value_t = cmd_guest::GuestModeArg::Passphrase)]
    guest_mode: cmd_guest::GuestModeArg,
    /// email-code mode: the address that receives the code (default: the only recipient)
    #[arg(long)]
    guest_recipient: Option<String>,
    /// Requested guest-link lifetime in seconds (the server clamps)
    #[arg(long)]
    guest_expiry: Option<i64>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PolicyArg {
    Auto,
    Require,
    Guest,
    Plaintext,
}

impl From<PolicyArg> for SendPolicy {
    fn from(p: PolicyArg) -> Self {
        match p {
            PolicyArg::Auto => SendPolicy::Auto,
            PolicyArg::Require => SendPolicy::RequireEncryption,
            PolicyArg::Guest => SendPolicy::GuestLink,
            PolicyArg::Plaintext => SendPolicy::AllowPlaintext,
        }
    }
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Show the fingerprint of an account's key (or a contact's)
    Show {
        #[arg(long)]
        address: String,
    },
    /// Export an account's public key (armored) to a file or stdout
    Export {
        #[arg(long)]
        address: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Import a correspondent's public key from a file ("-" for stdin)
    Import {
        #[arg(long)]
        address: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Fingerprint QR code (OPENPGP4FPR: payload) of an account's key, to be scanned
    Qr {
        #[arg(long)]
        account: String,
    },
    /// Upload an account's public key to the key directory and request the verification
    /// mail (`sealbox server set-url` first)
    Publish {
        #[arg(long)]
        account: Option<String>,
    },
    /// What the key directory publishes for an account's address
    DirectoryStatus {
        #[arg(long)]
        account: Option<String>,
    },
    /// Sync the inbox, open the directory's verification link and report the new state
    CompleteVerification {
        #[arg(long)]
        account: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AttachmentCmd {
    /// Save attachment INDEX of message ID to PATH
    Save {
        id: i64,
        index: usize,
        path: PathBuf,
    },
}

fn default_profile() -> PathBuf {
    if let Some(p) = std::env::var_os("SEALBOX_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(p).join("sealbox");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local").join("share").join("sealbox")
}

fn parse_endpoint(spec: &str) -> anyhow::Result<Endpoint> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        bail!("expected host:port:plain|tls|starttls, got {spec:?}");
    }
    let port: u16 = parts[1]
        .parse()
        .with_context(|| format!("bad port in {spec:?}"))?;
    let security = match parts[2].to_ascii_lowercase().as_str() {
        "plain" => Security::Plain,
        "tls" | "ssl" => Security::Tls,
        "starttls" => Security::StartTls,
        other => bail!("unknown security {other:?} (plain|tls|starttls)"),
    };
    Ok(Endpoint::new(parts[0], port, security))
}

/// Parse a special-use role name (`trash`, `junk`/`spam`, `archive`, …). An unknown name is
/// a usage error (exit 2), like any other invalid input.
fn parse_role(s: &str) -> anyhow::Result<FolderRole> {
    FolderRole::parse(s).ok_or_else(|| {
        sealbox_core::Error::InvalidInput(format!(
            "unknown folder role `{s}` (inbox|sent|drafts|trash|junk|archive|all|flagged)"
        ))
        .into()
    })
}

pub(crate) fn parse_provider(s: &str) -> anyhow::Result<ProviderId> {
    ProviderId::parse(s).ok_or_else(|| {
        sealbox_core::Error::InvalidInput(format!(
            "unknown provider `{s}` \
             (gmail|outlook|yahoo|icloud|fastmail|zoho|gmx|greenmail|generic)"
        ))
        .into()
    })
}

/// The account a command acts on: `--account` when given, else the only account of the
/// profile; with several accounts and no `--account` the choice is refused.
fn pick_account(accounts: &[AccountInfo], requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(r) = requested.map(str::trim).filter(|r| !r.is_empty()) {
        return Ok(accounts
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(r))
            .map(|a| a.email.clone())
            .unwrap_or_else(|| r.to_string()));
    }
    match accounts {
        [] => bail!("no accounts in this profile (run `sealbox account add` first)"),
        [one] => Ok(one.email.clone()),
        many => bail!(
            "several accounts: pass --account ({})",
            many.iter()
                .map(|a| a.email.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn print_directory_status(email: &str, s: &DirectoryStatus) {
    let what = match s.state.as_str() {
        "published" => "published: the directory serves this account's key".to_string(),
        "other_key" => "another key is published for this address (not this account's)".to_string(),
        "unpublished" => "not published".to_string(),
        "awaiting_verification" => "not published yet: no verification mail from the directory in the \
                                     mailbox so far (run `sealbox key publish` if none was requested)"
            .to_string(),
        "verification_failed" => "not published: the verification link was refused (expired or already \
                                   used); run `sealbox key publish` again for a fresh one"
            .to_string(),
        other => other.to_string(),
    };
    println!("{email} @ {}: {what}", s.server_url);
}

fn server_json(engine: &Engine) -> serde_json::Value {
    serde_json::json!({
        "server_url": engine.server_url(),
        "source": engine.server_url_source(),
        "directory_url": engine.directory_url(),
    })
}

fn print_server(engine: &Engine) {
    println!(
        "server:    {}  (source: {})",
        engine.server_url().as_deref().unwrap_or("(none)"),
        engine.server_url_source()
    );
    println!(
        "directory: {}",
        engine.directory_url().as_deref().unwrap_or("(none)")
    );
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::StartTls => "starttls",
        Security::Plain => "plain",
    }
}

fn auth_hint_text(h: &AuthHint) -> String {
    match h {
        AuthHint::OAuth2(p) => format!("OAuth2 sign-in ({p:?})"),
        AuthHint::AppPassword { help_url } => format!("app password required (see {help_url})"),
        AuthHint::Password => "regular mailbox password".to_string(),
    }
}

/// One line per stored batch of a sync, on stderr so stdout keeps the report: with `--json` a
/// JSON object per line (`{"event":"sync_progress","t_ms":…,…SyncProgress}`), else e.g.
/// `p01@sealbox.test INBOX newest: 200/500 fetched, 200 stored; 200 of 10000 stored locally`.
fn print_progress(p: &SyncProgress, json: bool, started: Instant) {
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if json {
        if let Ok(serde_json::Value::Object(mut o)) = serde_json::to_value(p) {
            o.insert("event".into(), "sync_progress".into());
            o.insert("t_ms".into(), ms.into());
            eprintln!("{}", serde_json::Value::Object(o));
        }
        return;
    }
    let phase = match p.phase {
        SyncPhase::Initial => "newest",
        SyncPhase::Incremental => "new",
        SyncPhase::Backfill => "older",
    };
    eprintln!(
        "{} {} {phase}: {}/{} fetched, {} stored; {} of {} stored locally{} ({:.1} s)",
        p.account,
        p.folder,
        p.fetched,
        p.planned,
        p.stored,
        p.local,
        p.total_known,
        if p.more_to_backfill {
            ", older mail to come"
        } else {
            ""
        },
        ms as f64 / 1000.0
    );
}

/// One line per account: what the run fetched, and what it converged. The `-N` and `~N flags`
/// parts appear only when the reconcile did something, so an ordinary quiet sync reads as it
/// always did.
fn print_sync_reports(reports: &[SyncReport], json: bool) -> anyhow::Result<()> {
    if json {
        return print_json(&reports);
    }
    for r in reports {
        println!(
            "{}: {} new, {} decrypted, {} failed ({})",
            r.account,
            r.new,
            r.decrypted,
            r.failed,
            r.folders
                .iter()
                .map(|f| format!(
                    "{} +{}{}{}{}{}",
                    f.name,
                    f.new,
                    if f.removed > 0 {
                        format!(" -{}", f.removed)
                    } else {
                        String::new()
                    },
                    if f.flags_changed > 0 {
                        format!(" ~{} flags", f.flags_changed)
                    } else {
                        String::new()
                    },
                    if f.uidvalidity_reset { " [resync]" } else { "" },
                    match (f.more_to_backfill, f.older_pending) {
                        (false, _) => String::new(),
                        (true, Some(n)) => format!(" [{n} older to backfill]"),
                        (true, None) => " [older mail to backfill]".to_string(),
                    }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn status_icons(m: &MessageSummary) -> String {
    let mut s = String::new();
    if m.was_encrypted && m.decrypted {
        s.push('🔒');
    }
    if m.signature.status == SigState::Good {
        s.push_str("✍️");
    }
    let warn = (m.was_encrypted && !m.decrypted)
        || m.signature.status == SigState::Bad
        || (m.was_signed && m.signature.status == SigState::UnknownKey);
    if warn || m.signature.key_changed {
        s.push('⚠');
    }
    if s.is_empty() {
        s.push('·');
    }
    s
}

fn fmt_date(ts: Option<i64>) -> String {
    ts.and_then(chrono_lite).unwrap_or_else(|| "-".into())
}

/// `YYYY-MM-DD HH:MM` in UTC without pulling chrono into the CLI.
fn chrono_lite(ts: i64) -> Option<String> {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    ))
}

fn print_list(rows: &[MessageSummary], show_account: bool) {
    if rows.is_empty() {
        println!("(no messages)");
        return;
    }
    for m in rows {
        let subj = m.subject.as_deref().unwrap_or("(no subject)");
        let from = m
            .from
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&m.from.address);
        let seen = if m.seen { " " } else { "*" };
        if show_account {
            println!(
                "{:>5} {}{:<4} {}  {:<24} {:<28} {}",
                m.id,
                seen,
                status_icons(m),
                fmt_date(m.date),
                truncate(&m.account, 24),
                truncate(from, 28),
                subj
            );
        } else {
            println!(
                "{:>5} {}{:<4} {}  {:<28} {}",
                m.id,
                seen,
                status_icons(m),
                fmt_date(m.date),
                truncate(from, 28),
                subj
            );
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn read_file_or_stdin(path: &Path) -> anyhow::Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn guess_content_type(path: &Path) -> String {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("txt") | Some("md") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("json") => "application/json",
        Some("zip") => "application/zip",
        Some("asc") => "application/pgp-keys",
        _ => "application/octet-stream",
    }
    .to_string()
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let profile = cli.profile.clone().unwrap_or_else(default_profile);
    cmd_profile::apply(&cli.key)?;
    let json = cli.json;
    match cli.command {
        Command::Account { cmd } => match cmd {
            AccountCmd::Add(a) => account_add(&profile, json, a).await,
            AccountCmd::SetProvider {
                account,
                provider,
                clear,
            } => {
                let engine = Engine::open(&profile)?;
                let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
                let id = match (clear, provider.as_deref()) {
                    (true, _) => None,
                    (false, Some(p)) => Some(parse_provider(p)?),
                    (false, None) => unreachable!("clap requires one of --provider / --clear"),
                };
                engine.set_account_provider(&email, id)?;
                let now = engine.provider_profile(&email)?;
                if json {
                    return print_json(&serde_json::json!({
                        "account": email,
                        "provider": id.map(|i| i.as_str()),
                        "stated": id.is_some(),
                        "profile": now.id.as_str(),
                    }));
                }
                match id {
                    Some(i) => println!("{email}: provider set to {}", i.as_str()),
                    None => println!(
                        "{email}: provider cleared; guessed from the host as {}",
                        now.id.as_str()
                    ),
                }
                Ok(())
            }
            AccountCmd::CreateHosted(a) => cmd_hosted::create(&profile, json, a).await,
            AccountCmd::HostedInfo(a) => cmd_hosted::info(&profile, json, a).await,
            AccountCmd::List => {
                let engine = Engine::open(&profile)?;
                let accounts = engine.list_accounts()?;
                if json {
                    return print_json(&accounts);
                }
                if accounts.is_empty() {
                    println!("(no accounts in {})", profile.display());
                }
                for a in accounts {
                    println!(
                        "{}  {}  imap={}:{}:{}  smtp={}:{}:{}  auth={:?}  key={}",
                        a.email,
                        if a.display_name.is_empty() {
                            "-"
                        } else {
                            &a.display_name
                        },
                        a.imap.host,
                        a.imap.port,
                        security_name(a.imap.security),
                        a.smtp.host,
                        a.smtp.port,
                        security_name(a.smtp.security),
                        a.auth_kind,
                        a.fingerprint.as_deref().unwrap_or("-")
                    );
                }
                Ok(())
            }
            AccountCmd::Remove { email } => {
                let engine = Engine::open(&profile)?;
                engine.remove_account(&email)?;
                if json {
                    print_json(&serde_json::json!({"removed": email}))?;
                } else {
                    println!("removed {email}");
                }
                Ok(())
            }
        },
        Command::Sync {
            account,
            role,
            window,
            backfill,
        } => {
            let mut cfg = EngineConfig::from_env();
            if let Some(w) = window {
                cfg.sync_window = w;
            }
            let engine = Engine::open_with(&profile, cfg)?;
            let started = Instant::now();
            let mut show = |p: SyncProgress| print_progress(&p, json, started);
            let reports = match (account, role) {
                (account, Some(role)) => {
                    let role = parse_role(&role)?;
                    let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
                    let mut r = engine.sync_folder_role(&email, role).await?;
                    if backfill {
                        r.merge(
                            engine
                                .backfill_with_progress(&email, None, &mut show)
                                .await?,
                        );
                    }
                    vec![r]
                }
                (Some(a), None) => {
                    let mut r = engine.sync_with_progress(&a, &mut show).await?;
                    if backfill {
                        r.merge(engine.backfill_with_progress(&a, None, &mut show).await?);
                    }
                    vec![r]
                }
                (None, None) => {
                    let accounts = engine.list_accounts()?;
                    let mut out = Vec::new();
                    for a in &accounts {
                        let r = match engine.sync_with_progress(&a.email, &mut show).await {
                            Ok(mut r) if backfill => match engine
                                .backfill_with_progress(&a.email, None, &mut show)
                                .await
                            {
                                Ok(b) => {
                                    r.merge(b);
                                    Ok(r)
                                }
                                Err(e) => Err(e),
                            },
                            other => other,
                        };
                        match r {
                            Ok(rep) => out.push(rep),
                            Err(e) => {
                                if accounts.len() == 1 {
                                    return Err(e.into());
                                }
                                eprintln!("sync {}: {e}", a.email);
                            }
                        }
                    }
                    out
                }
            };
            print_sync_reports(&reports, json)
        }
        Command::Reconcile { account, folder } => {
            let engine = Engine::open(&profile)?;
            let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
            let report = engine.reconcile_folder(&email, &folder).await?;
            print_sync_reports(&[report], json)
        }
        Command::Watch {
            account,
            timeout,
            once,
        } => {
            let engine = Engine::open(&profile)?;
            let deadline = timeout.map(|t| Instant::now() + Duration::from_secs(t));
            let idle = timeout
                .map(|t| Duration::from_secs(t.clamp(1, 29 * 60)))
                .unwrap_or(Duration::from_secs(25 * 60));
            let mut total_new = 0u32;
            engine
                .watch(&account, idle, |ev| {
                    let past_deadline = deadline.is_some_and(|d| Instant::now() >= d);
                    match &ev {
                        WatchEvent::Idle { folder } => {
                            if json {
                                let _ = print_json(&ev);
                            } else {
                                eprintln!("watching {folder} of {account} (IDLE)…");
                            }
                            !past_deadline
                        }
                        WatchEvent::NewMail { report } => {
                            total_new += report.new;
                            if json {
                                let _ = print_json(&ev);
                            } else {
                                println!(
                                    "{} new, {} decrypted, {} failed",
                                    report.new, report.decrypted, report.failed
                                );
                                if report.new > 0 {
                                    if let Ok(rows) = engine.list_messages(ListQuery {
                                        account: Some(account.clone()),
                                        folder: None,
                                        folder_role: None,
                                        limit: report.new as usize,
                                    }) {
                                        print_list(&rows, false);
                                    }
                                }
                                let _ = std::io::stdout().flush();
                            }
                            !(past_deadline || (once && report.new > 0))
                        }
                        WatchEvent::Timeout => {
                            if json {
                                let _ = print_json(&ev);
                            }
                            !past_deadline
                        }
                    }
                })
                .await?;
            if !json {
                eprintln!("watch finished: {total_new} new message(s)");
            }
            Ok(())
        }
        Command::Folders { account } => {
            let engine = Engine::open(&profile)?;
            let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
            let entries = engine.folder_role_entries(&email)?;
            if json {
                return print_json(&entries);
            }
            for e in &entries {
                println!(
                    "{:<8} {:<32} {}",
                    e.role.as_str(),
                    e.folder,
                    if e.learned {
                        "learned from the server"
                    } else {
                        "provider default (not confirmed yet)"
                    }
                );
            }
            Ok(())
        }
        Command::Move { id, to } => {
            let engine = Engine::open(&profile)?;
            let role = parse_role(&to)?;
            let r = engine.move_message(id, role).await?;
            if json {
                return print_json(&r);
            }
            match r.method {
                Some(m) => println!(
                    "moved {}: {} → {} ({:?})",
                    r.id, r.from_folder, r.to_folder, m
                ),
                None => println!("{} is already in {}", r.id, r.to_folder),
            }
            Ok(())
        }
        Command::Server { cmd } => {
            let engine = Engine::open(&profile)?;
            match cmd {
                ServerCmd::SetUrl { url, clear } => {
                    if clear {
                        engine.set_server_url(None)?;
                    } else {
                        engine.set_server_url(url)?;
                    }
                }
                ServerCmd::Show => {}
            }
            if json {
                return print_json(&server_json(&engine));
            }
            print_server(&engine);
            Ok(())
        }
        Command::List {
            account,
            folder,
            role,
            limit,
        } => {
            let engine = Engine::open(&profile)?;
            let unified = account.is_none();
            let folder_role = role.as_deref().map(parse_role).transpose()?;
            let rows = engine.list_messages(ListQuery {
                account,
                folder: Some(folder),
                folder_role,
                limit,
            })?;
            if json {
                return print_json(&rows);
            }
            print_list(&rows, unified);
            Ok(())
        }
        Command::Read {
            id,
            raw,
            no_mark,
            html,
            load_images,
        } => cmd_read::read(&profile, json, id, raw, no_mark, html, load_images).await,
        Command::Send(s) => send(&profile, json, s).await,
        Command::Contacts { cmd } => cmd_identity::contacts(&profile, json, cmd),
        Command::Kt { cmd } => cmd_identity::kt(&profile, json, cmd).await,
        Command::Key { cmd } => {
            let engine = Engine::open(&profile)?;
            match cmd {
                KeyCmd::Show { address } => {
                    let own = engine
                        .list_accounts()?
                        .into_iter()
                        .find(|a| a.email.eq_ignore_ascii_case(address.trim()));
                    if let Some(a) = own {
                        let fp = engine.my_fingerprint(&a.email)?;
                        if json {
                            return print_json(&serde_json::json!({
                                "address": a.email,
                                "fingerprint": fp,
                                "source": "own",
                            }));
                        }
                        println!("{}  {fp}  (own key)", a.email);
                        return Ok(());
                    }
                    let r = engine.resolve_recipient(&address, false)?;
                    if json {
                        return print_json(&r);
                    }
                    println!(
                        "{}  {}  {:?} ({:?})",
                        r.address,
                        r.fingerprint.as_deref().unwrap_or("-"),
                        r.recommendation,
                        r.source
                    );
                    Ok(())
                }
                KeyCmd::Export { address, file } => {
                    let armored = engine.export_public_key(&address)?;
                    match file {
                        Some(p) => {
                            std::fs::write(&p, armored.as_bytes())?;
                            if json {
                                print_json(&serde_json::json!({
                                    "address": address,
                                    "file": p,
                                    "fingerprint": engine.my_fingerprint(&address)?,
                                }))?;
                            } else {
                                println!("exported public key of {address} to {}", p.display());
                            }
                        }
                        None => {
                            if json {
                                print_json(&serde_json::json!({
                                    "address": address,
                                    "armored": armored,
                                    "fingerprint": engine.my_fingerprint(&address)?,
                                }))?;
                            } else {
                                print!("{armored}");
                                if !armored.ends_with('\n') {
                                    println!();
                                }
                            }
                        }
                    }
                    Ok(())
                }
                KeyCmd::Qr { account } => cmd_identity::key_qr(&engine, json, &account),
                KeyCmd::Publish { account } => {
                    let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
                    let r = engine.publish_key(&email).await?;
                    if json {
                        return print_json(&r);
                    }
                    println!("uploaded key {} to {}", r.fingerprint, r.server_url);
                    for (addr, state) in &r.status {
                        println!("  {addr}: {state}");
                    }
                    if r.token_issued {
                        println!(
                            "a verification mail is on its way to {email}; once it arrived run \
                             `sealbox key complete-verification --account {email}`"
                        );
                    } else {
                        println!("{email} is already published");
                    }
                    Ok(())
                }
                KeyCmd::DirectoryStatus { account } => {
                    let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
                    let s = engine.directory_status(&email).await?;
                    if json {
                        return print_json(&s);
                    }
                    print_directory_status(&email, &s);
                    Ok(())
                }
                KeyCmd::CompleteVerification { account } => {
                    let email = pick_account(&engine.list_accounts()?, account.as_deref())?;
                    let s = engine.complete_directory_verification(&email).await?;
                    if json {
                        return print_json(&s);
                    }
                    print_directory_status(&email, &s);
                    Ok(())
                }
                KeyCmd::Import { address, file } => {
                    let bytes = read_file_or_stdin(&file)?;
                    let armored = String::from_utf8(bytes).context("key file is not UTF-8")?;
                    let c = engine.import_peer_key(&address, &armored)?;
                    if json {
                        return print_json(&c);
                    }
                    println!(
                        "imported key {} for {} ({:?})",
                        c.fingerprint.as_deref().unwrap_or("-"),
                        c.address,
                        c.recommendation
                    );
                    Ok(())
                }
            }
        }
        Command::Attachment { cmd } => match cmd {
            AttachmentCmd::Save { id, index, path } => {
                let engine = Engine::open(&profile)?;
                let (info, data) = engine.get_attachment(id, index)?;
                let target = if path.is_dir() {
                    path.join(if info.filename.is_empty() {
                        format!("attachment-{id}-{index}")
                    } else {
                        info.filename.clone()
                    })
                } else {
                    path
                };
                std::fs::write(&target, &data)
                    .with_context(|| format!("writing {}", target.display()))?;
                if json {
                    print_json(&serde_json::json!({
                        "id": id, "index": index, "filename": info.filename,
                        "content_type": info.content_type, "size": data.len(), "path": target,
                    }))?;
                } else {
                    println!(
                        "saved {} ({} bytes) to {}",
                        info.filename,
                        data.len(),
                        target.display()
                    );
                }
                Ok(())
            }
        },
        Command::Flag { id, add, remove } => {
            let engine = Engine::open(&profile)?;
            let mut flags = Vec::new();
            if !add.is_empty() {
                flags = engine.set_flags(id, FlagOp::Add, &add).await?;
            }
            if !remove.is_empty() {
                flags = engine.set_flags(id, FlagOp::Remove, &remove).await?;
            }
            if json {
                print_json(&serde_json::json!({"id": id, "flags": flags}))?;
            } else {
                println!("{id}: {}", flags.join(" "));
            }
            Ok(())
        }
        Command::ProviderTest(args) => cmd_provider_test::run(&profile, json, args).await,
        Command::Spam { cmd } => cmd_spam::run(&profile, json, cmd).await,
        Command::Filter { cmd } => cmd_filter::run(&profile, json, cmd).await,
        Command::Delete { id } => {
            let engine = Engine::open(&profile)?;
            engine.delete_message(id).await?;
            if json {
                print_json(&serde_json::json!({"deleted": id}))?;
            } else {
                println!("deleted {id}");
            }
            Ok(())
        }
        Command::Settings { cmd } => cmd_settings::run(&profile, json, cmd).await,
        Command::Profile(a) => cmd_profile::run(&profile, json, a).await,
        Command::Guest { cmd } => cmd_guest::run(&profile, json, cmd).await,
        Command::Recovery { cmd } => cmd_recovery::run(&profile, json, cmd).await,
        Command::Search(a) => cmd_search::run(&profile, json, a),
        Command::Draft { cmd } => cmd_draft::run(&profile, json, cmd).await,
    }
}

async fn account_add(profile: &Path, json: bool, a: AddArgs) -> anyhow::Result<()> {
    let manual: Option<ServerConfig> = match (&a.imap, &a.smtp) {
        (Some(i), Some(s)) => {
            let domain = a
                .email
                .rsplit_once('@')
                .map(|(_, d)| d.to_string())
                .unwrap_or_default();
            Some(ServerConfig {
                imap: parse_endpoint(i)?,
                smtp: parse_endpoint(s)?,
                auth_hint: AuthHint::Password,
                display_name: format!("{domain} (manual)"),
                source: ConfigSource::Manual,
                username: UsernameForm::FullAddress,
            })
        }
        _ => None,
    };

    if a.dry_run {
        let cfg = match manual {
            Some(m) => m,
            None => match Engine::detect_servers_offline(&a.email) {
                Some(c) => c,
                None => {
                    let engine = Engine::open(profile)?;
                    engine.detect_servers(&a.email).await?
                }
            },
        };
        // The real run would refuse this configuration (plaintext towards a public host).
        sealbox_core::sealbox_mail::net_policy::check_server_config(&cfg)
            .map_err(sealbox_core::Error::from)?;
        let login = a.user.clone().unwrap_or_else(|| cfg.login_name(&a.email));
        if json {
            return print_json(&serde_json::json!({
                "email": a.email,
                "servers": cfg,
                "login": login,
                "auth_hint": auth_hint_text(&cfg.auth_hint),
            }));
        }
        println!("{}  ({:?})", cfg.display_name, cfg.source);
        println!(
            "  IMAP:  {}:{} {}",
            cfg.imap.host,
            cfg.imap.port,
            security_name(cfg.imap.security)
        );
        println!(
            "  SMTP:  {}:{} {}",
            cfg.smtp.host,
            cfg.smtp.port,
            security_name(cfg.smtp.security)
        );
        println!("  login: {login}");
        println!("  auth:  {}", auth_hint_text(&cfg.auth_hint));
        return Ok(());
    }

    if let Some(which) = a.oauth {
        return cmd_oauth::account_add_oauth(profile, json, &a, which, manual).await;
    }

    let password = match (&a.password, &a.password_env) {
        (Some(p), _) => p.clone(),
        (None, Some(var)) => {
            std::env::var(var).map_err(|_| anyhow!("environment variable {var} is not set"))?
        }
        (None, None) => {
            if std::io::stdin().is_terminal() {
                bail!("a password is required: --password-env VAR (or --password)");
            }
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            let s = s.trim_end_matches(['\r', '\n']).to_string();
            if s.is_empty() {
                bail!("a password is required: --password-env VAR (or --password)");
            }
            s
        }
    };
    let engine = Engine::open(profile)?;
    let info = engine
        .add_account(AddAccount {
            email: a.email.clone(),
            display_name: a.name.clone(),
            auth: AuthSpec::Password { password },
            servers: manual,
            login: a.user.clone(),
        })
        .await?;
    if let Some(p) = a.provider.as_deref() {
        engine.set_account_provider(&info.email, Some(parse_provider(p)?))?;
    }
    if json {
        return print_json(&info);
    }
    println!(
        "added {} (login {}, imap {}:{}, smtp {}:{})",
        info.email, info.login, info.imap.host, info.imap.port, info.smtp.host, info.smtp.port
    );
    println!(
        "key fingerprint: {}",
        info.fingerprint.as_deref().unwrap_or("-")
    );
    Ok(())
}

async fn send(profile: &Path, json: bool, s: SendArgs) -> anyhow::Result<()> {
    let text = match (&s.body, &s.body_file) {
        (Some(b), _) => b.clone(),
        (None, Some(f)) => {
            String::from_utf8(read_file_or_stdin(f)?).context("body is not UTF-8")?
        }
        (None, None) => {
            let err = clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "one of --body or --body-file is required\n",
            );
            err.exit();
        }
    };
    let mut attachments = Vec::new();
    for p in &s.attachments {
        let data =
            std::fs::read(p).with_context(|| format!("reading attachment {}", p.display()))?;
        attachments.push(AttachmentData {
            filename: p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment")
                .to_string(),
            content_type: guess_content_type(p),
            data,
        });
    }
    let engine = cmd_guest::engine_for_send(profile, s.guest_expiry)?;
    let compose = ComposeOptions {
        kind: if s.forward.is_some() {
            ComposeKind::Forward
        } else if s.in_reply_to.is_some() {
            ComposeKind::Reply
        } else {
            ComposeKind::New
        },
        quote: s.quote,
        forward_of: s.forward.clone(),
        skip_signature: s.no_signature,
    };
    let report = engine
        .send_with(
            &s.from,
            Draft {
                to: s.to.clone(),
                cc: s.cc.clone(),
                bcc: s.bcc.clone(),
                subject: s.subject.clone(),
                text,
                html: None,
                attachments,
                in_reply_to: s.in_reply_to.clone(),
                policy: s.policy.into(),
                guest_mode: s.guest_mode.into(),
                guest_recipient_hint: s.guest_recipient.clone(),
            },
            compose,
        )
        .await?;
    if json {
        return print_json(&report);
    }
    let how = match report.mode {
        SendMode::Encrypted => "🔒 encrypted + signed (PGP/MIME)",
        SendMode::Plaintext => "plaintext (with Autocrypt header)",
        SendMode::GuestLink => "🔗 guest link",
    };
    println!("sent <{}> {how}", report.message_id);
    for r in &report.recipients {
        println!(
            "  {:<32} {:?} {}",
            r.address,
            r.recommendation,
            r.fingerprint.as_deref().unwrap_or("-")
        );
    }
    if let Some(g) = &report.guest {
        cmd_guest::print_guest(g);
    }
    match (&report.sent_folder, report.sent_copy_appended) {
        (None, _) => eprintln!("warning: the Sent copy could not be stored on the server"),
        (Some(f), false) => eprintln!("(the provider stored the Sent copy in {f} itself)"),
        _ => {}
    }
    Ok(())
}

fn exit_code(err: &anyhow::Error) -> i32 {
    match err.downcast_ref::<sealbox_core::Error>() {
        Some(e) => e.exit_code(),
        None => 1,
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SEALBOX_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let json = cli.json;
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(()) => {}
        Err(e) => {
            let code = exit_code(&e);
            if json {
                let body = serde_json::json!({
                    "error": e.to_string(),
                    "exit_code": code,
                    "missing_keys": e
                        .downcast_ref::<sealbox_core::Error>()
                        .and_then(|c| match c {
                            sealbox_core::Error::RecipientsWithoutKeys { missing } => Some(missing.clone()),
                            _ => None,
                        }),
                });
                let _ = print_json(&body);
            } else {
                eprintln!("error: {e:#}");
                if code == 3 {
                    eprintln!("hint: use --policy plaintext (unencrypted) or --policy guest (passphrase link), or import the recipient's key with `sealbox key import`");
                }
            }
            std::process::exit(if code == EXIT_USAGE { EXIT_USAGE } else { code });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbox_core::AuthKind;

    fn acct(email: &str) -> AccountInfo {
        AccountInfo {
            id: 1,
            email: email.into(),
            display_name: String::new(),
            imap: Endpoint::new("imap.example.org", 993, Security::Tls),
            smtp: Endpoint::new("smtp.example.org", 465, Security::Tls),
            auth_kind: AuthKind::Password,
            login: email.into(),
            fingerprint: None,
            created_at: 0,
        }
    }

    #[test]
    fn pick_account_defaults_to_the_only_account() {
        let one = vec![acct("a@example.org")];
        assert_eq!(pick_account(&one, None).unwrap(), "a@example.org");
        // Case-insensitive match returns the stored spelling.
        assert_eq!(
            pick_account(&one, Some("A@Example.org")).unwrap(),
            "a@example.org"
        );
        // An unknown address is passed through so the engine reports "account not found".
        assert_eq!(
            pick_account(&one, Some("x@example.org")).unwrap(),
            "x@example.org"
        );
        assert!(pick_account(&[], None)
            .unwrap_err()
            .to_string()
            .contains("no accounts"));
        let two = vec![acct("a@example.org"), acct("b@example.org")];
        let err = pick_account(&two, None).unwrap_err().to_string();
        assert!(
            err.contains("--account") && err.contains("b@example.org"),
            "{err}"
        );
        assert_eq!(
            pick_account(&two, Some(" b@example.org ")).unwrap(),
            "b@example.org"
        );
    }

    #[test]
    fn roles_parse_with_aliases() {
        assert_eq!(parse_role("trash").unwrap(), FolderRole::Trash);
        assert_eq!(parse_role("Spam").unwrap(), FolderRole::Junk);
        assert_eq!(parse_role("bin").unwrap(), FolderRole::Trash);
        assert!(parse_role("outbox")
            .unwrap_err()
            .to_string()
            .contains("unknown folder role"));
    }

    #[test]
    fn dates_render_in_utc() {
        assert_eq!(chrono_lite(0).as_deref(), Some("1970-01-01 00:00"));
        assert_eq!(
            chrono_lite(1_700_000_000).as_deref(),
            Some("2023-11-14 22:13")
        );
    }
}
