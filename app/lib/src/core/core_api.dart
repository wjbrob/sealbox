import 'dart:typed_data';

import 'models.dart';

/// The seam between the Flutter UI and the Rust engine.
///
/// * `FrbCore` (lib/src/core/frb_core.dart) is backed by `sealbox-core` through
///   flutter_rust_bridge and is what `main.dart` installs.
/// * `FakeCore` (lib/src/core/fake_core.dart) is in-memory, deterministic and
///   dependency-free; widget tests and reviewers use it.
///
/// Every call is asynchronous because the real engine does I/O (IMAP, SQLite,
/// key lookups) off the UI thread. Ids are strings: the account id is the
/// address, the message id the engine's local row id.
///
/// The operations that arrived with the real engine (sync, contacts, keys,
/// flags, attachments, IDLE) live on [CoreMailOps]; screens reach them through
/// the [CoreApiOps] extension, which gives a `CoreApi` double that does not
/// implement them harmless defaults (empty contacts, no-op sync, …). The same
/// goes for [CoreIdentityOps], [CoreFolderOps], [CoreComposeOps], [CoreSpamOps],
/// [CoreServerOps], [CoreSearchOps] and [CoreDraftOps].
abstract class CoreApi {
  // -- bridge smoke tests ----------------------------------------------------
  Future<String> version();
  Future<String> greet(String name);

  // -- identity / keys -------------------------------------------------------
  /// Generates a real OpenPGP key pair and returns its fingerprint (the secret
  /// key is discarded; persistent keys are created with the account).
  Future<IdentityPreview> generateIdentityPreview({
    required String name,
    required String email,
  });

  /// The user's own identity key as shown in Settings (first account's key;
  /// `IdentityPreview.isEmpty` when there is no account yet).
  Future<IdentityPreview> myIdentity();

  /// Own accounts → Autocrypt peer state → imported keys → directory.
  Future<RecipientKeyInfo> lookupRecipientKey(String email);

  /// A guest-link passphrase. The engine generates the real one at send time
  /// and returns it in [SendReceipt.guestLinks]; this is for previews/doubles.
  Future<String> generateGuestPassphrase();

  // -- accounts --------------------------------------------------------------
  Future<ProviderDetection> detectProvider(String email);
  Future<List<Account>> listAccounts();
  Future<Account> addAccount(AccountSetup setup);
  Future<void> removeAccount(String accountId);

  // -- mail ------------------------------------------------------------------
  /// Unified inbox across all accounts (INBOX and Sent grouped into
  /// conversations), newest first.
  Future<List<MailThread>> listThreads();
  Future<MailThread?> getThread(String threadId);

  /// Sends [draft] from its account, each recipient as compose decided (encrypted, a guest
  /// link, or plaintext they were confirmed for), and returns what went out. One message can
  /// be several sends — encrypted, guest link (one per recipient for email-code links),
  /// confirmed plaintext, then a copy per Bcc recipient (`FrbCore.send`). When one fails
  /// after an earlier one went out it throws [PartialSendException]: who got the message
  /// (guest links and their passphrases included) and who did not, so sending again reaches
  /// only the rest. When nothing went out, that send's own error is rethrown.
  Future<SendReceipt> send(DraftMessage draft);

  // -- backup ----------------------------------------------------------------
  Future<BackupStatus> backupStatus();
  Future<BackupStatus> backupNow();
}

/// Engine operations beyond the base seam. `FrbCore` (real) and `FakeCore`
/// implement it; see [CoreApiOps] for the defaults other doubles get.
abstract class CoreMailOps {
  /// Everyone we hold a key or Autocrypt state for (own accounts excluded).
  Future<List<ContactKey>> contacts();

  /// ASCII-armored public key of one of our accounts.
  Future<String> exportPublicKey(String accountId);

  /// Import a correspondent's armored public key for [address].
  Future<ContactKey> importPeerKey(String address, String armored);

  /// One message with its decrypted body.
  Future<Message?> getMessage(String messageId);
  Future<AttachmentBytes> getAttachment(String messageId, int index);

  /// The sanitized HTML body of a message, or null when it has none — the only
  /// HTML a screen may render (docs/HTML_MAIL.md). [Message.body] stays the
  /// plain-text view.
  ///
  /// Pass [allowRemote] only after the user asked for images on *this* message:
  /// it is what lets the sender's server see that the mail was opened.
  Future<HtmlBody?> messageHtml(String messageId, {bool allowRemote = false});

  /// Fetch new mail for every account (INBOX + Sent). Never throws for a
  /// single failing account; see [SyncOutcome.errors]. The app syncs through
  /// [syncAccount] instead, which reports progress while it runs.
  Future<SyncOutcome> syncAll();

  /// Sync one account (INBOX, then its Sent folder when the server has one) and say how
  /// far it got: a [SyncEvent.progress] after every batch the engine stored (committed, so
  /// the list can show it at once), then one [SyncEvent.done] with the account's outcome,
  /// and the stream closes. A failed sync ends the stream with its error instead of an
  /// outcome. A folder's first sync stores only its newest 500 messages
  /// ([AccountSyncOutcome.moreToBackfill], see [backfill]). Cancelling the subscription
  /// only stops listening: the engine finishes the run and keeps what it stored.
  Stream<SyncEvent> syncAccount(String accountId);

  /// Older mail of [accountId] that a first sync's window left on the server, newest first:
  /// up to [max] messages (null: all of it) over every folder that has some, INBOX first,
  /// with the same events as [syncAccount]. With nothing left the stream is just the
  /// outcome (no network). The outcome's `moreToBackfill` says whether to ask again. The
  /// engine holds the account's mailbox lock while it runs — a manual sync or a watcher of
  /// the same account waits for it — so ask for a bounded [max] at a time.
  Stream<SyncEvent> backfill(String accountId, {int? max});

  /// IMAP IDLE for one account: emits [MailEventKind.idle] when the watcher is
  /// armed and [MailEventKind.newMail] after each server notification. Cancel
  /// the subscription to stop (the engine ends its loop at the next event).
  Stream<MailEvent> watch(String accountId);

  Future<void> markSeen(String messageId, {bool seen = true});
  Future<void> deleteMessage(String messageId);

  /// Which optional services the engine is configured with.
  Future<EngineCapabilities> capabilities();

  /// Conversations whose messages live in [folder] (newest first). Opening a
  /// conversation still shows every message of it across folders.
  Future<List<MailThread>> listThreadsIn(MailFolder folder);

  // -- per-account settings (signature, out-of-office) -----------------------
  Future<SignatureSettings> getSignature(String accountId);
  Future<SignatureSettings> setSignature(String accountId, SignatureSettings s);
  Future<AutoReplySettings> getAutoReply(String accountId);
  Future<AutoReplySettings> setAutoReply(String accountId, AutoReplySettings s);
  Future<List<AutoReplyEntry>> autoReplyLog(String accountId);

  /// How secrets are protected at rest (engine `profile_key_status`).
  Future<ProfileKeyStatus> profileKeyStatus();
}

/// Identity (G30) and recovery (G15) operations. `FrbCore` and `FakeCore`
/// implement them; other doubles get the [CoreApiOps] defaults ("not
/// available" errors, an unchecked key-transparency state).
abstract class CoreIdentityOps {
  /// Mark [address] verified with [fingerprint] (hex or `OPENPGP4FPR:`).
  /// Throws "fingerprint mismatch …" unless it is the contact's current key.
  Future<ContactKey> verifyContact(String address, String fingerprint);
  Future<ContactKey> unverifyContact(String address);

  /// Accept a changed key without checking it.
  Future<ContactKey> acknowledgeKeyChange(String address);

  /// `OPENPGP4FPR:<hex>` for one of our accounts (shown as a QR code).
  Future<String> fingerprintQrPayload(String accountId);

  /// Upper-case fingerprint from a scanned/pasted payload; throws when invalid.
  Future<String> parseFingerprintQr(String payload);

  /// Key-transparency audit of our own entry (configured server).
  Future<KtAudit> ktAudit(String accountId);

  /// The configured Sealbox server URL, if any.
  Future<String?> serverUrl();

  /// A fresh 12-word phrase for [accountId] (stored nowhere).
  Future<List<String>> recoveryPhraseCreate(String accountId);

  /// Validate typed words (no network). Throws for a wrong count / unknown word.
  Future<PhraseCheck> recoveryPhraseValidate(String words);

  /// Encrypt keys + contacts + settings with [phrase] and upload them.
  Future<BackupStatus> backupToServer(String accountId, String serverUrl, String phrase);

  /// Local backup bookkeeping and reminder for [accountId].
  Future<BackupStatus> recoveryStatus(String accountId);

  /// Restore an account on this device. With [password] the slot can also be
  /// found in the mailbox and the login is tested before anything is written.
  Future<Account> restoreFromServer(
    String serverUrl,
    String email,
    String phrase, {
    String? password,
  });

  /// Store the mailbox password of a restored account.
  Future<Account> setAccountCredential(String email, String password);

  /// Mail an Autocrypt Setup Message to ourselves; returns the setup code.
  Future<SetupExportResult> setupMessageExport(String accountId);

  /// Import a setup message (local message id, Message-ID or file path).
  Future<Account> setupMessageImport(String source, String setupCode);

  /// A fresh notification for a guest message sent earlier.
  Future<void> resendGuestLink(String messageId);
}

/// Folders by special-use role and moving messages between them. The engine
/// resolves a role per account to the folder the server calls it (learned from
/// `LIST` on sync, else the provider default). `FrbCore` and `FakeCore`
/// implement it; other doubles get the [CoreApiOps] defaults.
abstract class CoreFolderOps {
  /// Every role of [accountId] with the folder it maps to (no network).
  Future<List<FolderRoleInfo>> folderRoles(String accountId);

  /// Conversations with a message in the folder playing [role] — across every
  /// account, or only [accountId] — newest first; each thread holds the members
  /// in that folder. `listThreadsIn(MailFolder)` is this for the chip's role.
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId});

  /// Fetch the folder playing [role] (every account, or only [accountId]). INBOX
  /// runs the spam / filter / auto-reply passes. Like `syncAll` it never throws
  /// for one failing account: see [SyncOutcome.errors]. A role the server has no
  /// folder for is an empty, successful outcome.
  Future<SyncOutcome> syncFolder(FolderRole role, {String? accountId});

  /// Move a message to the folder playing [role] (created when missing). See
  /// [MoveResult] for what the list shows afterwards.
  Future<MoveResult> moveMessage(String messageId, FolderRole role);
}

/// What the engine adds to a draft on send: quote, forwarded message, signature
/// (`DraftMessage.compose`). `FrbCore` and `FakeCore` implement it.
abstract class CoreComposeOps {
  /// Exactly the bodies `send` would produce for [draft] (nothing is sent).
  /// Throws where sending would before any network: unknown account, or a reply
  /// to quote / a message to forward that is not stored.
  Future<ComposePreview> composePreview(DraftMessage draft);

  /// The account's signature block for a message of [kind]; null when it is off,
  /// empty or does not apply to that kind.
  Future<SignaturePreview?> signaturePreview(String accountId, ComposeKind kind);
}

/// Spam settings, feedback and explanations, and the user's filter rules.
/// `FrbCore` and `FakeCore` implement it.
abstract class CoreSpamOps {
  Future<SpamSettings> spamSettings(String accountId);

  /// Validated and normalised by the engine; returns what was stored. Invalid
  /// values throw `invalid input: …` and change nothing.
  Future<SpamSettings> setSpamSettings(String accountId, SpamSettings settings);

  /// Add (or with `add: false` remove) an address or domain on the allowlist;
  /// adding also takes it off the blocklist. Returns the new settings.
  Future<SpamSettings> spamAllow(String accountId, String entry, {bool add = true});

  /// Same for the blocklist.
  Future<SpamSettings> spamBlock(String accountId, String entry, {bool add = true});

  /// Model statistics and every account's spam state (local).
  Future<SpamStatus> spamStatus();

  /// Why a stored message got its label (offline).
  Future<SpamExplanation> spamExplain(String messageId);

  /// "Spam" / "Not spam": train the model, store the label and move the message
  /// to the junk folder or back to INBOX (it keeps its id).
  Future<SpamLearnResult> spamLearn(String messageId, {required bool isSpam});

  /// The account's rules in evaluation order.
  Future<List<FilterRule>> filterRules(String accountId);

  /// Store a new rule (`order: 0` appends); returns it with its id. Invalid rules
  /// (empty value, bad regex, no folder, a header field without a name, a flag
  /// with spaces/parentheses/quotes) throw `invalid input: …`.
  Future<FilterRule> addFilterRule(String accountId, FilterRule rule);
  Future<FilterRule> updateFilterRule(String accountId, FilterRule rule);

  /// False when there was no rule with that id.
  Future<bool> removeFilterRule(String accountId, int ruleId);
  Future<FilterRule> setFilterRuleEnabled(String accountId, int ruleId, bool enabled);

  /// Replace all rules in the given order (an editor saving its list): all are
  /// validated first; ids are reassigned and `order` becomes 10, 20, ….
  Future<List<FilterRule>> setFilterRules(String accountId, List<FilterRule> rules);

  /// Dry run of the rules against a stored message of the account.
  Future<FilterTestReport> testFilterRules(String accountId, String messageId);
}

/// The Sealbox server (runtime URL) and publishing the account key to its
/// directory. `FrbCore` and `FakeCore` implement it.
abstract class CoreServerOps {
  /// Set (or with null / empty clear) the server URL; stored in the profile, it
  /// wins over `SEALBOX_SERVER_URL`. Must be `http(s)://host[:port]`. Returns the
  /// effective URL afterwards (clearing falls back to the environment's).
  Future<String?> setServerUrl(String? url);

  /// Where `serverUrl()` comes from.
  Future<ServerUrlSource> serverUrlSource();

  /// Upload the key and request the verification mail ([PublishResult.tokenIssued]).
  /// Throws "no Sealbox server configured: … `sealbox server set-url` …" without a
  /// server, or the directory's error.
  Future<PublishResult> publishKey(String accountId);

  /// What the directory holds for the account's address. Never throws for a
  /// missing or unreachable server: [DirectoryState.noServer] /
  /// [DirectoryState.unreachable].
  Future<DirectoryStatus> directoryStatus(String accountId);

  /// Sync, find the directory's verification mail, follow its link, report the
  /// state ([DirectoryState.awaitingVerification] while the mail has not arrived).
  Future<DirectoryStatus> completeDirectoryVerification(String accountId);
}

/// Searching the stored mail (engine `search`, `rebuild_search_index`). Local only: the
/// index lives in memory, built from the decrypted bodies, and nothing is sent to a server.
/// `FrbCore` and `FakeCore` implement it.
abstract class CoreSearchOps {
  /// Messages matching [text] in subject, sender, recipients or body, best first. Every
  /// word must match (case- and accent-insensitive), the last one also as a prefix once it
  /// has 3 characters; text without a letter or digit finds nothing. [accountId] / [folder]
  /// narrow the search (null = every account / folder); [limit] is at most 500.
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  });

  /// Builds the search index now so the first search answers at once (the engine would
  /// build it on the first search otherwise). Safe to call again; it rebuilds.
  Future<SearchIndexInfo> warmSearchIndex();
}

/// Saved drafts (engine `drafts.rs`): local to this profile, subject and body sealed at rest
/// like message bodies, attachments referenced by path. `FrbCore` and `FakeCore` implement it.
abstract class CoreDraftOps {
  /// Saves [input]; `id: null` creates a draft, an id replaces that draft. Returns it as
  /// stored (with its id). Throws `account not found` / `invalid input: …` (a missing
  /// attachment file, a reply target that cannot be quoted).
  Future<SavedDraft> saveDraft(DraftInput input);

  /// Saved drafts, most recently updated first; [accountId] = only that account's.
  Future<List<SavedDraft>> listDrafts({String? accountId});

  /// One draft; throws `invalid input: no draft <id>` for an unknown id.
  Future<SavedDraft> getDraft(int id);

  /// Deletes a draft (and the copies of its attachment files: the engine's stored ones go
  /// with the draft); false when there was none with that id.
  Future<bool> deleteDraft(int id);

  /// Sends a saved draft as it is stored, with its own policy, and deletes it once the
  /// message is out (a failure keeps it). The compose screen sends through `send` instead,
  /// which can protect each recipient differently.
  Future<SendReceipt> sendDraft(int id);

  /// Syncs every account's drafts with its Drafts folder on the server (encrypted to the
  /// account's own key): brings in what other devices saved, uploads what changed here,
  /// removes what was sent or discarded elsewhere. Per-account failures are reported in
  /// [DraftSyncSummary.failures], not thrown.
  Future<DraftSyncSummary> syncDrafts();

  /// Keeps a copy of a file attached to a draft (named [name]) and returns its handle, for
  /// [SavedDraftAttachment.path]: the engine stores it sealed at rest like a received
  /// attachment (`blob:<id>`, [SavedDraftAttachment.blobHandle]), never as a plain file.
  Future<String> keepDraftAttachment(String name, Uint8List data);

  /// The bytes of a draft attachment ([SavedDraftAttachment.path]: a stored copy's handle,
  /// or a file path, e.g. a copy an earlier build kept under the profile). Throws when it is
  /// gone.
  Future<Uint8List> readDraftAttachment(String path);

  /// Deletes a copy made by [keepDraftAttachment] (or a file copy an earlier build made
  /// under the profile); any other path is left alone.
  Future<void> releaseDraftAttachment(String path);
}

/// [CoreMailOps] (and the other op interfaces) on any [CoreApi]: dispatches to the
/// implementation when the object has one, otherwise returns inert defaults for
/// reads and "not available in this build" errors for actions.
extension CoreApiOps on CoreApi {
  CoreMailOps? get _ops {
    final Object self = this;
    return self is CoreMailOps ? self : null;
  }

  CoreIdentityOps? get _id {
    final Object self = this;
    return self is CoreIdentityOps ? self : null;
  }

  CoreFolderOps? get _folders {
    final Object self = this;
    return self is CoreFolderOps ? self : null;
  }

  CoreComposeOps? get _compose {
    final Object self = this;
    return self is CoreComposeOps ? self : null;
  }

  CoreSpamOps? get _spam {
    final Object self = this;
    return self is CoreSpamOps ? self : null;
  }

  CoreServerOps? get _server {
    final Object self = this;
    return self is CoreServerOps ? self : null;
  }

  CoreSearchOps? get _search {
    final Object self = this;
    return self is CoreSearchOps ? self : null;
  }

  CoreDraftOps? get _drafts {
    final Object self = this;
    return self is CoreDraftOps ? self : null;
  }

  static Future<T> _na<T>(String what) =>
      Future<T>.error(UnsupportedError('$what is not available in this build'));

  Future<ContactKey> verifyContact(String address, String fingerprint) =>
      _id?.verifyContact(address, fingerprint) ?? _na('verification');

  Future<ContactKey> unverifyContact(String address) =>
      _id?.unverifyContact(address) ?? _na('verification');

  Future<ContactKey> acknowledgeKeyChange(String address) =>
      _id?.acknowledgeKeyChange(address) ?? _na('key-change handling');

  Future<String> fingerprintQrPayload(String accountId) =>
      _id?.fingerprintQrPayload(accountId) ?? _na('the fingerprint QR code');

  Future<String> parseFingerprintQr(String payload) =>
      _id?.parseFingerprintQr(payload) ?? _na('QR parsing');

  Future<KtAudit> ktAudit(String accountId) =>
      _id?.ktAudit(accountId) ??
      Future.value(KtAudit(state: KtState.unchecked, accountId: accountId));

  Future<String?> serverUrl() => _id?.serverUrl() ?? Future<String?>.value(null);

  Future<List<String>> recoveryPhraseCreate(String accountId) =>
      _id?.recoveryPhraseCreate(accountId) ?? _na('the recovery phrase');

  Future<PhraseCheck> recoveryPhraseValidate(String words) =>
      _id?.recoveryPhraseValidate(words) ?? _na('the recovery phrase');

  Future<BackupStatus> backupToServer(String accountId, String serverUrl, String phrase) =>
      _id?.backupToServer(accountId, serverUrl, phrase) ?? _na('backup');

  Future<BackupStatus> recoveryStatus(String accountId) =>
      _id?.recoveryStatus(accountId) ?? backupStatus();

  Future<Account> restoreFromServer(
    String serverUrl,
    String email,
    String phrase, {
    String? password,
  }) => _id?.restoreFromServer(serverUrl, email, phrase, password: password) ?? _na('restore');

  Future<Account> setAccountCredential(String email, String password) =>
      _id?.setAccountCredential(email, password) ?? _na('restore');

  Future<SetupExportResult> setupMessageExport(String accountId) =>
      _id?.setupMessageExport(accountId) ?? _na('device transfer');

  Future<Account> setupMessageImport(String source, String setupCode) =>
      _id?.setupMessageImport(source, setupCode) ?? _na('device transfer');

  Future<void> resendGuestLink(String messageId) =>
      _id?.resendGuestLink(messageId) ?? _na('resending guest links');

  Future<List<ContactKey>> contacts() =>
      _ops?.contacts() ?? Future.value(const <ContactKey>[]);

  Future<String> exportPublicKey(String accountId) =>
      _ops?.exportPublicKey(accountId) ??
      Future.error(UnsupportedError('key export is not available'));

  Future<ContactKey> importPeerKey(String address, String armored) =>
      _ops?.importPeerKey(address, armored) ??
      Future.error(UnsupportedError('key import is not available'));

  Future<Message?> getMessage(String messageId) =>
      _ops?.getMessage(messageId) ?? Future.value(null);

  Future<HtmlBody?> messageHtml(String messageId, {bool allowRemote = false}) =>
      _ops?.messageHtml(messageId, allowRemote: allowRemote) ?? Future.value(null);

  Future<AttachmentBytes> getAttachment(String messageId, int index) =>
      _ops?.getAttachment(messageId, index) ??
      Future.error(UnsupportedError('attachments are not available'));

  Future<SyncOutcome> syncAll() =>
      _ops?.syncAll() ?? Future.value(const SyncOutcome([]));

  /// Without engine support a sync stores nothing: no progress, one empty outcome.
  Stream<SyncEvent> syncAccount(String accountId) =>
      _ops?.syncAccount(accountId) ??
      Stream.value(SyncEvent.done(AccountSyncOutcome(account: accountId)));

  /// Without engine support there is never older mail to fetch.
  Stream<SyncEvent> backfill(String accountId, {int? max}) =>
      _ops?.backfill(accountId, max: max) ??
      Stream.value(SyncEvent.done(AccountSyncOutcome(account: accountId)));

  Stream<MailEvent> watch(String accountId) =>
      _ops?.watch(accountId) ?? const Stream<MailEvent>.empty();

  Future<void> markSeen(String messageId, {bool seen = true}) =>
      _ops?.markSeen(messageId, seen: seen) ?? Future.value();

  Future<void> deleteMessage(String messageId) =>
      _ops?.deleteMessage(messageId) ?? Future.value();

  Future<EngineCapabilities> capabilities() =>
      _ops?.capabilities() ??
      Future.value(const EngineCapabilities(guestLinks: true, keyDirectory: true));

  Future<List<MailThread>> listThreadsIn(MailFolder folder) =>
      _ops?.listThreadsIn(folder) ??
      (folder == MailFolder.inbox || folder == MailFolder.all
          ? listThreads()
          : Future.value(const <MailThread>[]));

  Future<SignatureSettings> getSignature(String accountId) =>
      _ops?.getSignature(accountId) ?? Future.value(const SignatureSettings());

  Future<SignatureSettings> setSignature(String accountId, SignatureSettings s) =>
      _ops?.setSignature(accountId, s) ??
      Future.error(UnsupportedError('settings are not available'));

  Future<AutoReplySettings> getAutoReply(String accountId) =>
      _ops?.getAutoReply(accountId) ?? Future.value(const AutoReplySettings());

  Future<AutoReplySettings> setAutoReply(String accountId, AutoReplySettings s) =>
      _ops?.setAutoReply(accountId, s) ??
      Future.error(UnsupportedError('settings are not available'));

  Future<List<AutoReplyEntry>> autoReplyLog(String accountId) =>
      _ops?.autoReplyLog(accountId) ?? Future.value(const <AutoReplyEntry>[]);

  Future<ProfileKeyStatus> profileKeyStatus() =>
      _ops?.profileKeyStatus() ?? Future.value(const ProfileKeyStatus.unknown());

  // -- folders by role ------------------------------------------------------------

  Future<List<FolderRoleInfo>> folderRoles(String accountId) =>
      _folders?.folderRoles(accountId) ?? Future.value(const <FolderRoleInfo>[]);

  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) =>
      _folders?.listThreadsInRole(role, accountId: accountId) ??
      (role.mailFolder == null
          ? Future.value(const <MailThread>[])
          : listThreadsIn(role.mailFolder!));

  Future<SyncOutcome> syncFolder(FolderRole role, {String? accountId}) =>
      _folders?.syncFolder(role, accountId: accountId) ?? Future.value(const SyncOutcome([]));

  Future<MoveResult> moveMessage(String messageId, FolderRole role) =>
      _folders?.moveMessage(messageId, role) ?? _na('moving messages');

  // -- compose ------------------------------------------------------------------------

  /// Without engine support the preview is the typed text, unchanged.
  Future<ComposePreview> composePreview(DraftMessage draft) =>
      _compose?.composePreview(draft) ??
      Future.value(
        ComposePreview(
          kind: draft.inReplyTo != null && draft.compose.kind == ComposeKind.newMessage
              ? ComposeKind.reply
              : draft.compose.kind,
          text: draft.body,
        ),
      );

  Future<SignaturePreview?> signaturePreview(String accountId, ComposeKind kind) =>
      _compose?.signaturePreview(accountId, kind) ?? Future<SignaturePreview?>.value(null);

  // -- spam and filter rules ----------------------------------------------------------

  Future<SpamSettings> spamSettings(String accountId) =>
      _spam?.spamSettings(accountId) ?? Future.value(const SpamSettings());

  Future<SpamSettings> setSpamSettings(String accountId, SpamSettings settings) =>
      _spam?.setSpamSettings(accountId, settings) ?? _na('spam settings');

  Future<SpamSettings> spamAllow(String accountId, String entry, {bool add = true}) =>
      _spam?.spamAllow(accountId, entry, add: add) ?? _na('spam settings');

  Future<SpamSettings> spamBlock(String accountId, String entry, {bool add = true}) =>
      _spam?.spamBlock(accountId, entry, add: add) ?? _na('spam settings');

  Future<SpamStatus> spamStatus() =>
      _spam?.spamStatus() ?? Future.value(const SpamStatus.empty());

  Future<SpamExplanation> spamExplain(String messageId) =>
      _spam?.spamExplain(messageId) ?? _na('spam explanations');

  Future<SpamLearnResult> spamLearn(String messageId, {required bool isSpam}) =>
      _spam?.spamLearn(messageId, isSpam: isSpam) ?? _na('spam feedback');

  Future<List<FilterRule>> filterRules(String accountId) =>
      _spam?.filterRules(accountId) ?? Future.value(const <FilterRule>[]);

  Future<FilterRule> addFilterRule(String accountId, FilterRule rule) =>
      _spam?.addFilterRule(accountId, rule) ?? _na('filter rules');

  Future<FilterRule> updateFilterRule(String accountId, FilterRule rule) =>
      _spam?.updateFilterRule(accountId, rule) ?? _na('filter rules');

  Future<bool> removeFilterRule(String accountId, int ruleId) =>
      _spam?.removeFilterRule(accountId, ruleId) ?? _na('filter rules');

  Future<FilterRule> setFilterRuleEnabled(String accountId, int ruleId, bool enabled) =>
      _spam?.setFilterRuleEnabled(accountId, ruleId, enabled) ?? _na('filter rules');

  Future<List<FilterRule>> setFilterRules(String accountId, List<FilterRule> rules) =>
      _spam?.setFilterRules(accountId, rules) ?? _na('filter rules');

  Future<FilterTestReport> testFilterRules(String accountId, String messageId) =>
      _spam?.testFilterRules(accountId, messageId) ?? _na('filter rules');

  // -- the Sealbox server and its key directory ---------------------------------------

  Future<String?> setServerUrl(String? url) =>
      _server?.setServerUrl(url) ?? _na('changing the server');

  Future<ServerUrlSource> serverUrlSource() =>
      _server?.serverUrlSource() ??
      serverUrl().then((u) => u == null ? ServerUrlSource.none : ServerUrlSource.environment);

  Future<PublishResult> publishKey(String accountId) =>
      _server?.publishKey(accountId) ?? _na('publishing to the key directory');

  Future<DirectoryStatus> directoryStatus(String accountId) =>
      _server?.directoryStatus(accountId) ??
      Future.value(DirectoryStatus(accountId: accountId, state: DirectoryState.unknown));

  Future<DirectoryStatus> completeDirectoryVerification(String accountId) =>
      _server?.completeDirectoryVerification(accountId) ?? _na('publishing to the key directory');

  // -- search (local) -------------------------------------------------------------------

  /// Without engine support search fails ("not available in this build") rather than
  /// answering "no results": an empty list would claim the mail was searched.
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) => _search?.search(text, accountId: accountId, folder: folder, limit: limit) ?? _na('search');

  Future<SearchIndexInfo> warmSearchIndex() =>
      _search?.warmSearchIndex() ?? Future.value(const SearchIndexInfo());

  // -- saved drafts ---------------------------------------------------------------------

  /// Whether this core keeps drafts at all (compose saves them only then).
  bool get supportsDrafts => _drafts != null;

  Future<SavedDraft> saveDraft(DraftInput input) =>
      _drafts?.saveDraft(input) ?? _na('saving drafts');

  Future<List<SavedDraft>> listDrafts({String? accountId}) =>
      _drafts?.listDrafts(accountId: accountId) ?? Future.value(const <SavedDraft>[]);

  Future<SavedDraft> getDraft(int id) => _drafts?.getDraft(id) ?? _na('saved drafts');

  Future<bool> deleteDraft(int id) => _drafts?.deleteDraft(id) ?? Future.value(false);

  Future<SendReceipt> sendDraft(int id) => _drafts?.sendDraft(id) ?? _na('sending drafts');

  Future<DraftSyncSummary> syncDrafts() =>
      _drafts?.syncDrafts() ?? Future.value(const DraftSyncSummary());

  Future<String> keepDraftAttachment(String name, Uint8List data) =>
      _drafts?.keepDraftAttachment(name, data) ?? _na('saving drafts');

  Future<Uint8List> readDraftAttachment(String path) =>
      _drafts?.readDraftAttachment(path) ?? _na('saved drafts');

  Future<void> releaseDraftAttachment(String path) =>
      _drafts?.releaseDraftAttachment(path) ?? Future.value();
}
