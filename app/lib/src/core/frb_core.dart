import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show debugPrint;

import '../providers/provider_table.dart';
import '../rust/api/engine.dart' as frb;
import '../rust/api/sealbox.dart' as frb_smoke;
import 'core_api.dart';
import 'errors.dart';
import 'models.dart';
import 'threading.dart';

/// `CoreApi` backed by `sealbox-core` through flutter_rust_bridge.
///
/// One [frb.Engine] per profile directory (SQLite store + keys). Accounts, mail,
/// sending, contacts, keys, identity (G30: key-change alerts, verification,
/// key transparency), recovery (G15: phrase, server backup, restore, setup
/// message), folders by special-use role, compose preview and signature, spam
/// and filter rules (G25), the key directory / runtime server URL, search and
/// saved drafts are all real engine calls.
class FrbCore
    implements
        CoreApi,
        CoreMailOps,
        CoreIdentityOps,
        CoreFolderOps,
        CoreComposeOps,
        CoreSpamOps,
        CoreServerOps,
        CoreSearchOps,
        CoreDraftOps {
  FrbCore(this._engine, {this.profileKeyOffered = false, this.migratedToRawKey = false});

  /// Open (creating if needed) the profile at [profileDir].
  ///
  /// With [profileKey] (the app lock's raw 32-byte key, `ProfileKeySource::Raw`,
  /// G27) the profile is opened with it. A profile keyed by another source — a
  /// desktop profile created before the app lock, keyed by the OS keyring — is
  /// opened the old way once and re-keyed to [profileKey] (`rewrap_profile`).
  /// Without a key the engine's default applies (desktop keyring /
  /// `SEALBOX_PROFILE_PASSPHRASE`; on mobile there is no default, so a key is
  /// required). A missing or wrong key throws [ProfileLockedException].
  static Future<FrbCore> open(String profileDir, {Uint8List? profileKey}) async {
    if (profileKey == null) {
      return FrbCore(await _guard(() => frb.Engine.open(profileDir: profileDir)));
    }
    try {
      final engine = await frb.Engine.openWithKey(profileDir: profileDir, profileKey: profileKey);
      return FrbCore(engine, profileKeyOffered: true);
    } catch (e) {
      if (!ProfileLockedException.matches(e)) rethrow;
    }
    final engine = await _guard(() => frb.Engine.open(profileDir: profileDir));
    await engine.rewrapProfileRaw(profileKey: profileKey);
    debugPrint('[sealbox] profile re-keyed to the app-lock key (was keyed by another source)');
    return FrbCore(engine, profileKeyOffered: true, migratedToRawKey: true);
  }

  static Future<frb.Engine> _guard(Future<frb.Engine> Function() open) async {
    try {
      return await open();
    } catch (e) {
      if (ProfileLockedException.matches(e)) throw ProfileLockedException('$e');
      rethrow;
    }
  }

  /// The app lock's raw key opened the profile.
  final bool profileKeyOffered;

  /// The profile was re-keyed from another source to the app-lock key on open.
  final bool migratedToRawKey;

  final frb.Engine _engine;

  String get profileDir => _engine.profileDir();

  // -- bridge smoke tests -----------------------------------------------------

  @override
  Future<String> version() async => frb_smoke.sealboxVersion();

  @override
  Future<String> greet(String name) async => frb_smoke.greet(name: name);

  // -- identity / keys --------------------------------------------------------

  @override
  Future<IdentityPreview> generateIdentityPreview({
    required String name,
    required String email,
  }) async {
    final p = await frb_smoke.generateIdentityPreview(name: name, email: email);
    return IdentityPreview(
      fingerprint: p.fingerprint,
      createdAt: _utc(p.createdAt),
      email: email,
    );
  }

  @override
  Future<IdentityPreview> myIdentity() async {
    final accounts = await _engine.listAccounts();
    if (accounts.isEmpty) {
      return IdentityPreview(fingerprint: '', createdAt: DateTime.now().toUtc());
    }
    final a = accounts.first;
    final fp = a.fingerprint ?? await _engine.myFingerprint(email: a.email);
    return IdentityPreview(
      fingerprint: fp,
      createdAt: _utc(a.createdAt),
      email: a.email,
    );
  }

  @override
  Future<RecipientKeyInfo> lookupRecipientKey(String email) async {
    final r = await _engine.resolveRecipient(
      address: email.trim(),
      replyToEncrypted: false,
    );
    return RecipientKeyInfo(
      email: r.address,
      hasKey: r.hasKey,
      source: r.hasKey ? _keySource(r.source) : null,
      fingerprint: r.fingerprint,
    );
  }

  @override
  Future<String> generateGuestPassphrase() async =>
      frb.generateGuestPassphrase();

  @override
  Future<List<ContactKey>> contacts() async =>
      [for (final c in await _engine.contacts()) _contact(c)];

  @override
  Future<String> exportPublicKey(String accountId) =>
      _engine.exportPublicKey(email: accountId);

  @override
  Future<ContactKey> importPeerKey(String address, String armored) async =>
      _contact(await _engine.importPeerKey(address: address, armored: armored));

  // -- accounts ---------------------------------------------------------------

  @override
  Future<ProviderDetection> detectProvider(String email) async {
    final domain = domainOf(email) ?? '';
    final table = detectProviderForEmail(email);
    if (table != null) return ProviderDetection(domain: domain, provider: table);
    // Not in the built-in table: let the engine try ISPDB → autoconfig → SRV →
    // MX → guesses over the network. Anything found is presented like a
    // table entry; failures fall through to manual settings.
    try {
      final cfg = await _engine.detectServers(email: email);
      return ProviderDetection(domain: domain, provider: _providerFrom(cfg, domain));
    } catch (_) {
      return ProviderDetection(domain: domain);
    }
  }

  @override
  Future<List<Account>> listAccounts() async =>
      [for (final a in await _engine.listAccounts()) _account(a)];

  @override
  Future<Account> addAccount(AccountSetup setup) async {
    if (setup.authMethod == AuthMethod.oauth2) {
      throw UnsupportedError(
        'OAuth sign-in is not available in this build (the Google/Microsoft '
        'client ids are pending, see docs/PROVIDERS_CONFORMANCE.md). Use an app '
        'password or manual server settings.',
      );
    }
    final secret = setup.secret ?? '';
    if (secret.isEmpty) throw ArgumentError('a password is required');
    final username = setup.username?.trim() ?? '';
    final table = detectProviderForEmail(setup.email);
    final isTable = table != null &&
        table.imap.host == setup.imap.host &&
        table.smtp.host == setup.smtp.host;
    final info = await _engine.addAccount(
      req: frb.AddAccount(
        email: setup.email.trim(),
        displayName: setup.displayName.trim().isEmpty ? null : setup.displayName.trim(),
        auth: frb.AuthSpec(kind: frb.AuthKind.password, password: secret),
        servers: frb.ServerConfig(
          imap: _endpoint(setup.imap),
          smtp: _endpoint(setup.smtp),
          authHint: frb.AuthHint(
            kind: setup.authMethod == AuthMethod.appPassword
                ? frb.AuthHintKind.appPassword
                : frb.AuthHintKind.password,
            helpUrl: table?.helpUrl,
          ),
          displayName: setup.providerName ?? setup.imap.host,
          source: isTable ? frb.ConfigSource.builtIn : frb.ConfigSource.manual,
          username: frb.UsernameForm.fullAddress,
        ),
        // The engine tries the full address and then the bare local part when
        // no explicit login is given; only pass one when the user changed it.
        login: username.isEmpty || username.toLowerCase() == setup.email.trim().toLowerCase()
            ? null
            : username,
      ),
    );
    return _account(info);
  }

  @override
  Future<void> removeAccount(String accountId) =>
      _engine.removeAccount(email: accountId);

  // -- mail -------------------------------------------------------------------

  static const _listLimit = 500;

  /// Every stored message of every folder (summaries only).
  static const _everything = frb.ListQuery(folder: '*', limit: 1 << 30);

  Future<List<frb.MessageSummary>> _allSummaries() => _engine.listMessages(
    query: const frb.ListQuery(folder: '*', limit: _listLimit),
  );

  @override
  Future<List<MailThread>> listThreads() => listThreadsIn(MailFolder.inbox);

  /// The chip's special-use role decides which folder that is on each account
  /// (`[Gmail]/Spam`, `Junk Email`, `Bulk Mail` …, as the server's `LIST` said);
  /// [MailFolder.all] keeps every folder.
  @override
  Future<List<MailThread>> listThreadsIn(MailFolder folder) async {
    final role = folder.role;
    return role == null ? _threadsWhere((_) => true) : listThreadsInRole(role);
  }

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) async {
    final inRole = await _engine.listMessages(
      query: frb.ListQuery(account: accountId, folderRole: _frbRole(role), limit: _listLimit),
    );
    final ids = {for (final s in inRole) s.id};
    return _threadsWhere((s) => ids.contains(s.id));
  }

  /// Conversations (grouped across every folder, so a thread has the same id here
  /// and in [getThread]) restricted to the members [keep] accepts.
  Future<List<MailThread>> _threadsWhere(bool Function(frb.MessageSummary) keep) async {
    final all = await _allSummaries();
    final groups = {
      for (final e in _group(all).entries)
        e.key: [
          for (final s in e.value)
            if (keep(s)) s,
        ],
    }..removeWhere((_, v) => v.isEmpty);
    final threads = <MailThread>[];
    for (final entry in groups.entries) {
      final messages = [for (final s in entry.value) _message(s, threadId: entry.key)];
      // The row previews the newest message with the snippet the engine stored with it, so
      // no body is read here (was one `getMessage` per conversation, ~800 per inbox load:
      // docs/PERFORMANCE.md). Mail without a stored snippet — nothing readable, e.g. not
      // decryptable on this device — still gets its body read for the preview. Bodies stay
      // empty until the thread is opened.
      messages.sort((a, b) => compareConversationOrder(a.date, a.id, b.date, b.id));
      final newest = messages.last;
      if (newest.engineSnippet == null) {
        final detail = await _tryDetail(newest.id);
        if (detail != null) {
          messages[messages.length - 1] = _withDetail(newest, detail);
        }
      }
      final root = _rootOf(entry.value);
      threads.add(
        MailThread(
          id: entry.key,
          subject: displaySubject(root.subject),
          accountId: root.account,
          messages: messages,
        ),
      );
    }
    threads.sort((a, b) => b.latest.date.compareTo(a.latest.date));
    return List.unmodifiable(threads);
  }

  @override
  Future<MailThread?> getThread(String threadId) async {
    // A conversation older than the newest [_listLimit] messages (a search result can be):
    // look through every stored summary once before saying it does not exist.
    final summaries =
        _group(await _allSummaries())[threadId] ??
        _group(await _engine.listMessages(query: _everything))[threadId];
    if (summaries == null) return null;
    final messages = <Message>[];
    for (final s in summaries) {
      final m = _message(s, threadId: threadId);
      final detail = await _tryDetail(m.id);
      messages.add(
        detail == null ? m : _withDetail(m, detail),
      );
    }
    final root = _rootOf(summaries);
    return MailThread(
      id: threadId,
      subject: displaySubject(root.subject),
      accountId: root.account,
      messages: messages,
    );
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    final id = int.tryParse(messageId);
    if (id == null) return null;
    try {
      final d = await _engine.getMessage(id: id);
      return _withDetail(_message(d.summary), d);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<HtmlBody?> messageHtml(String messageId, {bool allowRemote = false}) async {
    final id = int.tryParse(messageId);
    if (id == null) return null;
    try {
      final b = await _engine.messageHtml(id: id, allowRemote: allowRemote);
      if (b == null) return null;
      return HtmlBody(html: b.html, remoteImages: b.remoteImages, text: b.text);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<AttachmentBytes> getAttachment(String messageId, int index) async {
    final a = await _engine.getAttachment(id: int.parse(messageId), index: index);
    return AttachmentBytes(meta: _attachmentMeta(a.info), data: a.data);
  }

  @override
  Future<SyncOutcome> syncAll() async {
    final results = await _engine.syncAll();
    return SyncOutcome([
      for (final r in results)
        switch (r.report) {
          final report? => _outcome(report, error: r.error),
          null => AccountSyncOutcome(account: r.account, error: r.error),
        },
    ]);
  }

  @override
  Stream<SyncEvent> syncAccount(String accountId) =>
      _engine.syncAccountWithProgress(email: accountId).map(_syncEvent);

  @override
  Stream<SyncEvent> backfill(String accountId, {int? max}) =>
      _engine.backfillWithProgress(email: accountId, maxMessages: max).map(_syncEvent);

  /// A malformed event (a kind without its payload) fails the stream like an engine error.
  static SyncEvent _syncEvent(frb.SyncEvent e) => switch ((e.kind, e.progress, e.report)) {
    (frb.SyncEventKind.progress, final p?, _) => SyncEvent.progress(_progress(p)),
    (frb.SyncEventKind.done, _, final r?) => SyncEvent.done(_outcome(r)),
    _ => throw StateError('malformed sync event from the engine (${e.kind.name})'),
  };

  static SyncProgress _progress(frb.SyncProgress p) => SyncProgress(
    account: p.account,
    folder: p.folder,
    phase: switch (p.phase) {
      frb.SyncPhase.initial => SyncPhase.initial,
      frb.SyncPhase.incremental => SyncPhase.incremental,
      frb.SyncPhase.backfill => SyncPhase.backfill,
    },
    fetched: p.fetched,
    stored: p.stored,
    planned: p.planned,
    totalKnown: p.totalKnown,
    local: p.local,
    moreToBackfill: p.moreToBackfill,
  );

  static AccountSyncOutcome _outcome(frb.SyncReport r, {String? error}) {
    final counted = [for (final f in r.folders) ?f.olderPending];
    return AccountSyncOutcome(
      account: r.account,
      newMessages: r.new_,
      decrypted: r.decrypted,
      failed: r.failed,
      error: error,
      moreToBackfill: r.folders.any((f) => f.moreToBackfill),
      olderPending: counted.isEmpty ? null : counted.fold<int>(0, (a, b) => a + b),
      removed: r.folders.fold<int>(0, (a, f) => a + f.removed),
      flagsChanged: r.folders.fold<int>(0, (a, f) => a + f.flagsChanged),
    );
  }

  @override
  Stream<MailEvent> watch(String accountId) => _engine
      .watch(email: accountId, idleTimeoutSecs: 300)
      .map(
        (e) => switch (e.kind) {
          frb.WatchEventKind.idle => MailEvent(MailEventKind.idle, account: accountId),
          frb.WatchEventKind.newMail => MailEvent(
            MailEventKind.newMail,
            account: accountId,
            newMessages: e.report?.new_ ?? 0,
          ),
          frb.WatchEventKind.timeout => MailEvent(MailEventKind.timeout, account: accountId),
        },
      );

  @override
  Future<void> markSeen(String messageId, {bool seen = true}) async {
    await _engine.setFlags(
      id: int.parse(messageId),
      op: seen ? frb.FlagOp.add : frb.FlagOp.remove,
      flags: const ['\\Seen'],
    );
  }

  @override
  Future<void> deleteMessage(String messageId) =>
      _engine.deleteMessage(id: int.parse(messageId));

  /// The compose screen promises protection *per recipient* (lock / guest link /
  /// confirmed plaintext), while an engine send policy applies to the whole
  /// message. So one draft becomes up to three engine sends: PGP/MIME to the
  /// recipients with a key, a guest link to those without, plaintext only to
  /// those the user explicitly confirmed. Each gets its own Sent copy. A Cc
  /// recipient is decided like a To recipient and stays in Cc in its send (an
  /// address in both is a To recipient). A send that fails after an earlier one
  /// went out throws [PartialSendException]: who got it (guest links included)
  /// and who did not, the failed group and those not tried yet. When the first
  /// send fails nothing went out, and its error is rethrown as it is.
  @override
  Future<SendReceipt> send(DraftMessage draft) async {
    final confirmed = {for (final e in draft.plaintextConfirmedFor) e.toLowerCase()};
    final withKey = <String>[];
    final withoutKey = <String>[];
    final plain = <String>[];
    final seen = <String>{};
    final inCc = <String>{};
    final everyone = <String>[
      for (final a in draft.to)
        if (seen.add(a.toLowerCase())) a,
      for (final a in draft.cc)
        if (seen.add(a.toLowerCase()) && inCc.add(a.toLowerCase())) a,
    ];
    for (final to in everyone) {
      if (confirmed.contains(to.toLowerCase())) {
        plain.add(to);
        continue;
      }
      final r = await _engine.resolveRecipient(address: to, replyToEncrypted: false);
      (r.hasKey ? withKey : withoutKey).add(to);
    }
    final attachments = [
      for (final a in draft.attachments)
        frb.AttachmentData(filename: a.name, contentType: a.contentType, data: a.data),
    ];
    final guestMode = switch (draft.guestMode) {
      GuestMode.passphrase => frb.GuestMode.passphrase,
      GuestMode.oneClick => frb.GuestMode.oneClick,
      GuestMode.emailCode => frb.GuestMode.emailCode,
    };
    // `send_with` with default options is exactly `send`; the options only add the
    // engine's quote / forwarded message and control the signature.
    final opts = _composeOptions(draft.compose);
    Future<frb.SendReport> sendTo(List<String> group, frb.SendPolicy policy) => _engine.sendWith(
      accountEmail: draft.accountId,
      draft: frb.Draft(
        to: [
          for (final a in group)
            if (!inCc.contains(a.toLowerCase())) a,
        ],
        cc: [
          for (final a in group)
            if (inCc.contains(a.toLowerCase())) a,
        ],
        bcc: const [],
        subject: draft.subject,
        text: draft.body,
        attachments: attachments,
        inReplyTo: draft.inReplyTo,
        policy: policy,
        guestMode: guestMode,
        guestRecipientHint: null,
      ),
      opts: opts,
    );
    // An email-code link is bound to one recipient address (the code goes
    // there), so each key-less recipient gets their own link.
    final guestBatches = draft.guestMode == GuestMode.emailCode
        ? [for (final g in withoutKey) [g]]
        : [if (withoutKey.isNotEmpty) withoutKey];
    final encryptedTo = <String>[];
    final guestLinkTo = <String>[];
    final plaintextTo = <String>[];
    // One engine send each, in this order: (recipients, policy, where they count once sent).
    final groups = <(List<String>, frb.SendPolicy, List<String>)>[
      if (withKey.isNotEmpty) (withKey, frb.SendPolicy.auto, encryptedTo),
      for (final b in guestBatches) (b, frb.SendPolicy.guestLink, guestLinkTo),
      if (plain.isNotEmpty) (plain, frb.SendPolicy.allowPlaintext, plaintextTo),
    ];
    if (groups.isEmpty) throw ArgumentError('no recipients');
    final reports = <frb.SendReport>[];
    final links = <GuestLinkResult>[];
    SendReceipt receipt() => SendReceipt(
      encryptedTo: encryptedTo,
      guestLinkTo: guestLinkTo,
      plaintextTo: plaintextTo,
      messageId: reports.first.messageId,
      guestLinks: links,
      sentCopyAppended: reports.every((r) => r.sentCopyAppended),
    );
    for (final (i, (to, policy, sentTo)) in groups.indexed) {
      final frb.SendReport r;
      try {
        r = await sendTo(to, policy);
      } catch (e) {
        // The groups before this one went out, so a plain error would be wrong: sending
        // again (the user's only way on) would mail those recipients a second copy.
        if (reports.isEmpty) rethrow;
        throw PartialSendException(
          sent: receipt(),
          notSentTo: [for (final (rest, _, _) in groups.skip(i)) ...rest],
          reason: friendlyError(e),
        );
      }
      reports.add(r);
      sentTo.addAll(to);
      if (policy == frb.SendPolicy.guestLink && r.guest != null) {
        links.add(_guestLink(r.guest!, to));
      }
    }
    return receipt();
  }

  /// The engine's guest link (G29). The passphrase is passed on only for
  /// passphrase links: for the others it is already inside the URL fragment.
  static GuestLinkResult _guestLink(frb.GuestLinkInfo g, List<String> to) {
    final mode = switch (g.mode) {
      frb.GuestMode.passphrase => GuestMode.passphrase,
      frb.GuestMode.oneClick => GuestMode.oneClick,
      frb.GuestMode.emailCode => GuestMode.emailCode,
    };
    return GuestLinkResult(
      url: g.url,
      mode: mode,
      recipients: to,
      passphrase: mode == GuestMode.passphrase ? g.passphrase : null,
      expiresAt: _utc(g.expiresAt),
      secretInLink: g.secretInLink,
      recipientVerification: g.recipientVerification,
    );
  }

  static bool _loggedNoServer = false;

  @override
  Future<EngineCapabilities> capabilities() async {
    final guest = _engine.guestLinksAvailable();
    if (!guest && !_loggedNoServer) {
      _loggedNoServer = true;
      // The UI says "no Sealbox server" in plain words (L14); the variable name is for the log.
      debugPrint('[sealbox] SEALBOX_SERVER_URL is not set: guest links, server backups and the '
          'key-transparency log are unavailable in this run');
    }
    return _capabilities(guest);
  }

  EngineCapabilities _capabilities(bool guest) => EngineCapabilities(
    guestLinks: guest,
    keyDirectory: _engine.keyDirectoryAvailable(),
    // G29 landed: all three modes are implemented by the engine and server.
    guestModes: const {GuestMode.passphrase, GuestMode.oneClick, GuestMode.emailCode},
  );

  // -- per-account settings -----------------------------------------------------

  @override
  Future<SignatureSettings> getSignature(String accountId) async =>
      _signature(await _engine.getSignature(account: accountId));

  @override
  Future<SignatureSettings> setSignature(String accountId, SignatureSettings s) async =>
      _signature(
        await _engine.setSignature(
          account: accountId,
          settings: frb.SignatureSettings(
            enabled: s.enabled,
            text: s.text,
            html: s.html,
            placement: switch (s.placement) {
              SignaturePlacement.aboveQuote => frb.SignaturePlacement.aboveQuote,
              SignaturePlacement.belowQuote => frb.SignaturePlacement.belowQuote,
            },
            includeOn: switch (s.includeOn) {
              SignatureIncludeOn.newOnly => frb.SignatureIncludeOn.newOnly,
              SignatureIncludeOn.newAndReplies => frb.SignatureIncludeOn.newAndReplies,
              SignatureIncludeOn.all => frb.SignatureIncludeOn.all,
            },
          ),
        ),
      );

  @override
  Future<AutoReplySettings> getAutoReply(String accountId) async =>
      _autoReply(await _engine.getAutoReply(account: accountId));

  @override
  Future<AutoReplySettings> setAutoReply(String accountId, AutoReplySettings s) async =>
      _autoReply(
        await _engine.setAutoReply(
          account: accountId,
          settings: frb.AutoReplySettings(
            enabled: s.enabled,
            start: s.start == null ? null : s.start!.toUtc().millisecondsSinceEpoch ~/ 1000,
            end: s.end == null ? null : s.end!.toUtc().millisecondsSinceEpoch ~/ 1000,
            subjectTemplate: s.subjectTemplate,
            body: s.body,
            replyOncePerSenderDays: s.replyOncePerSenderDays,
            encryptWhenPossible: s.encryptWhenPossible,
            onlyToKnownContacts: s.onlyToKnownContacts,
          ),
        ),
      );

  @override
  Future<ProfileKeyStatus> profileKeyStatus() async {
    final s = await _engine.profileKeyStatus();
    return ProfileKeyStatus(
      source: s.source,
      wrappedRows: s.wrappedRows.toInt(),
      plaintextRows: s.plaintextRows.toInt(),
      kdf: s.kdf,
      fallback: s.fallback,
    );
  }

  @override
  Future<List<AutoReplyEntry>> autoReplyLog(String accountId) async => [
    for (final e in await _engine.autoReplyLog(account: accountId, limit: 50))
      AutoReplyEntry(
        sender: e.sender,
        sentAt: _utc(e.sentAt),
        encrypted: e.encrypted,
        messageId: e.messageId,
      ),
  ];

  static SignatureSettings _signature(frb.SignatureSettings s) => SignatureSettings(
    enabled: s.enabled,
    text: s.text,
    html: s.html,
    placement: switch (s.placement) {
      frb.SignaturePlacement.aboveQuote => SignaturePlacement.aboveQuote,
      frb.SignaturePlacement.belowQuote => SignaturePlacement.belowQuote,
    },
    includeOn: switch (s.includeOn) {
      frb.SignatureIncludeOn.newOnly => SignatureIncludeOn.newOnly,
      frb.SignatureIncludeOn.newAndReplies => SignatureIncludeOn.newAndReplies,
      frb.SignatureIncludeOn.all => SignatureIncludeOn.all,
    },
  );

  static AutoReplySettings _autoReply(frb.AutoReplySettings a) => AutoReplySettings(
    enabled: a.enabled,
    start: a.start == null ? null : _utc(a.start!),
    end: a.end == null ? null : _utc(a.end!),
    subjectTemplate: a.subjectTemplate,
    body: a.body,
    replyOncePerSenderDays: a.replyOncePerSenderDays,
    encryptWhenPossible: a.encryptWhenPossible,
    onlyToKnownContacts: a.onlyToKnownContacts,
  );

  // -- backup (G15) -------------------------------------------------------------

  /// Backup bookkeeping of the first account (Settings shows one card).
  @override
  Future<BackupStatus> backupStatus() async {
    final accounts = await _engine.listAccounts();
    if (accounts.isEmpty) return const BackupStatus(backedUp: false);
    return recoveryStatus(accounts.first.email);
  }

  /// The phrase is never stored, so a backup always needs it typed again; the
  /// UI uses [backupToServer] through the phrase dialog instead.
  @override
  Future<BackupStatus> backupNow() async {
    throw UnsupportedError('A backup needs your recovery phrase: use "Back up now" in Settings.');
  }

  @override
  Future<BackupStatus> recoveryStatus(String accountId) async {
    final s = await _engine.backupStatus(email: accountId);
    final last = s.lastBackup;
    return BackupStatus(
      backedUp: last != null,
      lastBackup: last == null ? null : _utc(last.createdAt).toLocal(),
      reminder: s.reminder,
      phraseCreatedAt: s.phraseCreatedAt == null ? null : _utc(s.phraseCreatedAt!).toLocal(),
      accountId: s.email,
      serverUrl: last?.serverUrl,
      bytes: last?.bytes.toInt(),
    );
  }

  @override
  Future<BackupStatus> backupToServer(String accountId, String serverUrl, String phrase) async {
    await _engine.backupToServer(email: accountId, serverUrl: serverUrl, phrase: phrase);
    return recoveryStatus(accountId);
  }

  @override
  Future<String?> serverUrl() async => _engine.serverUrl();

  @override
  Future<List<String>> recoveryPhraseCreate(String accountId) async =>
      (await _engine.recoveryPhraseCreate(email: accountId)).words;

  @override
  Future<PhraseCheck> recoveryPhraseValidate(String words) async {
    final p = frb.Engine.recoveryPhraseValidate(words: words);
    return PhraseCheck(words: p.words, checksumOk: p.checksumOk);
  }

  @override
  Future<Account> restoreFromServer(
    String serverUrl,
    String email,
    String phrase, {
    String? password,
  }) async {
    final info = password == null || password.isEmpty
        ? await _engine.restoreFromServer(serverUrl: serverUrl, email: email, phrase: phrase)
        : await _engine.restoreFromServerWith(
            serverUrl: serverUrl,
            email: email,
            phrase: phrase,
            opts: frb.RestoreOptions(
              credentials: frb.AuthSpec(kind: frb.AuthKind.password, password: password),
            ),
          );
    return _account(info);
  }

  @override
  Future<Account> setAccountCredential(String email, String password) async => _account(
    await _engine.setAccountCredential(
      email: email,
      auth: frb.AuthSpec(kind: frb.AuthKind.password, password: password),
    ),
  );

  @override
  Future<SetupExportResult> setupMessageExport(String accountId) async {
    final e = await _engine.setupMessageExport(email: accountId);
    return SetupExportResult(setupCode: e.setupCode, messageId: e.messageId);
  }

  @override
  Future<Account> setupMessageImport(String source, String setupCode) async =>
      _account(await _engine.setupMessageImport(source: source, setupCode: setupCode));

  // -- identity (G30) -----------------------------------------------------------

  @override
  Future<ContactKey> verifyContact(String address, String fingerprint) async =>
      _contact(await _engine.verifyContact(address: address, fingerprint: fingerprint));

  @override
  Future<ContactKey> unverifyContact(String address) async =>
      _contact(await _engine.unverifyContact(address: address));

  @override
  Future<ContactKey> acknowledgeKeyChange(String address) async =>
      _contact(await _engine.acknowledgeKeyChange(address: address));

  @override
  Future<String> fingerprintQrPayload(String accountId) =>
      _engine.fingerprintQrPayload(email: accountId);

  @override
  Future<String> parseFingerprintQr(String payload) async =>
      frb.Engine.parseFingerprintQr(payload: payload);

  @override
  Future<KtAudit> ktAudit(String accountId) async {
    if (_engine.serverUrl() == null && !_engine.keyDirectoryAvailable()) {
      return KtAudit(state: KtState.noServer, accountId: accountId);
    }
    try {
      final r = await _engine.ktAudit(email: accountId);
      return KtAudit.fromReport(
        accountId: accountId,
        logSize: r.logSize.toInt(),
        sthVerified: r.sthVerified,
        ownKeyIncluded: r.ownKeyIncluded,
        consistencyOk: r.consistencyOk,
        alerts: r.alerts,
        checkedAt: DateTime.now(),
      );
    } catch (e) {
      return KtAudit(
        state: KtState.unreachable,
        accountId: accountId,
        error: '$e',
        checkedAt: DateTime.now(),
      );
    }
  }

  @override
  Future<void> resendGuestLink(String messageId) async {
    await _engine.resendGuestLink(messageId: messageId);
  }

  // -- folders by special-use role ----------------------------------------------

  @override
  Future<List<FolderRoleInfo>> folderRoles(String accountId) async => [
    for (final e in await _engine.folderRoleEntries(email: accountId))
      FolderRoleInfo(
        accountId: accountId,
        role: _role(e.role),
        folder: e.folder,
        learned: e.learned,
      ),
  ];

  @override
  Future<SyncOutcome> syncFolder(FolderRole role, {String? accountId}) async {
    final accounts = accountId != null
        ? [accountId]
        : [for (final a in await _engine.listAccounts()) a.email];
    final out = <AccountSyncOutcome>[];
    for (final a in accounts) {
      try {
        final r = await _engine.syncFolderRole(email: a, role: _frbRole(role));
        out.add(
          AccountSyncOutcome(
            account: a,
            newMessages: r.new_,
            decrypted: r.decrypted,
            failed: r.failed,
          ),
        );
      } catch (e) {
        out.add(AccountSyncOutcome(account: a, error: friendlyError(e)));
      }
    }
    return SyncOutcome(out);
  }

  @override
  Future<MoveResult> moveMessage(String messageId, FolderRole role) async {
    final r = await _engine.moveMessage(id: int.parse(messageId), role: _frbRole(role));
    return MoveResult(
      messageId: '${r.id}',
      fromFolder: r.fromFolder,
      toFolder: r.toFolder,
      method: switch (r.method) {
        null => null,
        frb.MoveMethod.move => MoveMethod.move,
        frb.MoveMethod.copyExpunge => MoveMethod.copyExpunge,
      },
    );
  }

  static frb.FolderRole _frbRole(FolderRole r) => switch (r) {
    FolderRole.inbox => frb.FolderRole.inbox,
    FolderRole.sent => frb.FolderRole.sent,
    FolderRole.drafts => frb.FolderRole.drafts,
    FolderRole.trash => frb.FolderRole.trash,
    FolderRole.junk => frb.FolderRole.junk,
    FolderRole.archive => frb.FolderRole.archive,
    FolderRole.all => frb.FolderRole.all,
    FolderRole.flagged => frb.FolderRole.flagged,
  };

  static FolderRole _role(frb.FolderRole r) => switch (r) {
    frb.FolderRole.inbox => FolderRole.inbox,
    frb.FolderRole.sent => FolderRole.sent,
    frb.FolderRole.drafts => FolderRole.drafts,
    frb.FolderRole.trash => FolderRole.trash,
    frb.FolderRole.junk => FolderRole.junk,
    frb.FolderRole.archive => FolderRole.archive,
    frb.FolderRole.all => FolderRole.all,
    frb.FolderRole.flagged => FolderRole.flagged,
  };

  // -- compose: quoting and the signature ---------------------------------------

  @override
  Future<ComposePreview> composePreview(DraftMessage draft) async {
    final p = await _engine.composePreview(
      accountEmail: draft.accountId,
      draft: frb.Draft(
        to: draft.to,
        cc: const [],
        bcc: const [],
        subject: draft.subject,
        text: draft.body,
        attachments: const [],
        inReplyTo: draft.inReplyTo,
        policy: frb.SendPolicy.auto,
        guestMode: frb.GuestMode.passphrase,
        guestRecipientHint: null,
      ),
      opts: _composeOptions(draft.compose),
    );
    return ComposePreview(
      kind: _composeKind(p.kind),
      text: p.text,
      html: p.html,
      signatureApplied: p.signatureApplied,
      forwardedAttachments: p.forwardedAttachments,
    );
  }

  @override
  Future<SignaturePreview?> signaturePreview(String accountId, ComposeKind kind) async {
    final p = await _engine.signaturePreview(accountEmail: accountId, kind: _frbComposeKind(kind));
    if (p == null) return null;
    return SignaturePreview(
      text: p.text,
      html: p.html,
      placement: switch (p.placement) {
        frb.SignaturePlacement.aboveQuote => SignaturePlacement.aboveQuote,
        frb.SignaturePlacement.belowQuote => SignaturePlacement.belowQuote,
      },
    );
  }

  static frb.ComposeOptions _composeOptions(ComposeOptions o) => frb.ComposeOptions(
    kind: _frbComposeKind(o.kind),
    quote: o.quote,
    forwardOf: o.forwardOf,
    skipSignature: o.skipSignature,
  );

  static frb.ComposeKind _frbComposeKind(ComposeKind k) => switch (k) {
    ComposeKind.newMessage => frb.ComposeKind.new_,
    ComposeKind.reply => frb.ComposeKind.reply,
    ComposeKind.forward => frb.ComposeKind.forward,
  };

  static ComposeKind _composeKind(frb.ComposeKind k) => switch (k) {
    frb.ComposeKind.new_ => ComposeKind.newMessage,
    frb.ComposeKind.reply => ComposeKind.reply,
    frb.ComposeKind.forward => ComposeKind.forward,
  };

  // -- spam (G25) ---------------------------------------------------------------

  @override
  Future<SpamSettings> spamSettings(String accountId) async =>
      _spamSettings(await _engine.spamSettings(email: accountId));

  @override
  Future<SpamSettings> setSpamSettings(String accountId, SpamSettings settings) async =>
      _spamSettings(
        await _engine.setSpamSettings(
          email: accountId,
          settings: frb.SpamSettings(
            enabled: settings.enabled,
            unsureThreshold: settings.unsureThreshold,
            spamThreshold: settings.spamThreshold,
            dnsblEnabled: settings.dnsblEnabled,
            moveToFolder: settings.moveToFolder,
            allowlist: settings.allowlist,
            blocklist: settings.blocklist,
          ),
        ),
      );

  @override
  Future<SpamSettings> spamAllow(String accountId, String entry, {bool add = true}) async =>
      _spamSettings(await _engine.spamAllow(email: accountId, entry: entry, add: add));

  @override
  Future<SpamSettings> spamBlock(String accountId, String entry, {bool add = true}) async =>
      _spamSettings(await _engine.spamBlock(email: accountId, entry: entry, add: add));

  @override
  Future<SpamStatus> spamStatus() async {
    final s = await _engine.spamStatus();
    return SpamStatus(
      modelSpamMessages: s.modelSpamMessages,
      modelHamMessages: s.modelHamMessages,
      modelTokens: s.modelTokens,
      modelConfidence: s.modelConfidence,
      accounts: [
        for (final a in s.accounts)
          SpamAccountStatus(
            accountId: a.email,
            settings: _spamSettings(a.settings),
            spamFolder: a.spamFolder,
            spamCount: a.messagesSpam,
            unsureCount: a.messagesUnsure,
            hamCount: a.messagesHam,
            filterRuleCount: a.filterRules,
          ),
      ],
    );
  }

  @override
  Future<SpamExplanation> spamExplain(String messageId) async {
    final e = await _engine.spamExplain(id: int.parse(messageId));
    final f = e.features;
    return SpamExplanation(
      messageId: '${e.id}',
      accountId: e.account,
      folder: e.folder,
      from: e.from,
      subject: e.subject,
      stored: StoredSpamInfo(
        score: e.stored.score,
        label: e.stored.label == null ? null : _spamLabel(e.stored.label!),
        reasons: [for (final r in e.stored.reasons) _spamReason(r)],
        learned: e.stored.learned == null ? null : _spamLabel(e.stored.learned!),
      ),
      verdict: _verdict(e.verdict),
      settings: _spamSettings(e.settings),
      features: SpamFeatures(
        fromAddress: f.fromAddress,
        fromName: f.fromName,
        replyTo: f.replyTo,
        urls: f.urls,
        attachments: f.attachments,
        receivedDepth: f.receivedDepth,
        lastExternalIp: f.lastExternalIp,
        authPresent: f.auth.present,
        spf: f.auth.spf == null ? null : _authResult(f.auth.spf!),
        dkim: f.auth.dkim == null ? null : _authResult(f.auth.dkim!),
        dmarc: f.auth.dmarc == null ? null : _authResult(f.auth.dmarc!),
        htmlOnly: f.htmlOnly,
        tokens: f.tokens,
      ),
      filters: _filterOutcome(e.filters),
    );
  }

  @override
  Future<SpamLearnResult> spamLearn(String messageId, {required bool isSpam}) async {
    final r = await _engine.spamLearn(id: int.parse(messageId), isSpam: isSpam);
    return SpamLearnResult(
      messageId: '${r.id}',
      learned: _spamLabel(r.learned),
      previouslyLearned: r.previouslyLearned == null ? null : _spamLabel(r.previouslyLearned!),
      movedTo: r.movedTo,
      modelSpamMessages: r.modelSpamMessages,
      modelHamMessages: r.modelHamMessages,
      verdict: _verdict(r.verdict),
    );
  }

  static SpamSettings _spamSettings(frb.SpamSettings s) => SpamSettings(
    enabled: s.enabled,
    unsureThreshold: s.unsureThreshold,
    spamThreshold: s.spamThreshold,
    dnsblEnabled: s.dnsblEnabled,
    moveToFolder: s.moveToFolder,
    allowlist: s.allowlist,
    blocklist: s.blocklist,
  );

  static SpamLabel _spamLabel(frb.SpamLabel l) => switch (l) {
    frb.SpamLabel.ham => SpamLabel.ham,
    frb.SpamLabel.unsure => SpamLabel.unsure,
    frb.SpamLabel.spam => SpamLabel.spam,
  };

  static SpamReason _spamReason(frb.SpamReason r) =>
      SpamReason(code: r.code, weight: r.weight, detail: r.detail);

  static SpamVerdict _verdict(frb.SpamVerdict v) => SpamVerdict(
    spamProbability: v.spamProbability,
    label: _spamLabel(v.label),
    reasons: [for (final r in v.reasons) _spamReason(r)],
    bayesLogOdds: v.bayesLogOdds,
    bayesConfidence: v.bayesConfidence,
    rulesScore: v.rulesScore,
    logOdds: v.logOdds,
  );

  static SpamAuthResult _authResult(frb.SpamAuthResult r) => switch (r) {
    frb.SpamAuthResult.pass => SpamAuthResult.pass,
    frb.SpamAuthResult.fail => SpamAuthResult.fail,
    frb.SpamAuthResult.softFail => SpamAuthResult.softFail,
    frb.SpamAuthResult.neutral => SpamAuthResult.neutral,
    frb.SpamAuthResult.none => SpamAuthResult.none,
    frb.SpamAuthResult.other => SpamAuthResult.other,
  };

  static FilterOutcome _filterOutcome(frb.FilterOutcome o) => FilterOutcome(
    // `Int64List` elements are `int` on native and `BigInt` on the web build.
    matchedRuleIds: [for (final id in o.matched) id.toInt()],
    moveTo: o.moveTo,
    addFlags: o.addFlags,
    markRead: o.markRead,
    star: o.star,
    errors: [for (final e in o.errors) FilterRuleError(ruleId: e.ruleId, error: e.error)],
  );

  // -- filter rules (G25) -----------------------------------------------------------

  @override
  Future<List<FilterRule>> filterRules(String accountId) async =>
      [for (final r in await _engine.filterRules(email: accountId)) _filterRule(r)];

  @override
  Future<FilterRule> addFilterRule(String accountId, FilterRule rule) async =>
      _filterRule(await _engine.addFilterRule(email: accountId, rule: _frbFilterRule(rule)));

  @override
  Future<FilterRule> updateFilterRule(String accountId, FilterRule rule) async =>
      _filterRule(await _engine.updateFilterRule(email: accountId, rule: _frbFilterRule(rule)));

  @override
  Future<bool> removeFilterRule(String accountId, int ruleId) =>
      _engine.removeFilterRule(email: accountId, id: ruleId);

  @override
  Future<FilterRule> setFilterRuleEnabled(String accountId, int ruleId, bool enabled) async =>
      _filterRule(
        await _engine.setFilterRuleEnabled(email: accountId, id: ruleId, enabled: enabled),
      );

  @override
  Future<List<FilterRule>> setFilterRules(String accountId, List<FilterRule> rules) async => [
    for (final r in await _engine.setFilterRules(
      email: accountId,
      rules: [for (final r in rules) _frbFilterRule(r)],
    ))
      _filterRule(r),
  ];

  @override
  Future<FilterTestReport> testFilterRules(String accountId, String messageId) async {
    final t = await _engine.testFilterRules(email: accountId, messageId: int.parse(messageId));
    return FilterTestReport(
      messageId: '${t.messageId}',
      outcome: _filterOutcome(t.outcome),
      rules: [
        for (final r in t.rules)
          FilterRuleResult(ruleId: r.id, description: r.description, matched: r.matched),
      ],
    );
  }

  static FilterRule _filterRule(frb.FilterRule r) => FilterRule(
    id: r.id,
    order: r.order,
    enabled: r.enabled,
    name: r.name,
    stop: r.stop,
    condition: FilterCondition(
      field: switch (r.matcher.field.kind) {
        frb.FilterFieldKind.from => FilterField.from,
        frb.FilterFieldKind.to => FilterField.to,
        frb.FilterFieldKind.cc => FilterField.cc,
        frb.FilterFieldKind.subject => FilterField.subject,
        frb.FilterFieldKind.listId => FilterField.listId,
        frb.FilterFieldKind.header => FilterField.header,
        frb.FilterFieldKind.body => FilterField.body,
      },
      headerName: r.matcher.field.header,
      op: switch (r.matcher.op) {
        frb.FilterOp.contains => FilterOp.contains,
        frb.FilterOp.equals => FilterOp.equals,
        frb.FilterOp.regex => FilterOp.regex,
        frb.FilterOp.domain => FilterOp.domain,
      },
      value: r.matcher.value,
      caseInsensitive: r.matcher.caseInsensitive,
    ),
    action: FilterAction(
      kind: switch (r.action.kind) {
        frb.FilterActionKind.moveTo => FilterActionKind.moveTo,
        frb.FilterActionKind.addFlag => FilterActionKind.addFlag,
        frb.FilterActionKind.markRead => FilterActionKind.markRead,
        frb.FilterActionKind.star => FilterActionKind.star,
      },
      folder: r.action.folder,
      flag: r.action.flag,
    ),
  );

  static frb.FilterRule _frbFilterRule(FilterRule r) => frb.FilterRule(
    id: r.id,
    order: r.order,
    enabled: r.enabled,
    name: r.name,
    stop: r.stop,
    matcher: frb.FilterMatch(
      field: frb.FilterField(
        kind: switch (r.condition.field) {
          FilterField.from => frb.FilterFieldKind.from,
          FilterField.to => frb.FilterFieldKind.to,
          FilterField.cc => frb.FilterFieldKind.cc,
          FilterField.subject => frb.FilterFieldKind.subject,
          FilterField.listId => frb.FilterFieldKind.listId,
          FilterField.header => frb.FilterFieldKind.header,
          FilterField.body => frb.FilterFieldKind.body,
        },
        header: r.condition.headerName,
      ),
      op: switch (r.condition.op) {
        FilterOp.contains => frb.FilterOp.contains,
        FilterOp.equals => frb.FilterOp.equals,
        FilterOp.regex => frb.FilterOp.regex,
        FilterOp.domain => frb.FilterOp.domain,
      },
      value: r.condition.value,
      caseInsensitive: r.condition.caseInsensitive,
    ),
    action: frb.FilterAction(
      kind: switch (r.action.kind) {
        FilterActionKind.moveTo => frb.FilterActionKind.moveTo,
        FilterActionKind.addFlag => frb.FilterActionKind.addFlag,
        FilterActionKind.markRead => frb.FilterActionKind.markRead,
        FilterActionKind.star => frb.FilterActionKind.star,
      },
      folder: r.action.folder,
      flag: r.action.flag,
    ),
  );

  // -- the Sealbox server and its key directory -------------------------------------

  @override
  Future<String?> setServerUrl(String? url) => _engine.setServerUrl(url: url);

  @override
  Future<ServerUrlSource> serverUrlSource() async => switch (_engine.serverUrlSource()) {
    'settings' => ServerUrlSource.settings,
    'environment' => ServerUrlSource.environment,
    _ => ServerUrlSource.none,
  };

  @override
  Future<PublishResult> publishKey(String accountId) async {
    final r = await _engine.publishKey(email: accountId);
    return PublishResult(
      accountId: accountId,
      fingerprint: r.fingerprint,
      serverUrl: r.serverUrl,
      addressStates: {for (final a in r.status) a.address: a.state},
      tokenIssued: r.tokenIssued,
    );
  }

  @override
  Future<DirectoryStatus> directoryStatus(String accountId) async {
    if (_engine.directoryUrl() == null) {
      return DirectoryStatus(accountId: accountId, state: DirectoryState.noServer);
    }
    try {
      return _directoryStatus(accountId, await _engine.directoryStatus(email: accountId));
    } catch (e) {
      if (_isNoServer(e)) {
        return DirectoryStatus(accountId: accountId, state: DirectoryState.noServer);
      }
      if (!_isDirectoryOrConnection(e)) rethrow;
      return DirectoryStatus(
        accountId: accountId,
        state: DirectoryState.unreachable,
        serverUrl: _engine.directoryUrl(),
        error: friendlyError(e),
      );
    }
  }

  @override
  Future<DirectoryStatus> completeDirectoryVerification(String accountId) async =>
      _directoryStatus(accountId, await _engine.completeDirectoryVerification(email: accountId));

  static DirectoryStatus _directoryStatus(String accountId, frb.DirectoryStatus s) =>
      DirectoryStatus(
        accountId: accountId,
        state: DirectoryState.parse(s.state),
        serverUrl: s.serverUrl,
        published: s.published,
        fingerprintMatches: s.fingerprintMatches,
      );

  /// The engine's `Error::ServerNotConfigured` crosses the bridge as text.
  static bool _isNoServer(Object e) => '$e'.contains('no Sealbox server configured');

  /// `key directory: …` (HTTP / directory refusals) and `connection: …` errors.
  static bool _isDirectoryOrConnection(Object e) {
    final s = friendlyError(e);
    return s.startsWith('key directory:') || s.startsWith('connection:');
  }

  // -- search (local) -------------------------------------------------------------

  @override
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) async {
    final hits = await _engine.search(
      query: frb.SearchQuery(
        account: accountId,
        text: text,
        folder: folder,
        limit: limit.clamp(0, 500),
      ),
    );
    return [
      for (final h in hits)
        SearchResult.fromRaw(message: _message(h.summary), snippet: h.snippet, rank: h.rank),
    ];
  }

  @override
  Future<SearchIndexInfo> warmSearchIndex() async {
    final s = await _engine.rebuildSearchIndex();
    return SearchIndexInfo(documents: s.documents.toInt(), memoryBytes: s.memoryBytes.toInt());
  }

  // -- saved drafts ----------------------------------------------------------------

  /// The account [keepDraftAttachment] stores the next copy for. The engine lets only drafts
  /// of the account that stored a copy reference it, and [keepDraftAttachment] is not told
  /// the draft's account: this is the account of the draft saved last (else the first
  /// account), and [saveDraft] moves a copy kept for another account to the draft's.
  String? _draftAccount;

  /// Copies [saveDraft] moved to another account: the blob id a handle names → the blob
  /// holding the bytes now. Compose keeps the first handle on screen, so later saves and
  /// reads go through this.
  final Map<int, int> _movedBlobs = {};

  @override
  Future<SavedDraft> saveDraft(DraftInput input) async {
    _draftAccount = input.accountId;
    final moved = <int, int>{}; // blob stored for another account → its copy for this one
    final attachments = <frb.DraftAttachment>[];
    Set<int>? owned;
    for (final a in input.attachments) {
      final handle = a.blobId;
      if (handle == null) {
        attachments.add(
          frb.DraftAttachment(path: a.path, name: a.name, contentType: a.contentType),
        );
        continue;
      }
      var id = _movedBlobs[handle] ?? handle;
      owned ??= {
        for (final b in await _engine.listDraftBlobs(accountEmail: input.accountId)) b.id,
      };
      if (!owned.contains(id)) {
        final blob = await _engine.getDraftBlob(id: id);
        final copy = await _engine.putDraftBlob(
          accountEmail: input.accountId,
          filename: blob.info.filename,
          contentType: blob.info.contentType,
          data: blob.data,
        );
        moved[id] = copy;
        owned.add(copy);
        id = copy;
      }
      attachments.add(
        frb.DraftAttachment(path: '', blobId: id, name: a.name, contentType: a.contentType),
      );
    }
    final frb.SavedDraft saved;
    try {
      saved = await _engine.saveDraft(input: _frbDraftInput(input, attachments));
    } catch (_) {
      for (final copy in moved.values) {
        try {
          await _engine.deleteDraftBlob(id: copy);
        } catch (_) {
          // Unreferenced: the start-up sweep deletes it.
        }
      }
      rethrow;
    }
    // The draft names the copies now: later saves and reads of these handles go to them,
    // and the blobs they were made from are nobody's.
    for (final a in input.attachments) {
      final handle = a.blobId;
      final copy = handle == null ? null : moved[_movedBlobs[handle] ?? handle];
      if (copy != null) _movedBlobs[handle!] = copy;
    }
    for (final entry in moved.entries) {
      _movedBlobs[entry.key] = entry.value;
      await _engine.deleteDraftBlob(id: entry.key);
    }
    _schedulePush(saved.id);
    return _savedDraft(saved);
  }

  /// Pushes running per draft id, and the ids saved again while theirs ran.
  final Map<int, Future<void>> _pushes = {};
  final Set<int> _pushAgain = {};

  /// Puts draft [id] on the server (`push_draft`: its account's Drafts folder, encrypted to
  /// the account's own key) in the background — never awaited by a save. Saves while a push
  /// runs fold into one more push; a failed push is left to the next Drafts sync.
  void _schedulePush(int id) {
    if (_pushes.containsKey(id)) {
      _pushAgain.add(id);
      return;
    }
    _pushes[id] = () async {
      try {
        do {
          _pushAgain.remove(id);
          try {
            await _engine.pushDraft(id: id);
          } catch (e) {
            debugPrint('[sealbox] draft $id stays local until a Drafts sync: ${friendlyError(e)}');
            return;
          }
        } while (_pushAgain.contains(id));
      } finally {
        _pushes.remove(id);
        _pushAgain.remove(id);
      }
    }();
  }

  /// Completes when the background pushes started so far are done (tests).
  Future<void> get pushesDone => Future.wait([..._pushes.values]);

  /// The server state of draft [id]: pushed or not, changed since, its origin.
  Future<DraftServerState?> draftServerInfo(int id) async {
    final i = await _engine.draftServerInfo(id: id);
    if (i == null) return null;
    return DraftServerState(
      uuid: i.uuid,
      onServer: i.onServer,
      pending: i.pending,
      origin: i.origin == frb.DraftOrigin.server ? DraftOrigin.server : DraftOrigin.thisDevice,
      remoteFiles: i.remoteFiles,
    );
  }

  @override
  Future<DraftSyncSummary> syncDrafts() async {
    var imported = 0, updated = 0, uploaded = 0, removedHere = 0, removedThere = 0;
    var unreadable = 0;
    final failures = <String>[];
    for (final a in await _engine.listAccounts()) {
      try {
        final r = await _engine.syncDrafts(accountEmail: a.email);
        imported += r.imported;
        updated += r.updated;
        uploaded += r.uploaded;
        removedHere += r.removedLocally;
        removedThere += r.removedOnServer;
        unreadable += r.unreadable;
      } catch (e) {
        failures.add('${a.email}: ${friendlyError(e)}');
      }
    }
    return DraftSyncSummary(
      imported: imported,
      updated: updated,
      uploaded: uploaded,
      removedLocally: removedHere,
      removedOnServer: removedThere,
      unreadable: unreadable,
      failures: failures,
    );
  }

  @override
  Future<List<SavedDraft>> listDrafts({String? accountId}) async => [
    for (final d in await _engine.listDrafts(account: accountId)) _savedDraft(d),
  ];

  @override
  Future<SavedDraft> getDraft(int id) async => _savedDraft(await _engine.getDraft(id: id));

  /// The engine deletes the draft with its stored copies; file copies an earlier build made
  /// for it are released here.
  @override
  Future<bool> deleteDraft(int id) async {
    final files = await _fileCopiesOf(id);
    String? account;
    try {
      account = (await _engine.getDraft(id: id)).account;
    } catch (_) {
      account = null;
    }
    final deleted = await _engine.deleteDraft(id: id);
    if (deleted) await _releaseAll(files);
    // Its server copy goes in the background: the engine keeps a tombstone, and a drafts
    // sync of the account removes the copy (and brings in what changed elsewhere).
    if (deleted && account != null) {
      final email = account;
      unawaited(() async {
        try {
          await _engine.syncDrafts(accountEmail: email);
        } catch (e) {
          debugPrint('[sealbox] draft $id: its server copy stays until a sync: ${friendlyError(e)}');
        }
      }());
    }
    return deleted;
  }

  /// The engine sends the draft with its own policy (one message for everyone) and deletes
  /// it with its stored copies; file copies an earlier build made for it go too.
  @override
  Future<SendReceipt> sendDraft(int id) async {
    final files = await _fileCopiesOf(id);
    final r = await _engine.sendDraft(id: id);
    await _releaseAll(files);
    final everyone = [for (final s in r.recipients) s.address];
    return SendReceipt(
      encryptedTo: r.mode == frb.SendMode.encrypted ? everyone : const [],
      guestLinkTo: r.mode == frb.SendMode.guestLink ? everyone : const [],
      plaintextTo: r.mode == frb.SendMode.plaintext ? everyone : const [],
      messageId: r.messageId,
      guestLinks: [if (r.guest case final g?) _guestLink(g, everyone)],
      sentCopyAppended: r.sentCopyAppended,
    );
  }

  /// Where builds before the engine sealed draft attachments kept their copies:
  /// `<profile>/draft-attachments/<dir>/<name>`, plain files (threat-model R16). Drafts saved
  /// then still name them: they are read and released as before, and swept once orphaned
  /// (`draft_attachment_sweep.dart`). New copies are engine blobs ([keepDraftAttachment]).
  String get draftAttachmentDir => '$profileDir${Platform.pathSeparator}draft-attachments';

  /// Stores the file in the engine, sealed at rest like a received attachment
  /// (`put_draft_blob`), and returns its handle (`blob:<id>`). Nothing is written as a file.
  @override
  Future<String> keepDraftAttachment(String name, Uint8List data) async {
    Future<String> put(String account) async => SavedDraftAttachment.blobHandle(
      await _engine.putDraftBlob(
        accountEmail: account,
        filename: name.trim(),
        contentType: '',
        data: data,
      ),
    );
    final remembered = _draftAccount;
    if (remembered != null) {
      try {
        return await put(remembered);
      } catch (_) {
        _draftAccount = null; // removed meanwhile: fall back to the first account
      }
    }
    final accounts = await _engine.listAccounts();
    if (accounts.isEmpty) throw StateError('no account to keep a draft attachment for');
    return put(accounts.first.email);
  }

  @override
  Future<Uint8List> readDraftAttachment(String path) async {
    final handle = SavedDraftAttachment.blobIdOf(path);
    if (handle == null) return File(path).readAsBytes();
    return (await _engine.getDraftBlob(id: _movedBlobs[handle] ?? handle)).data;
  }

  /// A handle: deletes the blob it was made for (a copy [saveDraft] moved to another
  /// account belongs to that draft now and goes with it). A path: deletes it only when it
  /// is an earlier build's copy under [draftAttachmentDir].
  @override
  Future<void> releaseDraftAttachment(String path) async {
    final handle = SavedDraftAttachment.blobIdOf(path);
    if (handle != null) {
      await _engine.deleteDraftBlob(id: handle);
      return;
    }
    final root = Directory(draftAttachmentDir);
    final file = File(path);
    if (!await root.exists() || !await file.exists()) return;
    // Only our own copies, after resolving links and `..`: a draft may name any file.
    final rootReal = await root.resolveSymbolicLinks();
    final fileReal = await file.resolveSymbolicLinks();
    final sep = Platform.pathSeparator;
    if (!fileReal.startsWith('$rootReal$sep')) return;
    await File(fileReal).delete();
    final parent = File(fileReal).parent;
    if (parent.parent.path == rootReal && await parent.list().isEmpty) await parent.delete();
  }

  /// The file name a kept copy is stored under: no path separators or control characters,
  /// never empty, `.` or `..`, at most 120 characters (the end, with the extension, kept).
  static String safeAttachmentFileName(String name) {
    var n = name.replaceAll(RegExp(r'[/\\\x00-\x1f\x7f]'), '_').trim();
    if (n.isEmpty || n == '.' || n == '..') n = 'attachment';
    if (n.length > 120) n = n.substring(n.length - 120);
    return n;
  }

  /// The engine's sweep of stored copies no saved draft references (more than ten minutes
  /// old), for every account; returns how many it deleted. Run at start-up.
  Future<int> sweepDraftBlobs() async {
    var n = 0;
    for (final a in await _engine.listAccounts()) {
      n += await _engine.sweepDraftBlobs(accountEmail: a.email);
    }
    return n;
  }

  /// The file paths draft [id] names (copies of earlier builds; stored copies go with the
  /// draft in the engine).
  Future<List<String>> _fileCopiesOf(int id) async {
    try {
      return [
        for (final a in (await _engine.getDraft(id: id)).attachments)
          if (a.blobId == null) a.path,
      ];
    } catch (_) {
      return const [];
    }
  }

  Future<void> _releaseAll(List<String> paths) async {
    for (final p in paths) {
      try {
        await releaseDraftAttachment(p);
      } catch (e) {
        debugPrint('[sealbox] could not remove a draft attachment copy: ${friendlyError(e)}');
      }
    }
  }

  static frb.DraftInput _frbDraftInput(DraftInput i, List<frb.DraftAttachment> attachments) =>
      frb.DraftInput(
    id: i.id,
    account: i.accountId,
    kind: _frbComposeKind(i.kind),
    inReplyTo: i.inReplyTo,
    forwardOf: i.forwardOf,
    quote: i.quote,
    to: i.to,
    cc: i.cc,
    bcc: i.bcc,
    subject: i.subject,
    bodyText: i.body,
    attachments: attachments,
    policy: switch (i.policy) {
      SendPolicy.auto => frb.SendPolicy.auto,
      SendPolicy.requireEncryption => frb.SendPolicy.requireEncryption,
      SendPolicy.guestLink => frb.SendPolicy.guestLink,
      SendPolicy.allowPlaintext => frb.SendPolicy.allowPlaintext,
    },
    guestMode: switch (i.guestMode) {
      GuestMode.passphrase => frb.GuestMode.passphrase,
      GuestMode.oneClick => frb.GuestMode.oneClick,
      GuestMode.emailCode => frb.GuestMode.emailCode,
    },
    guestRecipientHint: i.guestRecipientHint,
    noSignature: i.noSignature,
  );

  static SavedDraft _savedDraft(frb.SavedDraft d) => SavedDraft(
    id: d.id,
    accountId: d.account,
    kind: _composeKind(d.kind),
    inReplyTo: d.inReplyTo,
    forwardOf: d.forwardOf,
    quote: d.quote,
    references: d.references,
    to: d.to,
    cc: d.cc,
    bcc: d.bcc,
    subject: d.subject,
    body: d.bodyText,
    attachments: [
      for (final a in d.attachments)
        SavedDraftAttachment(
          path: switch (a.blobId) {
            final int id => SavedDraftAttachment.blobHandle(id),
            null => a.path,
          },
          name: a.name,
          contentType: a.contentType,
        ),
    ],
    policy: switch (d.policy) {
      frb.SendPolicy.auto => SendPolicy.auto,
      frb.SendPolicy.requireEncryption => SendPolicy.requireEncryption,
      frb.SendPolicy.guestLink => SendPolicy.guestLink,
      frb.SendPolicy.allowPlaintext => SendPolicy.allowPlaintext,
    },
    guestMode: switch (d.guestMode) {
      frb.GuestMode.passphrase => GuestMode.passphrase,
      frb.GuestMode.oneClick => GuestMode.oneClick,
      frb.GuestMode.emailCode => GuestMode.emailCode,
    },
    guestRecipientHint: d.guestRecipientHint,
    noSignature: d.noSignature,
    createdAt: _utc(d.createdAt),
    updatedAt: _utc(d.updatedAt),
    origin: d.origin == frb.DraftOrigin.server ? DraftOrigin.server : DraftOrigin.thisDevice,
    remoteFiles: d.remoteFiles,
  );

  // -- conversions --------------------------------------------------------------

  static DateTime _utc(int seconds) =>
      DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

  Future<frb.MessageDetail?> _tryDetail(String id) async {
    try {
      return await _engine.getMessage(id: int.parse(id));
    } catch (_) {
      return null;
    }
  }

  /// The member a conversation is named after (see `conversationRoot`): the
  /// earliest member that answers no other member — never a reply that happens
  /// to share its parent's second.
  static frb.MessageSummary _rootOf(List<frb.MessageSummary> members) =>
      conversationRoot<frb.MessageSummary>(
        members,
        messageId: (s) => s.messageId,
        answers: (s) => [...s.inReplyTo, ...s.references],
      );

  /// Groups summaries by conversation (the engine's `thread_id`, see
  /// `threading.dart`); map order is newest conversation first, each group
  /// oldest-first (`compareConversationOrder`).
  static Map<String, List<frb.MessageSummary>> _group(List<frb.MessageSummary> all) =>
      groupConversations<frb.MessageSummary>(
        all,
        account: (s) => s.account,
        subject: (s) => s.subject,
        date: (s) => _utc(s.date ?? s.receivedAt),
        id: (s) => '${s.id}',
        // Reference threading: the store's References / In-Reply-To key.
        reference: (s) => s.threadId,
      );

  /// A sent, unencrypted copy carrying a `…/g/<id>` link is a guest-link
  /// notification (the engine keeps its secret for resends).
  static final _guestUrl = RegExp(r'https?://\S+/g/[A-Za-z0-9_-]+');

  static Message _withDetail(Message m, frb.MessageDetail d) {
    final body = _bodyOf(d);
    return m.copyWith(
      body: body,
      attachments: _attachments(d),
      guestLink: m.isSent && m.state != EncryptionState.encrypted && _guestUrl.hasMatch(body),
    );
  }

  static String _bodyOf(frb.MessageDetail d) {
    final text = d.text;
    if (text != null && text.trim().isNotEmpty) return text;
    final html = d.html;
    if (html != null && html.trim().isNotEmpty) return htmlToText(html);
    final err = d.summary.decryptError;
    if (d.summary.wasEncrypted && !d.summary.decrypted) {
      return 'This message is encrypted, but not to a key on this device'
          '${err == null ? '.' : ': $err'}';
    }
    return '';
  }

  static List<AttachmentMeta> _attachments(frb.MessageDetail d) =>
      [for (final a in d.attachments) _attachmentMeta(a)];

  static AttachmentMeta _attachmentMeta(frb.AttachmentInfo a) => AttachmentMeta(
    index: a.index,
    filename: a.filename,
    contentType: a.contentType,
    size: a.size,
    contentId: a.contentId,
  );

  static Contact _contactOf(frb.Address a) => Contact(email: a.address, name: a.name);

  static EncryptionState _state(frb.MessageSummary m) {
    if (m.wasEncrypted) {
      return m.decrypted ? EncryptionState.encrypted : EncryptionState.undecryptable;
    }
    if (m.wasSigned && m.signature.status == frb.SigState.good) {
      return EncryptionState.signed;
    }
    return EncryptionState.plaintext;
  }

  static SignatureState _sig(frb.SigState s) => switch (s) {
    frb.SigState.none => SignatureState.none,
    frb.SigState.good => SignatureState.good,
    frb.SigState.bad => SignatureState.bad,
    frb.SigState.unknownKey => SignatureState.unknownKey,
  };

  static Message _message(frb.MessageSummary s, {String? threadId}) => Message(
    id: '${s.id}',
    threadId: threadId ?? conversationIdOf(s.account, s.subject, s.threadId),
    accountId: s.account,
    from: _contactOf(s.from),
    to: [for (final a in s.to) _contactOf(a)],
    cc: [for (final a in s.cc) _contactOf(a)],
    subject: displaySubject(s.subject),
    body: '',
    date: _utc(s.date ?? s.receivedAt),
    state: _state(s),
    signer: s.signature.status == frb.SigState.good ? s.signature.fingerprint : null,
    signerAddress: s.signature.status == frb.SigState.good ? s.signature.signer : null,
    unread: !s.seen,
    folder: s.folder,
    uid: s.uid,
    signatureState: _sig(s.signature.status),
    decryptError: s.decryptError,
    messageId: s.messageId,
    keyChanged: s.signature.keyChanged,
    signerVerified: s.signature.signerVerified,
    inReplyTo: s.inReplyTo,
    references: s.references,
    engineThreadId: s.threadId,
    protectedSubject: s.protectedSubject,
    engineSnippet: s.snippet,
  );

  static KeySource _keySource(frb.KeySource s) => switch (s) {
    frb.KeySource.autocrypt => KeySource.autocrypt,
    frb.KeySource.gossip => KeySource.gossip,
    frb.KeySource.imported => KeySource.imported,
    frb.KeySource.directory => KeySource.directory,
    frb.KeySource.own => KeySource.own,
    frb.KeySource.none => KeySource.autocrypt,
  };

  static ContactKey _contact(frb.Contact c) => ContactKey(
    address: c.address,
    hasKey: c.fingerprint != null && c.recommendation != frb.Recommendation.disable,
    source: _keySource(c.source),
    fingerprint: c.fingerprint,
    preferEncrypt: c.preferEncrypt == frb.PreferEncrypt.mutual,
    lastSeen: c.lastSeen == null ? null : _utc(c.lastSeen!),
    verified: c.verified,
    verifiedAt: c.verifiedAt == null ? null : _utc(c.verifiedAt!),
    keyChangedAt: c.keyChangedAt == null ? null : _utc(c.keyChangedAt!),
    previousFingerprint: c.previousFingerprint,
  );

  static ConnectionSecurity _security(frb.Security s) => switch (s) {
    frb.Security.tls => ConnectionSecurity.tls,
    frb.Security.startTls => ConnectionSecurity.starttls,
    frb.Security.plain => ConnectionSecurity.plain,
  };

  static frb.Endpoint _endpoint(ServerSettings s) => frb.Endpoint(
    host: s.host,
    port: s.port,
    security: switch (s.security) {
      ConnectionSecurity.tls => frb.Security.tls,
      ConnectionSecurity.starttls => frb.Security.startTls,
      ConnectionSecurity.plain => frb.Security.plain,
    },
  );

  static Account _account(frb.AccountInfo a) {
    final table = detectProviderForEmail(a.email);
    final AuthMethod auth;
    if (a.authKind == frb.AuthKind.oAuth) {
      auth = AuthMethod.oauth2;
    } else if (table?.auth == AuthMethod.appPassword ||
        (table?.allowsAppPasswordFallback ?? false)) {
      auth = AuthMethod.appPassword;
    } else {
      auth = AuthMethod.password;
    }
    return Account(
      id: a.email,
      email: a.email,
      displayName: a.displayName.isEmpty ? a.email.split('@').first : a.displayName,
      // Manual/IMAP accounts: the address's domain reads better than the host
      // (which the subtitle shows anyway).
      providerName: table?.displayName ?? (domainOf(a.email) ?? a.imap.host),
      authMethod: auth,
      imapHost: a.imap.host,
      smtpHost: a.smtp.host,
      fingerprint: a.fingerprint,
      createdAt: _utc(a.createdAt),
      login: a.login,
      imapPort: a.imap.port,
      smtpPort: a.smtp.port,
    );
  }

  static ProviderConfig _providerFrom(frb.ServerConfig cfg, String domain) {
    final hint = cfg.authHint;
    final AuthMethod auth;
    OAuthIdp? idp;
    switch (hint.kind) {
      case frb.AuthHintKind.oAuth2:
        if (hint.oauthProvider == frb.OAuthProvider.google) {
          auth = AuthMethod.oauth2;
          idp = OAuthIdp.google;
        } else if (hint.oauthProvider == frb.OAuthProvider.microsoft) {
          auth = AuthMethod.oauth2;
          idp = OAuthIdp.microsoft;
        } else {
          auth = AuthMethod.appPassword;
        }
      case frb.AuthHintKind.appPassword:
        auth = AuthMethod.appPassword;
      case frb.AuthHintKind.password:
        auth = AuthMethod.password;
    }
    final source = switch (cfg.source) {
      frb.ConfigSource.builtIn => 'built-in table',
      frb.ConfigSource.ispdb => 'Mozilla ISPDB',
      frb.ConfigSource.domainAutoconfig => 'the domain\'s autoconfig',
      frb.ConfigSource.srv => 'DNS SRV records',
      frb.ConfigSource.mx => 'the MX record',
      frb.ConfigSource.guess => 'probing common host names',
      frb.ConfigSource.manual => 'manual settings',
    };
    return ProviderConfig(
      id: 'discovered-$domain',
      displayName: cfg.displayName.isEmpty ? domain : cfg.displayName,
      domains: [domain],
      imap: ServerSettings(cfg.imap.host, cfg.imap.port, _security(cfg.imap.security)),
      smtp: ServerSettings(cfg.smtp.host, cfg.smtp.port, _security(cfg.smtp.security)),
      auth: auth,
      oauthIdp: idp,
      helpUrl: hint.helpUrl ?? '',
      appPasswordSteps: hint.kind == frb.AuthHintKind.appPassword
          ? const ['Generate an app password with your provider and paste it below.']
          : const [],
      note: 'Found via $source. Check the servers before you continue.',
    );
  }
}
