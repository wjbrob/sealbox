import 'dart:async';
import 'dart:math';

import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

/// Deterministic [FakeCore] for goldens, accessibility checks and the UX flow.
///
/// It is a subclass, not a wrapper, so every `CoreApi` member the app owner
/// adds to `FakeCore` is inherited unchanged; only what the rendered pixels
/// depend on is overridden:
///
///  * message dates are re-based onto a fixed *local* [anchor] (15 Jun 2026
///    14:05), so the relative times in the inbox ("15 Jun") and the full
///    timestamps in the thread view are identical across runs and time zones;
///  * the identity's creation time and the backup time are fixed;
///  * the guest passphrase comes from a seeded `Random`;
///  * saved drafts are created and updated at [anchor], and search results carry
///    the re-based dates;
///  * [detectGate] / [connectGate] hold `detectProvider` / `addAccount` open,
///    so the "Detecting provider…" and "Connecting…" steps can be captured
///    without leaving a timer pending;
///  * with [syncOnAddAccount] the mailbox fills with the sample threads
///    re-homed to the account just added (what a first sync does) and [send]
///    appends the sent copy to the matching thread — the engine the
///    end-to-end flow test runs against.
class GoldenCore extends FakeCore {
  GoldenCore({
    super.seeded = true,
    super.latency = Duration.zero,
    this.syncOnAddAccount = false,
    this.detectGate,
    this.connectGate,
    this.backupReminder = false,
  }) : _constructedAt = DateTime.now(),
       super(random: Random(7), clock: () => anchor);

  /// Every sample date is expressed relative to this (local) instant.
  static final DateTime anchor = DateTime(2026, 6, 15, 14, 5);
  static final DateTime identityCreatedAt = DateTime(2026, 6, 1, 9, 30);
  static final DateTime backupAt = DateTime(2026, 6, 14, 22, 15);

  /// The sample mailbox's own addresses, replaced when re-homing.
  static const sampleOwnAddresses = {'alice.rivera@gmail.com', 'alice@fastmail.com'};

  final bool syncOnAddAccount;

  /// Report "no backup yet" with the engine's reminder (inbox/settings banner).
  final bool backupReminder;

  /// Fixed time of a simulated key change (thread / contact goldens).
  static final DateTime keyChangedAt = DateTime(2026, 6, 15, 9, 41);
  final Completer<void>? detectGate;
  final Completer<void>? connectGate;

  final DateTime _constructedAt;
  List<MailThread>? _threads;
  bool _backedUp = false;
  int _sent = 0;

  Future<void> _io() =>
      latency == Duration.zero ? Future<void>.value() : Future<void>.delayed(latency);

  // -- live updates ----------------------------------------------------------

  /// IMAP IDLE as the engine does it: one `idle` event once armed, then the stream stays
  /// open until the subscriber cancels. (FakeCore's stream closes right after its event,
  /// which a live-updates watcher reads as a lost session and reconnects.) Captures and the
  /// UX flow with live updates on therefore show a steady "on" and leave no timer behind.
  @override
  Stream<MailEvent> watch(String accountId) {
    late final StreamController<MailEvent> c;
    c = StreamController<MailEvent>(
      onListen: () => c.add(MailEvent(MailEventKind.idle, account: accountId)),
      onCancel: () => c.close(),
    );
    return c.stream;
  }

  // -- identity --------------------------------------------------------------

  @override
  Future<IdentityPreview> myIdentity() async {
    final id = await super.myIdentity();
    return IdentityPreview(
      fingerprint: id.fingerprint,
      createdAt: identityCreatedAt,
      email: id.email,
    );
  }

  // -- accounts --------------------------------------------------------------

  @override
  Future<ProviderDetection> detectProvider(String email) async {
    await detectGate?.future;
    return super.detectProvider(email);
  }

  @override
  Future<Account> addAccount(AccountSetup setup) async {
    await connectGate?.future;
    final account = await super.addAccount(setup);
    if (syncOnAddAccount) {
      final me = Contact(email: account.email, name: account.displayName);
      _threads = [
        ...?_threads,
        ...await _rebasedSample(accountId: account.id, me: me),
      ];
    }
    return account;
  }

  @override
  Future<void> removeAccount(String accountId) async {
    await super.removeAccount(accountId);
    _threads?.removeWhere((t) => t.accountId == accountId);
  }

  // -- mail ------------------------------------------------------------------

  Future<List<MailThread>> _ensureThreads() async =>
      _threads ??= await _rebasedSample();

  @override
  Future<List<MailThread>> listThreads() async {
    await _io();
    final sorted = [...await _ensureThreads()]
      ..sort((a, b) => b.latest.date.compareTo(a.latest.date));
    return List.unmodifiable(sorted);
  }

  @override
  Future<MailThread?> getThread(String threadId) async {
    await _io();
    MailThread? own;
    for (final t in await _ensureThreads()) {
      if (t.id == threadId) own = t;
    }
    final parked = [
      for (final m in await _parkedOf(threadId))
        if (own == null || !own.messages.any((x) => x.id == m.id)) m,
    ];
    if (own == null && parked.isEmpty) {
      // A conversation FakeCore keeps in a folder without a role (its review samples).
      final other = await super.getThread(threadId);
      return other == null ? null : _rebasedThread(other);
    }
    if (parked.isEmpty) return own;
    return MailThread(
      id: threadId,
      subject: own?.subject ?? parked.first.subject,
      accountId: own?.accountId ?? parked.first.accountId,
      messages: [...?own?.messages, ...parked],
    );
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    await _io();
    for (final t in await _ensureThreads()) {
      for (final m in t.messages) {
        if (m.id == messageId) return m;
      }
    }
    // A message FakeCore keeps elsewhere (Spam, Trash, Archive).
    final other = await super.getMessage(messageId);
    return other == null ? null : _rebasedMessage(other);
  }

  @override
  Future<void> markSeen(String messageId, {bool seen = true}) async {
    await _io();
    _rewriteThreadOf(messageId, (t) => [
      for (final m in t.messages)
        if (m.id == messageId) m.copyWith(unread: !seen) else m,
    ]);
    // FakeCore's own copy too: a message parked in Spam / Trash lives only there.
    await super.markSeen(messageId, seen: seen);
  }

  @override
  Future<void> deleteMessage(String messageId) async {
    await _io();
    _rewriteThreadOf(messageId, (t) => [
      for (final m in t.messages)
        if (m.id != messageId) m,
    ]);
    // And FakeCore's un-rebased copy, so a moved message is never found twice.
    await super.deleteMessage(messageId);
  }

  // -- search: FakeCore also searches its parked (wall-clock dated) copies; show them
  // re-based, and order equal ranks newest first by the dates the rows show.

  @override
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) async {
    final results = [
      for (final r in await super.search(text, accountId: accountId, folder: folder, limit: limit))
        SearchResult(message: _rebasedMessage(r.message), snippet: r.snippet, rank: r.rank),
    ];
    results.sort((a, b) {
      final byRank = b.rank.compareTo(a.rank);
      return byRank != 0 ? byRank : b.message.date.compareTo(a.message.date);
    });
    return results;
  }

  // -- folders by role: FakeCore parks moved / junk messages itself (with wall-clock
  // dates); serve them re-based like the inbox, and mirror moves back into it.

  /// Not re-based yet: FakeCore's seed dates are "now" minus minutes, the anchor
  /// lies months before any run of these tests.
  bool _raw(Message m) => m.date.isAfter(anchor.add(const Duration(days: 30)));

  Message _rebasedMessage(Message m) => !_raw(m)
      ? m
      : _copy(
          m,
          accountId: m.accountId,
          from: m.from,
          to: m.to,
          cc: m.cc,
          date: anchor.subtract(
            Duration(minutes: (_constructedAt.difference(m.date).inMilliseconds / 60000).round()),
          ),
        );

  MailThread _rebasedThread(MailThread t) => MailThread(
    id: t.id,
    subject: t.subject,
    accountId: t.accountId,
    messages: [for (final m in t.messages) _rebasedMessage(m)],
  );

  // FakeCore sorts before these dates are re-based (its parked seeds carry wall-clock dates),
  // so sort again: newest first by the dates the rows show.
  static List<MailThread> _newestFirst(Iterable<MailThread> threads) =>
      List.unmodifiable([...threads]..sort((a, b) => b.latest.date.compareTo(a.latest.date)));

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) async =>
      _newestFirst([
        for (final t in await super.listThreadsInRole(role, accountId: accountId)) _rebasedThread(t),
      ]);

  @override
  Future<List<MailThread>> listThreadsIn(MailFolder folder) async => _newestFirst([
    for (final t in await super.listThreadsIn(folder)) _rebasedThread(t),
  ]);

  /// Every message of the conversation that FakeCore keeps outside the inbox
  /// copy (Spam, Trash, Archive …).
  Future<List<Message>> _parkedOf(String threadId) async {
    final out = <Message>[];
    for (final role in const [FolderRole.junk, FolderRole.trash, FolderRole.archive, FolderRole.drafts]) {
      for (final t in await super.listThreadsInRole(role)) {
        if (t.id != threadId) continue;
        for (final m in t.messages) {
          if (!out.any((x) => x.id == m.id)) out.add(_rebasedMessage(m));
        }
      }
    }
    return out;
  }

  @override
  Future<MoveResult> moveMessage(String messageId, FolderRole role) async {
    final r = await super.moveMessage(messageId, role);
    if (r.moved && (role == FolderRole.inbox || role == FolderRole.sent)) {
      // FakeCore put it into its own inbox list; this class serves its re-based copy.
      final moved = await super.getMessage(messageId);
      if (moved != null) {
        final m = _rebasedMessage(moved);
        final threads = await _ensureThreads();
        final i = threads.indexWhere((t) => t.id == m.threadId);
        if (i >= 0) {
          final t = threads[i];
          threads[i] = MailThread(
            id: t.id,
            subject: t.subject,
            accountId: t.accountId,
            messages: [...t.messages.where((x) => x.id != m.id), m],
          );
        } else {
          threads.add(MailThread(id: m.threadId, subject: m.subject, accountId: m.accountId, messages: [m]));
        }
      }
    }
    return r;
  }

  void _rewriteThreadOf(String messageId, List<Message> Function(MailThread) messages) {
    final threads = _threads;
    if (threads == null) return;
    for (var i = 0; i < threads.length; i++) {
      final t = threads[i];
      if (!t.messages.any((m) => m.id == messageId)) continue;
      final rest = messages(t);
      if (rest.isEmpty) {
        threads.removeAt(i);
      } else {
        threads[i] = MailThread(
          id: t.id,
          subject: t.subject,
          accountId: t.accountId,
          messages: rest,
        );
      }
      return;
    }
  }

  /// Delegates the policy decision to [FakeCore.send], then appends the sent
  /// copy to the thread whose subject the draft replies to (so the flow test
  /// can see "the Sent copy" like a real sync would show it).
  @override
  Future<SendReceipt> send(DraftMessage draft) async {
    final receipt = await super.send(draft);
    final threads = await _ensureThreads();
    final subject = draft.subject.trim().toLowerCase();
    final i = threads.indexWhere(
      (t) =>
          t.accountId == draft.accountId &&
          (t.subject.toLowerCase() == subject ||
              're: ${t.subject.toLowerCase()}' == subject),
    );
    if (i < 0) return receipt;
    final accounts = await super.listAccounts();
    final account = accounts.firstWhere(
      (a) => a.id == draft.accountId,
      orElse: () => accounts.first,
    );
    final n = ++_sent;
    final old = threads[i];
    threads[i] = MailThread(
      id: old.id,
      subject: old.subject,
      accountId: old.accountId,
      messages: [
        ...old.messages,
        Message(
          id: 'sent-$n',
          threadId: old.id,
          accountId: old.accountId,
          from: Contact(email: account.email, name: account.displayName),
          to: [for (final e in draft.to) Contact(email: e)],
          subject: draft.subject,
          body: draft.body,
          date: anchor.add(Duration(minutes: n)),
          state: receipt.plaintextTo.isNotEmpty
              ? EncryptionState.plaintext
              : EncryptionState.encrypted,
          folder: 'Sent',
          messageId: 'sent-$n@sealbox.test',
          guestLink: receipt.guestLinkTo.isNotEmpty,
        ),
      ],
    );
    return receipt;
  }

  // -- compose preview -------------------------------------------------------

  static final _utcStamp = RegExp(
    r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
    r'(\d{4}) (\d\d):(\d\d):(\d\d) \+0000',
  );
  static const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  static const _days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  /// FakeCore writes quote / forward headers in UTC; the anchor is local time, so
  /// the goldens would depend on the host's time zone. Show them in local time.
  @override
  Future<ComposePreview> composePreview(DraftMessage draft) async {
    final p = await super.composePreview(draft);
    String two(int n) => n.toString().padLeft(2, '0');
    final text = p.text.replaceAllMapped(_utcStamp, (m) {
      final utc = DateTime.utc(
        int.parse(m[4]!),
        _months.indexOf(m[3]!) + 1,
        int.parse(m[2]!),
        int.parse(m[5]!),
        int.parse(m[6]!),
        int.parse(m[7]!),
      );
      final l = utc.toLocal();
      return '${_days[l.weekday - 1]}, ${l.day} ${_months[l.month - 1]} ${l.year} '
          '${two(l.hour)}:${two(l.minute)}';
    });
    return ComposePreview(
      kind: p.kind,
      text: text,
      html: p.html,
      signatureApplied: p.signatureApplied,
      forwardedAttachments: p.forwardedAttachments,
    );
  }

  // -- backup ----------------------------------------------------------------

  @override
  Future<BackupStatus> backupStatus() async {
    await _io();
    final accounts = await super.listAccounts();
    final account = accounts.isEmpty ? null : accounts.first.id;
    return _backedUp
        ? BackupStatus(
            backedUp: true,
            lastBackup: backupAt,
            accountId: account,
            serverUrl: configuredServer,
            phraseCreatedAt: backupAt,
          )
        : BackupStatus(
            backedUp: false,
            accountId: account,
            reminder: backupReminder && account != null ? 'no backup yet' : null,
          );
  }

  @override
  Future<BackupStatus> recoveryStatus(String accountId) => backupStatus();

  @override
  Future<BackupStatus> backupToServer(String accountId, String serverUrl, String phrase) async {
    await super.backupToServer(accountId, serverUrl, phrase);
    _backedUp = true;
    return backupStatus();
  }

  // -- identity ----------------------------------------------------------------

  /// [FakeCore.simulateKeyChange] at the fixed [keyChangedAt], also marking
  /// the message in the re-based copy this class serves.
  @override
  void simulateKeyChange(String address, {String? messageId, DateTime? at}) =>
      super.simulateKeyChange(address, messageId: messageId, at: at ?? keyChangedAt);

  final _keyChanged = <String, String?>{};
  final _signerVerifiedIds = <String>{};

  @override
  void markKeyChanged(String messageId, {String? signer}) {
    super.markKeyChanged(messageId, signer: signer);
    _keyChanged[messageId] = signer;
    _rewriteThreadOf(messageId, (t) => [
      for (final m in t.messages)
        if (m.id == messageId)
          m.copyWith(keyChanged: true, signer: m.signer == null ? null : signer)
        else
          m,
    ]);
  }

  /// Mark a message as signed by the verified key (thread goldens).
  @override
  void markSignerVerified(String messageId) {
    super.markSignerVerified(messageId);
    _signerVerifiedIds.add(messageId);
    _rewriteThreadOf(messageId, (t) => [
      for (final m in t.messages)
        if (m.id == messageId) m.copyWith(signerVerified: true) else m,
    ]);
  }

  @override
  Future<BackupStatus> backupNow() async {
    _backedUp = true;
    return backupStatus();
  }

  // -- sample data, re-based onto the fixed anchor ---------------------------

  /// The [FakeCore] sample threads with every date moved so that "now" at
  /// seeding time becomes [anchor]. The sample's offsets are whole minutes, so
  /// rounding to the minute removes the milliseconds between the two
  /// `DateTime.now()` calls. With [accountId]/[me] the threads are re-homed
  /// to another account (the flow test's freshly added one).
  Future<List<MailThread>> _rebasedSample({String? accountId, Contact? me}) async {
    final List<MailThread> raw;
    final DateTime seededAt;
    if (accountId == null) {
      raw = await super.listThreads();
      seededAt = _constructedAt;
    } else {
      seededAt = DateTime.now();
      raw = await FakeCore(latency: Duration.zero, random: Random(7)).listThreads();
    }

    Contact map(Contact c) =>
        me != null && sampleOwnAddresses.contains(c.email.toLowerCase()) ? me : c;
    DateTime rebase(DateTime d) => anchor.subtract(
      Duration(minutes: (seededAt.difference(d).inMilliseconds / 60000).round()),
    );

    return [
      for (final t in raw)
        MailThread(
          id: t.id,
          subject: t.subject,
          accountId: accountId ?? t.accountId,
          messages: [
            for (final m in t.messages)
              _copy(
                m,
                accountId: accountId ?? m.accountId,
                from: map(m.from),
                to: [for (final c in m.to) map(c)],
                cc: [for (final c in m.cc) map(c)],
                date: rebase(m.date),
              ).copyWith(
                keyChanged: m.keyChanged || _keyChanged.containsKey(m.id),
                signer: m.signer == null ? null : _keyChanged[m.id],
                signerVerified: m.signerVerified || _signerVerifiedIds.contains(m.id),
              ),
          ],
        ),
    ];
  }

  /// Field-complete copy (`Message.copyWith` only covers body / unread /
  /// attachments). Keep in step with `Message` in lib/src/core/models.dart:
  /// a field left out here would silently vanish from the goldens.
  static Message _copy(
    Message m, {
    required String accountId,
    required Contact from,
    required List<Contact> to,
    required List<Contact> cc,
    required DateTime date,
  }) => Message(
    id: m.id,
    threadId: m.threadId,
    accountId: accountId,
    from: from,
    to: to,
    cc: cc,
    subject: m.subject,
    body: m.body,
    date: date,
    state: m.state,
    signer: m.signer,
    unread: m.unread,
    folder: m.folder,
    uid: m.uid,
    signatureState: m.signatureState,
    attachments: m.attachments,
    decryptError: m.decryptError,
    messageId: m.messageId,
    keyChanged: m.keyChanged,
    signerVerified: m.signerVerified,
    guestLink: m.guestLink,
    inReplyTo: m.inReplyTo,
    references: m.references,
    engineThreadId: m.engineThreadId,
    signerAddress: m.signerAddress,
    protectedSubject: m.protectedSubject,
    engineSnippet: m.engineSnippet,
  );
}
