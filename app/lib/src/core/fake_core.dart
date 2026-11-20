import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import '../providers/provider_table.dart';
import 'core_api.dart';
import 'errors.dart';
import 'models.dart';

/// One engine send of [FakeCore.send] (a `send_with` call of `FrbCore.send`): who it was
/// addressed to, with which policy, and whether it went out ([FakeCore.failSendPolicy],
/// [FakeCore.failSendTo]).
class FakeSendWithCall {
  const FakeSendWithCall({
    required this.to,
    required this.cc,
    required this.policy,
    required this.delivered,
  });

  final List<String> to;
  final List<String> cc;
  final SendPolicy policy;
  final bool delivered;

  /// To and Cc.
  List<String> get recipients => [...to, ...cc];

  /// `auto → bob@sealbox.test`, `guestLink → dana@example.org (failed)`.
  @override
  String toString() => '${policy.name} → ${recipients.join(', ')}${delivered ? '' : ' (failed)'}';
}

/// In-memory `CoreApi` with realistic sample data.
///
/// Used by widget tests (`latency: Duration.zero`) and for design review without
/// a mail server. The real engine is `FrbCore`. Deterministic apart from the
/// guest passphrase.
///
/// Beyond the inbox it fakes the UI-wave APIs: a Spam folder holding one prize
/// scam with a spam explanation ([junkSampleId]), two filter rules on the first
/// account, moves that relocate messages between folders (Gmail folder names on
/// the gmail.com account, generic ones elsewhere), a compose preview that adds
/// quote and signature like the engine, a key-directory status that walks
/// unpublished → awaiting verification → published, and a settable server URL.
/// Search matches substrings of the sample messages (every word must match) and
/// marks them in the snippet like the engine; drafts live in memory, attachment
/// copies too, under handles like the engine's stored copies (`blob:<n>`).
class FakeCore
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
  FakeCore({
    this.latency = const Duration(milliseconds: 400),
    bool seeded = true,
    Random? random,
    DateTime Function()? clock,
  }) : _random = random ?? Random.secure(),
       clock = clock ?? DateTime.now {
    if (seeded) {
      _accounts.addAll(_seedAccounts());
      _threads.addAll(_seedThreads());
      _parked.addAll(_seedParked());
      _rules['acct-1'] = [..._seedRules()];
      _storedSpam[junkSampleId] = SpamLabel.spam;
    }
  }

  /// Simulated I/O delay so spinners are visible in the demo.
  final Duration latency;
  final Random _random;

  /// When drafts are created / updated (goldens pin it).
  final DateTime Function() clock;

  final List<Account> _accounts = [];
  final List<MailThread> _threads = [];
  BackupStatus _backup = const BackupStatus(backedUp: false);
  int _nextId = 100;

  /// Addresses whose keys "we already know" (Autocrypt / directory / WKD).
  static const Map<String, RecipientKeyInfo> knownKeys = {
    'bob@sealbox.test': RecipientKeyInfo(
      email: 'bob@sealbox.test',
      hasKey: true,
      source: KeySource.autocrypt,
      fingerprint: '9F4B2E1C7A5D30186B2F4E9C1D7A3B5F0E6C8D2A',
    ),
    'carol@proton.me': RecipientKeyInfo(
      email: 'carol@proton.me',
      hasKey: true,
      source: KeySource.directory,
      fingerprint: '2C7D9A1F4E6B8035C1D2E3F4A5B6C7D8E9F0A1B2',
    ),
    'erik@posteo.de': RecipientKeyInfo(
      email: 'erik@posteo.de',
      hasKey: true,
      source: KeySource.wkd,
      fingerprint: '7E1A3C5B9D2F4068A1B3C5D7E9F0A2B4C6D8E0F1',
    ),
    'heidi@delta.chat': RecipientKeyInfo(
      email: 'heidi@delta.chat',
      hasKey: true,
      source: KeySource.autocrypt,
      fingerprint: '4D8F2A6C0E1B3579B2C4D6E8F0A1B3C5D7E9F1A3',
    ),
    'grace@fairemail.test': RecipientKeyInfo(
      email: 'grace@fairemail.test',
      hasKey: true,
      source: KeySource.keyserver,
      fingerprint: 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
    ),
  };

  static const _myFingerprint = '3A9F1C2B4D5E6F708192A3B4C5D6E7F809A1B2C3';

  /// Keys added through [importPeerKey] in this session.
  final Map<String, RecipientKeyInfo> _imported = {};

  Future<void> _io() =>
      latency == Duration.zero ? Future.value() : Future.delayed(latency);

  // -- bridge smoke tests ----------------------------------------------------

  @override
  Future<String> version() async => '0.0.0-fake';

  @override
  Future<String> greet(String name) async => 'Hello, $name! (FakeCore)';

  // -- identity / keys -------------------------------------------------------

  @override
  Future<IdentityPreview> generateIdentityPreview({
    required String name,
    required String email,
  }) async {
    await _io();
    // Not a real key: a deterministic 40-hex string derived from the input.
    final seed = '$name <$email>'.codeUnits.fold<int>(17, (h, c) => h * 31 + c);
    final r = Random(seed);
    final hex = List.generate(40, (_) => r.nextInt(16).toRadixString(16))
        .join()
        .toUpperCase();
    return IdentityPreview(fingerprint: hex, createdAt: DateTime.now().toUtc());
  }

  @override
  Future<IdentityPreview> myIdentity() async {
    await _io();
    return IdentityPreview(
      fingerprint: _myFingerprint,
      createdAt: DateTime.utc(2026, 10, 1, 9, 30),
      email: _accounts.isEmpty ? null : _accounts.first.email,
    );
  }

  @override
  Future<RecipientKeyInfo> lookupRecipientKey(String email) async {
    await _io();
    final e = email.trim().toLowerCase();
    return knownKeys[e] ?? _imported[e] ?? RecipientKeyInfo.unknown(email.trim());
  }

  @override
  Future<List<ContactKey>> contacts() async {
    await _io();
    return [
      for (final k in [...knownKeys.values, ..._imported.values]) _contactFor(k.email)!,
    ];
  }

  // -- identity (G30) ----------------------------------------------------------

  /// Per-address identity state layered over [knownKeys] / imported keys.
  final Map<String, ContactKey> _identity = {};

  /// The configured server for key transparency, backups and guest links;
  /// null simulates a build without one.
  String? configuredServer = 'https://sealbox.example';

  /// What [ktAudit] reports (the review tour and goldens pick a state).
  KtState ktState = KtState.verified;

  ContactKey? _contactFor(String address) {
    final e = address.trim().toLowerCase();
    final state = _identity[e];
    if (state != null) return state;
    final k = knownKeys[e] ?? _imported[e];
    if (k == null) return null;
    return ContactKey(
      address: k.email,
      hasKey: k.hasKey,
      source: k.source ?? KeySource.imported,
      fingerprint: k.fingerprint,
      preferEncrypt: k.source == KeySource.autocrypt,
    );
  }

  ContactKey _requireContact(String address) =>
      _contactFor(address) ?? (throw ArgumentError('no contact $address'));

  /// Simulate what the engine does when mail from [address] arrives with a
  /// different key: the contact is flagged (previous key remembered, not
  /// verified any more) and, with [messageId], that message carries
  /// `key_changed`. Used by the review tour and the goldens (the real loop
  /// cannot provoke a key change).
  void simulateKeyChange(String address, {String? messageId, DateTime? at}) {
    final c = _requireContact(address);
    final seed = c.address.codeUnits.fold<int>(11, (h, x) => h * 31 + x);
    final r = Random(seed);
    final fresh = List.generate(40, (_) => r.nextInt(16).toRadixString(16)).join().toUpperCase();
    _identity[c.address.toLowerCase()] = ContactKey(
      address: c.address,
      hasKey: true,
      source: KeySource.autocrypt,
      fingerprint: fresh,
      preferEncrypt: c.preferEncrypt,
      lastSeen: c.lastSeen,
      keyChangedAt: at ?? DateTime.now(),
      previousFingerprint: c.fingerprint,
    );
    if (messageId != null) markKeyChanged(messageId, signer: fresh);
  }

  /// Set `key_changed` on one stored message (see [simulateKeyChange]); a
  /// signed message then carries the new key's fingerprint as its signer.
  void markKeyChanged(String messageId, {String? signer}) {
    for (var i = 0; i < _threads.length; i++) {
      final t = _threads[i];
      if (!t.messages.any((m) => m.id == messageId)) continue;
      _threads[i] = MailThread(
        id: t.id,
        subject: t.subject,
        accountId: t.accountId,
        messages: [
          for (final m in t.messages)
            if (m.id == messageId)
              m.copyWith(keyChanged: true, signer: m.signer == null ? null : signer)
            else
              m,
        ],
      );
    }
  }

  /// Set `signer_verified` on one stored message (test / review setup).
  void markSignerVerified(String messageId) {
    for (var i = 0; i < _threads.length; i++) {
      final t = _threads[i];
      if (!t.messages.any((m) => m.id == messageId)) continue;
      _threads[i] = MailThread(
        id: t.id,
        subject: t.subject,
        accountId: t.accountId,
        messages: [
          for (final m in t.messages)
            if (m.id == messageId) m.copyWith(signerVerified: true) else m,
        ],
      );
    }
  }

  /// Mark [address] verified without going through the screen (test setup).
  void simulateVerified(String address, {DateTime? at}) {
    final c = _requireContact(address);
    _identity[c.address.toLowerCase()] = c.copyWith(
      verified: true,
      verifiedAt: at ?? DateTime.now(),
      clearKeyChange: true,
    );
  }

  static String _hex(String s) => s.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '').toUpperCase();

  @override
  Future<ContactKey> verifyContact(String address, String fingerprint) async {
    await _io();
    final c = _requireContact(address);
    var given = fingerprint.trim();
    if (given.toUpperCase().startsWith('OPENPGP4FPR:')) given = await parseFingerprintQr(given);
    if (_hex(given) != _hex(c.fingerprint ?? '')) {
      throw ArgumentError(
        'invalid input: fingerprint mismatch: ${_hex(given)} is not the current key of ${c.address}',
      );
    }
    final v = c.copyWith(verified: true, verifiedAt: DateTime.now(), clearKeyChange: true);
    _identity[c.address.toLowerCase()] = v;
    return v;
  }

  @override
  Future<ContactKey> unverifyContact(String address) async {
    await _io();
    final c = _requireContact(address);
    final v = c.copyWith(verified: false, clearVerifiedAt: true);
    _identity[c.address.toLowerCase()] = v;
    return v;
  }

  @override
  Future<ContactKey> acknowledgeKeyChange(String address) async {
    await _io();
    final c = _requireContact(address);
    final v = c.copyWith(clearKeyChange: true);
    _identity[c.address.toLowerCase()] = v;
    return v;
  }

  @override
  Future<String> fingerprintQrPayload(String accountId) async {
    await _io();
    return 'OPENPGP4FPR:$_myFingerprint';
  }

  @override
  Future<String> parseFingerprintQr(String payload) async {
    final m = RegExp(r'^openpgp4fpr:([0-9a-f]{40}|[0-9a-f]{64})(#.*)?$', caseSensitive: false)
        .firstMatch(payload.trim());
    if (m == null) throw ArgumentError('invalid input: not an OPENPGP4FPR: payload');
    return m.group(1)!.toUpperCase();
  }

  @override
  Future<KtAudit> ktAudit(String accountId) async {
    await _io();
    if (configuredServer == null) return KtAudit(state: KtState.noServer, accountId: accountId);
    return switch (ktState) {
      KtState.verified => KtAudit.fromReport(
        accountId: accountId,
        logSize: 42,
        sthVerified: true,
        ownKeyIncluded: true,
        consistencyOk: true,
        alerts: const [],
      ),
      KtState.alert => KtAudit.fromReport(
        accountId: accountId,
        logSize: 43,
        sthVerified: true,
        ownKeyIncluded: false,
        consistencyOk: true,
        alerts: [
          'SUBSTITUTION: ${_emailOf(accountId)} published with key 0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD, '
              'expected $_myFingerprint',
        ],
      ),
      KtState.unreachable => KtAudit(
        state: KtState.unreachable,
        accountId: accountId,
        error: 'connection error: https://sealbox.example: connection refused',
      ),
      final s => KtAudit(state: s, accountId: accountId),
    };
  }

  String _emailOf(String accountId) =>
      _accounts.where((a) => a.id == accountId).firstOrNull?.email ?? accountId;

  // -- recovery (G15) ----------------------------------------------------------

  /// A valid BIP39 phrase (the reference vector) the fake accepts for restore.
  static const samplePhrase = [
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'about',
  ];

  /// The phrase [recoveryPhraseCreate] hands out (real BIP39 words).
  static const createdPhrase = [
    'orbit', 'velvet', 'harbor', 'copper', 'lantern', 'meadow',
    'quartz', 'timber', 'willow', 'anchor', 'basil', 'glacier',
  ];

  static final _fakeWordList = {...samplePhrase, ...createdPhrase, 'zoo', 'wrong', 'abstract'};

  DateTime? _phraseCreatedAt;

  @override
  Future<String?> serverUrl() async => configuredServer;

  @override
  Future<List<String>> recoveryPhraseCreate(String accountId) async {
    await _io();
    _phraseCreatedAt = DateTime.now();
    return createdPhrase;
  }

  @override
  Future<PhraseCheck> recoveryPhraseValidate(String words) async {
    final tokens = words
        .toLowerCase()
        .split(RegExp(r'[^a-z]+'))
        .where((t) => t.isNotEmpty)
        .toList();
    if (tokens.length != 12) {
      throw ArgumentError(
        'invalid input: a recovery phrase has 12 words; got ${tokens.length}',
      );
    }
    for (var i = 0; i < tokens.length; i++) {
      if (!_fakeWordList.contains(tokens[i])) {
        throw ArgumentError(
          'invalid input: word ${i + 1} of the recovery phrase is not in the word list',
        );
      }
    }
    final ok = _same(tokens, samplePhrase) || _same(tokens, createdPhrase);
    return PhraseCheck(words: tokens, checksumOk: ok);
  }

  static bool _same(List<String> a, List<String> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  Future<BackupStatus> backupToServer(String accountId, String serverUrl, String phrase) async {
    await _io();
    final check = await recoveryPhraseValidate(phrase);
    if (!check.checksumOk) {
      throw ArgumentError(
        'invalid input: the recovery phrase checksum does not match: a word is wrong or two '
        'words are swapped',
      );
    }
    _backup = BackupStatus(
      backedUp: true,
      lastBackup: DateTime.now(),
      accountId: accountId,
      serverUrl: serverUrl,
      bytes: 3712,
      phraseCreatedAt: _phraseCreatedAt,
    );
    return _backup;
  }

  @override
  Future<BackupStatus> recoveryStatus(String accountId) async {
    await _io();
    return _withReminder(_backup, accountId: accountId);
  }

  BackupStatus _withReminder(BackupStatus b, {String? accountId}) => b.backedUp
      ? b
      : BackupStatus(
          backedUp: false,
          accountId: accountId ?? (_accounts.isEmpty ? null : _accounts.first.email),
          phraseCreatedAt: _phraseCreatedAt,
          reminder: _accounts.isEmpty ? null : 'no backup yet',
        );

  @override
  Future<Account> restoreFromServer(
    String serverUrl,
    String email,
    String phrase, {
    String? password,
  }) async {
    await _io();
    final check = await recoveryPhraseValidate(phrase);
    if (!check.checksumOk) {
      throw ArgumentError(
        'invalid input: the recovery phrase checksum does not match: a word is wrong or two '
        'words are swapped',
      );
    }
    final e = email.trim().toLowerCase();
    if (e.startsWith('nobackup')) {
      throw ArgumentError('invalid input: no backup for $e on $serverUrl (tried 3A9F…)');
    }
    if (!_same(check.words, samplePhrase)) {
      throw StateError(
        'connection error: the backup server refused the recovery token (401): wrong recovery '
        'phrase for this address',
      );
    }
    final detection = detectProviderForEmail(e);
    final account = Account(
      id: e,
      email: e,
      displayName: e.split('@').first,
      providerName: detection?.displayName ?? (domainOf(e) ?? e),
      authMethod: AuthMethod.appPassword,
      imapHost: detection?.imap.host ?? 'imap.${domainOf(e)}',
      smtpHost: detection?.smtp.host ?? 'smtp.${domainOf(e)}',
      fingerprint: _myFingerprint,
    );
    _accounts.removeWhere((a) => a.email == e);
    _accounts.add(account);
    return account;
  }

  @override
  Future<Account> setAccountCredential(String email, String password) async {
    await _io();
    if (password.trim().isEmpty) throw ArgumentError('a password is required');
    return _accounts.firstWhere(
      (a) => a.email.toLowerCase() == email.trim().toLowerCase(),
      orElse: () => throw ArgumentError('account not found: $email'),
    );
  }

  @override
  Future<SetupExportResult> setupMessageExport(String accountId) async {
    await _io();
    return const SetupExportResult(
      setupCode: '1742-0398-5521-8806-3317-9045-6620-1189-4473',
      messageId: 'setup.7f3a@sealbox.example',
    );
  }

  @override
  Future<Account> setupMessageImport(String source, String setupCode) async {
    await _io();
    final digits = setupCode.replaceAll(RegExp(r'[^0-9]'), '');
    if (digits.length != 36) {
      throw ArgumentError('invalid input: wrong setup code or damaged setup message');
    }
    if (_accounts.isEmpty) throw ArgumentError('add the account first');
    return _accounts.first;
  }

  final List<String> resent = [];

  @override
  Future<void> resendGuestLink(String messageId) async {
    await _io();
    resent.add(messageId);
  }

  @override
  Future<String> exportPublicKey(String accountId) async {
    await _io();
    return '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'
        'FakeCore key for $accountId (not a real key)\n'
        '-----END PGP PUBLIC KEY BLOCK-----\n';
  }

  @override
  Future<ContactKey> importPeerKey(String address, String armored) async {
    await _io();
    if (!armored.contains('BEGIN PGP PUBLIC KEY BLOCK')) {
      throw ArgumentError('not an armored OpenPGP public key');
    }
    final e = address.trim().toLowerCase();
    final seed = e.codeUnits.fold<int>(5, (h, c) => h * 31 + c);
    final r = Random(seed);
    final fp = List.generate(40, (_) => r.nextInt(16).toRadixString(16))
        .join()
        .toUpperCase();
    _imported[e] = RecipientKeyInfo(
      email: e,
      hasKey: true,
      source: KeySource.imported,
      fingerprint: fp,
    );
    return ContactKey(address: e, hasKey: true, source: KeySource.imported, fingerprint: fp);
  }

  static const _words = [
    'harbor', 'copper', 'lantern', 'meadow', 'quartz', 'saffron', 'timber',
    'velvet', 'willow', 'zephyr', 'anchor', 'basil', 'cobalt', 'dune',
    'ember', 'falcon', 'glacier', 'heron', 'indigo', 'juniper', 'kestrel',
    'lagoon', 'marble', 'nectar', 'orchid', 'pebble', 'raven', 'summit',
  ];

  @override
  Future<String> generateGuestPassphrase() async {
    return List.generate(
      5,
      (_) => _words[_random.nextInt(_words.length)],
    ).join('-');
  }

  // -- accounts --------------------------------------------------------------

  @override
  Future<ProviderDetection> detectProvider(String email) async {
    await _io();
    await holdDetect?.future;
    return ProviderDetection(
      domain: domainOf(email) ?? '',
      provider: detectProviderForEmail(email),
    );
  }

  @override
  Future<List<Account>> listAccounts() async {
    await _io();
    return List.unmodifiable(_accounts);
  }

  /// Review hooks (review P5): while set, [detectProvider] answers only once [holdDetect]
  /// completes and [addAccount] only once [holdConnect] does (a gate completed with an
  /// error fails the call with it: a refused connection), so the review tour can capture
  /// the transient "Detecting provider…" / "Connecting to …" states. Null: no wait.
  Completer<void>? holdDetect;
  Completer<void>? holdConnect;

  @override
  Future<Account> addAccount(AccountSetup setup) async {
    await _io();
    await holdConnect?.future;
    final account = Account(
      id: 'acct-${_nextId++}',
      email: setup.email,
      displayName: setup.displayName.isEmpty
          ? setup.email.split('@').first
          : setup.displayName,
      providerName: setup.providerName ?? setup.imap.host,
      authMethod: setup.authMethod,
      imapHost: setup.imap.host,
      smtpHost: setup.smtp.host,
    );
    _accounts.add(account);
    return account;
  }

  @override
  Future<void> removeAccount(String accountId) async {
    await _io();
    _accounts.removeWhere((a) => a.id == accountId);
    _threads.removeWhere((t) => t.accountId == accountId);
  }

  // -- mail ------------------------------------------------------------------

  @override
  Future<List<MailThread>> listThreads() async {
    await _io();
    final sorted = [..._threads]
      ..sort((a, b) => b.latest.date.compareTo(a.latest.date));
    return List.unmodifiable(sorted);
  }

  @override
  Future<List<MailThread>> listThreadsIn(MailFolder folder) async {
    final all = await listThreads();
    return _withParked([
      for (final t in all)
        if (t.messages.any((m) => folder.matches(m.folder))) t,
    ], folder.matches);
  }

  @override
  Future<MailThread?> getThread(String threadId) async {
    await _io();
    MailThread? base;
    for (final t in _threads) {
      if (t.id == threadId) {
        base = t;
        break;
      }
    }
    final parked = [
      for (final m in _parked)
        if (m.threadId == threadId) m,
    ];
    if (parked.isEmpty) return base;
    return base == null ? _threadOf(parked) : _merged(base, parked);
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    await _io();
    for (final t in _threads) {
      for (final m in t.messages) {
        if (m.id == messageId) return m;
      }
    }
    return _parkedMessage(messageId);
  }

  @override
  Future<HtmlBody?> messageHtml(String messageId, {bool allowRemote = false}) async {
    await _io();
    if (messageId != htmlSampleId) return null;
    return HtmlBody(
      html: allowRemote ? _htmlSampleLoaded : _htmlSampleBlocked,
      remoteImages: 2,
      text: _htmlSampleText,
    );
  }

  @override
  Future<AttachmentBytes> getAttachment(String messageId, int index) async {
    await _io();
    final m = await getMessage(messageId);
    final meta = m?.attachments.where((a) => a.index == index).firstOrNull;
    if (meta == null) throw StateError('no attachment $index on $messageId');
    return AttachmentBytes(meta: meta, data: Uint8List(meta.size));
  }

  @override
  Future<SyncOutcome> syncAll() async {
    await _io();
    return SyncOutcome([
      for (final a in _accounts) AccountSyncOutcome(account: a.email),
    ]);
  }

  /// Test hooks for [syncAccount] / [backfill]. When set, the stream the hook returns is the
  /// run: the test adds the [SyncEvent.progress] events and the final [SyncEvent.done] (or
  /// an error) itself, e.g. through a `StreamController`. Null: a run that stores nothing
  /// and finishes after [latency] with an empty outcome (nothing left to backfill).
  Stream<SyncEvent> Function(String accountId)? syncScript;
  Stream<SyncEvent> Function(String accountId, int? max)? backfillScript;

  /// Every [syncAccount] (`sync <id>`) and [backfill] (`backfill <id> <max|all>`) call, in
  /// order.
  final List<String> syncRuns = [];

  @override
  Stream<SyncEvent> syncAccount(String accountId) {
    syncRuns.add('sync $accountId');
    return syncScript?.call(accountId) ?? _emptyRun(accountId);
  }

  @override
  Stream<SyncEvent> backfill(String accountId, {int? max}) {
    syncRuns.add('backfill $accountId ${max ?? 'all'}');
    return backfillScript?.call(accountId, max) ?? _emptyRun(accountId);
  }

  Stream<SyncEvent> _emptyRun(String accountId) => Stream.fromFuture(() async {
    await _io();
    final email = _accounts.where((a) => a.id == accountId).firstOrNull?.email ?? accountId;
    return SyncEvent.done(AccountSyncOutcome(account: email));
  }());

  @override
  /// IMAP IDLE as the engine does it: one `idle` event once armed, then the stream stays
  /// open until the subscriber cancels — a stream that closed right after its event reads
  /// as a lost session to a live-updates watcher, which would reconnect forever.
  Stream<MailEvent> watch(String accountId) {
    late final StreamController<MailEvent> c;
    c = StreamController<MailEvent>(
      onListen: () => c.add(MailEvent(MailEventKind.idle, account: accountId)),
      onCancel: () => c.close(),
    );
    return c.stream;
  }

  @override
  Future<void> markSeen(String messageId, {bool seen = true}) async {
    await _io();
    for (var i = 0; i < _threads.length; i++) {
      final t = _threads[i];
      if (!t.messages.any((m) => m.id == messageId)) continue;
      _threads[i] = MailThread(
        id: t.id,
        subject: t.subject,
        accountId: t.accountId,
        messages: [
          for (final m in t.messages)
            if (m.id == messageId) m.copyWith(unread: !seen) else m,
        ],
      );
      return;
    }
    final i = _parked.indexWhere((m) => m.id == messageId);
    if (i >= 0) _parked[i] = _parked[i].copyWith(unread: !seen);
  }

  @override
  Future<void> deleteMessage(String messageId) async {
    await _io();
    for (var i = _threads.length - 1; i >= 0; i--) {
      final t = _threads[i];
      if (!t.messages.any((m) => m.id == messageId)) continue;
      final rest = [
        for (final m in t.messages)
          if (m.id != messageId) m,
      ];
      if (rest.isEmpty) {
        _threads.removeAt(i);
      } else {
        _threads[i] = MailThread(
          id: t.id,
          subject: t.subject,
          accountId: t.accountId,
          messages: rest,
        );
      }
      return;
    }
    _parked.removeWhere((m) => m.id == messageId);
  }

  /// Every message [send] sent in full, oldest first (tests read what went out; a message
  /// that went out in part is in [sendWithCalls]).
  final List<DraftMessage> sentMessages = [];

  /// Every engine send [send] made, oldest first. Like `FrbCore.send`, one message goes out
  /// as up to three: to the recipients with a key, to those without (a guest link; one per
  /// recipient for [GuestMode.emailCode]), then to those the user confirmed plaintext for.
  final List<FakeSendWithCall> sendWithCalls = [];

  /// The engine send with this policy fails (`server unreachable`), as when the server goes
  /// away midway: when an earlier one went out, [send] throws a [PartialSendException].
  SendPolicy? failSendPolicy;

  /// The engine send to this address fails the same way (one email-code link of several).
  String? failSendTo;

  @override
  Future<SendReceipt> send(DraftMessage draft) async {
    await _io();
    final encrypted = <String>[];
    final guest = <String>[];
    final plain = <String>[];
    final confirmed = {for (final e in draft.plaintextConfirmedFor) e.toLowerCase()};
    final seen = <String>{};
    for (final to in [...draft.to, ...draft.cc]) {
      if (!seen.add(to.toLowerCase())) continue;
      final key = knownKeys[to.toLowerCase()];
      if (key != null) {
        encrypted.add(to);
      } else if (confirmed.contains(to.toLowerCase())) {
        plain.add(to);
      } else {
        guest.add(to);
      }
    }
    final guestBatches = draft.guestMode == GuestMode.emailCode
        ? [for (final g in guest) [g]]
        : [if (guest.isNotEmpty) guest];
    final encryptedTo = <String>[];
    final guestLinkTo = <String>[];
    final plaintextTo = <String>[];
    final groups = <(List<String>, SendPolicy, List<String>)>[
      if (encrypted.isNotEmpty) (encrypted, SendPolicy.auto, encryptedTo),
      for (final b in guestBatches) (b, SendPolicy.guestLink, guestLinkTo),
      if (plain.isNotEmpty) (plain, SendPolicy.allowPlaintext, plaintextTo),
    ];
    final links = <GuestLinkResult>[];
    SendReceipt receipt() => SendReceipt(
      encryptedTo: encryptedTo,
      guestLinkTo: guestLinkTo,
      plaintextTo: plaintextTo,
      guestLinks: links,
    );
    for (final (i, (to, policy, sentTo)) in groups.indexed) {
      try {
        _sendWith(draft, to, policy);
      } catch (e) {
        if (i == 0) rethrow;
        throw PartialSendException(
          sent: receipt(),
          notSentTo: [for (final (rest, _, _) in groups.skip(i)) ...rest],
          reason: friendlyError(e),
        );
      }
      sentTo.addAll(to);
      if (policy == SendPolicy.guestLink) links.add(await _guestLink(to, draft.guestMode));
    }
    sentMessages.add(draft);
    return receipt();
  }

  /// One engine send of [send], recorded in [sendWithCalls]; fails when [failSendPolicy] or
  /// [failSendTo] says so.
  void _sendWith(DraftMessage draft, List<String> to, SendPolicy policy) {
    final cc = {for (final a in draft.cc) a.toLowerCase()}
      ..removeAll([for (final a in draft.to) a.toLowerCase()]);
    final fails =
        policy == failSendPolicy || to.any((a) => a.toLowerCase() == failSendTo?.toLowerCase());
    sendWithCalls.add(
      FakeSendWithCall(
        to: [
          for (final a in to)
            if (!cc.contains(a.toLowerCase())) a,
        ],
        cc: [
          for (final a in to)
            if (cc.contains(a.toLowerCase())) a,
        ],
        policy: policy,
        delivered: !fails,
      ),
    );
    if (fails) throw StateError('server unreachable');
  }

  /// The guest link a send to [to] made (one-click: the secret in the URL).
  Future<GuestLinkResult> _guestLink(List<String> to, GuestMode mode) async {
    final id = (_nextId++).toRadixString(16);
    final secret = await generateGuestPassphrase();
    return GuestLinkResult(
      url: mode == GuestMode.oneClick
          ? 'https://guest.sealbox.test/m/$id#$secret'
          : 'https://guest.sealbox.test/m/$id',
      mode: mode,
      recipients: to,
      passphrase: mode == GuestMode.passphrase ? secret : null,
      expiresAt: DateTime.utc(2026, 7, 15),
      secretInLink: mode == GuestMode.oneClick,
      recipientVerification: mode == GuestMode.emailCode,
    );
  }

  /// What [capabilities] reports for guest-link modes (tests narrow it to
  /// the pre-G29 engine, which only does one-click).
  Set<GuestMode> guestModes = const {GuestMode.passphrase, GuestMode.oneClick, GuestMode.emailCode};

  @override
  Future<EngineCapabilities> capabilities() async =>
      EngineCapabilities(guestLinks: true, keyDirectory: true, guestModes: guestModes);

  // -- per-account settings --------------------------------------------------

  final Map<String, SignatureSettings> _signatures = {};
  final Map<String, AutoReplySettings> _autoReplies = {};

  @override
  Future<SignatureSettings> getSignature(String accountId) async {
    await _io();
    return _signatures[accountId] ?? const SignatureSettings();
  }

  @override
  Future<SignatureSettings> setSignature(String accountId, SignatureSettings s) async {
    await _io();
    final stored = s.copyWith(text: s.text.trimRight());
    _signatures[accountId] = stored;
    return stored;
  }

  @override
  Future<AutoReplySettings> getAutoReply(String accountId) async {
    await _io();
    return _autoReplies[accountId] ?? const AutoReplySettings();
  }

  @override
  Future<AutoReplySettings> setAutoReply(String accountId, AutoReplySettings s) async {
    await _io();
    if (s.enabled && s.body.trim().isEmpty) {
      throw ArgumentError('auto-reply: a message body is required to enable the responder');
    }
    if (s.start != null && s.end != null && !s.end!.isAfter(s.start!)) {
      throw ArgumentError('auto-reply: the end of the absence must be after its start');
    }
    _autoReplies[accountId] = s;
    return s;
  }

  @override
  Future<List<AutoReplyEntry>> autoReplyLog(String accountId) async {
    await _io();
    return const [];
  }

  /// What [profileKeyStatus] reports; tests set it to exercise both copies.
  ProfileKeyStatus profileKey = const ProfileKeyStatus.unknown();

  @override
  Future<ProfileKeyStatus> profileKeyStatus() async {
    await _io();
    return profileKey;
  }

  // -- backup ----------------------------------------------------------------

  @override
  Future<BackupStatus> backupStatus() async {
    await _io();
    return _withReminder(_backup);
  }

  @override
  Future<BackupStatus> backupNow() async {
    await _io();
    _backup = BackupStatus(backedUp: true, lastBackup: DateTime.now());
    return _backup;
  }

  // -- folders by special-use role ---------------------------------------------

  /// Messages that live outside the inbox conversations ([_threads]): Spam,
  /// Trash, Archive, Drafts. Each keeps its conversation id, so [getThread]
  /// shows the whole conversation and moving it back rejoins it.
  final List<Message> _parked = [];

  /// The seeded prize scam in the first account's Spam folder.
  static const junkSampleId = 'm-junk-1';

  /// The folder of the two review samples below: a user folder no role and no chip but
  /// "All mail" shows, so the inbox (and every golden and count built on it) is unchanged.
  static const samplesFolder = 'Review samples';

  /// N1: encrypted to a key this device does not hold; the provider has only its `...`.
  static const undecryptableSampleId = 'm-undecryptable-1';

  /// R4: a good signature made with a key that belongs to another address than From.
  static const signerMismatchSampleId = 'm-signer-mismatch-1';

  /// An HTML newsletter in [samplesFolder]: two remote images (blocked until the user asks),
  /// an inline `cid:` logo and two links — what `MessageBody` renders (docs/HTML_MAIL.md).
  static const htmlSampleId = 'm-html-1';

  /// The sample's body exactly as the engine's sanitizer would return it: remote images are
  /// placeholders, the links carry the fixed `rel`, no CSS and no script anywhere.
  static const _htmlSampleBlocked =
      '<h1>Your October statement</h1>'
      '<p>Hello <b>Alice</b>, your statement for October is ready. '
      '<a href="https://statements.example/october" '
      'rel="noopener noreferrer nofollow">View it online</a> or reply to this mail.</p>'
      '<span class="sealbox-blocked-image" '
      'data-src="https://cdn.example/newsletter/header.png"></span>'
      '<table><thead><tr><th>Item</th><th>Amount</th></tr></thead>'
      '<tbody><tr><td>Subscription</td><td>12.00 EUR</td></tr>'
      '<tr><td>Storage</td><td>3.50 EUR</td></tr></tbody></table>'
      '<p><img src="cid:logo@statements.example" alt="Example Bank"></p>'
      '<blockquote>Questions? <a href="mailto:help@statements.example" '
      'rel="noopener noreferrer nofollow">help@statements.example</a></blockquote>'
      '<span class="sealbox-blocked-image" '
      'data-src="https://track.example/open/4417.gif"></span>';

  /// The same body with the two remote images loaded ("Load images" tapped).
  static String get _htmlSampleLoaded => _htmlSampleBlocked
      .replaceAll(
        '<span class="sealbox-blocked-image" '
            'data-src="https://cdn.example/newsletter/header.png"></span>',
        '<img src="https://cdn.example/newsletter/header.png" alt="October statement">',
      )
      .replaceAll(
        '<span class="sealbox-blocked-image" '
            'data-src="https://track.example/open/4417.gif"></span>',
        '<img src="https://track.example/open/4417.gif" alt="">',
      );

  /// The plain-text view of the sample (what [Message.body] and `HtmlBody.text` hold).
  static const _htmlSampleText =
      'Your October statement\n\n'
      'Hello Alice, your statement for October is ready. View it online '
      '<https://statements.example/october> or reply to this mail.\n\n'
      'Item\tAmount\nSubscription\t12.00 EUR\nStorage\t3.50 EUR\n\n'
      '[Example Bank]\n\n> Questions? help@statements.example';

  static const _gmailFolders = {
    FolderRole.inbox: 'INBOX',
    FolderRole.sent: '[Gmail]/Sent Mail',
    FolderRole.drafts: '[Gmail]/Drafts',
    FolderRole.trash: '[Gmail]/Trash',
    FolderRole.junk: '[Gmail]/Spam',
    FolderRole.archive: '[Gmail]/All Mail',
    FolderRole.all: '[Gmail]/All Mail',
    FolderRole.flagged: '[Gmail]/Starred',
  };

  static const _genericFolders = {
    FolderRole.inbox: 'INBOX',
    FolderRole.sent: 'Sent',
    FolderRole.drafts: 'Drafts',
    FolderRole.trash: 'Trash',
    FolderRole.junk: 'Junk',
    FolderRole.archive: 'Archive',
    FolderRole.all: 'Archive',
    FolderRole.flagged: 'Flagged',
  };

  /// The roles a fake "first sync" confirmed (the rest are provider defaults).
  static const _learnedRoles = {FolderRole.inbox, FolderRole.sent, FolderRole.trash, FolderRole.junk};

  /// The account by id (`acct-1`) or address (what `FrbCore` uses as the id).
  Account? _account(String accountId) =>
      _accounts.where((a) => a.id == accountId || a.email == accountId).firstOrNull;

  Account _requireAccount(String accountId) =>
      _account(accountId) ?? (throw ArgumentError('account not found: $accountId'));

  /// The folder [role] has on [accountId] here: Gmail's names on a gmail.com
  /// account, the engine's generic defaults otherwise.
  String folderNameFor(String accountId, FolderRole role) {
    final a = _account(accountId);
    final gmail = a != null && a.imapHost.contains('gmail');
    return (gmail ? _gmailFolders : _genericFolders)[role]!;
  }

  bool _inRole(Message m, FolderRole role) =>
      m.folder.toLowerCase() == folderNameFor(m.accountId, role).toLowerCase() ||
      (role.mailFolder?.matches(m.folder) ?? false);

  Message? _parkedMessage(String id) => _parked.where((m) => m.id == id).firstOrNull;

  static MailThread _threadOf(List<Message> messages) => MailThread(
    id: messages.first.threadId,
    subject: messages.first.subject,
    accountId: messages.first.accountId,
    messages: messages,
  );

  static MailThread _merged(MailThread t, List<Message> more) => MailThread(
    id: t.id,
    subject: t.subject,
    accountId: t.accountId,
    messages: [...t.messages, ...more],
  );

  /// [base] plus the parked messages [inFolder] accepts: merged into their
  /// conversation when [base] has it, else as a conversation of their own.
  /// Without such messages [base] comes back unchanged (the inbox, always).
  List<MailThread> _withParked(List<MailThread> base, bool Function(String folder) inFolder) {
    final groups = <String, List<Message>>{};
    for (final m in _parked) {
      if (inFolder(m.folder)) (groups[m.threadId] ??= []).add(m);
    }
    if (groups.isEmpty) return base;
    final out = [
      for (final t in base) groups.containsKey(t.id) ? _merged(t, groups.remove(t.id)!) : t,
      for (final g in groups.values) _threadOf(g),
    ]..sort((a, b) => b.latest.date.compareTo(a.latest.date));
    return List.unmodifiable(out);
  }

  @override
  Future<List<FolderRoleInfo>> folderRoles(String accountId) async {
    await _io();
    final a = _requireAccount(accountId);
    return [
      for (final r in FolderRole.values)
        FolderRoleInfo(
          accountId: accountId,
          role: r,
          folder: folderNameFor(a.id, r),
          learned: _learnedRoles.contains(r),
        ),
    ];
  }

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) async {
    final base = await listThreads();
    final all = _withParked(base, (_) => true);
    bool mine(String id) => accountId == null || _account(accountId)?.id == _account(id)?.id;
    final out = <MailThread>[];
    for (final t in all) {
      if (!mine(t.accountId)) continue;
      final members = [
        for (final m in t.messages)
          if (_inRole(m, role)) m,
      ];
      if (members.isNotEmpty) {
        out.add(MailThread(id: t.id, subject: t.subject, accountId: t.accountId, messages: members));
      }
    }
    out.sort((a, b) => b.latest.date.compareTo(a.latest.date));
    return List.unmodifiable(out);
  }

  /// Nothing new arrives in the fake; every account reports an empty sync.
  @override
  Future<SyncOutcome> syncFolder(FolderRole role, {String? accountId}) async {
    await _io();
    final accounts = accountId == null ? _accounts : [_requireAccount(accountId)];
    return SyncOutcome([for (final a in accounts) AccountSyncOutcome(account: a.email)]);
  }

  /// Relocates the message at once and keeps its id. (The engine drops the local
  /// copy instead; it reappears with a new id when that folder is synced.)
  @override
  Future<MoveResult> moveMessage(String messageId, FolderRole role) async {
    final m = await getMessage(messageId) ?? _parkedMessage(messageId);
    if (m == null) throw ArgumentError('message not found: $messageId');
    final dest = folderNameFor(m.accountId, role);
    if (m.folder.toLowerCase() == dest.toLowerCase()) {
      return MoveResult(messageId: messageId, fromFolder: m.folder, toFolder: dest);
    }
    await deleteMessage(messageId); // also leaves a subclass's own copy of the inbox
    _parked.removeWhere((p) => p.id == messageId);
    final moved = m.copyWith(folder: dest);
    if (role == FolderRole.inbox || role == FolderRole.sent) {
      final i = _threads.indexWhere((t) => t.id == moved.threadId);
      if (i >= 0) {
        _threads[i] = _merged(_threads[i], [moved]);
      } else {
        _threads.add(_threadOf([moved]));
      }
    } else {
      _parked.add(moved);
    }
    return MoveResult(
      messageId: messageId,
      fromFolder: m.folder,
      toFolder: dest,
      method: MoveMethod.move,
    );
  }

  // -- compose: quoting and the signature ---------------------------------------

  /// The signature the preview uses until one was saved with [setSignature] in
  /// this session (Settings keeps showing the stored, disabled default).
  static SignatureSettings fakeSignature(String displayName) => SignatureSettings(
    enabled: true,
    text: '$displayName\nSent with Sealbox — end-to-end encrypted',
  );

  SignatureSettings _effectiveSignature(String accountId) {
    final a = _account(accountId);
    return _signatures[accountId] ??
        (a == null ? const SignatureSettings() : _signatures[a.id] ?? fakeSignature(a.displayName));
  }

  static bool _applies(SignatureIncludeOn on, ComposeKind kind) => switch (on) {
    SignatureIncludeOn.newOnly => kind == ComposeKind.newMessage,
    SignatureIncludeOn.newAndReplies => kind != ComposeKind.forward,
    SignatureIncludeOn.all => true,
  };

  static String _signatureBlock(SignatureSettings s) => '-- \n${s.text.replaceAll('\r\n', '\n').trimRight()}\n';

  @override
  Future<SignaturePreview?> signaturePreview(String accountId, ComposeKind kind) async {
    await _io();
    _requireAccount(accountId);
    final s = _effectiveSignature(accountId);
    if (!s.enabled || s.isEmpty || !_applies(s.includeOn, kind)) return null;
    return SignaturePreview(
      text: s.text.trim().isEmpty ? '' : _signatureBlock(s),
      html: s.html == null || s.html!.trim().isEmpty
          ? null
          : '<div class="sealbox-signature">-- <br>\n${s.html}</div>',
      placement: s.placement,
    );
  }

  /// Like the engine: typed text, then signature and quote (order per the
  /// signature's placement), each after a blank line.
  @override
  Future<ComposePreview> composePreview(DraftMessage draft) async {
    await _io();
    _requireAccount(draft.accountId);
    final o = draft.compose;
    final kind = o.kind == ComposeKind.newMessage && draft.inReplyTo != null ? ComposeKind.reply : o.kind;
    String? quoted;
    var forwarded = const <String>[];
    if (kind == ComposeKind.reply && o.quote) {
      final original = draft.inReplyTo == null ? null : await getMessage(draft.inReplyTo!);
      if (original == null) {
        throw ArgumentError('invalid input: cannot quote: the replied-to message is not stored locally');
      }
      quoted = 'On ${_rfc2822(original.date)}, ${original.from} wrote:\n${_prefixLines(original.body)}';
    } else if (kind == ComposeKind.forward) {
      final original = o.forwardOf == null ? null : await getMessage(o.forwardOf!);
      if (original == null) {
        throw ArgumentError(
          'invalid input: forward: `forward_of` must name a stored message (local id or Message-ID)',
        );
      }
      forwarded = [for (final a in original.attachments) a.filename];
      quoted = '-------- Forwarded Message --------\n'
          'Subject: ${original.subject}\n'
          'Date: ${_rfc2822(original.date)}\n'
          'From: ${original.from}\n'
          '${original.to.isEmpty ? '' : 'To: ${original.to.join(', ')}\n'}'
          '\n${original.body.trimRight()}\n';
    }
    final sig = _effectiveSignature(draft.accountId);
    final useSig = !o.skipSignature && sig.enabled && !sig.isEmpty && _applies(sig.includeOn, kind);
    final sigBlock = useSig && sig.text.trim().isNotEmpty ? _signatureBlock(sig) : null;
    final blocks = sig.placement == SignaturePlacement.belowQuote ? [quoted, sigBlock] : [sigBlock, quoted];
    final out = StringBuffer(draft.body.replaceAll('\r\n', '\n'));
    for (final b in blocks.whereType<String>()) {
      var t = out.toString();
      if (t.isNotEmpty && !t.endsWith('\n')) out.write('\n');
      t = out.toString();
      if (t.isNotEmpty && !t.endsWith('\n\n')) out.write('\n');
      out.write(b);
      if (!b.endsWith('\n')) out.write('\n');
    }
    return ComposePreview(
      kind: kind,
      text: out.toString(),
      signatureApplied: useSig,
      forwardedAttachments: forwarded,
    );
  }

  static String _prefixLines(String text) {
    final b = StringBuffer();
    for (final line in text.replaceAll('\r\n', '\n').trimRight().split('\n')) {
      b.write(line.isEmpty ? '>' : (line.startsWith('>') ? '>$line' : '> $line'));
      b.write('\n');
    }
    return b.toString();
  }

  static String _rfc2822(DateTime d) {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    final u = d.toUtc();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${days[u.weekday - 1]}, ${u.day} ${months[u.month - 1]} ${u.year} '
        '${two(u.hour)}:${two(u.minute)}:${two(u.second)} +0000';
  }

  // -- spam -----------------------------------------------------------------------

  final Map<String, SpamSettings> _spamSettings = {};

  /// Labels as stored at "sync" time ([junkSampleId] is spam).
  final Map<String, SpamLabel> _storedSpam = {};

  /// The user's own verdicts ([spamLearn]).
  final Map<String, SpamLabel> _learnedSpam = {};
  int _modelSpam = 12;
  int _modelHam = 31;

  SpamSettings _spamFor(String accountId) {
    final a = _account(accountId);
    return _spamSettings[a?.id ?? accountId] ?? const SpamSettings();
  }

  @override
  Future<SpamSettings> spamSettings(String accountId) async {
    await _io();
    _requireAccount(accountId);
    return _spamFor(accountId);
  }

  /// The engine's checks and normalisation.
  @override
  Future<SpamSettings> setSpamSettings(String accountId, SpamSettings settings) async {
    await _io();
    final a = _requireAccount(accountId);
    for (final (name, v) in [
      ('unsure_threshold', settings.unsureThreshold),
      ('spam_threshold', settings.spamThreshold),
    ]) {
      if (v.isNaN || v < 0 || v > 1) throw ArgumentError('invalid input: $name must be between 0 and 1');
    }
    if (settings.unsureThreshold > settings.spamThreshold) {
      throw ArgumentError('invalid input: unsure_threshold must not exceed spam_threshold');
    }
    final folder = settings.moveToFolder.trim();
    if (folder.isEmpty) throw ArgumentError('invalid input: move_to_folder must not be empty');
    if (folder.toUpperCase() == 'INBOX') throw ArgumentError('invalid input: move_to_folder cannot be INBOX');
    List<String> clean(List<String> list) {
      final out = <String>[];
      for (final e in list) {
        final x = e.trim().replaceFirst(RegExp('^@+'), '').toLowerCase();
        if (x.isEmpty || x.contains(RegExp(r'\s'))) {
          throw ArgumentError('invalid input: `$x` is not an address or domain');
        }
        if (!out.contains(x)) out.add(x);
      }
      return out;
    }

    final stored = settings.copyWith(
      moveToFolder: folder,
      allowlist: clean(settings.allowlist),
      blocklist: clean(settings.blocklist),
    );
    _spamSettings[a.id] = stored;
    return stored;
  }

  Future<SpamSettings> _list(String accountId, String entry, bool add, {required bool allow}) async {
    final s = _spamFor(accountId);
    final e = entry.trim().replaceFirst(RegExp('^@+'), '').toLowerCase();
    final allowlist = [for (final x in s.allowlist) if (x != e) x];
    final blocklist = [for (final x in s.blocklist) if (x != e) x];
    if (add) (allow ? allowlist : blocklist).add(e);
    return setSpamSettings(accountId, s.copyWith(allowlist: allowlist, blocklist: blocklist));
  }

  @override
  Future<SpamSettings> spamAllow(String accountId, String entry, {bool add = true}) =>
      _list(accountId, entry, add, allow: true);

  @override
  Future<SpamSettings> spamBlock(String accountId, String entry, {bool add = true}) =>
      _list(accountId, entry, add, allow: false);

  Future<List<Message>> _allMessages() async => [
    for (final t in await listThreads()) ...t.messages,
    ..._parked,
  ];

  SpamLabel _labelOf(Message m) =>
      _learnedSpam[m.id] ??
      _storedSpam[m.id] ??
      (_inRole(m, FolderRole.junk) ? SpamLabel.spam : SpamLabel.ham);

  @override
  Future<SpamStatus> spamStatus() async {
    await _io();
    final all = await _allMessages();
    return SpamStatus(
      modelSpamMessages: _modelSpam,
      modelHamMessages: _modelHam,
      modelTokens: 2417,
      modelConfidence: 0.62,
      accounts: [
        for (final a in _accounts)
          SpamAccountStatus(
            accountId: a.id,
            settings: _spamFor(a.id),
            spamFolder: _spamFor(a.id).usesServerJunkFolder
                ? folderNameFor(a.id, FolderRole.junk)
                : _spamFor(a.id).moveToFolder,
            spamCount: all.where((m) => m.accountId == a.id && _labelOf(m) == SpamLabel.spam).length,
            unsureCount: all.where((m) => m.accountId == a.id && _labelOf(m) == SpamLabel.unsure).length,
            hamCount: all.where((m) => m.accountId == a.id && _labelOf(m) == SpamLabel.ham).length,
            filterRuleCount: (_rules[a.id] ?? const []).length,
          ),
      ],
    );
  }

  SpamVerdict _verdictFor(Message m, SpamLabel label) {
    final scam = m.id == junkSampleId;
    final reasons = switch (label) {
      SpamLabel.spam when scam => const [
        SpamReason(code: 'scam_language', weight: 2.0, detail: 'prize / winner wording: "won", "gift card", "claim"'),
        SpamReason(code: 'dmarc_fail', weight: 2.5, detail: 'DMARC fail for prize-claims.example'),
        SpamReason(code: 'spf_fail', weight: 1.5, detail: 'SPF fail: 203.0.113.7 is not allowed to send for prize-claims.example'),
        SpamReason(code: 'raw_ip_url', weight: 1.5, detail: 'link to a bare IP address: 203.0.113.7'),
        SpamReason(code: 'excessive_punctuation', weight: 0.6, detail: '"!!!" in the subject'),
      ],
      SpamLabel.spam => const [
        SpamReason(code: 'user_feedback', detail: 'marked as spam by the user'),
      ],
      SpamLabel.unsure => const [
        SpamReason(code: 'reply_to_mismatch', weight: 1.0, detail: 'Reply-To differs from From'),
      ],
      SpamLabel.ham => [
        if (m.signature == SignatureState.good)
          SpamReason(code: 'signed_by_contact', detail: 'good OpenPGP signature by ${m.from.email}')
        else
          const SpamReason(code: 'known_sender', weight: -1.5, detail: 'you have written to this sender before'),
      ],
    };
    final p = switch (label) {
      SpamLabel.spam => scam ? 0.987 : 1.0,
      SpamLabel.unsure => 0.62,
      SpamLabel.ham => m.signature == SignatureState.good ? 0.0 : 0.04,
    };
    final rules = reasons.fold<double>(0, (n, r) => n + r.weight);
    return SpamVerdict(
      spamProbability: p,
      label: label,
      reasons: reasons,
      bayesLogOdds: scam ? 2.3 : -1.1,
      bayesConfidence: 0.62,
      rulesScore: rules,
      logOdds: scam ? 4.33 : -3.2,
    );
  }

  @override
  Future<SpamExplanation> spamExplain(String messageId) async {
    final m = await getMessage(messageId) ?? _parkedMessage(messageId);
    if (m == null) throw ArgumentError('message not found: $messageId');
    final label = _labelOf(m);
    final scam = m.id == junkSampleId;
    final stored = _storedSpam[m.id] ?? (_inRole(m, FolderRole.junk) ? SpamLabel.spam : SpamLabel.ham);
    return SpamExplanation(
      messageId: m.id,
      accountId: m.accountId,
      folder: m.folder,
      from: '${m.from}',
      subject: m.subject,
      stored: StoredSpamInfo(
        score: _verdictFor(m, stored).spamProbability,
        label: stored,
        reasons: _verdictFor(m, stored).reasons,
        learned: _learnedSpam[m.id],
      ),
      verdict: _verdictFor(m, label),
      settings: _spamFor(m.accountId),
      features: SpamFeatures(
        fromAddress: m.from.email,
        fromName: m.from.name,
        replyTo: scam ? 'payout@prize-claims.example' : null,
        urls: [for (final u in RegExp(r'https?://[^\s)>]+').allMatches(m.body)) u.group(0)!],
        attachments: [for (final a in m.attachments) '${a.filename} (${a.contentType})'],
        receivedDepth: scam ? 4 : 3,
        lastExternalIp: scam ? '203.0.113.7' : '198.51.100.20',
        authPresent: true,
        spf: scam ? SpamAuthResult.fail : SpamAuthResult.pass,
        dkim: scam ? SpamAuthResult.none : SpamAuthResult.pass,
        dmarc: scam ? SpamAuthResult.fail : SpamAuthResult.pass,
        tokens: m.body.split(RegExp(r'\W+')).where((w) => w.length > 2).toSet().length,
      ),
      filters: _applyRules(_rules[_account(m.accountId)?.id ?? m.accountId] ?? const [], m),
    );
  }

  /// Like the engine: train, store the label, move to the junk folder (spam) or
  /// back to INBOX (not spam). The message keeps its id.
  @override
  Future<SpamLearnResult> spamLearn(String messageId, {required bool isSpam}) async {
    final m = await getMessage(messageId) ?? _parkedMessage(messageId);
    if (m == null) throw ArgumentError('message not found: $messageId');
    final label = isSpam ? SpamLabel.spam : SpamLabel.ham;
    final previous = _learnedSpam[messageId];
    if (previous != label) {
      if (previous == SpamLabel.spam) _modelSpam--;
      if (previous == SpamLabel.ham) _modelHam--;
      isSpam ? _modelSpam++ : _modelHam++;
      _learnedSpam[messageId] = label;
    }
    final settings = _spamFor(m.accountId);
    final junk = settings.usesServerJunkFolder ? folderNameFor(m.accountId, FolderRole.junk) : settings.moveToFolder;
    final inJunk = m.folder.toLowerCase() == junk.toLowerCase();
    String? movedTo;
    if (isSpam && !inJunk) {
      movedTo = (await moveMessage(messageId, FolderRole.junk)).toFolder;
      await markSeen(messageId);
    } else if (!isSpam && inJunk) {
      movedTo = (await moveMessage(messageId, FolderRole.inbox)).toFolder;
    }
    final verdict = _verdictFor(m, label);
    return SpamLearnResult(
      messageId: messageId,
      learned: label,
      previouslyLearned: previous,
      movedTo: movedTo,
      modelSpamMessages: _modelSpam,
      modelHamMessages: _modelHam,
      verdict: SpamVerdict(
        spamProbability: verdict.spamProbability,
        label: label,
        reasons: [
          SpamReason(code: 'user_feedback', detail: 'marked as ${isSpam ? 'spam' : 'ham'} by the user'),
          ...verdict.reasons.where((r) => r.code != 'user_feedback'),
        ],
        bayesLogOdds: verdict.bayesLogOdds,
        bayesConfidence: verdict.bayesConfidence,
        rulesScore: verdict.rulesScore,
        logOdds: verdict.logOdds,
      ),
    );
  }

  // -- filter rules -----------------------------------------------------------------

  /// Rules per account id; [_seedRules] gives the first account two.
  final Map<String, List<FilterRule>> _rules = {};
  int _nextRuleId = 3;

  List<FilterRule> _rulesOf(String accountId) => _rules[_requireAccount(accountId).id] ??= [];

  /// The engine's validation (`FilterRule::validate` + the CLI parser's checks).
  static void _validateRule(FilterRule r) {
    if (r.condition.value.trim().isEmpty) throw ArgumentError('invalid input: the value must not be empty');
    if (r.condition.field == FilterField.header && (r.condition.headerName ?? '').trim().isEmpty) {
      throw ArgumentError('invalid input: invalid filter rule: header: needs a header name');
    }
    if (r.condition.op == FilterOp.regex) {
      try {
        RegExp(r.condition.value);
      } on FormatException catch (e) {
        throw ArgumentError('invalid input: regex: ${e.message}');
      }
    }
    switch (r.action.kind) {
      case FilterActionKind.moveTo when (r.action.folder ?? '').trim().isEmpty:
        throw ArgumentError('invalid input: the target folder must not be empty');
      case FilterActionKind.addFlag
          when (r.action.flag ?? '').isEmpty || r.action.flag!.contains(RegExp(r'[\s(){}"%*]')):
        throw ArgumentError('invalid input: invalid filter rule: `${r.action.flag ?? ''}` is not a valid IMAP flag');
      default:
    }
  }

  List<FilterRule> _sorted(List<FilterRule> rules) =>
      [...rules]..sort((a, b) => a.order != b.order ? a.order.compareTo(b.order) : a.id.compareTo(b.id));

  @override
  Future<List<FilterRule>> filterRules(String accountId) async {
    await _io();
    return List.unmodifiable(_sorted(_rulesOf(accountId)));
  }

  @override
  Future<FilterRule> addFilterRule(String accountId, FilterRule rule) async {
    await _io();
    _validateRule(rule);
    final rules = _rulesOf(accountId);
    final maxOrder = rules.fold<int>(0, (m, r) => r.order > m ? r.order : m);
    final stored = rule.copyWith(id: _nextRuleId++, order: rule.order == 0 ? maxOrder + 10 : rule.order);
    rules.add(stored);
    return stored;
  }

  @override
  Future<FilterRule> updateFilterRule(String accountId, FilterRule rule) async {
    await _io();
    _validateRule(rule);
    final rules = _rulesOf(accountId);
    final i = rules.indexWhere((r) => r.id == rule.id);
    if (i < 0) throw ArgumentError('invalid input: no filter rule ${rule.id} for $accountId');
    rules[i] = rule;
    return rule;
  }

  @override
  Future<bool> removeFilterRule(String accountId, int ruleId) async {
    await _io();
    final rules = _rulesOf(accountId);
    final before = rules.length;
    rules.removeWhere((r) => r.id == ruleId);
    return rules.length != before;
  }

  @override
  Future<FilterRule> setFilterRuleEnabled(String accountId, int ruleId, bool enabled) async {
    await _io();
    final rules = _rulesOf(accountId);
    final i = rules.indexWhere((r) => r.id == ruleId);
    if (i < 0) throw ArgumentError('invalid input: no filter rule $ruleId for $accountId');
    return rules[i] = rules[i].copyWith(enabled: enabled);
  }

  @override
  Future<List<FilterRule>> setFilterRules(String accountId, List<FilterRule> rules) async {
    await _io();
    rules.forEach(_validateRule);
    final stored = [
      for (var i = 0; i < rules.length; i++) rules[i].copyWith(id: _nextRuleId++, order: (i + 1) * 10),
    ];
    _rules[_requireAccount(accountId).id] = stored;
    return List.unmodifiable(stored);
  }

  @override
  Future<FilterTestReport> testFilterRules(String accountId, String messageId) async {
    final m = await getMessage(messageId) ?? _parkedMessage(messageId);
    if (m == null) throw ArgumentError('message not found: $messageId');
    final account = _requireAccount(accountId);
    if (_account(m.accountId)?.id != account.id) {
      throw ArgumentError('invalid input: message $messageId does not belong to $accountId');
    }
    final enabled = [for (final r in _sorted(_rulesOf(accountId))) if (r.enabled) r];
    return FilterTestReport(
      messageId: messageId,
      outcome: _applyRules(enabled, m),
      rules: [
        for (final r in enabled) FilterRuleResult(ruleId: r.id, description: r.summary, matched: _matches(r, m)),
      ],
    );
  }

  /// The engine's semantics: enabled rules in order, flags accumulate, the first
  /// move wins, `stop` ends the evaluation.
  FilterOutcome _applyRules(List<FilterRule> rules, Message m) {
    final matched = <int>[];
    String? moveTo;
    final flags = <String>[];
    var read = false;
    var star = false;
    for (final r in _sorted(rules)) {
      if (!r.enabled || !_matches(r, m)) continue;
      matched.add(r.id);
      switch (r.action.kind) {
        case FilterActionKind.moveTo:
          moveTo ??= r.action.folder;
        case FilterActionKind.addFlag:
          if (!flags.contains(r.action.flag)) flags.add(r.action.flag!);
        case FilterActionKind.markRead:
          read = true;
        case FilterActionKind.star:
          star = true;
      }
      if (r.stop) break;
    }
    return FilterOutcome(matchedRuleIds: matched, moveTo: moveTo, addFlags: flags, markRead: read, star: star);
  }

  static bool _matches(FilterRule r, Message m) {
    final c = r.condition;
    final isAddress = c.field == FilterField.from || c.field == FilterField.to || c.field == FilterField.cc;
    final values = switch (c.field) {
      FilterField.from => [m.from],
      FilterField.to => m.to,
      FilterField.cc => m.cc,
      _ => const <Contact>[],
    };
    final texts = switch (c.field) {
      FilterField.subject => [m.subject],
      FilterField.body => [m.body],
      FilterField.from || FilterField.to || FilterField.cc => [
        for (final v in values) ...[v.email, '$v'],
      ],
      FilterField.listId || FilterField.header => const <String>[],
    };
    String norm(String s) => c.caseInsensitive ? s.toLowerCase() : s;
    final want = norm(c.value.trim());
    return switch (c.op) {
      FilterOp.contains => texts.any((t) => norm(t).contains(want)),
      FilterOp.equals => texts.any((t) => norm(t) == want),
      FilterOp.regex => texts.any((t) => RegExp(c.value, caseSensitive: !c.caseInsensitive).hasMatch(t)),
      FilterOp.domain => isAddress &&
          values.any((v) {
            final d = v.email.split('@').last.toLowerCase();
            final w = want.replaceFirst(RegExp('^@+'), '').toLowerCase();
            return d == w || d.endsWith('.$w');
          }),
    };
  }

  // -- the Sealbox server and its key directory -----------------------------------

  /// What `SEALBOX_SERVER_URL` says in this fake; [setServerUrl] overrides it.
  String? environmentServer = 'https://sealbox.example';
  bool _serverFromSettings = false;

  /// The states [directoryStatus] walks through on successive calls (the last
  /// one sticks); [publishKey] and [completeDirectoryVerification] jump ahead.
  /// Tests and the review tour may replace it, e.g. `[DirectoryState.otherKey]`.
  List<DirectoryState> directoryProgression = const [
    DirectoryState.unpublished,
    DirectoryState.awaitingVerification,
    DirectoryState.published,
  ];
  int _directoryStep = 0;

  DirectoryState get _directoryState =>
      directoryProgression[_directoryStep.clamp(0, directoryProgression.length - 1)];

  void _jumpTo(DirectoryState s) {
    final i = directoryProgression.indexOf(s);
    if (i >= 0 && i > _directoryStep) _directoryStep = i;
  }

  /// The engine's refusal without a server, word for word.
  static String get noServerError =>
      'no Sealbox server configured: no key directory: run `sealbox server set-url <url>` or set '
      'SEALBOX_SERVER_URL / SEALBOX_DIRECTORY_URL';

  @override
  Future<String?> setServerUrl(String? url) async {
    await _io();
    final u = url?.trim() ?? '';
    if (u.isEmpty) {
      _serverFromSettings = false;
      configuredServer = environmentServer;
      return configuredServer;
    }
    final clean = u.replaceFirst(RegExp(r'/+$'), '');
    final ok = (clean.startsWith('http://') || clean.startsWith('https://')) && clean.length > 'https://'.length;
    if (!ok) throw ArgumentError('invalid input: server URL must be http(s)://host[:port], got `$u`');
    configuredServer = clean;
    _serverFromSettings = true;
    return clean;
  }

  @override
  Future<ServerUrlSource> serverUrlSource() async {
    if (configuredServer == null) return ServerUrlSource.none;
    return _serverFromSettings ? ServerUrlSource.settings : ServerUrlSource.environment;
  }

  @override
  Future<PublishResult> publishKey(String accountId) async {
    await _io();
    final a = _requireAccount(accountId);
    final server = configuredServer;
    if (server == null) throw StateError(noServerError);
    final already = _directoryState == DirectoryState.published;
    if (!already) _jumpTo(DirectoryState.awaitingVerification);
    return PublishResult(
      accountId: accountId,
      fingerprint: _myFingerprint,
      serverUrl: server,
      addressStates: {a.email: already ? 'published' : 'pending'},
      tokenIssued: !already,
    );
  }

  @override
  Future<DirectoryStatus> directoryStatus(String accountId) async {
    await _io();
    _requireAccount(accountId);
    final server = configuredServer;
    if (server == null) return DirectoryStatus(accountId: accountId, state: DirectoryState.noServer);
    final state = _directoryState;
    if (_directoryStep < directoryProgression.length - 1) _directoryStep++;
    return _statusOf(accountId, server, state);
  }

  @override
  Future<DirectoryStatus> completeDirectoryVerification(String accountId) async {
    await _io();
    _requireAccount(accountId);
    final server = configuredServer;
    if (server == null) throw StateError(noServerError);
    _jumpTo(DirectoryState.published);
    return _statusOf(accountId, server, _directoryState);
  }

  static DirectoryStatus _statusOf(String accountId, String server, DirectoryState state) => DirectoryStatus(
    accountId: accountId,
    state: state,
    serverUrl: server,
    published: state == DirectoryState.published || state == DirectoryState.otherKey,
    fingerprintMatches: switch (state) {
      DirectoryState.published => true,
      DirectoryState.otherKey => false,
      _ => null,
    },
  );

  // -- search -----------------------------------------------------------------------

  static final _alnum = RegExp(r'[\p{L}\p{N}]', unicode: true);

  /// Substring search over every sample message (threads and parked ones): each word
  /// must occur in the subject, the sender, a recipient or the body, case-insensitively.
  /// Ranked like the engine's column weights (subject 3, sender 2, recipients 1.5, body 1),
  /// newest first on ties; the snippet is up to 16 words of the body around the first
  /// match with every matched word marked, or the start of the body.
  @override
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) async {
    await _io();
    final words = [
      for (final w in text.toLowerCase().split(RegExp(r'\s+')))
        if (_alnum.hasMatch(w)) w,
    ];
    if (words.isEmpty) return const [];
    final max = limit <= 0 ? 50 : limit.clamp(1, 500);
    final hits = <(double, Message)>[];
    for (final m in await _allMessages()) {
      if (accountId != null && m.accountId != accountId && _account(accountId)?.id != m.accountId) {
        continue;
      }
      if (folder != null && folder != '*' && m.folder.toLowerCase() != folder.toLowerCase()) {
        continue;
      }
      final people = [
        for (final c in [...m.to, ...m.cc]) '${c.name ?? ''} ${c.email}',
      ];
      final fields = <(double, String)>[
        (3, m.subject),
        (2, '${m.from.name ?? ''} ${m.from.email}'),
        (1.5, people.join(' ')),
        (1, m.body),
      ];
      var rank = 0.0;
      var all = true;
      for (final w in words) {
        var best = 0.0;
        for (final (weight, value) in fields) {
          if (value.toLowerCase().contains(w) && weight > best) best = weight;
        }
        if (best == 0) {
          all = false;
          break;
        }
        rank += best;
      }
      if (all) hits.add((rank, m));
    }
    hits.sort((a, b) => a.$1 != b.$1 ? b.$1.compareTo(a.$1) : b.$2.date.compareTo(a.$2.date));
    return [
      for (final (rank, m) in hits.take(max))
        SearchResult.fromRaw(message: m, snippet: fakeSnippet(m.body, words), rank: rank),
    ];
  }

  /// The engine's snippet shape: whitespace collapsed, up to 16 words around the first
  /// word containing one of [words] (each occurrence wrapped in U+E000 … U+E001), `…` where
  /// it was cut; the first 16 words when the body does not match; empty without a body.
  static String fakeSnippet(String body, List<String> words) {
    final tokens = body.split(RegExp(r'\s+')).where((t) => t.isNotEmpty).toList();
    if (tokens.isEmpty) return '';
    bool hit(String t) => words.any((w) => t.toLowerCase().contains(w));
    final first = tokens.indexWhere(hit);
    final start = first < 0 ? 0 : (first - 5).clamp(0, tokens.length);
    final end = (start + 16).clamp(0, tokens.length);
    String mark(String t) {
      final lower = t.toLowerCase();
      final out = StringBuffer();
      var i = 0;
      while (i < t.length) {
        var len = 0;
        for (final w in words) {
          if (w.length > len && lower.startsWith(w, i)) len = w.length;
        }
        if (len == 0) {
          out.write(t[i]);
          i++;
        } else {
          out.write('$snippetMatchStart${t.substring(i, i + len)}$snippetMatchEnd');
          i += len;
        }
      }
      return out.toString();
    }

    return [
      if (start > 0) '…',
      for (final t in tokens.sublist(start, end)) mark(t),
      if (end < tokens.length) '…',
    ].join(' ');
  }

  @override
  Future<SearchIndexInfo> warmSearchIndex() async {
    await _io();
    final n = (await _allMessages()).length;
    return SearchIndexInfo(documents: n, memoryBytes: n * 1800);
  }

  // -- saved drafts -----------------------------------------------------------------

  final List<SavedDraft> _drafts = [];
  int _nextDraftId = 1;
  final Map<String, Uint8List> _draftFiles = {};
  final Map<String, String> _draftFileNames = {};
  int _nextDraftFile = 1;

  /// The prefix of [keepDraftAttachment]'s handles: `blob:<n>`, like the engine's stored
  /// copies ([SavedDraftAttachment.blobHandle]).
  static const draftFilePrefix = SavedDraftAttachment.blobHandlePrefix;

  /// The kept attachment copies (handle → bytes); tests check they are released.
  Map<String, Uint8List> get draftFiles => Map.unmodifiable(_draftFiles);

  /// Ids of the drafts "pushed to the server" after each save, in order (FrbCore pushes in
  /// the background after every save).
  final List<int> pushedDrafts = [];

  /// How often [syncDrafts] ran.
  int draftSyncs = 0;

  final List<(DraftInput, int)> _serverDrafts = [];

  /// A draft another device saved: the next [syncDrafts] brings it in, marked
  /// [DraftOrigin.server], with [remoteFiles] file references left on that device.
  void queueServerDraft(DraftInput input, {int remoteFiles = 0}) =>
      _serverDrafts.add((input, remoteFiles));

  @override
  Future<DraftSyncSummary> syncDrafts() async {
    await _io();
    draftSyncs++;
    final queued = [..._serverDrafts];
    _serverDrafts.clear();
    for (final (input, remoteFiles) in queued) {
      final saved = await saveDraft(input);
      pushedDrafts.removeLast(); // brought in, not pushed
      _drafts
        ..removeWhere((d) => d.id == saved.id)
        ..add(
          SavedDraft(
            id: saved.id,
            accountId: saved.accountId,
            kind: saved.kind,
            inReplyTo: saved.inReplyTo,
            forwardOf: saved.forwardOf,
            quote: saved.quote,
            to: saved.to,
            cc: saved.cc,
            bcc: saved.bcc,
            subject: saved.subject,
            body: saved.body,
            attachments: saved.attachments,
            policy: saved.policy,
            guestMode: saved.guestMode,
            guestRecipientHint: saved.guestRecipientHint,
            noSignature: saved.noSignature,
            createdAt: saved.createdAt,
            updatedAt: saved.updatedAt,
            origin: DraftOrigin.server,
            remoteFiles: remoteFiles,
          ),
        );
    }
    return DraftSyncSummary(imported: queued.length);
  }

  /// Like the engine: an id is never handed out twice; saving with an id replaces that
  /// draft (or re-creates it under that id); the kind follows `inReplyTo` / `forwardOf`; a
  /// stored copy must exist and lends its name to an attachment that has none.
  @override
  Future<SavedDraft> saveDraft(DraftInput input) async {
    await _io();
    final account = _requireAccount(input.accountId);
    final id = input.id;
    if (id != null && id <= 0) throw ArgumentError('invalid input: draft ids are positive');
    final attachments = [
      for (final a in input.attachments)
        if (a.blobId == null)
          a
        else if (_draftFiles.containsKey(a.path))
          SavedDraftAttachment(
            path: a.path,
            name: a.name.trim().isEmpty ? _draftFileNames[a.path] ?? '' : a.name,
            contentType: a.contentType,
          )
        else
          throw ArgumentError('invalid input: draft attachment: no stored blob ${a.blobId}'),
    ];
    final reply = input.inReplyTo?.trim();
    final forward = input.forwardOf?.trim();
    final hasReply = reply != null && reply.isNotEmpty;
    final hasForward = forward != null && forward.isNotEmpty;
    if (hasReply && hasForward) {
      throw ArgumentError('invalid input: a draft replies or forwards, not both');
    }
    final ComposeKind kind;
    if (hasReply && input.kind != ComposeKind.forward) {
      kind = ComposeKind.reply;
    } else if (hasForward && input.kind != ComposeKind.reply) {
      kind = ComposeKind.forward;
    } else if (!hasReply && !hasForward && input.kind == ComposeKind.newMessage) {
      kind = ComposeKind.newMessage;
    } else if (input.kind == ComposeKind.reply) {
      throw ArgumentError('invalid input: a reply draft needs in_reply_to');
    } else {
      throw ArgumentError('invalid input: a forward draft needs forward_of');
    }
    final now = clock();
    final existing = _drafts.where((d) => d.id == id).firstOrNull;
    final newId = id ?? _nextDraftId++;
    if (newId >= _nextDraftId) _nextDraftId = newId + 1;
    List<String> clean(List<String> l) => [
      for (final a in l)
        if (a.trim().isNotEmpty) a.trim(),
    ];
    final saved = SavedDraft(
      id: newId,
      accountId: account.id,
      kind: kind,
      inReplyTo: hasReply ? reply : null,
      forwardOf: hasForward ? forward : null,
      quote: input.quote,
      to: clean(input.to),
      cc: clean(input.cc),
      bcc: clean(input.bcc),
      subject: input.subject,
      body: input.body,
      attachments: attachments,
      policy: input.policy,
      guestMode: input.guestMode,
      guestRecipientHint: input.guestRecipientHint,
      noSignature: input.noSignature,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      origin: existing?.origin ?? DraftOrigin.thisDevice,
      remoteFiles: existing?.remoteFiles ?? 0,
    );
    _drafts
      ..removeWhere((d) => d.id == newId)
      ..add(saved);
    pushedDrafts.add(newId);
    return saved;
  }

  @override
  Future<List<SavedDraft>> listDrafts({String? accountId}) async {
    await _io();
    final account = accountId == null ? null : _requireAccount(accountId);
    final list = [
      for (final d in _drafts)
        if (account == null || d.accountId == account.id) d,
    ];
    list.sort((a, b) {
      final byTime = b.updatedAt.compareTo(a.updatedAt);
      return byTime != 0 ? byTime : b.id.compareTo(a.id);
    });
    return List.unmodifiable(list);
  }

  @override
  Future<SavedDraft> getDraft(int id) async {
    await _io();
    return _drafts.where((d) => d.id == id).firstOrNull ??
        (throw ArgumentError('invalid input: no draft $id'));
  }

  @override
  Future<bool> deleteDraft(int id) async {
    await _io();
    final d = _drafts.where((d) => d.id == id).firstOrNull;
    if (d == null) return false;
    _drafts.remove(d);
    for (final a in d.attachments) {
      await releaseDraftAttachment(a.path);
    }
    return true;
  }

  /// Sends the stored draft through [send] (per-recipient decisions, no confirmed
  /// plaintext) and deletes it afterwards; a failure keeps it.
  @override
  Future<SendReceipt> sendDraft(int id) async {
    final d = await getDraft(id);
    final receipt = await send(
      DraftMessage(
        accountId: d.accountId,
        to: d.to,
        cc: d.cc,
        subject: d.subject,
        body: d.body,
        guestMode: d.guestMode,
        inReplyTo: d.inReplyTo,
        attachments: [
          for (final a in d.attachments)
            DraftAttachment(
              name: a.displayName,
              contentType: a.contentType,
              data: await readDraftAttachment(a.path),
              storedPath: a.path,
            ),
        ],
        compose: ComposeOptions(
          kind: d.kind,
          quote: d.quote,
          forwardOf: d.forwardOf,
          skipSignature: d.noSignature,
        ),
      ),
    );
    await deleteDraft(id);
    return receipt;
  }

  @override
  Future<String> keepDraftAttachment(String name, Uint8List data) async {
    await _io();
    final handle = SavedDraftAttachment.blobHandle(_nextDraftFile++);
    _draftFiles[handle] = Uint8List.fromList(data);
    _draftFileNames[handle] = name.trim().isEmpty ? 'attachment' : name.trim();
    return handle;
  }

  @override
  Future<Uint8List> readDraftAttachment(String path) async {
    await _io();
    return _draftFiles[path] ?? (throw StateError('draft attachment $path: No such file'));
  }

  @override
  Future<void> releaseDraftAttachment(String path) async {
    if (SavedDraftAttachment.blobIdOf(path) == null) return;
    _draftFiles.remove(path);
    _draftFileNames.remove(path);
  }

  // -- sample data -----------------------------------------------------------

  static List<Account> _seedAccounts() => const [
    Account(
      id: 'acct-1',
      email: 'alice.rivera@gmail.com',
      displayName: 'Alice Rivera',
      providerName: 'Gmail',
      authMethod: AuthMethod.oauth2,
      imapHost: 'imap.gmail.com',
      smtpHost: 'smtp.gmail.com',
    ),
    Account(
      id: 'acct-2',
      email: 'alice@fastmail.com',
      displayName: 'Alice Rivera',
      providerName: 'Fastmail',
      authMethod: AuthMethod.appPassword,
      imapHost: 'imap.fastmail.com',
      smtpHost: 'smtp.fastmail.com',
    ),
  ];

  static List<MailThread> _seedThreads() {
    final now = DateTime.now();
    const me = Contact(email: 'alice.rivera@gmail.com', name: 'Alice Rivera');
    const me2 = Contact(email: 'alice@fastmail.com', name: 'Alice Rivera');
    const bob = Contact(email: 'bob@sealbox.test', name: 'Bob Nakamura');
    const carol = Contact(email: 'carol@proton.me', name: 'Carol Okafor');
    const dana = Contact(email: 'dana@example.org', name: 'Dana Whitfield');
    const erik = Contact(email: 'erik@posteo.de', name: 'Erik Lindqvist');
    const heidi = Contact(email: 'heidi@delta.chat', name: 'Heidi Baumann');
    const ivan = Contact(email: 'ivan.petrov@hotmail.com', name: 'Ivan Petrov');
    const gh = Contact(email: 'notifications@github.com', name: 'GitHub');
    const fm = Contact(email: 'support@fastmail.com', name: 'Fastmail');

    return [
      MailThread(
        id: 't-budget',
        subject: 'Q4 budget — final numbers',
        accountId: 'acct-1',
        messages: [
          Message(
            id: 'm-1',
            threadId: 't-budget',
            accountId: 'acct-1',
            from: bob,
            to: const [me],
            subject: 'Q4 budget — final numbers',
            date: now.subtract(const Duration(hours: 1, minutes: 12)),
            state: EncryptionState.encrypted,
            signer: '9F4B2E1C7A5D30186B2F4E9C1D7A3B5F0E6C8D2A',
            signerAddress: 'bob@sealbox.test',
            unread: true,
            body:
                'Alice,\n\nAttached (well, inline) are the final Q4 numbers. '
                'Headcount stays flat, the vendor line drops 8% after the renegotiation.\n\n'
                'Please do not forward this outside the finance group.\n\n— Bob',
          ),
          Message(
            id: 'm-0',
            threadId: 't-budget',
            accountId: 'acct-1',
            from: me,
            to: const [bob],
            subject: 'Q4 budget — draft',
            date: now.subtract(const Duration(days: 1, hours: 3)),
            state: EncryptionState.encrypted,
            body: 'Bob — can you send the final numbers when legal signs off?',
          ),
        ],
      ),
      MailThread(
        id: 't-thunderbird',
        subject: 'Re: keys for the Thunderbird interop test',
        accountId: 'acct-1',
        messages: [
          Message(
            id: 'm-2',
            threadId: 't-thunderbird',
            accountId: 'acct-1',
            from: carol,
            to: const [me],
            subject: 'Re: keys for the Thunderbird interop test',
            date: now.subtract(const Duration(hours: 3)),
            state: EncryptionState.encrypted,
            signer: '2C7D9A1F4E6B8035C1D2E3F4A5B6C7D8E9F0A1B2',
            signerAddress: 'carol@proton.me',
            unread: true,
            body:
                'Decrypted fine in Thunderbird 128 — the protected Subject showed up '
                'correctly and the Autocrypt header imported your key on first contact.\n\n'
                'Next: let me try replying from Proton.',
          ),
        ],
      ),
      MailThread(
        id: 't-lunch',
        subject: 'Lunch Thursday?',
        accountId: 'acct-1',
        messages: [
          Message(
            id: 'm-3',
            threadId: 't-lunch',
            accountId: 'acct-1',
            from: dana,
            to: const [me],
            subject: 'Lunch Thursday?',
            date: now.subtract(const Duration(hours: 5, minutes: 40)),
            state: EncryptionState.plaintext,
            body:
                'The Lebanese place near the station, 12:30? '
                'Let me know if Thursday does not work.',
          ),
        ],
      ),
      MailThread(
        id: 't-release',
        subject: 'sealbox-crypto 0.3 release notes (signed)',
        accountId: 'acct-2',
        messages: [
          Message(
            id: 'm-4',
            threadId: 't-release',
            accountId: 'acct-2',
            from: erik,
            to: const [me2],
            subject: 'sealbox-crypto 0.3 release notes (signed)',
            date: now.subtract(const Duration(hours: 9)),
            state: EncryptionState.signed,
            signer: '7E1A3C5B9D2F4068A1B3C5D7E9F0A2B4C6D8E0F1',
            signerAddress: 'erik@posteo.de',
            body:
                'Signed release notes, cleartext on purpose so the list archive can index them.\n\n'
                '* SEIPDv2 when the peer advertises it\n* Argon2 S2K for guest envelopes\n'
                '* gpg interop both directions in CI',
          ),
        ],
      ),
      MailThread(
        id: 't-guest-reply',
        subject: 'Re: Contract draft (via guest link)',
        accountId: 'acct-1',
        messages: [
          Message(
            id: 'm-5a',
            threadId: 't-guest-reply',
            accountId: 'acct-1',
            from: me,
            to: const [ivan],
            subject: 'Contract draft',
            date: now.subtract(const Duration(days: 1, hours: 6)),
            state: EncryptionState.encrypted,
            body:
                'Ivan — the draft is behind the guest link; the passphrase is the one I '
                'gave you on the phone.',
          ),
          Message(
            id: 'm-5',
            threadId: 't-guest-reply',
            accountId: 'acct-1',
            from: ivan,
            to: const [me],
            subject: 'Re: Contract draft (via guest link)',
            date: now.subtract(const Duration(hours: 22)),
            state: EncryptionState.encrypted,
            body:
                'Opened it in the browser, worked first time. Two comments on clause 4, '
                'otherwise fine by me.\n\n(sent from the Sealbox guest page)',
          ),
        ],
      ),
      MailThread(
        id: 't-github',
        subject: '[sealbox/sealbox] G1 gate passed (#42)',
        accountId: 'acct-2',
        messages: [
          Message(
            id: 'm-6',
            threadId: 't-github',
            accountId: 'acct-2',
            from: gh,
            to: const [me2],
            subject: '[sealbox/sealbox] G1 gate passed (#42)',
            date: now.subtract(const Duration(days: 1, hours: 2)),
            state: EncryptionState.plaintext,
            body:
                'All checks have passed: cargo test -p sealbox-crypto --test gate_g1. '
                'gpg interop: both directions OK.',
          ),
        ],
      ),
      MailThread(
        id: 't-heidi',
        subject: 'Photos from the Autocrypt meetup',
        accountId: 'acct-1',
        messages: [
          Message(
            id: 'm-7',
            threadId: 't-heidi',
            accountId: 'acct-1',
            from: heidi,
            to: const [me, carol],
            subject: 'Photos from the Autocrypt meetup',
            date: now.subtract(const Duration(days: 2, hours: 4)),
            state: EncryptionState.encrypted,
            signer: '4D8F2A6C0E1B3579B2C4D6E8F0A1B3C5D7E9F1A3',
            signerAddress: 'heidi@delta.chat',
            body:
                'Encrypted to both of you with gossip keys, so you can reply-all encrypted. '
                'Photos are in the attachment (not shown in this preview build).',
          ),
        ],
      ),
      MailThread(
        id: 't-fastmail',
        subject: 'Your new app password',
        accountId: 'acct-2',
        messages: [
          Message(
            id: 'm-8',
            threadId: 't-fastmail',
            accountId: 'acct-2',
            from: fm,
            to: const [me2],
            subject: 'Your new app password',
            date: now.subtract(const Duration(days: 3)),
            state: EncryptionState.plaintext,
            body:
                'An app password named "Sealbox" was created for your account. '
                'If this was not you, revoke it in Settings → Privacy & Security.',
          ),
        ],
      ),
    ];
  }

  /// The first account's Spam folder: one prize scam (see [spamExplain]); and in the
  /// second account's [samplesFolder] an undecryptable mail (review N1) and one signed with
  /// someone else's key (R4) — not the first account's, whose spam counts a golden shows.
  static List<Message> _seedParked() {
    final now = DateTime.now();
    const me = Contact(email: 'alice.rivera@gmail.com', name: 'Alice Rivera');
    const me2 = Contact(email: 'alice@fastmail.com', name: 'Alice Rivera');
    const bob = Contact(email: 'bob@sealbox.test', name: 'Bob Nakamura');
    return [
      Message(
        id: undecryptableSampleId,
        threadId: 't-undecryptable',
        accountId: 'acct-2',
        from: bob,
        to: const [me2],
        subject: '...',
        date: now.subtract(const Duration(hours: 2, minutes: 5)),
        state: EncryptionState.undecryptable,
        folder: samplesFolder,
        messageId: 'enc-4417@sealbox.test',
        body: 'This message is encrypted, but not to a key on this device.',
      ),
      Message(
        id: signerMismatchSampleId,
        threadId: 't-signer-mismatch',
        accountId: 'acct-2',
        from: bob,
        to: const [me2],
        subject: 'Updated bank details for the Q4 invoice',
        date: now.subtract(const Duration(hours: 2, minutes: 30)),
        state: EncryptionState.encrypted,
        signer: '5B0E7D2A9C14F3E86A0D4B7C2E9F1A3D6C8B0E42',
        signerAddress: 'accounts@nakamura-billing.example',
        unread: true,
        folder: samplesFolder,
        messageId: 'invoice-0931@nakamura-billing.example',
        protectedSubject: true,
        body:
            'Alice,\n\nOur bank details changed this week: please send the Q4 payment to the '
            'new account in the attached letter, and keep it between us until finance announces '
            'it.\n\n— Bob',
      ),
      Message(
        id: htmlSampleId,
        threadId: 't-html-statement',
        accountId: 'acct-2',
        from: const Contact(
          email: 'statements@statements.example',
          name: 'Example Bank',
        ),
        to: const [me2],
        subject: 'Your October statement',
        date: now.subtract(const Duration(hours: 3)),
        state: EncryptionState.plaintext,
        folder: samplesFolder,
        messageId: 'statement-october@statements.example',
        attachments: const [
          AttachmentMeta(index: 0, filename: 'logo.png', contentType: 'image/png', size: 2048),
        ],
        body: _htmlSampleText,
      ),
      Message(
        id: junkSampleId,
        threadId: 't-junk-prize',
        accountId: 'acct-1',
        from: const Contact(email: 'winner@prize-claims.example', name: 'Prize Department'),
        to: const [me],
        subject: 'Congratulations!!! You have won a 1,000 € gift card',
        date: now.subtract(const Duration(hours: 4, minutes: 20)),
        state: EncryptionState.plaintext,
        unread: true,
        folder: '[Gmail]/Spam',
        messageId: 'prize-7731@prize-claims.example',
        body:
            'Dear winner,\n\nYour address was selected in our monthly draw. Claim your '
            '1,000 € gift card within 24 hours at http://203.0.113.7/claim before it expires.\n\n'
            'Prize Department',
      ),
    ];
  }

  /// Two rules on the first account: newsletters into a folder (matches nothing
  /// in the sample mailbox), and a star for the finance contact's mail (matches
  /// "Q4 budget").
  static List<FilterRule> _seedRules() => const [
    FilterRule(
      id: 1,
      order: 10,
      name: 'Newsletters',
      condition: FilterCondition(field: FilterField.subject, op: FilterOp.contains, value: '[newsletter]'),
      action: FilterAction.moveTo('Newsletters'),
    ),
    FilterRule(
      id: 2,
      order: 20,
      name: 'Finance',
      condition: FilterCondition(field: FilterField.from, op: FilterOp.domain, value: 'sealbox.test'),
      action: FilterAction.star(),
    ),
  ];
}
