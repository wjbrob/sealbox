import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../lock/lock_providers.dart';
import '../lock/secret_store.dart';
import 'core_api.dart';
import 'errors.dart';
import 'models.dart';

export 'core_api.dart' show CoreApi, CoreApiOps, CoreMailOps;

/// The one injection point for the engine. `main.dart` overrides it with
/// `FrbCore`, tests with `FakeCore`. Reading it without an override is a bug.
final coreApiProvider = Provider<CoreApi>(
  (ref) => throw StateError(
    'coreApiProvider must be overridden (FrbCore in main.dart, FakeCore in tests)',
  ),
);

final coreInfoProvider = FutureProvider<CoreInfo>((ref) async {
  final core = ref.watch(coreApiProvider);
  return CoreInfo(
    version: await core.version(),
    greeting: await core.greet('Flutter'),
  );
});

final accountsProvider = FutureProvider<List<Account>>(
  (ref) => ref.watch(coreApiProvider).listAccounts(),
);

/// The folder chip selected in the message list (INBOX by default).
final folderProvider = NotifierProvider<FolderController, MailFolder>(FolderController.new);

class FolderController extends Notifier<MailFolder> {
  @override
  MailFolder build() => MailFolder.inbox;

  void set(MailFolder f) => state = f;
}

/// The list under the selected chip, by the chip's special-use role
/// (`listThreadsInRole`; "All mail" has no role and lists every folder). Inbox rows
/// also carry the conversation's Sent members, so a reply you just sent is the row's
/// newest line (conversation view); the other chips hold only their own folder's
/// members, which is what their actions act on.
final threadsProvider = FutureProvider<List<MailThread>>((ref) async {
  final core = ref.watch(coreApiProvider);
  final role = ref.watch(folderProvider).role;
  if (role == null) return core.listThreadsIn(MailFolder.all);
  final inRole = await core.listThreadsInRole(role);
  if (role != FolderRole.inbox || inRole.isEmpty) return inRole;
  final sent = {for (final t in await core.listThreadsInRole(FolderRole.sent)) t.id: t};
  return List.unmodifiable([
    for (final t in inRole)
      if (sent[t.id] case final s?)
        MailThread(
          id: t.id,
          subject: t.subject,
          accountId: t.accountId,
          messages: [
            ...t.messages,
            for (final m in s.messages)
              if (!t.messages.any((x) => x.id == m.id)) m,
          ],
        )
      else
        t,
  ]..sort((a, b) => b.latest.date.compareTo(a.latest.date)));
});

final threadProvider = FutureProvider.family<MailThread?, String>(
  (ref, id) => ref.watch(coreApiProvider).getThread(id),
);

final identityProvider = FutureProvider<IdentityPreview>(
  (ref) => ref.watch(coreApiProvider).myIdentity(),
);

final recipientKeyProvider = FutureProvider.family<RecipientKeyInfo, String>(
  (ref, email) => ref.watch(coreApiProvider).lookupRecipientKey(email),
);

final backupStatusProvider = FutureProvider<BackupStatus>(
  (ref) => ref.watch(coreApiProvider).backupStatus(),
);

final contactsProvider = FutureProvider<List<ContactKey>>(
  (ref) => ref.watch(coreApiProvider).contacts(),
);

final capabilitiesProvider = FutureProvider<EngineCapabilities>(
  (ref) => ref.watch(coreApiProvider).capabilities(),
);

final signatureProvider = FutureProvider.family<SignatureSettings, String>(
  (ref, accountId) => ref.watch(coreApiProvider).getSignature(accountId),
);

final autoReplyProvider = FutureProvider.family<AutoReplySettings, String>(
  (ref, accountId) => ref.watch(coreApiProvider).getAutoReply(accountId),
);

final autoReplyLogProvider = FutureProvider.family<List<AutoReplyEntry>, String>(
  (ref, accountId) => ref.watch(coreApiProvider).autoReplyLog(accountId),
);

final profileKeyStatusProvider = FutureProvider<ProfileKeyStatus>(
  (ref) => ref.watch(coreApiProvider).profileKeyStatus(),
);

/// Light / dark / system. Settings and the review tour change it. The choice is kept in the
/// app lock's store next to the live-updates choice ([ThemePreference], [themeModeStoreKey]),
/// and the lock screen shown before the engine opens (`LockGateApp`) reads the same entry, so
/// the lock and the app look alike from their first frames (review P6). Without the lock
/// (widget tests, `SEALBOX_APP_LOCK=off`) the choice lasts for the session.
final themeModeProvider = NotifierProvider<ThemeModeController, ThemeMode>(
  ThemeModeController.new,
);

class ThemeModeController extends Notifier<ThemeMode> {
  ThemePreference? _pref;

  /// Completes once the stored choice was read and applied (at once without a store; also at
  /// once when the lock screen already read it in this process).
  Future<void> get loaded => _pref?.load() ?? Future<void>.value();

  @override
  ThemeMode build() {
    final store = ref.watch(liveUpdatesStoreProvider);
    if (store == null) {
      _pref = null;
      return ThemeMode.system;
    }
    final pref = _pref = ThemePreference.of(store);
    void follow() {
      if (ref.mounted) state = pref.value;
    }

    pref.addListener(follow);
    ref.onDispose(() => pref.removeListener(follow));
    unawaited(pref.load());
    // What the lock screen read is known here already: no flash of the system theme.
    return pref.value;
  }

  /// The user's choice: applied at once and stored for the next launch (and its lock
  /// screen). The returned future completes when it is stored; a failing store keeps the
  /// choice for this session only.
  Future<void> set(ThemeMode mode) {
    final pref = _pref;
    if (pref == null) {
      state = mode;
      return Future<void>.value();
    }
    return pref.set(mode);
  }
}

/// Key of the stored theme choice (`system` / `light` / `dark`), next to
/// [liveUpdatesStoreKey] in the same store.
const themeModeStoreKey = 'sealbox.v1.prefs.theme';

/// The theme choice kept in an app-lock [SecretStore] under [themeModeStoreKey]. One object
/// per store and process: the lock screen reads it before its first frame, before the engine
/// (and so the app's providers) exist, and [themeModeProvider] then starts from the value
/// already read, so the first frame after an unlock is in the chosen theme too.
class ThemePreference extends ValueNotifier<ThemeMode> {
  ThemePreference._(this._store) : super(ThemeMode.system);

  static final _byStore = Expando<ThemePreference>('ThemePreference');

  /// The preference kept in [store] (the same object for the same store).
  static ThemePreference of(SecretStore store) => _byStore[store] ??= ThemePreference._(store);

  final SecretStore _store;
  Future<void>? _loading;
  bool _read = false;
  bool _chosen = false;
  Future<void> _writes = Future<void>.value();

  /// [value] is final for now: the stored choice was read, or a choice was made since.
  bool get settled => _read || _chosen;

  /// Reads the stored choice once and applies it; later calls share that read. Never throws:
  /// an unreadable store, or nothing stored, leaves [ThemeMode.system].
  Future<void> load() => _loading ??= _load();

  Future<void> _load() async {
    String? stored;
    try {
      stored = await _store.read(themeModeStoreKey);
    } catch (e) {
      debugPrint('[sealbox] theme: could not read the stored choice: ${friendlyError(e)}');
    }
    _read = true;
    // A choice made while the store was being read wins over what it held.
    final mode = ThemeMode.values.asNameMap()[stored];
    if (!_chosen && mode != null) value = mode;
  }

  /// Applies [mode] at once and stores it; writes run in order, so the last choice is the one
  /// kept. The future completes when it is stored; a failing store keeps it for the session.
  Future<void> set(ThemeMode mode) {
    _chosen = true;
    value = mode;
    return _writes = _writes.then((_) async {
      try {
        await _store.write(themeModeStoreKey, mode.name);
      } catch (e) {
        debugPrint('[sealbox] theme: could not store the choice: ${friendlyError(e)}');
      }
    });
  }
}

/// State of the "fetch new mail" action shown in the inbox app bar.
class SyncStatus {
  const SyncStatus({
    this.running = false,
    this.last,
    this.lastAt,
    this.ranOnce = false,
    this.progress,
  });

  final bool running;
  final SyncOutcome? last;
  final DateTime? lastAt;

  /// True once a sync was attempted in this process (drives the automatic
  /// first sync when the inbox opens).
  final bool ranOnce;

  /// While [running]: the batch the sync stored last — account, folder, phase and counts
  /// (see [SyncProgress]); null before the first one and when no sync runs.
  final SyncProgress? progress;

  SyncStatus copyWith({bool? running, SyncOutcome? last, DateTime? lastAt, bool? ranOnce}) =>
      SyncStatus(
        running: running ?? this.running,
        last: last ?? this.last,
        lastAt: lastAt ?? this.lastAt,
        ranOnce: ranOnce ?? this.ranOnce,
        progress: progress,
      );
}

/// How often the list re-reads the store while a sync or a backfill stores mail: the first
/// stored batch shows at once, later ones at most this often, and the end once more.
const kSyncRefreshEvery = Duration(seconds: 2);

/// Throttles the list refreshes of a run that stores batch after batch: [stored] refreshes at
/// once when no refresh ran in the last [every], otherwise once when that interval is over,
/// so the list is never more than [every] behind the store. The run's owner refreshes once
/// more at the end and [cancel]s this. Timers only (no wall clock), so widget tests drive it
/// with fake time.
class SyncListRefresher {
  SyncListRefresher(this._refresh, {this.every = kSyncRefreshEvery});

  final void Function() _refresh;
  final Duration every;
  Timer? _window;
  bool _behind = false;

  /// A batch was stored.
  void stored() {
    if (_window != null) {
      _behind = true;
      return;
    }
    _refresh();
    _window = Timer(every, _windowEnded);
  }

  void _windowEnded() {
    _window = null;
    if (!_behind) return;
    _behind = false;
    _refresh();
    _window = Timer(every, _windowEnded);
  }

  void cancel() {
    _window?.cancel();
    _window = null;
    _behind = false;
  }
}

/// Syncs every account, one after the other and one run at a time, through
/// `CoreMailOps.syncAccount`: each stored batch updates [SyncStatus.progress] and refreshes
/// the list (the first batch at once, then at most every [kSyncRefreshEvery]); at the end the
/// list, open conversations and contacts re-read the store, and every account whose outcome
/// says older mail is left gets a background backfill ([backfillProvider]). A failing account
/// is reported in the outcome and does not stop the others.
class SyncController extends Notifier<SyncStatus> {
  StreamSubscription<SyncEvent>? _run;
  Completer<AccountSyncOutcome>? _runDone;
  SyncListRefresher? _refresher;

  @override
  SyncStatus build() {
    ref.onDispose(() {
      _run?.cancel();
      _run = null;
      _refresher?.cancel();
      final done = _runDone;
      if (done != null && !done.isCompleted) {
        done.complete(const AccountSyncOutcome(account: '*', error: 'cancelled'));
      }
    });
    return const SyncStatus();
  }

  Future<SyncOutcome?> syncNow() async {
    if (state.running) return null;
    state = SyncStatus(running: true, ranOnce: true, last: state.last, lastAt: state.lastAt);
    final core = ref.read(coreApiProvider);
    // Told, not listening: the backfill controller reading this one would be a cycle.
    final backfill = ref.read(backfillProvider.notifier)..syncStarted();
    final refresher = _refresher = SyncListRefresher(() {
      if (ref.mounted) ref.invalidate(threadsProvider);
    });
    try {
      final accounts = await core.listAccounts();
      final parts = <AccountSyncOutcome>[];
      final older = <String>[];
      for (final a in accounts) {
        if (!ref.mounted) return null;
        final o = await _sync(core, a, refresher);
        parts.add(o);
        if (o.ok && o.moreToBackfill) older.add(a.id);
      }
      refresher.cancel();
      final outcome = SyncOutcome(parts);
      if (!ref.mounted) return outcome;
      state = SyncStatus(running: false, ranOnce: true, last: outcome, lastAt: DateTime.now());
      // The list and every open conversation (family) re-read the store.
      ref.invalidate(threadsProvider);
      ref.invalidate(threadProvider);
      ref.invalidate(contactsProvider);
      backfill.syncEnded(older);
      return outcome;
    } catch (e) {
      refresher.cancel();
      if (!ref.mounted) return null;
      state = SyncStatus(
        running: false,
        ranOnce: true,
        last: SyncOutcome([AccountSyncOutcome(account: '*', error: '$e')]),
        lastAt: DateTime.now(),
      );
      backfill.syncEnded(const []);
      return state.last;
    }
  }

  /// One account's run: its batches go into [state] and the list; returns its outcome, or
  /// its error as one.
  Future<AccountSyncOutcome> _sync(CoreApi core, Account account, SyncListRefresher refresher) {
    final done = _runDone = Completer<AccountSyncOutcome>();
    AccountSyncOutcome? outcome;
    // The previous account's last batch says nothing about this one.
    state = SyncStatus(running: true, ranOnce: true, last: state.last, lastAt: state.lastAt);
    void finish(AccountSyncOutcome o) {
      _run = null;
      if (!done.isCompleted) done.complete(o);
    }

    try {
      _run = core
          .syncAccount(account.id)
          .listen(
            (e) {
              if (!ref.mounted) return;
              if (e.progress case final p?) {
                state = SyncStatus(
                  running: true,
                  ranOnce: true,
                  last: state.last,
                  lastAt: state.lastAt,
                  progress: p,
                );
                refresher.stored();
              }
              outcome = e.outcome ?? outcome;
            },
            onError: (Object e) =>
                finish(AccountSyncOutcome(account: account.email, error: friendlyError(e))),
            onDone: () => finish(
              outcome ??
                  AccountSyncOutcome(
                    account: account.email,
                    error: 'the sync ended without a report',
                  ),
            ),
            cancelOnError: true,
          );
    } catch (e) {
      finish(AccountSyncOutcome(account: account.email, error: friendlyError(e)));
    }
    return done.future;
  }
}

final syncControllerProvider = NotifierProvider<SyncController, SyncStatus>(
  SyncController.new,
);

// -- background backfill: the older mail a first sync's window left on the server --------

/// Older messages one background backfill step asks the engine for. The engine holds the
/// account's mailbox lock for a whole step, so new mail (a watcher round, "Fetch new mail")
/// waits for at most one step, and stopping takes effect when the step is over.
const kBackfillStep = 1000;

/// What the background backfill is doing; the inbox shows it as a quiet line under its
/// title (`Key('backfill-status')`).
class BackfillStatus {
  const BackfillStatus({
    this.accountId,
    this.progress,
    this.queued = const [],
    this.failures = 0,
    this.retryIn,
    this.error,
    this.paused = false,
  });

  /// The account whose older mail is being fetched (or that waits to retry); null when idle.
  final String? accountId;

  /// The batch its backfill stored last (null before the first one).
  final SyncProgress? progress;

  /// Accounts waiting their turn: one backfill runs at a time.
  final List<String> queued;

  /// Consecutive failed steps of [accountId].
  final int failures;

  /// After a failed step: the wait before the next attempt ([liveRetryDelay]).
  final Duration? retryIn;

  /// Why the last step failed.
  final String? error;

  /// No step starts now: a sync runs (it needs the same mailbox lock and fetches 1,000 older
  /// messages itself), or the app is in the background (paused, on a phone).
  final bool paused;

  bool get active => accountId != null;

  static const _keep = Object();

  BackfillStatus copyWith({
    Object? accountId = _keep,
    Object? progress = _keep,
    List<String>? queued,
    int? failures,
    Object? retryIn = _keep,
    Object? error = _keep,
    bool? paused,
  }) => BackfillStatus(
    accountId: identical(accountId, _keep) ? this.accountId : accountId as String?,
    progress: identical(progress, _keep) ? this.progress : progress as SyncProgress?,
    queued: queued ?? this.queued,
    failures: failures ?? this.failures,
    retryIn: identical(retryIn, _keep) ? this.retryIn : retryIn as Duration?,
    error: identical(error, _keep) ? this.error : error as String?,
    paused: paused ?? this.paused,
  );
}

/// Errors a backfill does not retry on its own: a rejected login (retrying can lock the
/// account at the provider), no OAuth sign-in, an account the engine no longer has. The next
/// sync that reports older mail asks again.
bool isPermanentBackfillError(Object error) =>
    isPermanentWatchError(error) || friendlyError(error).contains('account not found');

/// Fetches the older mail a first sync's window left on the server, in the background. After a
/// sync whose outcome says `moreToBackfill`, [SyncController] asks for it ([request]); one
/// account at a time, [kBackfillStep] messages per `CoreMailOps.backfill` call until nothing
/// is left. Its batches refresh the list like a sync's do (at most every [kSyncRefreshEvery])
/// and each account's end once more. A failed step is retried after 1 s, 2 s, 4 s … 60 s
/// ([liveRetryDelay], like live updates); [isPermanentBackfillError]s stop the account until a
/// sync asks again. No step starts while a sync runs ([syncStarted] / [syncEnded]) or while
/// the app is in the background; removing an account drops its backfill. A step already
/// running finishes (the engine cannot stop between batches) and keeps what it stored.
class BackfillController extends Notifier<BackfillStatus> {
  StreamSubscription<SyncEvent>? _step;
  Timer? _retry;
  SyncListRefresher? _refresher;
  bool _syncing = false;
  bool _background = false;

  /// Identifies the current step; events of a step that was dropped are ignored.
  int _stepId = 0;

  bool get _paused => _syncing || _background;

  @override
  BackfillStatus build() {
    final lifecycle = AppLifecycleListener(
      onStateChange: (s) => _setBackground(s == AppLifecycleState.paused),
    );
    ref.listen<AsyncValue<List<Account>>>(accountsProvider, (_, next) {
      if (next.value case final accounts?) _dropRemoved(accounts);
    });
    ref.onDispose(() {
      lifecycle.dispose();
      _stopStep();
      _retry?.cancel();
      _retry = null;
    });
    return BackfillStatus(paused: _paused);
  }

  /// Fetch [accountId]'s older mail in the background. Already queued or running: nothing
  /// changes, except that one waiting to retry after a failure tries again now.
  void request(String accountId) {
    if (!ref.mounted) return;
    final s = state;
    if (s.accountId == accountId) {
      if (_retry != null) {
        _retry!.cancel();
        _retry = null;
        state = s.copyWith(retryIn: null);
        _next();
      }
      return;
    }
    if (s.queued.contains(accountId)) return;
    state = s.accountId == null
        ? BackfillStatus(accountId: accountId, queued: s.queued, paused: _paused)
        : s.copyWith(queued: [...s.queued, accountId]);
    _next();
  }

  /// A sync starts ([SyncController]): no step starts until it ends — it needs the same
  /// mailbox lock, and it fetches some older mail itself.
  void syncStarted() {
    _syncing = true;
    _pausedChanged();
  }

  /// The sync ended; the accounts in [olderLeft] reported older mail still on the server.
  void syncEnded(Iterable<String> olderLeft) {
    _syncing = false;
    for (final id in olderLeft) {
      request(id);
    }
    _pausedChanged();
  }

  void _setBackground(bool background) {
    _background = background;
    _pausedChanged();
  }

  void _pausedChanged() {
    if (!ref.mounted) return;
    if (state.paused != _paused) state = state.copyWith(paused: _paused);
    _next();
  }

  /// Starts the current account's next step unless one runs, a retry waits, or it is paused.
  void _next() {
    if (!ref.mounted || _step != null || _retry != null || _paused) return;
    final accountId = state.accountId;
    if (accountId == null) return;
    final stepId = ++_stepId;
    final refresher = _refresher ??= SyncListRefresher(() {
      if (ref.mounted) ref.invalidate(threadsProvider);
    });
    AccountSyncOutcome? outcome;
    try {
      _step = ref
          .read(coreApiProvider)
          .backfill(accountId, max: kBackfillStep)
          .listen(
            (e) {
              if (stepId != _stepId || !ref.mounted) return;
              if (e.progress case final p?) {
                state = state.copyWith(progress: p);
                refresher.stored();
              }
              outcome = e.outcome ?? outcome;
            },
            onError: (Object e) => _failed(stepId, e),
            onDone: () {
              final o = outcome;
              if (o == null) {
                _failed(stepId, StateError('the backfill ended without a report'));
              } else if (!o.ok) {
                _failed(stepId, o.error!);
              } else {
                _stepDone(stepId, o);
              }
            },
            cancelOnError: true,
          );
    } catch (e) {
      _failed(stepId, e);
    }
  }

  void _stepDone(int stepId, AccountSyncOutcome outcome) {
    if (stepId != _stepId) return;
    _step = null;
    if (!ref.mounted) return;
    state = state.copyWith(failures: 0, retryIn: null, error: null);
    if (outcome.moreToBackfill) {
      _next();
    } else {
      _advance();
    }
  }

  void _failed(int stepId, Object error) {
    if (stepId != _stepId) return;
    _step = null;
    if (!ref.mounted) return;
    final why = friendlyError(error);
    if (isPermanentBackfillError(error)) {
      debugPrint('[sealbox] backfill of ${state.accountId} stopped: $why');
      _advance();
      return;
    }
    final failures = state.failures + 1;
    final delay = liveRetryDelay(failures);
    state = state.copyWith(failures: failures, retryIn: delay, error: why);
    _retry = Timer(delay, () {
      _retry = null;
      if (!ref.mounted) return;
      state = state.copyWith(retryIn: null);
      _next();
    });
  }

  /// The current account is done (or dropped): refresh once more, start the next one.
  void _advance() {
    _stopStep();
    _retry?.cancel();
    _retry = null;
    ref.invalidate(threadsProvider);
    ref.invalidate(threadProvider);
    ref.invalidate(contactsProvider);
    final rest = state.queued;
    state = BackfillStatus(
      accountId: rest.firstOrNull,
      queued: rest.skip(1).toList(),
      paused: _paused,
    );
    _next();
  }

  /// Ignores the running step's further events (the engine still finishes it) and stops its
  /// list refreshes.
  void _stopStep() {
    _stepId++;
    _step?.cancel();
    _step = null;
    _refresher?.cancel();
    _refresher = null;
  }

  void _dropRemoved(List<Account> accounts) {
    if (!ref.mounted) return;
    final ids = {for (final a in accounts) a.id};
    final s = state;
    final queued = [
      for (final id in s.queued)
        if (ids.contains(id)) id,
    ];
    if (s.accountId != null && !ids.contains(s.accountId)) {
      _stopStep();
      _retry?.cancel();
      _retry = null;
      state = BackfillStatus(
        accountId: queued.firstOrNull,
        queued: queued.skip(1).toList(),
        paused: _paused,
      );
      _next();
    } else if (queued.length != s.queued.length) {
      state = s.copyWith(queued: queued);
    }
  }
}

final backfillProvider = NotifierProvider<BackfillController, BackfillStatus>(
  BackfillController.new,
);

// -- live updates (IMAP IDLE) -----------------------------------------------------------

/// Whether live updates are on before the user has chosen (Settings → Appearance & sync).
///
/// On since 2026-10-29: every account then holds one more IMAP connection (the watchers
/// reconnect with backoff and stop on a rejected login), and the G17 integration gate is
/// deterministic with watchers running (conversation-root fix). It was off before because
/// a watcher's own syncs raced the gate's sync timing. A stored choice always wins over it.
const bool kLiveUpdatesDefault = true;

/// Where the live-updates choice is kept between launches: the app lock's store, i.e. the
/// OS keystore (or, without one, the profile-local file) where the lock keeps its own
/// auto-lock and biometrics settings. The app has no other preference store; the theme
/// choice is kept here too ([ThemePreference]). `null` when the app runs without the lock
/// (widget tests, scripted runs with `SEALBOX_APP_LOCK=off`): choices then last for the
/// session.
final liveUpdatesStoreProvider = Provider<SecretStore?>((ref) => ref.watch(appLockProvider)?.store);

/// Key of the stored choice (`on` / `off`). Per device in the OS keystore: the lock's
/// per-profile key prefix is private to `AppLockController`. The file fallback and the
/// review loop's throw-away profiles are per profile anyway.
const liveUpdatesStoreKey = 'sealbox.v1.prefs.live_updates';

/// Whether the app keeps an IMAP IDLE watcher per account ([liveWatchProvider]). Starts at
/// [kLiveUpdatesDefault] and switches to the stored choice as soon as it is read. Safe to
/// turn on: the engine serialises syncs per account (its mailbox lock, unit tested in
/// `sealbox-core`), so a watcher's sync and a manual fetch of the same account queue
/// behind each other instead of overlapping.
final liveUpdatesProvider = NotifierProvider<LiveUpdatesController, bool>(
  LiveUpdatesController.new,
);

class LiveUpdatesController extends Notifier<bool> {
  bool _chosen = false;
  Future<void> _loaded = Future<void>.value();
  Future<void> _writes = Future<void>.value();

  /// Completes once the stored choice was read and applied (at once without a store).
  Future<void> get loaded => _loaded;

  @override
  bool build() {
    final store = ref.watch(liveUpdatesStoreProvider);
    if (store != null) _loaded = _load(store);
    return kLiveUpdatesDefault;
  }

  Future<void> _load(SecretStore store) async {
    final String? stored;
    try {
      stored = await store.read(liveUpdatesStoreKey);
    } catch (e) {
      debugPrint('[sealbox] live updates: could not read the stored choice: ${friendlyError(e)}');
      return;
    }
    // A choice made while the store was being read wins over what it held.
    if (!ref.mounted || _chosen) return;
    if (stored == 'on' || stored == 'off') state = stored == 'on';
  }

  /// The user's choice: applied at once and stored for the next launch (writes run in
  /// order, so the last choice is the one kept). The returned future completes when it is
  /// stored; a failing store keeps the choice for this session only.
  Future<void> set(bool on) {
    _chosen = true;
    state = on;
    final store = ref.read(liveUpdatesStoreProvider);
    if (store == null) return Future<void>.value();
    return _writes = _writes.then((_) async {
      try {
        await store.write(liveUpdatesStoreKey, on ? 'on' : 'off');
      } catch (e) {
        debugPrint('[sealbox] live updates: could not store the choice: ${friendlyError(e)}');
      }
    });
  }
}

/// First wait before reconnecting a watcher whose session failed or ended.
const kLiveRetryFirst = Duration(seconds: 1);

/// The longest wait between two reconnect attempts.
const kLiveRetryMax = Duration(seconds: 60);

/// How long a watcher must stay armed before its backoff starts over (see [LiveWatchState.failures]).
const kLiveStableAfter = Duration(seconds: 30);

/// The wait before the next attempt after [failures] consecutive failed sessions:
/// 1 s, 2 s, 4 s, … doubling up to [kLiveRetryMax].
Duration liveRetryDelay(int failures) {
  if (failures <= 1) return kLiveRetryFirst;
  final ms = kLiveRetryFirst.inMilliseconds << (failures - 1).clamp(0, 20);
  return Duration(milliseconds: ms.clamp(0, kLiveRetryMax.inMilliseconds));
}

/// Errors a watcher does not retry on its own ([LiveWatchPhase.stopped]): the server has no
/// IDLE, the server rejected the credentials (`sealbox-mail` `ImapError::LoginRejected`,
/// `login to HOST rejected (MECHANISM): …`), or it offers no OAuth sign-in. Retrying a
/// rejected login every minute can lock the account at the provider; a manual fetch tries
/// again. A `BYE` greeting ("authentication failed: …", a busy server) stays a retry.
bool isPermanentWatchError(Object error) {
  final s = friendlyError(error).toLowerCase();
  return isIdleUnsupportedError(error) ||
      _loginRejected.hasMatch(s) ||
      s.contains('does not offer oauth sign-in');
}

final _loginRejected = RegExp(r'login to \S+ rejected \(');

/// The server does not advertise IMAP IDLE (`sealbox-mail` `ImapError::IdleUnsupported`).
bool isIdleUnsupportedError(Object error) =>
    friendlyError(error).toLowerCase().contains('does not advertise idle');

/// What one account's IMAP IDLE watcher is doing.
enum LiveWatchPhase {
  /// Signing in and arming IDLE (the first attempt, or a retry).
  connecting,

  /// Armed: the server announces new mail and the watcher syncs it.
  live,

  /// The last session failed or ended; the next attempt starts after [LiveWatchState.retryIn].
  waiting,

  /// Not retried on its own ([isPermanentWatchError]); a manual fetch tries again unless the
  /// server has no IDLE at all.
  stopped,
}

/// One account's watcher.
class LiveWatchState {
  const LiveWatchState({
    this.phase = LiveWatchPhase.connecting,
    this.failures = 0,
    this.retryIn,
    this.error,
  });

  final LiveWatchPhase phase;

  /// Consecutive sessions that failed or ended since the watcher last proved healthy: an
  /// IDLE round that completed (new mail or the server's timeout), or [kLiveStableAfter]
  /// armed without an error. A session that dies right after arming does not count as
  /// healthy, so a server that drops every IDLE is not hammered once a second.
  final int failures;

  /// [LiveWatchPhase.waiting]: the wait before the next attempt.
  final Duration? retryIn;

  /// Why the last session ended ([LiveWatchPhase.waiting] / [LiveWatchPhase.stopped]).
  final String? error;
}

/// The overall state the inbox app bar shows (`Key('live-status')`).
enum LiveStatus {
  /// Live updates are off, or every watcher stopped.
  off,

  /// Watchers are signing in (no failure yet).
  connecting,

  /// Every running watcher is armed.
  on,

  /// At least one watcher lost its session and waits to reconnect.
  reconnecting,
}

class LiveUpdatesState {
  const LiveUpdatesState({required this.enabled, this.accounts = const {}});

  /// The Settings switch ([liveUpdatesProvider]).
  final bool enabled;

  /// Watchers by account id (empty while off).
  final Map<String, LiveWatchState> accounts;

  LiveStatus get status {
    if (!enabled) return LiveStatus.off;
    final phases = {for (final a in accounts.values) a.phase};
    if (phases.contains(LiveWatchPhase.waiting)) return LiveStatus.reconnecting;
    if (phases.contains(LiveWatchPhase.connecting)) return LiveStatus.connecting;
    if (phases.length == 1 && phases.single == LiveWatchPhase.stopped) return LiveStatus.off;
    return LiveStatus.on;
  }
}

/// One IMAP IDLE watcher per account while live updates are on. A session that errors or
/// ends is reconnected after [liveRetryDelay] (1 s, 2 s, 4 s … 60 s), which starts over
/// once the watcher proved healthy (see [LiveWatchState.failures]); new mail refreshes the
/// list and any open conversation. Turning live updates off, or removing an account, cancels
/// its watcher. Started by the first screen that shows the state (the inbox app bar,
/// Settings) and kept for the app's lifetime.
final liveWatchProvider = NotifierProvider<LiveWatchController, LiveUpdatesState>(
  LiveWatchController.new,
);

class LiveWatchController extends Notifier<LiveUpdatesState> {
  final _watches = <String, _AccountWatch>{};

  /// The notifier outlives its builds (Riverpod reuses it when the switch flips), so work
  /// scheduled by one build checks that it is still the current, undisposed one.
  int _build = 0;
  bool _active = false;

  @override
  LiveUpdatesState build() {
    final enabled = ref.watch(liveUpdatesProvider);
    final build = ++_build;
    _active = true;
    ref.onDispose(() {
      if (build == _build) _active = false;
      for (final w in _watches.values) {
        w.dispose();
      }
      _watches.clear();
    });
    if (!enabled) return const LiveUpdatesState(enabled: false);
    // Not during build: starting a watcher can publish a state at once.
    ref.listen<AsyncValue<List<Account>>>(accountsProvider, (_, next) {
      final list = next.value;
      if (list == null) return;
      scheduleMicrotask(() {
        if (build == _build) _reconcile(list);
      });
    }, fireImmediately: true);
    return const LiveUpdatesState(enabled: true);
  }

  bool get _disposed => !_active;

  void _reconcile(List<Account> accounts) {
    if (_disposed) return;
    final ids = {for (final a in accounts) a.id};
    var changed = false;
    for (final id in [..._watches.keys]) {
      if (ids.contains(id)) continue;
      _watches.remove(id)!.dispose();
      changed = true;
    }
    final core = ref.read(coreApiProvider);
    for (final id in ids) {
      if (_watches.containsKey(id)) continue;
      final w = _AccountWatch(id, core, onChange: _publish, onNewMail: _newMail);
      _watches[id] = w;
      w.start();
      changed = true;
    }
    if (changed) _publish();
  }

  void _publish() {
    if (_disposed) return;
    state = LiveUpdatesState(
      enabled: true,
      accounts: {for (final e in _watches.entries) e.key: e.value.state},
    );
  }

  /// Like a finished fetch: the list, open conversations and contacts re-read the store.
  void _newMail() {
    if (_disposed) return;
    ref.invalidate(threadsProvider);
    ref.invalidate(threadProvider);
    ref.invalidate(contactsProvider);
  }

  /// A manual fetch: every waiting or stopped watcher tries again now, with a fresh backoff
  /// (a server without IDLE is not asked again).
  void retryNow() {
    if (_disposed) return;
    for (final w in _watches.values) {
      w.retryNow();
    }
  }
}

class _AccountWatch {
  _AccountWatch(this.accountId, this._core, {required this.onChange, required this.onNewMail});

  final String accountId;
  final CoreApi _core;
  final void Function() onChange;
  final void Function() onNewMail;

  LiveWatchState state = const LiveWatchState();
  StreamSubscription<MailEvent>? _sub;
  Timer? _retry;
  Timer? _stable;

  /// Identifies the current session; callbacks of an older one are ignored.
  int _session = 0;
  bool _disposed = false;
  bool _unsupported = false;

  void start() {
    if (_disposed) return;
    _retry?.cancel();
    _retry = null;
    final session = ++_session;
    state = LiveWatchState(phase: LiveWatchPhase.connecting, failures: state.failures);
    try {
      _sub = _core
          .watch(accountId)
          .listen(
            (e) => _event(session, e),
            onError: (Object e) => _ended(session, e),
            onDone: () => _ended(session, null),
            cancelOnError: true,
          );
    } catch (e) {
      _ended(session, e);
      return;
    }
    onChange();
  }

  void _event(int session, MailEvent e) {
    if (_disposed || session != _session) return;
    var failures = state.failures;
    if (e.kind == MailEventKind.idle) {
      // Armed. Healthy only if it stays up (or completes a round, below).
      _stable ??= Timer(kLiveStableAfter, () {
        _stable = null;
        if (_disposed || session != _session) return;
        state = LiveWatchState(phase: state.phase, failures: 0);
        onChange();
      });
    } else {
      _stable?.cancel();
      _stable = null;
      failures = 0;
    }
    state = LiveWatchState(phase: LiveWatchPhase.live, failures: failures);
    onChange();
    if (e.kind == MailEventKind.newMail && e.newMessages > 0) onNewMail();
  }

  void _ended(int session, Object? error) {
    if (_disposed || session != _session) return;
    _session++; // a late onDone after onError belongs to the finished session
    _sub = null;
    _stable?.cancel();
    _stable = null;
    final reason = error == null ? 'the connection ended' : friendlyError(error);
    if (error != null && isPermanentWatchError(error)) {
      _unsupported = isIdleUnsupportedError(error);
      state = LiveWatchState(
        phase: LiveWatchPhase.stopped,
        failures: state.failures,
        error: reason,
      );
      onChange();
      return;
    }
    final failures = state.failures + 1;
    final delay = liveRetryDelay(failures);
    state = LiveWatchState(
      phase: LiveWatchPhase.waiting,
      failures: failures,
      retryIn: delay,
      error: reason,
    );
    _retry = Timer(delay, start);
    onChange();
  }

  void retryNow() {
    if (_disposed) return;
    final p = state.phase;
    if (p != LiveWatchPhase.waiting && p != LiveWatchPhase.stopped) return;
    if (p == LiveWatchPhase.stopped && _unsupported) return;
    state = const LiveWatchState(phase: LiveWatchPhase.connecting);
    start();
  }

  void dispose() {
    _disposed = true;
    _session++;
    _sub?.cancel();
    _sub = null;
    _retry?.cancel();
    _retry = null;
    _stable?.cancel();
    _stable = null;
  }
}

// -- identity (G30) and recovery (G15) ------------------------------------------

/// Key-transparency audit per account. Runs once per session when Settings
/// opens; "Check now" invalidates it.
final ktAuditProvider = FutureProvider.family<KtAudit, String>(
  (ref, accountId) => ref.watch(coreApiProvider).ktAudit(accountId),
);

/// Backup bookkeeping + reminder per account.
final recoveryStatusProvider = FutureProvider.family<BackupStatus, String>(
  (ref, accountId) => ref.watch(coreApiProvider).recoveryStatus(accountId),
);

/// The configured Sealbox server (backups, guest links, key transparency).
final serverUrlProvider = FutureProvider<String?>(
  (ref) => ref.watch(coreApiProvider).serverUrl(),
);

/// `OPENPGP4FPR:` payload of one of our accounts (the QR code).
final fingerprintQrProvider = FutureProvider.family<String, String>(
  (ref, accountId) => ref.watch(coreApiProvider).fingerprintQrPayload(accountId),
);

/// The contact behind [address] (null when we hold no state for it).
final contactProvider = FutureProvider.family<ContactKey?, String>((ref, address) async {
  final list = await ref.watch(contactsProvider.future);
  final a = address.trim().toLowerCase();
  for (final c in list) {
    if (c.address.toLowerCase() == a) return c;
  }
  return null;
});

/// After verify / accept / unverify: everything that shows identity state.
void invalidateIdentity(WidgetRef ref) {
  ref.invalidate(contactsProvider);
  ref.invalidate(contactProvider);
  ref.invalidate(threadsProvider);
  ref.invalidate(threadProvider);
}

// -- folders by role: first-open sync of Spam / Trash / Archive ---------------------

/// Whether a chip's folder needs a sync of its own when it is opened: INBOX and
/// Sent come with every fetch (`syncAll`); Spam, Trash and Archive do not.
bool roleNeedsOwnSync(FolderRole? role) =>
    role == FolderRole.junk || role == FolderRole.trash || role == FolderRole.archive;

/// Sync bookkeeping of one role's folder across the accounts (this session).
class RoleSyncState {
  const RoleSyncState({
    this.synced = const {},
    this.attempted = const {},
    this.running = false,
    this.last,
    this.lastAt,
  });

  /// Accounts whose folder for this role was fetched successfully this session.
  final Set<String> synced;

  /// Accounts a sync was attempted for (successful or not): the automatic
  /// first-open sync runs once per account; a failure waits for "Sync now".
  final Set<String> attempted;
  final bool running;
  final SyncOutcome? last;
  final DateTime? lastAt;

  bool syncedAll(Iterable<Account> accounts) => accounts.every((a) => synced.contains(a.id));

  /// The first error of the last sync, if any.
  String? get lastError => last?.errors.firstOrNull?.error;

  RoleSyncState copyWith({
    Set<String>? synced,
    Set<String>? attempted,
    bool? running,
    SyncOutcome? last,
    DateTime? lastAt,
  }) => RoleSyncState(
    synced: synced ?? this.synced,
    attempted: attempted ?? this.attempted,
    running: running ?? this.running,
    last: last ?? this.last,
    lastAt: lastAt ?? this.lastAt,
  );
}

/// Runs `syncFolder(role)` per account: automatically the first time a chip is
/// opened in a session ([ensureSynced]), on pull-to-refresh / the sync button
/// ([syncNow]), and again after something was moved into that folder ([markStale]):
/// the real engine drops a moved message locally until its new folder is fetched.
class FolderSyncController extends Notifier<Map<FolderRole, RoleSyncState>> {
  @override
  Map<FolderRole, RoleSyncState> build() => const {};

  RoleSyncState of(FolderRole role) => state[role] ?? const RoleSyncState();

  void _put(FolderRole role, RoleSyncState s) => state = {...state, role: s};

  /// Syncs the accounts that were not tried yet this session (none: returns null).
  Future<SyncOutcome?> ensureSynced(FolderRole role, List<Account> accounts) {
    final s = of(role);
    final todo = [
      for (final a in accounts)
        if (!s.attempted.contains(a.id)) a,
    ];
    if (todo.isEmpty || s.running) return Future.value(null);
    return _sync(role, todo);
  }

  /// Syncs every account's folder for [role] now (refresh / "Sync now").
  Future<SyncOutcome?> syncNow(FolderRole role, List<Account> accounts) =>
      of(role).running ? Future.value(null) : _sync(role, accounts);

  /// Something was moved into [role]'s folder of [accountId]: fetch it again on the
  /// next open (the engine shows the message there only after that sync).
  void markStale(FolderRole role, String accountId) {
    final s = of(role);
    if (!s.attempted.contains(accountId) && !s.synced.contains(accountId)) return;
    _put(
      role,
      s.copyWith(
        synced: {...s.synced}..remove(accountId),
        attempted: {...s.attempted}..remove(accountId),
      ),
    );
  }

  Future<SyncOutcome?> _sync(FolderRole role, List<Account> accounts) async {
    if (accounts.isEmpty) return null;
    final start = of(role);
    _put(role, start.copyWith(running: true, attempted: {...start.attempted, ...accounts.map((a) => a.id)}));
    final core = ref.read(coreApiProvider);
    final parts = <AccountSyncOutcome>[];
    final ok = <String>{};
    for (final a in accounts) {
      try {
        final o = await core.syncFolder(role, accountId: a.id);
        parts.addAll(o.accounts);
        if (o.errors.isEmpty) ok.add(a.id);
      } catch (e) {
        parts.add(AccountSyncOutcome(account: a.email, error: friendlyError(e)));
      }
    }
    final outcome = SyncOutcome(parts);
    if (!ref.mounted) return outcome;
    final now = of(role);
    _put(
      role,
      now.copyWith(
        running: false,
        synced: {...now.synced.where((id) => !accounts.any((a) => a.id == id)), ...ok},
        last: outcome,
        lastAt: DateTime.now(),
      ),
    );
    ref.invalidate(threadsProvider);
    ref.invalidate(threadProvider);
    return outcome;
  }
}

final folderSyncProvider = NotifierProvider<FolderSyncController, Map<FolderRole, RoleSyncState>>(
  FolderSyncController.new,
);

/// Every special-use role of an account with its server folder (no network).
final folderRolesProvider = FutureProvider.family<List<FolderRoleInfo>, String>(
  (ref, accountId) => ref.watch(coreApiProvider).folderRoles(accountId),
);

// -- spam and filter rules ----------------------------------------------------------

final spamStatusProvider = FutureProvider<SpamStatus>(
  (ref) => ref.watch(coreApiProvider).spamStatus(),
);

final spamSettingsProvider = FutureProvider.family<SpamSettings, String>(
  (ref, accountId) => ref.watch(coreApiProvider).spamSettings(accountId),
);

final filterRulesProvider = FutureProvider.family<List<FilterRule>, String>(
  (ref, accountId) => ref.watch(coreApiProvider).filterRules(accountId),
);

// -- the Sealbox server and its key directory ---------------------------------------

/// Where the effective server URL comes from (settings / environment / none).
final serverUrlSourceProvider = FutureProvider<ServerUrlSource>(
  (ref) => ref.watch(coreApiProvider).serverUrlSource(),
);

/// What the key directory holds for one account. Read once per invalidation: the
/// engine asks the server each time.
final directoryStatusProvider = FutureProvider.family<DirectoryStatus, String>(
  (ref, accountId) => ref.watch(coreApiProvider).directoryStatus(accountId),
);

/// After the server URL changed: everything that depends on the server.
void invalidateServer(WidgetRef ref) {
  ref.invalidate(serverUrlProvider);
  ref.invalidate(serverUrlSourceProvider);
  ref.invalidate(capabilitiesProvider);
  ref.invalidate(backupStatusProvider);
  ref.invalidate(recoveryStatusProvider);
  ref.invalidate(directoryStatusProvider);
  ref.invalidate(ktAuditProvider);
}
