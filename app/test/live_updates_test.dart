import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/lock/secret_store.dart';

import 'helpers.dart';

// Live updates (IMAP IDLE): the Settings choice is stored (the app lock's store), and a
// watcher whose stream errors or ends reconnects with exponential backoff instead of
// dying silently; the inbox app bar shows the state (Key('live-status')).

/// FakeCore whose IDLE streams the test drives: every `watch` call opens a session.
class LiveCore extends FakeCore {
  LiveCore() : super(latency: Duration.zero);

  final sessions = <({String account, StreamController<MailEvent> stream})>[];

  /// `listThreadsInRole` calls: the inbox list re-reading the store.
  int listCalls = 0;

  @override
  Stream<MailEvent> watch(String accountId) {
    final c = StreamController<MailEvent>();
    sessions.add((account: accountId, stream: c));
    return c.stream;
  }

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) {
    listCalls++;
    return super.listThreadsInRole(role, accountId: accountId);
  }

  int sessionsOf(String account) => sessions.where((s) => s.account == account).length;

  StreamController<MailEvent> current(String account) =>
      sessions.lastWhere((s) => s.account == account).stream;

  void emit(String account, MailEventKind kind, {int newMessages = 0}) =>
      current(account).add(MailEvent(kind, account: account, newMessages: newMessages));

  void fail(String account, [Object? error]) =>
      current(account).addError(error ?? Exception('IMAP: connection reset by peer'));

  bool listening(String account) => current(account).hasListener;
}

/// A store holding [value] under the live-updates key (none for null).
MemorySecretStore storeWith(String? value) {
  final s = MemorySecretStore();
  if (value != null) s.values[liveUpdatesStoreKey] = value;
  return s;
}

const gmail = 'acct-1';
const fastmail = 'acct-2';

Future<LiveCore> pumpInbox(WidgetTester tester, {String stored = 'on', LiveCore? core}) async {
  setSurface(tester, desktop);
  final c = core ?? LiveCore();
  await tester.pumpWidget(
    buildApp(core: c, overrides: [liveUpdatesStoreProvider.overrideWithValue(storeWith(stored))]),
  );
  await tester.pumpAndSettle();
  return c;
}

Finder statusIs(LiveStatus s) => find.byKey(ValueKey('live-status-${s.name}'));

/// Delivers what the test streams emitted (one microtask flush) and draws the frame the
/// resulting state change scheduled, without moving the clock.
Future<void> flush(WidgetTester tester) async {
  await tester.pump();
  await tester.pump();
}

String tooltipOfStatus(WidgetTester tester) => tester
    .widget<Tooltip>(
      find.descendant(of: find.byKey(const Key('live-status')), matching: find.byType(Tooltip)),
    )
    .message!;

void main() {
  test('backoff: 1 s, 2 s, 4 s … doubling, capped at 60 s', () {
    expect(
      [for (var n = 1; n <= 9; n++) liveRetryDelay(n).inSeconds],
      [1, 2, 4, 8, 16, 32, 60, 60, 60],
    );
    expect(liveRetryDelay(0), kLiveRetryFirst);
    expect(liveRetryDelay(1000), kLiveRetryMax);
  });

  test('permanent errors: no IDLE, rejected sign-in; network trouble is retried', () {
    expect(isPermanentWatchError(Exception('IMAP: server does not advertise IDLE')), isTrue);
    expect(isIdleUnsupportedError('AnyhowException(IMAP: server does not advertise IDLE)'), isTrue);
    expect(
      isPermanentWatchError(
        'AnyhowException(IMAP: login to imap.gmail.com rejected (LOGIN): [AUTHENTICATIONFAILED] '
        'Invalid credentials)',
      ),
      isTrue,
    );
    expect(
      isPermanentWatchError('IMAP: authentication failed: * BYE too many connections'),
      isFalse,
      reason: 'a BYE greeting is a busy server: retried with backoff',
    );
    expect(
      isPermanentWatchError('imap.example.org does not offer OAuth sign-in over IMAP (no …)'),
      isTrue,
    );
    expect(
      isPermanentWatchError('IMAP: connect to 10.0.0.1:993 failed: Connection refused'),
      isFalse,
    );
    expect(isPermanentWatchError('timed out after 30s'), isFalse);
  });

  testWidgets('a watch error shows "reconnecting"; the watcher reconnects after 1 s and recovers', (
    tester,
  ) async {
    final core = await pumpInbox(tester);
    expect(core.sessionsOf(gmail), 1);
    expect(core.sessionsOf(fastmail), 1);
    expect(statusIs(LiveStatus.connecting), findsOneWidget);

    core.emit(gmail, MailEventKind.idle);
    core.emit(fastmail, MailEventKind.idle);
    await flush(tester);
    expect(statusIs(LiveStatus.on), findsOneWidget);
    expect(tooltipOfStatus(tester), contains('Live updates on'));

    core.fail(gmail);
    await flush(tester);
    expect(statusIs(LiveStatus.reconnecting), findsOneWidget);
    expect(
      tooltipOfStatus(tester),
      contains('alice.rivera@gmail.com in 1 s (IMAP: connection reset by peer)'),
    );
    expect(
      tester.getSemantics(find.byKey(const Key('live-status'))),
      matchesSemantics(label: 'Live updates reconnecting', tooltip: tooltipOfStatus(tester)),
    );

    await tester.pump(const Duration(milliseconds: 999));
    expect(core.sessionsOf(gmail), 1, reason: 'not before the backoff');
    await tester.pump(const Duration(milliseconds: 1));
    expect(core.sessionsOf(gmail), 2);
    expect(core.sessionsOf(fastmail), 1, reason: 'the other account was never touched');
    await flush(tester);
    expect(statusIs(LiveStatus.connecting), findsOneWidget);

    core.emit(gmail, MailEventKind.idle);
    await flush(tester);
    expect(statusIs(LiveStatus.on), findsOneWidget);
  });

  testWidgets('the backoff doubles while sessions keep failing and starts over once healthy', (
    tester,
  ) async {
    final core = await pumpInbox(tester);
    Future<void> failAndExpectRetryAfter(int seconds) async {
      final before = core.sessionsOf(gmail);
      core.fail(gmail);
      await flush(tester);
      await tester.pump(Duration(seconds: seconds) - const Duration(milliseconds: 1));
      expect(core.sessionsOf(gmail), before, reason: 'still waiting (${seconds}s)');
      await tester.pump(const Duration(milliseconds: 1));
      expect(core.sessionsOf(gmail), before + 1, reason: 'retried after ${seconds}s');
    }

    await failAndExpectRetryAfter(1);
    await failAndExpectRetryAfter(2);
    await failAndExpectRetryAfter(4);
    // Arming alone does not prove a session healthy: one that dies right after `idle`
    // keeps backing off (a server that drops every IDLE is not hammered once a second).
    core.emit(gmail, MailEventKind.idle);
    await flush(tester);
    await failAndExpectRetryAfter(8);
    // An IDLE round that completed (the server's timeout) proves it: back to 1 s.
    core.emit(gmail, MailEventKind.timeout);
    await flush(tester);
    await failAndExpectRetryAfter(1);
    // So does staying armed for kLiveStableAfter.
    await failAndExpectRetryAfter(2);
    core.emit(gmail, MailEventKind.idle);
    await tester.pump(kLiveStableAfter);
    await failAndExpectRetryAfter(1);
  });

  testWidgets('a stream that ends is reconnected like one that failed', (tester) async {
    final core = await pumpInbox(tester);
    core.emit(gmail, MailEventKind.idle);
    core.emit(fastmail, MailEventKind.idle);
    await flush(tester);
    await core.current(fastmail).close();
    await flush(tester);
    expect(statusIs(LiveStatus.reconnecting), findsOneWidget);
    expect(tooltipOfStatus(tester), contains('alice@fastmail.com in 1 s (the connection ended)'));
    await tester.pump(const Duration(seconds: 1));
    expect(core.sessionsOf(fastmail), 2);
  });

  testWidgets('new mail from a watcher refreshes the list', (tester) async {
    final core = await pumpInbox(tester);
    core.emit(gmail, MailEventKind.idle);
    await flush(tester);
    final before = core.listCalls;
    core.emit(gmail, MailEventKind.newMail);
    await tester.pumpAndSettle();
    expect(core.listCalls, before, reason: 'a newMail event without new messages changes nothing');
    core.emit(gmail, MailEventKind.newMail, newMessages: 2);
    await tester.pumpAndSettle();
    expect(core.listCalls, greaterThan(before));
  });

  testWidgets('a rejected sign-in stops the watcher; "Fetch new mail" tries again', (tester) async {
    final core = await pumpInbox(tester);
    core.emit(fastmail, MailEventKind.idle);
    core.fail(
      gmail,
      'AnyhowException(IMAP: login to imap.gmail.com rejected (LOGIN): [AUTHENTICATIONFAILED] x)',
    );
    await flush(tester);
    expect(statusIs(LiveStatus.on), findsOneWidget, reason: 'the other account is still live');
    expect(tooltipOfStatus(tester), contains('Stopped for alice.rivera@gmail.com'));
    await tester.pump(const Duration(minutes: 5));
    expect(core.sessionsOf(gmail), 1, reason: 'no automatic retry after a rejected login');

    await tester.tap(find.byKey(const Key('inbox-sync')));
    await tester.pumpAndSettle();
    expect(core.sessionsOf(gmail), 2);
  });

  testWidgets('a server without IDLE stops for good; every account stopped reads "off"', (
    tester,
  ) async {
    final core = await pumpInbox(tester);
    for (final a in [gmail, fastmail]) {
      core.fail(a, Exception('IMAP: server does not advertise IDLE'));
    }
    await flush(tester);
    expect(statusIs(LiveStatus.off), findsOneWidget);
    expect(tooltipOfStatus(tester), contains('the server does not support IMAP IDLE'));
    await tester.tap(find.byKey(const Key('inbox-sync')));
    await tester.pumpAndSettle();
    expect(core.sessionsOf(gmail), 1, reason: 'a server without IDLE is not asked again');
  });

  testWidgets('"Fetch new mail" reconnects a waiting watcher at once', (tester) async {
    final core = await pumpInbox(tester);
    // Push the backoff to 60 s.
    for (var i = 0; i < 7; i++) {
      core.fail(gmail);
      await flush(tester);
      await tester.pump(liveRetryDelay(i + 1));
    }
    core.fail(gmail);
    await flush(tester);
    final waiting = core.sessionsOf(gmail);
    expect(tooltipOfStatus(tester), contains('in 60 s'));
    await tester.tap(find.byKey(const Key('inbox-sync')));
    await tester.pumpAndSettle();
    expect(core.sessionsOf(gmail), waiting + 1);
  });

  testWidgets('turning live updates off in Settings cancels every watcher', (tester) async {
    final store = storeWith('on');
    final core = LiveCore();
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(
        core: core,
        initialLocation: '/settings',
        overrides: [liveUpdatesStoreProvider.overrideWithValue(store)],
      ),
    );
    await tester.pumpAndSettle();
    expect(
      core.listening(gmail) && core.listening(fastmail),
      isTrue,
      reason: 'Settings starts them',
    );
    final tile = find.byKey(const Key('settings-live-updates'));
    await tester.scrollUntilVisible(tile, 200, scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('settings-live-status')), findsOneWidget);

    await tester.tap(tile);
    await tester.pumpAndSettle();
    expect(core.listening(gmail), isFalse);
    expect(core.listening(fastmail), isFalse);
    expect(store.values[liveUpdatesStoreKey], 'off');
    expect(find.byKey(const Key('settings-live-status')), findsNothing);
    await tester.pump(const Duration(minutes: 2));
    expect(core.sessions, hasLength(2), reason: 'nothing reconnects while off');

    await tester.tap(tile);
    await tester.pumpAndSettle();
    expect(store.values[liveUpdatesStoreKey], 'on');
    expect(core.sessions, hasLength(4));
  });

  testWidgets('removing an account cancels its watcher', (tester) async {
    final core = await pumpInbox(tester);
    final element = tester.element(find.byKey(const Key('live-status')));
    await core.removeAccount(fastmail);
    ProviderScope.containerOf(element).invalidate(accountsProvider);
    await tester.pumpAndSettle();
    expect(core.listening(fastmail), isFalse);
    expect(core.listening(gmail), isTrue);
  });

  testWidgets('with live updates off the app bar says so, and no watcher runs', (tester) async {
    final core = await pumpInbox(tester, stored: 'off');
    expect(core.sessions, isEmpty);
    expect(statusIs(LiveStatus.off), findsOneWidget);
    expect(tooltipOfStatus(tester), startsWith('Live updates are off'));
    expect(
      tester.getSemantics(find.byKey(const Key('live-status'))),
      matchesSemantics(label: 'Live updates off', tooltip: tooltipOfStatus(tester)),
    );
  });

  group('the stored choice', () {
    ProviderContainer containerWith(SecretStore? store) => ProviderContainer(
      overrides: [
        coreApiProvider.overrideWithValue(LiveCore()),
        liveUpdatesStoreProvider.overrideWithValue(store),
      ],
    );

    test('survives a new ProviderContainer (the next launch)', () async {
      final store = MemorySecretStore();
      final first = containerWith(store);
      expect(first.read(liveUpdatesProvider), kLiveUpdatesDefault);
      await first.read(liveUpdatesProvider.notifier).loaded;
      expect(first.read(liveUpdatesProvider), kLiveUpdatesDefault, reason: 'nothing stored yet');
      await first.read(liveUpdatesProvider.notifier).set(!kLiveUpdatesDefault);
      first.dispose();
      expect(store.values[liveUpdatesStoreKey], kLiveUpdatesDefault ? 'off' : 'on');

      final second = containerWith(store);
      await second.read(liveUpdatesProvider.notifier).loaded;
      expect(second.read(liveUpdatesProvider), !kLiveUpdatesDefault);
      await second.read(liveUpdatesProvider.notifier).set(kLiveUpdatesDefault);
      second.dispose();

      final third = containerWith(store);
      await third.read(liveUpdatesProvider.notifier).loaded;
      expect(third.read(liveUpdatesProvider), kLiveUpdatesDefault);
      third.dispose();
    });

    test('the last of quick successive choices is the one stored', () async {
      // The first write is slow (a keyring prompt); the second must not land before it.
      final store = _GatedWriteStore();
      final c = containerWith(store);
      final ctl = c.read(liveUpdatesProvider.notifier);
      final first = ctl.set(true);
      final second = ctl.set(false);
      await Future<void>.delayed(Duration.zero);
      store.releaseFirstWrite();
      await Future.wait([first, second]);
      expect(store.values[liveUpdatesStoreKey], 'off');
      expect(c.read(liveUpdatesProvider), isFalse);
      c.dispose();
    });

    test('a choice made while the stored one is being read wins', () async {
      final store = _SlowStore('on');
      final c = containerWith(store);
      final ctl = c.read(liveUpdatesProvider.notifier);
      await ctl.set(false);
      store.release();
      await ctl.loaded;
      expect(c.read(liveUpdatesProvider), isFalse);
      c.dispose();
    });

    test('without a store (no app lock) it lasts for the session', () async {
      final c = containerWith(null);
      await c.read(liveUpdatesProvider.notifier).set(true);
      expect(c.read(liveUpdatesProvider), isTrue);
      c.dispose();
    });

    test('an unreadable or unwritable store leaves the default / the session choice', () async {
      final c = containerWith(_BrokenStore());
      await c.read(liveUpdatesProvider.notifier).loaded;
      expect(c.read(liveUpdatesProvider), kLiveUpdatesDefault);
      await c.read(liveUpdatesProvider.notifier).set(!kLiveUpdatesDefault);
      expect(c.read(liveUpdatesProvider), !kLiveUpdatesDefault);
      c.dispose();
    });

    test('garbage in the store is ignored', () async {
      final c = containerWith(storeWith('maybe'));
      await c.read(liveUpdatesProvider.notifier).loaded;
      expect(c.read(liveUpdatesProvider), kLiveUpdatesDefault);
      c.dispose();
    });
  });

  testWidgets('the Settings switch starts from the stored choice and stores a change', (
    tester,
  ) async {
    final store = storeWith('on');
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(
        core: LiveCore(),
        initialLocation: '/settings',
        overrides: [liveUpdatesStoreProvider.overrideWithValue(store)],
      ),
    );
    await tester.pumpAndSettle();
    final tile = find.byKey(const Key('settings-live-updates'));
    await tester.scrollUntilVisible(tile, 200, scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    expect(tester.widget<SwitchListTile>(tile).value, isTrue);
    await tester.tap(tile);
    await tester.pumpAndSettle();
    expect(tester.widget<SwitchListTile>(tile).value, isFalse);
    expect(store.values[liveUpdatesStoreKey], 'off');
  });
}

/// Holds its read until [release] (a slow OS keystore).
class _SlowStore extends MemorySecretStore {
  _SlowStore(String value) {
    values[liveUpdatesStoreKey] = value;
  }

  final _gate = Completer<void>();

  void release() => _gate.complete();

  /// Returns what was stored when the read began, like a keystore round trip that a
  /// write issued meanwhile does not change.
  @override
  Future<String?> read(String key) async {
    final value = values[key];
    await _gate.future;
    return value;
  }
}

/// Holds its first write until [releaseFirstWrite]; later writes go through at once.
class _GatedWriteStore extends MemorySecretStore {
  final _gate = Completer<void>();
  var _writes = 0;

  void releaseFirstWrite() => _gate.complete();

  @override
  Future<void> write(String key, String value) async {
    if (_writes++ == 0) await _gate.future;
    await super.write(key, value);
  }
}

class _BrokenStore extends MemorySecretStore {
  @override
  Future<String?> read(String key) => Future.error(StateError('keyring locked'));

  @override
  Future<void> write(String key, String value) => Future.error(StateError('keyring locked'));
}
