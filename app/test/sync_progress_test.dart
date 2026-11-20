import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart' show buildTheme;
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/inbox/sync_progress.dart';
import 'package:sealbox_app/src/providers/provider_table.dart';

import 'helpers.dart';

// Sync progress in the inbox (docs/PERFORMANCE.md, "What the app does with it"): a sync says
// how far it got under the title and in a bar that fills, the list shows stored batches at
// once and then at most every 2 s, and the older mail a first sync's window left on the
// server loads in the background — step by step, paused while a sync runs or the app is in
// the background, retried with backoff, dropped with its account.

const gmail = 'acct-1';
const fastmail = 'acct-2';
const gmailAddress = 'alice.rivera@gmail.com';

/// One sync or backfill call the test drives.
class Run {
  Run(this.accountId, this.max);

  final String accountId;
  final int? max;
  final events = StreamController<SyncEvent>();

  String get email => accountId == gmail ? gmailAddress : 'alice@fastmail.com';

  void batch({
    SyncPhase phase = SyncPhase.initial,
    int fetched = 200,
    int planned = 500,
    int local = 200,
    int total = 10000,
    String folder = 'INBOX',
  }) => events.add(
    SyncEvent.progress(
      SyncProgress(
        account: email,
        folder: folder,
        phase: phase,
        fetched: fetched,
        stored: fetched,
        planned: planned,
        totalKnown: total,
        local: local,
        moreToBackfill: true,
      ),
    ),
  );

  void done({bool more = false, int newMessages = 0}) {
    events.add(
      SyncEvent.done(
        AccountSyncOutcome(account: email, newMessages: newMessages, moreToBackfill: more),
      ),
    );
    events.close();
  }

  void fail(Object error) {
    events.addError(error);
    events.close();
  }
}

/// FakeCore whose syncs and backfills the test drives, counting inbox list loads.
class ScriptedCore extends FakeCore {
  ScriptedCore({super.seeded}) : super(latency: Duration.zero) {
    syncScript = (id) => (syncs..add(Run(id, null))).last.events.stream;
    backfillScript = (id, max) => (backfills..add(Run(id, max))).last.events.stream;
  }

  final syncs = <Run>[];
  final backfills = <Run>[];

  /// `listThreadsInRole(inbox)` calls: the inbox list re-reading the store.
  int inboxLoads = 0;

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) {
    if (role == FolderRole.inbox) inboxLoads++;
    return super.listThreadsInRole(role, accountId: accountId);
  }
}

/// The inbox on a desktop window; its automatic first sync is running (no event yet).
Future<ScriptedCore> pumpInbox(WidgetTester tester, {ScriptedCore? core}) async {
  setSurface(tester, desktop);
  final c = core ?? ScriptedCore();
  await tester.pumpWidget(buildApp(core: c));
  await settle(tester);
  return c;
}

/// Pumps until nothing is scheduled but the bar (an indeterminate bar animates forever).
Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 10; i++) {
    await tester.pump(const Duration(milliseconds: 50));
  }
}

String? statusLine(WidgetTester tester, String key) {
  final f = find.byKey(Key(key));
  return f.evaluate().isEmpty ? null : tester.widget<Text>(f).data;
}

LinearProgressIndicator? bar(WidgetTester tester) {
  final f = find.byKey(const Key('sync-progress'));
  return f.evaluate().isEmpty ? null : tester.widget<LinearProgressIndicator>(f);
}

ProviderContainer container(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byKey(const Key('inbox-sync'))));

/// The running sync of both accounts ends (Gmail's run unless it already did); [gmailMore]:
/// Gmail has older mail left.
Future<void> finishSync(WidgetTester tester, ScriptedCore core, {bool gmailMore = false}) async {
  final g = core.syncs.lastWhere((r) => r.accountId == gmail);
  if (!g.events.isClosed) {
    g.done(more: gmailMore);
    await settle(tester);
  }
  core.syncs.lastWhere((r) => r.accountId == fastmail).done();
  await settle(tester);
}

void main() {
  test('labels: phases, folders, accounts, thousands', () {
    SyncProgress p(SyncPhase phase, {String folder = 'INBOX'}) => SyncProgress(
      account: 'a@x',
      folder: folder,
      phase: phase,
      fetched: 3410,
      planned: 10000,
      totalKnown: 12000,
      local: 4200,
    );
    expect(syncProgressLabel(null), 'Fetching mail…');
    expect(syncProgressLabel(p(SyncPhase.initial)), 'Fetching newest mail… 3,410 of 10,000');
    expect(syncProgressLabel(p(SyncPhase.incremental)), 'Fetching mail… 3,410 of 10,000');
    expect(syncProgressLabel(p(SyncPhase.backfill)), 'Loading older mail… 4,200 of 12,000');
    expect(
      syncProgressLabel(p(SyncPhase.initial, folder: '[Gmail]/Sent Mail'), account: 'a@x'),
      'Fetching newest mail in Sent Mail… 3,410 of 10,000 · a@x',
    );
    expect(syncProgressFraction(p(SyncPhase.initial)), closeTo(0.341, 1e-9));
    expect(syncProgressFraction(p(SyncPhase.backfill)), closeTo(0.35, 1e-9));
    expect(syncProgressFraction(null), isNull);
    expect(
      backfillLabel(const BackfillStatus(accountId: 'x')),
      'Loading older mail in the background…',
    );
    expect(
      backfillLabel(BackfillStatus(accountId: 'x', progress: p(SyncPhase.backfill))),
      'Loading older mail… 4,200 of 12,000',
    );
    expect(
      backfillLabel(const BackfillStatus(accountId: 'x', retryIn: Duration(seconds: 4))),
      'Loading older mail paused · trying again in 4 s',
    );
    expect([0, 999, 1000, 1234567].map(groupedCount), ['0', '999', '1,000', '1,234,567']);
  });

  // The guideline checks in a11y_test.dart look text up by its semantics node, and the status
  // line merges into the app bar title's: measure its colour pair directly as well.
  test('the status line reads at 4.5:1 or more on the app bar, light and dark', () {
    double ratio(Color a, Color b) {
      final (la, lb) = (a.computeLuminance(), b.computeLuminance());
      return (la > lb ? la + 0.05 : lb + 0.05) / (la > lb ? lb + 0.05 : la + 0.05);
    }

    for (final b in Brightness.values) {
      final s = buildTheme(b).colorScheme;
      // The app bar's colour at rest and scrolled under.
      for (final bg in [s.surface, s.surfaceContainer]) {
        expect(ratio(s.onSurfaceVariant, bg), greaterThanOrEqualTo(4.5), reason: '$b on $bg');
      }
    }
  });

  testWidgets('a sync says how far it got: line under the title, a bar that fills', (tester) async {
    final core = await pumpInbox(tester);
    expect(core.syncRuns, ['sync $gmail'], reason: 'one account at a time');
    expect(statusLine(tester, 'sync-status'), 'Fetching mail…');
    expect(bar(tester)!.value, isNull, reason: 'nothing known yet: indeterminate');

    core.syncs.single.batch();
    await settle(tester);
    expect(statusLine(tester, 'sync-status'), 'Fetching newest mail… 200 of 500 · $gmailAddress');
    expect(bar(tester)!.value, closeTo(0.4, 1e-9));
    expect(bar(tester)!.semanticsLabel, 'Sync progress');

    core.syncs.single.batch(fetched: 500, local: 500);
    await settle(tester);
    expect(bar(tester)!.value, 1.0);
    core.syncs.single.done();
    await settle(tester);
    expect(core.syncRuns, ['sync $gmail', 'sync $fastmail']);
    expect(
      statusLine(tester, 'sync-status'),
      'Fetching mail…',
      reason: 'the next account: nothing stored yet',
    );
    await finishSync(tester, core);
    expect(core.syncRuns, ['sync $gmail', 'sync $fastmail']);
    expect(find.byKey(const Key('sync-status')), findsNothing);
    expect(bar(tester), isNull);
    expect(find.byKey(const Key('backfill-status')), findsNothing, reason: 'nothing older left');
    final sync = container(tester).read(syncControllerProvider);
    expect((sync.running, sync.progress), (false, null));
    expect(sync.last!.errors, isEmpty);
    expect(sync.last!.accounts.map((a) => a.account), [gmailAddress, 'alice@fastmail.com']);
  });

  testWidgets('the list shows the first batch at once, then at most every 2 s, then the end', (
    tester,
  ) async {
    final core = await pumpInbox(tester);
    final run = core.syncs.single;
    final before = core.inboxLoads;
    int loads() => core.inboxLoads - before;

    run.batch();
    await tester.pump();
    await tester.pump();
    expect(loads(), 1, reason: 'the first stored batch shows at once');
    for (final fetched in [250, 300]) {
      await tester.pump(const Duration(milliseconds: 500));
      run.batch(fetched: fetched);
      await tester.pump();
    }
    expect(loads(), 1, reason: 'within 2 s of the last refresh');
    await tester.pump(const Duration(seconds: 1));
    await tester.pump();
    expect(loads(), 2, reason: 'the stored batches show when the 2 s are over');
    await tester.pump(const Duration(seconds: 3));
    expect(loads(), 2, reason: 'nothing new stored: no refresh');
    run.batch(fetched: 350);
    await tester.pump();
    await tester.pump();
    expect(loads(), 3, reason: 'more than 2 s since the last refresh: at once');
    await finishSync(tester, core);
    expect(loads(), 4, reason: 'and once at the end');
  });

  testWidgets('an empty inbox counts the first sync in its title (no second line)', (tester) async {
    final core = ScriptedCore(seeded: false);
    await core.addAccount(
      const AccountSetup(
        email: 'alice@example.org',
        displayName: 'Alice',
        authMethod: AuthMethod.password,
        imap: ServerSettings('imap.example.org', 993, ConnectionSecurity.tls),
        smtp: ServerSettings('smtp.example.org', 587, ConnectionSecurity.starttls),
      ),
    );
    await pumpInbox(tester, core: core);
    expect(find.text('Fetching mail…'), findsOneWidget);
    final run = core.syncs.single;
    run.events.add(
      const SyncEvent.progress(
        SyncProgress(
          account: 'alice@example.org',
          folder: 'INBOX',
          phase: SyncPhase.initial,
          fetched: 200,
          planned: 500,
          local: 200,
          totalKnown: 10000,
        ),
      ),
    );
    await settle(tester);
    expect(find.text('Fetching newest mail… 200 of 500'), findsOneWidget);
    expect(find.byKey(const Key('sync-status')), findsNothing, reason: 'said once, not twice');
    run.done();
    await settle(tester);
    expect(find.text('Nothing here yet.'), findsOneWidget);
  });

  testWidgets('older mail loads in the background, a step at a time, quietly', (tester) async {
    final core = await pumpInbox(tester);
    await finishSync(tester, core, gmailMore: true);
    expect(core.syncRuns.last, 'backfill $gmail $kBackfillStep');
    expect(statusLine(tester, 'backfill-status'), 'Loading older mail in the background…');
    expect(bar(tester), isNull, reason: 'quiet: no bar');
    final refresh = tester.widget<IconButton>(find.byKey(const Key('inbox-sync')));
    expect(refresh.onPressed, isNotNull, reason: 'the backfill never blocks a fetch');

    final before = core.inboxLoads;
    core.backfills.single.batch(phase: SyncPhase.backfill, local: 700);
    await settle(tester);
    expect(
      statusLine(tester, 'backfill-status'),
      'Loading older mail… 700 of 10,000 · $gmailAddress',
    );
    expect(core.inboxLoads, before + 1, reason: 'stored batches refresh the list like a sync');

    core.backfills.single.done(more: true);
    await settle(tester);
    expect(core.backfills, hasLength(2), reason: 'more left: the next step');
    expect(core.backfills.last.max, kBackfillStep);
    expect(
      statusLine(tester, 'backfill-status'),
      'Loading older mail… 700 of 10,000 · $gmailAddress',
      reason: 'no flicker between steps',
    );
    core.backfills.last.batch(phase: SyncPhase.backfill, local: 10000);
    await settle(tester);
    core.backfills.last.done();
    await tester.pump(const Duration(seconds: 3));
    expect(find.byKey(const Key('backfill-status')), findsNothing);
    expect(core.backfills, hasLength(2));
    expect(container(tester).read(backfillProvider).active, isFalse);
  });

  testWidgets('a failed step is retried after 1 s, 2 s, …; the line says when', (tester) async {
    final core = await pumpInbox(tester);
    await finishSync(tester, core, gmailMore: true);
    core.backfills.single.fail(Exception('IMAP: connection reset by peer'));
    await settle(tester);
    expect(
      statusLine(tester, 'backfill-status'),
      'Loading older mail paused · trying again in 1 s',
    );
    await tester.pump(const Duration(seconds: 1));
    expect(core.backfills, hasLength(2));
    core.backfills.last.fail(Exception('IMAP: connection reset by peer'));
    await settle(tester);
    expect(
      statusLine(tester, 'backfill-status'),
      'Loading older mail paused · trying again in 2 s',
    );
    await tester.pump(const Duration(seconds: 1));
    expect(core.backfills, hasLength(2), reason: 'backoff doubled');
    await tester.pump(const Duration(seconds: 1));
    expect(core.backfills, hasLength(3));
    core.backfills.last.done();
    await settle(tester);
    expect(find.byKey(const Key('backfill-status')), findsNothing);
    expect(container(tester).read(backfillProvider).failures, 0);
  });

  testWidgets('a rejected login stops the backfill until a sync asks again', (tester) async {
    final core = await pumpInbox(tester);
    await finishSync(tester, core, gmailMore: true);
    core.backfills.single.fail(
      Exception('IMAP: login to imap.gmail.com rejected (LOGIN): [AUTHENTICATIONFAILED] x'),
    );
    await settle(tester);
    expect(find.byKey(const Key('backfill-status')), findsNothing);
    await tester.pump(const Duration(minutes: 5));
    expect(core.backfills, hasLength(1), reason: 'never retried on its own');

    await tester.tap(find.byKey(const Key('inbox-sync')));
    await settle(tester);
    await finishSync(tester, core, gmailMore: true);
    expect(core.backfills, hasLength(2), reason: 'the sync said older mail is left');
    core.backfills.last.done();
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('no step starts while a sync runs; it goes on after', (tester) async {
    final core = await pumpInbox(tester);
    await finishSync(tester, core, gmailMore: true);
    await tester.tap(find.byKey(const Key('inbox-sync')));
    await settle(tester);
    expect(statusLine(tester, 'sync-status'), 'Fetching mail…', reason: 'the sync has the line');
    expect(find.byKey(const Key('backfill-status')), findsNothing);
    core.backfills.single.done(more: true);
    await settle(tester);
    expect(core.backfills, hasLength(1), reason: 'paused: the sync needs the mailbox lock');
    expect(container(tester).read(backfillProvider).paused, isTrue);
    await finishSync(tester, core, gmailMore: true);
    expect(core.backfills, hasLength(2), reason: 'resumed once the sync ended, no duplicate');
    expect(container(tester).read(backfillProvider).queued, isEmpty);
    core.backfills.last.done();
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('in the background no step starts until the app is back', (tester) async {
    final core = await pumpInbox(tester);
    final binding = tester.binding;
    binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await finishSync(tester, core, gmailMore: true);
    for (final s in [
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
    ]) {
      binding.handleAppLifecycleStateChanged(s);
    }
    core.backfills.single.done(more: true);
    await tester.pump(const Duration(seconds: 10));
    expect(core.backfills, hasLength(1), reason: 'the running step finished; no new one');
    for (final s in [
      AppLifecycleState.hidden,
      AppLifecycleState.inactive,
      AppLifecycleState.resumed,
    ]) {
      binding.handleAppLifecycleStateChanged(s);
    }
    await settle(tester);
    expect(core.backfills, hasLength(2));
    core.backfills.last.done();
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('removing the account drops its backfill', (tester) async {
    final core = await pumpInbox(tester);
    await finishSync(tester, core, gmailMore: true);
    expect(container(tester).read(backfillProvider).accountId, gmail);
    await core.removeAccount(gmail);
    container(tester).invalidate(accountsProvider);
    await settle(tester);
    expect(container(tester).read(backfillProvider).active, isFalse);
    expect(find.byKey(const Key('backfill-status')), findsNothing);
    core.backfills.single.done(more: true);
    await tester.pump(const Duration(seconds: 10));
    expect(core.backfills, hasLength(1), reason: 'its late outcome starts nothing');
  });

  testWidgets('a list row previews the snippet the engine stored', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(buildApp(core: _SnippetCore()));
    await tester.pumpAndSettle();
    expect(find.text('Stored with the message, no body read'), findsOneWidget);
  });
}

/// One conversation whose newest message carries an engine snippet and no body.
class _SnippetCore extends FakeCore {
  _SnippetCore() : super(latency: Duration.zero);

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) async {
    if (role != FolderRole.inbox) return const [];
    return [
      MailThread(
        id: 't-snippet',
        subject: 'Quarterly numbers',
        accountId: gmail,
        messages: [
          Message(
            id: 'm-snippet',
            threadId: 't-snippet',
            accountId: gmail,
            from: const Contact(email: 'bob@sealbox.test', name: 'Bob'),
            to: const [Contact(email: gmailAddress)],
            subject: 'Quarterly numbers',
            body: '',
            date: DateTime(2026, 6, 15, 9),
            state: EncryptionState.plaintext,
            engineSnippet: 'Stored with the message,\n no body read',
          ),
        ],
      ),
    ];
  }
}
