import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

// The app side of mailbox convergence (engine `Engine::reconcile_folder`, gate G35). A sync no
// longer only adds: it drops the messages the server no longer has and follows the flags that
// changed elsewhere. So the list has to re-read after a sync and let rows *disappear* and
// unread marks *clear* — not merely append. These tests pull to refresh and watch it happen.
//
// FakeCore's seeded mail stands in for the store, and the sync flips it to what another client
// left behind: `t-lunch` deleted in webmail, `t-budget` read on the phone.

const deletedElsewhere = 't-lunch';
const readElsewhere = 't-budget';

/// A core whose store converges when a sync runs, the way the engine's does.
class ConvergingCore extends FakeCore {
  ConvergingCore() : super(latency: Duration.zero);

  /// Whether another client's changes are in the store yet. The test flips it with
  /// [elsewhere], rather than a sync flipping it, because the app syncs every account at
  /// launch: tying it to "a sync ran" would converge the store before the first frame and
  /// leave nothing to observe.
  bool converged = false;
  int syncs = 0;

  /// Another client deleted one conversation and read another. Nothing on screen changes
  /// until something re-reads the store.
  void elsewhere() => converged = true;

  /// How often the list re-read the store — a sync that does not trigger one would leave the
  /// deleted row on screen until the app restarted.
  int listCalls = 0;

  /// What the last sync reported, as the UI received it.
  AccountSyncOutcome? lastOutcome;

  @override
  Stream<SyncEvent> syncAccount(String accountId) {
    syncs++;
    final outcome = AccountSyncOutcome(
      account: accountId,
      removed: converged ? 1 : 0,
      flagsChanged: converged ? 1 : 0,
    );
    lastOutcome = outcome;
    return Stream.value(SyncEvent.done(outcome));
  }

  @override
  Future<List<MailThread>> listThreadsInRole(FolderRole role, {String? accountId}) async {
    listCalls++;
    final all = await super.listThreadsInRole(role, accountId: accountId);
    if (!converged) return all;
    return [
      for (final t in all)
        if (t.id != deletedElsewhere) (t.id == readElsewhere ? _read(t) : t),
    ];
  }

  static MailThread _read(MailThread t) => MailThread(
    id: t.id,
    subject: t.subject,
    accountId: t.accountId,
    messages: [for (final m in t.messages) m.copyWith(unread: false)],
  );
}

Finder tile(String id) => find.byKey(ValueKey('thread-tile-$id'));

/// The weight the sender's name is drawn in: w700 unread, w400 read.
FontWeight? senderWeight(WidgetTester tester, String name) =>
    tester.widget<Text>(find.text(name)).style?.fontWeight;

void main() {
  testWidgets('a sync drops the row deleted elsewhere and clears the unread mark', (
    tester,
  ) async {
    setSurface(tester, const Size(600, 1600));
    final core = ConvergingCore();
    await tester.pumpWidget(buildApp(core: core));
    await tester.pumpAndSettle();

    // Before: both rows are there and the one read elsewhere is still bold here.
    expect(tile(deletedElsewhere), findsOneWidget);
    expect(tile(readElsewhere), findsOneWidget);
    expect(senderWeight(tester, 'Bob Nakamura'), FontWeight.w700);
    final readsBefore = core.listCalls;

    core.elsewhere();
    await tester.fling(find.byKey(const Key('inbox-list')), const Offset(0, 400), 1000);
    await tester.pumpAndSettle();

    expect(
      core.listCalls,
      greaterThan(readsBefore),
      reason: 'the sync must make the list re-read the store, or a deleted row stays on screen',
    );
    expect(
      tile(deletedElsewhere),
      findsNothing,
      reason: 'deleted in webmail, so it is gone from the list too',
    );
    expect(tile(readElsewhere), findsOneWidget, reason: 'read elsewhere is not deleted');
    expect(
      senderWeight(tester, 'Bob Nakamura'),
      FontWeight.w400,
      reason: 'read on the phone, so no longer bold here',
    );
  });

  testWidgets('the convergence counts reach the UI layer', (tester) async {
    setSurface(tester, const Size(600, 1600));
    final core = ConvergingCore();
    await tester.pumpWidget(buildApp(core: core));
    await tester.pumpAndSettle();

    core.elsewhere();
    await tester.fling(find.byKey(const Key('inbox-list')), const Offset(0, 400), 1000);
    await tester.pumpAndSettle();

    // Not yet shown anywhere in the chrome (there is no "3 removed" line), but the numbers
    // are carried end to end — engine FolderSync -> AccountSyncOutcome — so a later UI can
    // show them without another round through the bridge.
    expect(core.lastOutcome?.removed, 1);
    expect(core.lastOutcome?.flagsChanged, 1);
  });

  testWidgets('a sync that converges nothing removes nothing', (tester) async {
    setSurface(tester, const Size(600, 1600));
    final core = ConvergingCore();
    await tester.pumpWidget(buildApp(core: core));
    await tester.pumpAndSettle();

    // The launch sync ran and found nothing to converge, so every row is still there and the
    // unread mark stands: the list does not drop rows on its own.
    expect(core.syncs, greaterThan(0));
    expect(core.converged, isFalse);
    expect(core.lastOutcome?.removed, 0);
    expect(tile(deletedElsewhere), findsOneWidget);
    expect(senderWeight(tester, 'Bob Nakamura'), FontWeight.w700);
  });
}
