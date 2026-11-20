import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

// Drafts on the server, in the app: every save pushes the draft (FrbCore runs push_draft in
// the background; FakeCore records it), opening the Drafts list runs a drafts sync (another
// device's draft comes in, marked as such, with a note about the files that stayed on that
// device), and compose explains those files when the draft is opened.

FakeCore core() => FakeCore(latency: Duration.zero);

void main() {
  testWidgets('opening the Drafts list syncs: another device\'s draft comes in, marked', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    final mine = await c.saveDraft(
      const DraftInput(accountId: 'acct-1', subject: 'Written here', body: 'x'),
    );
    expect(c.pushedDrafts, [mine.id], reason: 'a save pushes the draft');
    c.queueServerDraft(
      const DraftInput(
        accountId: 'acct-1',
        to: ['bob@sealbox.test'],
        subject: 'Started on the laptop',
        body: 'Numbers attached on the laptop.',
      ),
      remoteFiles: 2,
    );
    await tester.pumpWidget(buildApp(core: c));
    await tester.pumpAndSettle();
    expect(c.draftSyncs, 0, reason: 'only the Drafts list syncs drafts');
    await tester.tap(find.byKey(const Key('folder-chip-drafts')));
    await tester.pumpAndSettle();
    expect(c.draftSyncs, 1);
    final drafts = await c.listDrafts();
    final theirs = drafts.firstWhere((d) => d.subject == 'Started on the laptop');
    expect((theirs.origin, theirs.remoteFiles), (DraftOrigin.server, 2));
    expect(c.pushedDrafts, [mine.id], reason: 'a draft brought in is not pushed back');
    final row = find.byKey(ValueKey('draft-tile-${theirs.id}'));
    expect(row, findsOneWidget, reason: 'listed after the sync');
    expect(
      find.descendant(of: row, matching: find.byKey(const Key('draft-origin-server'))),
      findsOneWidget,
    );
    expect(find.descendant(of: row, matching: find.text('From another device')), findsOneWidget);
    expect(
      find.descendant(of: row, matching: find.text('2 files on the other device')),
      findsOneWidget,
    );
    final here = find.byKey(ValueKey('draft-tile-${mine.id}'));
    expect(
      find.descendant(of: here, matching: find.byKey(const Key('draft-origin-server'))),
      findsNothing,
      reason: 'a draft saved here carries no origin tag',
    );
    expect(find.byKey(const Key('drafts-sync-problem')), findsNothing);
    // Pull to refresh syncs again.
    await tester.fling(find.byKey(const Key('drafts-list')), const Offset(0, 400), 1000);
    await tester.pumpAndSettle();
    expect(c.draftSyncs, 2);
  });

  testWidgets('a failing drafts sync says so above the list; the stored drafts still show', (
    tester,
  ) async {
    setSurface(tester, phone);
    final c = _FailingSync();
    await c.saveDraft(const DraftInput(accountId: 'acct-1', subject: 'Still here'));
    await tester.pumpWidget(buildApp(core: c));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('folder-chip-drafts')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('drafts-sync-problem')), findsOneWidget);
    expect(find.textContaining('drafts from your other devices may be missing'), findsOneWidget);
    expect(find.text('Still here'), findsOneWidget);
  });

  testWidgets('compose explains the files that stayed on the device that saved the draft', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    c.queueServerDraft(
      const DraftInput(accountId: 'acct-1', subject: 'From the laptop', body: 'see files'),
      remoteFiles: 1,
    );
    await c.syncDrafts();
    final d = (await c.listDrafts()).single;
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose?draft=${d.id}'));
    await tester.pumpAndSettle();
    final notice = find.byKey(const Key('compose-notice'));
    expect(notice, findsOneWidget);
    expect(
      find.descendant(
        of: notice,
        matching: find.textContaining('A file attached on the device that saved this draft'),
      ),
      findsOneWidget,
    );
  });
}

/// FakeCore whose drafts sync cannot reach the server for one account.
class _FailingSync extends FakeCore {
  _FailingSync() : super(latency: Duration.zero);

  @override
  Future<DraftSyncSummary> syncDrafts() async {
    await super.syncDrafts();
    return const DraftSyncSummary(failures: ['alice.rivera@gmail.com: connection refused']);
  }
}
