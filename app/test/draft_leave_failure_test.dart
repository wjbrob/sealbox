import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';

import 'helpers.dart';

// Drafts hygiene (a): the save made when compose is left used to fail silently, losing the
// message. Now a snackbar on the screen the user went to says "Draft could not be saved: …"
// with Retry, and the message is kept (in memory) until it is saved: the next new compose
// brings it back and saves it again.

/// FakeCore whose draft saves fail while [failing] is set (a full disk, a locked store).
class FlakyDrafts extends FakeCore {
  FlakyDrafts() : super(latency: Duration.zero);

  bool failing = false;
  int saves = 0;

  @override
  Future<SavedDraft> saveDraft(DraftInput input) async {
    saves++;
    if (failing) throw StateError('database is locked');
    return super.saveDraft(input);
  }
}

ProviderContainer containerOf(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byType(Scaffold).first));

void go(WidgetTester tester, String location) =>
    GoRouter.of(tester.element(find.byType(Scaffold).first)).go(location);

String fieldText(WidgetTester tester, String key) =>
    tester.widget<TextField>(find.byKey(Key(key))).controller!.text;

/// Compose with a subject and text typed, then left for the inbox while saves fail.
Future<FlakyDrafts> leaveWhileFailing(WidgetTester tester) async {
  setSurface(tester, desktop);
  final c = FlakyDrafts();
  await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
  await tester.pumpAndSettle();
  await tester.enterText(find.byKey(const Key('compose-subject')), 'Board minutes');
  await tester.enterText(find.byKey(const Key('compose-body')), 'Draft of the minutes, part 1.');
  c.failing = true;
  go(tester, '/inbox');
  await tester.pumpAndSettle();
  return c;
}

const failedText = 'Draft could not be saved: database is locked';

void main() {
  testWidgets('a save that fails on leaving is reported with Retry; Retry saves it', (
    tester,
  ) async {
    final c = await leaveWhileFailing(tester);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget, reason: 'compose was left');
    expect(find.byKey(const Key('draft-save-failed-snackbar')), findsOneWidget);
    expect(find.text(failedText), findsOneWidget);
    expect(await c.listDrafts(), isEmpty);
    expect(containerOf(tester).read(unsavedComposeProvider), hasLength(1), reason: 'kept');

    c.failing = false;
    await tester.tap(find.byKey(const Key('draft-save-retry')));
    await tester.pumpAndSettle();
    final saved = (await c.listDrafts()).single;
    expect(saved.subject, 'Board minutes');
    expect(saved.body, 'Draft of the minutes, part 1.');
    expect(find.byKey(const Key('draft-saved-snackbar')), findsOneWidget);
    expect(containerOf(tester).read(unsavedComposeProvider), isEmpty, reason: 'saved: let go');

    // Nothing to bring back: a new compose starts empty.
    go(tester, '/compose');
    await tester.pumpAndSettle();
    expect(fieldText(tester, 'compose-subject'), isEmpty);
    expect(find.byKey(const Key('compose-notice')), findsNothing);
  });

  testWidgets('a retry that fails again is reported again', (tester) async {
    final c = await leaveWhileFailing(tester);
    final before = c.saves;
    await tester.tap(find.byKey(const Key('draft-save-retry')));
    await tester.pumpAndSettle();
    expect(c.saves, before + 1, reason: 'it did try again');
    expect(find.text(failedText), findsOneWidget, reason: 'the new failure, not silence');
    expect(find.byKey(const Key('draft-saved-snackbar')), findsNothing);
    expect(await c.listDrafts(), isEmpty);
  });

  testWidgets('the text is never lost: the next new compose brings it back and saves it', (
    tester,
  ) async {
    final c = await leaveWhileFailing(tester);
    c.failing = false;
    go(tester, '/compose');
    await tester.pumpAndSettle();
    expect(fieldText(tester, 'compose-subject'), 'Board minutes');
    expect(fieldText(tester, 'compose-body'), 'Draft of the minutes, part 1.');
    expect(find.byKey(const Key('compose-notice')), findsOneWidget);
    expect(find.textContaining('could not be saved as a draft when you left it'), findsOneWidget);
    final saved = (await c.listDrafts()).single;
    expect(saved.subject, 'Board minutes', reason: 'saved again at once');
    expect(find.textContaining('Draft saved'), findsOneWidget);

    // The old snackbar's Retry no longer saves: this compose owns the message now.
    final retry = find.byKey(const Key('draft-save-retry'));
    expect(retry, findsOneWidget, reason: 'the snackbar is still up');
    await tester.tap(retry);
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), hasLength(1), reason: 'never two drafts of one message');
    expect(find.byKey(const Key('draft-saved-snackbar')), findsNothing);

    // Edited and left again (saves work now): the same draft, updated.
    await tester.enterText(find.byKey(const Key('compose-body')), 'Draft of the minutes, final.');
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect((await c.listDrafts()).single.body, 'Draft of the minutes, final.');
    expect(find.byKey(const Key('draft-save-failed-snackbar')), findsNothing);
  });

  testWidgets('a message whose earlier autosave worked keeps its draft when it comes back', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = FlakyDrafts();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Budget');
    await tester.pump(ComposeController.autosaveDelay);
    await tester.pumpAndSettle();
    final first = (await c.listDrafts()).single;
    await tester.enterText(find.byKey(const Key('compose-body')), 'Numbers below.');
    c.failing = true;
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect(find.text(failedText), findsOneWidget);
    expect((await c.listDrafts()).single.body, isEmpty, reason: 'the stored draft is stale');

    c.failing = false;
    go(tester, '/compose');
    await tester.pumpAndSettle();
    final again = (await c.listDrafts()).single;
    expect(again.id, first.id, reason: 'the same draft continued, not a second one');
    expect(again.body, 'Numbers below.');
  });

  testWidgets('leaving an untouched compose reports nothing', (tester) async {
    setSurface(tester, desktop);
    final c = FlakyDrafts()..failing = true;
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect(c.saves, 0);
    expect(find.byKey(const Key('draft-save-failed-snackbar')), findsNothing);
  });
}
