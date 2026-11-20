import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/core/threading.dart';
import 'package:sealbox_app/src/features/inbox/inbox_list_pane.dart' show threadSubjectKey;

import 'helpers.dart';

// Review N1 (review/desktop/2026-10-29/REVIEW.md): a conversation whose mail could not be
// decrypted showed the provider's placeholder "..." as its title. FakeCore's sample
// (FakeCore.undecryptableSampleId, folder "Review samples": only "All mail" lists it)
// is encrypted to a key this device does not hold.

Future<void> openAllMail(WidgetTester tester) async {
  final chip = find.byKey(const Key('folder-chip-all'));
  await tester.ensureVisible(chip);
  await tester.pumpAndSettle();
  await tester.tap(chip);
  await tester.pumpAndSettle();
}

Text textIn(WidgetTester tester, Finder scope, String text) =>
    tester.widget<Text>(find.descendant(of: scope, matching: find.text(text)));

void main() {
  testWidgets('list row: "Encrypted message" in italics, the key keeps the raw subject', (
    tester,
  ) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
    await tester.pumpAndSettle();
    expect(
      find.byKey(const ValueKey('thread-tile-t-undecryptable')),
      findsNothing,
      reason: 'not in INBOX',
    );

    await openAllMail(tester);
    final row = find.byKey(const ValueKey('thread-tile-t-undecryptable'));
    expect(row, findsOneWidget);
    expect(find.descendant(of: row, matching: find.text('...')), findsNothing);
    final title = textIn(tester, row, 'Encrypted message');
    expect(title.style?.fontStyle, FontStyle.italic);
    final scheme = Theme.of(tester.element(row)).colorScheme;
    expect(title.style?.color, scheme.onSurfaceVariant);
    // The lock badge still says why; tests and tours keep finding the row by its subject.
    expect(
      find.descendant(of: row, matching: find.byKey(const ValueKey('lock-badge-undecryptable'))),
      findsOneWidget,
    );
    expect(find.byKey(threadSubjectKey('...')), findsOneWidget);

    // An ordinary row is untouched.
    final budget = find.byKey(const ValueKey('thread-tile-t-budget'));
    final normal = textIn(tester, budget, 'Q4 budget — final numbers');
    expect(normal.style?.fontStyle, isNot(FontStyle.italic));
  });

  testWidgets('thread header: "Encrypted message" in italics; the app bar names the folder', (
    tester,
  ) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/inbox/t/t-undecryptable'),
    );
    await tester.pumpAndSettle();
    final header = tester.widget<Text>(find.byKey(const Key('thread-subject')));
    expect(header.data, encryptedMessageTitle);
    expect(header.style?.fontStyle, FontStyle.italic);
    expect(
      header.style?.color,
      Theme.of(tester.element(find.byKey(const Key('thread-subject')))).colorScheme.onSurfaceVariant,
    );
    expect(find.text('...'), findsNothing);
    expect(tester.widget<Text>(find.byKey(const Key('thread-title'))).data, FakeCore.samplesFolder);
    expect(find.byKey(const ValueKey('lock-badge-undecryptable')), findsOneWidget);
    expect(find.text('This message is encrypted, but not to a key on this device.'), findsOneWidget);
  });

  testWidgets('a readable subject keeps the plain header style', (tester) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/inbox/t/t-budget'),
    );
    await tester.pumpAndSettle();
    final header = tester.widget<Text>(find.byKey(const Key('thread-subject')));
    expect(header.data, 'Q4 budget — final numbers');
    expect(header.style?.fontStyle, isNot(FontStyle.italic));
  });

  testWidgets('filter dry run: the picker and the report say "Encrypted message" in italics', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero);
    // The sample lives on the second account, which has no rule yet ("Test" needs one).
    await core.addFilterRule(
      'acct-2',
      const FilterRule(
        id: 0,
        order: 0,
        name: 'From Bob',
        condition: FilterCondition(
          field: FilterField.from,
          op: FilterOp.contains,
          value: 'bob@',
        ),
        action: FilterAction.star(),
      ),
    );
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings/filters?account=acct-2'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('filters-test')));
    await tester.pumpAndSettle();

    final picker = find.byKey(const Key('filters-test-picker'));
    expect(picker, findsOneWidget);
    expect(find.descendant(of: picker, matching: find.text('...')), findsNothing);
    final row = find.byKey(const ValueKey('filter-test-pick-${FakeCore.undecryptableSampleId}'));
    final title = textIn(tester, row, encryptedMessageTitle);
    expect(title.style?.fontStyle, FontStyle.italic);
    expect(title.style?.color, Theme.of(tester.element(row)).colorScheme.onSurfaceVariant);
    // A readable subject keeps the plain style.
    final normal = textIn(
      tester,
      find.byKey(const ValueKey('filter-test-pick-${FakeCore.signerMismatchSampleId}')),
      'Updated bank details for the Q4 invoice',
    );
    expect(normal.style?.fontStyle, isNot(FontStyle.italic));

    await tester.tap(row);
    await tester.pumpAndSettle();
    final report = find.byKey(const Key('filters-test-report'));
    expect(report, findsOneWidget);
    expect(find.descendant(of: report, matching: find.textContaining('...')), findsNothing);
    final rich = tester.widget<RichText>(
      find.descendant(of: find.byKey(const Key('filters-test-title')), matching: find.byType(RichText)),
    );
    expect(rich.text.toPlainText(), 'Test: $encryptedMessageTitle');
    final spans = <TextSpan>[];
    rich.text.visitChildren((s) {
      if (s is TextSpan && s.text != null) spans.add(s);
      return true;
    });
    final placeholder = spans.singleWhere((s) => s.text == encryptedMessageTitle);
    expect(placeholder.style?.fontStyle, FontStyle.italic);
    expect(find.descendant(of: report, matching: find.text('matches')), findsOneWidget);
  });

  testWidgets('"Why is this spam?" sheet: "Encrypted message" in italics instead of "..."', (
    tester,
  ) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/inbox/t/t-undecryptable'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('thread-more')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('thread-spam-explain')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('spam-explain-sheet')), findsOneWidget);

    final line = find.byKey(const Key('spam-explain-from'));
    final rich = tester.widget<RichText>(find.descendant(of: line, matching: find.byType(RichText)));
    expect(rich.text.toPlainText(), 'Bob Nakamura <bob@sealbox.test> · $encryptedMessageTitle');
    expect(rich.text.toPlainText(), isNot(contains('...')));
    TextStyle? styleOf(String text) {
      TextStyle? found;
      rich.text.visitChildren((s) {
        if (s is TextSpan && s.text == text) found = s.style;
        return found == null;
      });
      return found;
    }

    expect(styleOf(encryptedMessageTitle)?.fontStyle, FontStyle.italic);
    expect(styleOf('Bob Nakamura <bob@sealbox.test> · ')?.fontStyle, isNot(FontStyle.italic));
  });

  testWidgets('the spam sheet of readable mail keeps its plain subject line', (tester) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/inbox/t/t-junk-prize'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('thread-more')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('thread-spam-explain')));
    await tester.pumpAndSettle();
    final line = tester.widget<Text>(find.byKey(const Key('spam-explain-from')));
    expect(line.data, contains('· Congratulations!!! You have won a 1,000 € gift card'));
    expect(line.style?.fontStyle, isNot(FontStyle.italic));
  });

  test('the sample behind these tests', () async {
    final core = FakeCore(latency: Duration.zero);
    final m = (await core.getMessage(FakeCore.undecryptableSampleId))!;
    expect(
      (m.subject, m.state, m.folder),
      ('...', EncryptionState.undecryptable, FakeCore.samplesFolder),
    );
    expect(subjectUnreadable(m), isTrue);
    final inbox = await core.listThreadsIn(MailFolder.inbox);
    expect(inbox.map((t) => t.id), isNot(contains('t-undecryptable')));
    expect((await core.listThreadsIn(MailFolder.all)).map((t) => t.id), contains('t-undecryptable'));
  });
}
