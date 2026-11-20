import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Goldens of the UI wave (folders by role, spam & filters, the key directory,
// the compose preview):
//
//   spam_settings      (full matrix)  Settings → Spam: model status, thresholds with the
//                                     engine's labels, DNSBL with its privacy note, folder
//   filters_list       (full matrix)  Settings → Filters: the two seeded rules, drag
//                                     handles and enable switches, Test / Add rule
//   filters_editor     (reduced B)    the add-rule sheet
//   spam_explain       (reduced A)    "Why is this spam?" over the prize scam in Spam
//   inbox_spam_folder  (reduced B)    the Spam chip after its first-open sync
//   settings_publish_awaiting (reduced A)  My key → key directory: waiting for the mail
//   compose_reply_preview     (reduced B)  a reply's Preview: signature above the engine's quote

/// Scrolls the lazy list until [f] is built, then places it [alignment] down the viewport.
Future<void> _revealIn(WidgetTester tester, Finder f, {double alignment = 0.0}) async {
  await tester.scrollUntilVisible(f, 200, scrollable: find.byType(Scrollable).first);
  await tester.pumpAndSettle();
  await Scrollable.ensureVisible(tester.element(f), alignment: alignment);
  await tester.pumpAndSettle();
}

void main() {
  for (final v in fullMatrix) {
    testVariant('golden spam_settings $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(),
        initialLocation: '/settings/spam?account=acct-1',
      );
      expect(find.byKey(const Key('spam-model')), findsOneWidget);
      expect(find.text('Possibly spam from 50 %'), findsOneWidget);
      await expectGolden(tester, 'spam', 'settings', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden filters_list $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(),
        initialLocation: '/settings/filters?account=acct-1',
      );
      expect(find.byKey(const ValueKey('filter-rule-1')), findsOneWidget);
      expect(find.byKey(const ValueKey('filter-rule-2')), findsOneWidget);
      await expectGolden(tester, 'filters', 'list', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden filters_editor $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(),
        initialLocation: '/settings/filters?account=acct-1',
      );
      await tester.tap(find.byKey(const Key('filters-add')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('filter-editor')), findsOneWidget);
      await expectGolden(tester, 'filters', 'editor', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden spam_explain $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-junk-prize');
      await tester.tap(find.byKey(const Key('thread-more')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('thread-spam-explain')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('spam-explain-sheet')), findsOneWidget);
      expect(find.text('Spam · 99 %'), findsOneWidget);
      await expectGolden(tester, 'spam', 'explain', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden inbox_spam_folder $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore());
      await tester.tap(find.byKey(const Key('folder-chip-spam')));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('thread-tile-t-junk-prize')), findsOneWidget);
      await expectGolden(tester, 'inbox', 'spam_folder', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden settings_publish_awaiting $v', v, (tester) async {
      final core = GoldenCore()..directoryProgression = const [DirectoryState.awaitingVerification];
      await pumpSealbox(tester, core: core, initialLocation: '/settings');
      await _revealIn(tester, find.byKey(const Key('directory-status')), alignment: 0.15);
      expect(find.byKey(const ValueKey('directory-state-awaitingVerification')), findsOneWidget);
      await expectGolden(tester, 'settings', 'publish_awaiting', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden compose_reply_preview $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose?reply=t-budget');
      await _revealIn(tester, find.byKey(const Key('compose-preview-text')));
      expect(find.text('Reply with quote'), findsOneWidget);
      expect(
        tester.widget<SelectableText>(find.byKey(const Key('compose-preview-text'))).data,
        contains('> Alice,'),
      );
      await expectGolden(tester, 'compose', 'reply_preview', v);
    });
  }

  test('the fixtures behind these goldens', () async {
    final core = GoldenCore();
    expect((await core.listThreadsInRole(FolderRole.junk)).single.latest.date.year, 2026);
    expect(
      (await core.getMessage(FakeCore.junkSampleId))!.date.isBefore(DateTime(2026, 7)),
      isTrue,
      reason: 're-based like the inbox',
    );
  });
}
