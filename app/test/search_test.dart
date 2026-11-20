import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/search/search_controller.dart';
import 'package:sealbox_app/src/features/search/search_screen.dart';

import 'helpers.dart';

// The search screen (route /search, `features/search/`): the inbox action opens it with a
// focused field, results arrive 300 ms after typing stops, matched words are bold, every
// state is honest (hint, no results, error with retry), a result opens its conversation —
// pushed on a phone so Back returns to the results, beside the results on a wide window —
// and Escape clears, then closes.

/// FakeCore that records every search and can fail the next ones.
class _RecordingCore extends FakeCore {
  _RecordingCore() : super(latency: Duration.zero);

  final List<String> queries = [];
  int failures = 0;

  @override
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) async {
    queries.add(text);
    if (failures > 0) {
      failures--;
      throw StateError('the index is busy');
    }
    return super.search(text, accountId: accountId, folder: folder, limit: limit);
  }
}

/// FakeCore whose search for [slowQuery] waits for [gate] (an answer that arrives late).
class _SlowCore extends FakeCore {
  _SlowCore(this.slowQuery) : super(latency: Duration.zero);

  final String slowQuery;
  final gate = Completer<void>();

  @override
  Future<List<SearchResult>> search(
    String text, {
    String? accountId,
    String? folder,
    int limit = 50,
  }) async {
    if (text == slowQuery) await gate.future;
    return super.search(text, accountId: accountId, folder: folder, limit: limit);
  }
}

Finder get field => find.byKey(const Key('search-field'));

Future<void> openSearch(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('inbox-search')));
  await tester.pumpAndSettle();
}

/// Types [text] and lets the debounce run out.
Future<void> search(WidgetTester tester, String text) async {
  await tester.enterText(field, text);
  await tester.pump(MailSearchController.debounce);
  await tester.pumpAndSettle();
}

/// The spans of a result's snippet as (text, bold).
List<(String, bool)> snippetSpans(WidgetTester tester, String messageId) {
  final rich = tester.widget<RichText>(
    find.descendant(
      of: find.byKey(ValueKey('search-snippet-$messageId')),
      matching: find.byType(RichText),
    ),
  );
  final out = <(String, bool)>[];
  rich.text.visitChildren((span) {
    if (span is TextSpan && span.text != null) {
      out.add((span.text!, span.style?.fontWeight == FontWeight.w700));
    }
    return true;
  });
  return out;
}

void main() {
  testWidgets('the inbox action opens search: field focused, an honest hint', (tester) async {
    setSurface(tester, phone);
    final core = _RecordingCore();
    await tester.pumpWidget(buildApp(core: core));
    await tester.pumpAndSettle();
    expect(find.byTooltip('Search mail'), findsOneWidget);
    await openSearch(tester);
    expect(tester.widget<TextField>(field).focusNode!.hasFocus, isTrue);
    expect(find.byKey(const Key('search-hint')), findsOneWidget);
    expect(find.textContaining('The search runs on this device'), findsOneWidget);
    expect(core.queries, isEmpty);
  });

  testWidgets('results come 300 ms after typing stops; one query, the matched words in bold', (
    tester,
  ) async {
    setSurface(tester, phone);
    final core = _RecordingCore();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/search'));
    await tester.pumpAndSettle();
    await tester.enterText(field, 'reneg');
    await tester.pump(const Duration(milliseconds: 200));
    await tester.enterText(field, 'renegotiation');
    await tester.pump(MailSearchController.debounce - const Duration(milliseconds: 1));
    expect(core.queries, isEmpty, reason: 'still typing');
    await tester.pump(const Duration(milliseconds: 2));
    expect(core.queries, ['renegotiation'], reason: 'only the text typing stopped at');
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('search-count')), findsOneWidget);
    expect(find.text('1 result'), findsOneWidget);
    final tile = find.byKey(const ValueKey('search-result-m-1'));
    expect(tile, findsOneWidget);
    expect(find.descendant(of: tile, matching: find.text('Bob Nakamura')), findsOneWidget);
    expect(
      find.descendant(of: tile, matching: find.text('Q4 budget — final numbers')),
      findsOneWidget,
    );
    expect(
      find.descendant(of: tile, matching: find.text('Inbox')),
      findsOneWidget,
      reason: 'folder',
    );
    expect(
      find.descendant(of: tile, matching: find.byKey(const ValueKey('lock-badge-encrypted'))),
      findsOneWidget,
    );
    final spans = snippetSpans(tester, 'm-1');
    expect(spans.where((s) => s.$2).map((s) => s.$1), ['renegotiation']);
    expect(spans.map((s) => s.$1).join(), contains('after the renegotiation.'));
  });

  testWidgets('an answer for older text never replaces the answer for the current text', (
    tester,
  ) async {
    setSurface(tester, phone);
    final core = _SlowCore('renegotiation');
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/search'));
    await tester.pumpAndSettle();
    await tester.enterText(field, 'renegotiation');
    await tester.pump(MailSearchController.debounce);
    await tester.pump(); // that search is still on its way (a spinner: no settling)
    expect(find.byKey(const Key('search-loading')), findsOneWidget);
    await search(tester, 'lebanese');
    expect(find.byKey(const ValueKey('search-result-m-3')), findsOneWidget);
    core.gate.complete();
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('search-result-m-3')), findsOneWidget);
    expect(find.byKey(const ValueKey('search-result-m-1')), findsNothing, reason: 'stale');
  });

  testWidgets('no results says so for the exact query; symbols alone are not searched', (
    tester,
  ) async {
    setSurface(tester, phone);
    final core = _RecordingCore();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/search'));
    await tester.pumpAndSettle();
    await search(tester, 'zebracorn');
    expect(find.byKey(const Key('search-empty')), findsOneWidget);
    expect(find.text('No results for “zebracorn”'), findsOneWidget);
    await search(tester, '--- ?');
    expect(find.byKey(const Key('search-hint')), findsOneWidget);
    expect(core.queries, ['zebracorn'], reason: 'text without a letter or digit is not sent');
  });

  testWidgets('an error is shown with Retry, which searches again', (tester) async {
    setSurface(tester, phone);
    final core = _RecordingCore()..failures = 1;
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/search'));
    await tester.pumpAndSettle();
    await search(tester, 'budget');
    expect(find.byKey(const Key('search-error')), findsOneWidget);
    expect(find.text('the index is busy'), findsOneWidget);
    await tester.tap(find.byKey(const Key('search-retry')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('search-error')), findsNothing);
    expect(find.byKey(const ValueKey('search-result-m-1')), findsOneWidget);
    expect(core.queries, ['budget', 'budget']);
  });

  testWidgets('phone: a result opens its conversation; Back returns to the results', (
    tester,
  ) async {
    setSurface(tester, phone);
    await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/inbox'));
    await tester.pumpAndSettle();
    await openSearch(tester);
    await search(tester, 'lebanese');
    await tester.tap(find.byKey(const ValueKey('search-result-m-3')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('thread-messages')), findsOneWidget);
    expect(find.textContaining('The Lebanese place near the station'), findsWidgets);
    final ctx = tester.element(find.byKey(const Key('thread-messages')));
    expect(GoRouter.of(ctx).state.uri.toString(), '/inbox/t/t-lunch?from=search');
    await tester.tap(find.byType(BackButton));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('search-result-m-3')), findsOneWidget);
    expect(tester.widget<TextField>(field).controller!.text, 'lebanese');
  });

  testWidgets('phone: the system Back closes the search (back to the inbox, not out)', (
    tester,
  ) async {
    setSurface(tester, phone);
    await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/inbox'));
    await tester.pumpAndSettle();
    await openSearch(tester);
    await search(tester, 'lebanese');
    await tester.tap(find.byKey(const ValueKey('search-result-m-3')));
    await tester.pumpAndSettle();
    expect(await tester.binding.handlePopRoute(), isTrue);
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('search-result-m-3')), findsOneWidget, reason: 'results');
    expect(await tester.binding.handlePopRoute(), isTrue, reason: 'handled, not leaving the app');
    await tester.pumpAndSettle();
    expect(field, findsNothing);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  });

  testWidgets('wide: results stay in the list pane beside the conversation; closing keeps it', (
    tester,
  ) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/inbox'));
    await tester.pumpAndSettle();
    await openSearch(tester);
    expect(find.byKey(const Key('search-detail-placeholder')), findsOneWidget);
    expect(find.byKey(const Key('inbox-list')), findsNothing, reason: 'results own the list pane');
    await search(tester, 'thunderbird');
    await tester.tap(find.byKey(const ValueKey('search-result-m-2')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('thread-messages')), findsOneWidget);
    expect(find.byKey(const Key('search-results')), findsOneWidget, reason: 'still beside it');
    expect(
      tester.widget<ListTile>(find.byKey(const ValueKey('search-result-m-2'))).selected,
      isTrue,
    );
    await tester.tap(find.byKey(const Key('search-close')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('search-results')), findsNothing);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
    expect(
      find.byKey(const Key('thread-messages')),
      findsOneWidget,
      reason: 'the conversation stays',
    );
  });

  testWidgets('Escape clears the field, a second Escape closes the search', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/inbox'));
    await tester.pumpAndSettle();
    await openSearch(tester);
    await search(tester, 'budget');
    expect(find.byKey(const Key('search-results')), findsOneWidget);
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(field).controller!.text, isEmpty);
    expect(find.byKey(const Key('search-hint')), findsOneWidget);
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pumpAndSettle();
    expect(field, findsNothing);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  });

  testWidgets('mail we sent shows its recipients; folder names read like the chips', (
    tester,
  ) async {
    expect(folderLabel('INBOX'), 'Inbox');
    expect(folderLabel('[Gmail]/Sent Mail'), 'Sent');
    expect(folderLabel('Junk Email'), 'Spam');
    expect(folderLabel('Review samples'), 'Review samples');
    expect(folderLabel('Lists/rust-users'), 'rust-users');
    setSurface(tester, phone);
    await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/search'));
    await tester.pumpAndSettle();
    await search(tester, 'legal signs off');
    final tile = find.byKey(const ValueKey('search-result-m-0'));
    expect(find.descendant(of: tile, matching: find.text('To Bob Nakamura')), findsOneWidget);
  });

  group('accessibility', () {
    for (final (name, size) in [('phone', phone), ('desktop', desktop)]) {
      testWidgets('results on $name: contrast, labelled targets', (tester) async {
        final handle = tester.ensureSemantics();
        setSurface(tester, size);
        await tester.pumpWidget(buildApp(core: _RecordingCore(), initialLocation: '/search'));
        await tester.pumpAndSettle();
        await search(tester, 'alice');
        expect(find.byKey(const Key('search-results')), findsOneWidget);
        await expectLater(tester, meetsGuideline(textContrastGuideline));
        await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
        if (size == phone) {
          await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
        }
        // One node per result: who, what, and where.
        final node = tester.getSemantics(find.byKey(const ValueKey('search-result-m-1')));
        expect(node.label, contains('Bob Nakamura'));
        expect(node.label, contains('Q4 budget — final numbers'));
        expect(node.label, contains('Inbox'));
        expect(node, isSemantics(isButton: true, hasTapAction: true, label: node.label));
        handle.dispose();
      });
    }
  });
}
