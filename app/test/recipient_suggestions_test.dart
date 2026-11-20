import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/recipient_suggestions.dart';

import 'helpers.dart';

// Compose recipient autocomplete: typing in To suggests addresses from `contacts()` (never
// our own accounts or someone already added); arrows + Enter or a tap pick one.

ContactKey contact(String address, {bool hasKey = true}) =>
    ContactKey(address: address, hasKey: hasKey, source: KeySource.autocrypt);

/// FakeCore whose contacts also hold one of our own addresses (the engine excludes them;
/// the field must not rely on that).
class _OwnInContactsCore extends FakeCore {
  _OwnInContactsCore() : super(latency: Duration.zero);

  @override
  Future<List<ContactKey>> contacts() async => [
    ...await super.contacts(),
    contact('alice.rivera@gmail.com'),
    contact('alice.b@example.org', hasKey: false),
  ];
}

final toField = find.byKey(const Key('compose-to'));
final suggestions = find.byKey(const Key('recipient-suggestions'));
Finder suggestion(String address) => find.byKey(ValueKey('recipient-suggestion-$address'));
Finder pill(String address) => find.byKey(ValueKey('recipient-pill-$address'));

bool highlighted(WidgetTester tester, String address) =>
    tester.widget<ListTile>(suggestion(address)).selected;

List<String> shown(WidgetTester tester) => [
  for (final t in tester.widgetList<ListTile>(
    find.descendant(of: suggestions, matching: find.byType(ListTile)),
  ))
    (t.key! as ValueKey<String>).value.replaceFirst('recipient-suggestion-', ''),
];

Future<void> openCompose(WidgetTester tester, {FakeCore? core, Size size = desktop}) async {
  setSurface(tester, size);
  await tester.pumpWidget(
    buildApp(
      core: core ?? FakeCore(latency: Duration.zero),
      initialLocation: '/compose',
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> type(WidgetTester tester, String text) async {
  await tester.enterText(toField, text);
  await tester.pumpAndSettle();
}

void main() {
  group('ranking', () {
    final contacts = [
      contact('carol@proton.me'),
      contact('erik@posteo.de'),
      contact('bob@sealbox.test'),
      contact('heidi@delta.chat'),
      contact('grace@fairemail.test'),
      contact('pro@example.org'),
    ];
    List<String> rank(String q, {Set<String> exclude = const {}, int limit = 10}) => [
      for (final s in recipientSuggestions(q, contacts, exclude: exclude, limit: limit)) s.address,
    ];

    test('exact, then prefix, then a word start, then anywhere; alphabetical within', () {
      expect(rank('pro'), ['pro@example.org', 'carol@proton.me']);
      expect(rank('e'), [
        'erik@posteo.de', // prefix
        'pro@example.org', // word start ("example")
        'bob@sealbox.test', // anywhere …
        'carol@proton.me',
        'grace@fairemail.test',
        'heidi@delta.chat',
      ]);
      expect(rank('BOB@SEALBOX.TEST '), ['bob@sealbox.test'], reason: 'case and space');
      expect(rank('delta'), ['heidi@delta.chat']);
      expect(rank('zzz'), isEmpty);
      expect(rank('  '), isEmpty);
    });

    test('excluded addresses, duplicates and the limit', () {
      expect(rank('e', exclude: {'erik@posteo.de', 'bob@sealbox.test'}), [
        'pro@example.org',
        'carol@proton.me',
        'grace@fairemail.test',
        'heidi@delta.chat',
      ]);
      expect(rank('e', limit: 2), ['erik@posteo.de', 'pro@example.org']);
      expect(recipientSuggestions('e', contacts), hasLength(kMaxRecipientSuggestions));
      final twice = recipientSuggestions('bob', [
        contact('bob@sealbox.test'),
        contact('Bob@Sealbox.test'),
      ]);
      expect(twice, hasLength(1));
    });

    test('the match is where the ranking found it (bold in the list)', () {
      final s = recipientSuggestions('proton', contacts).single;
      expect(s.address.substring(s.matchStart, s.matchStart + s.matchLength), 'proton');
    });

    test('the status line uses the recipient pill\'s words', () {
      expect(suggestionStatus(contact('a@b.c')).text, 'encrypted · Autocrypt');
      expect(suggestionStatus(contact('a@b.c', hasKey: false)).text, 'guest link · no key yet');
      expect(
        suggestionStatus(
          contact('a@b.c').copyWith(keyChangedAt: DateTime(2026), previousFingerprint: 'AB'),
        ).text,
        'key changed · compare fingerprints',
      );
      expect(
        suggestionStatus(contact('a@b.c').copyWith(verified: true)).text,
        'encrypted · verified · Autocrypt',
      );
    });
  });

  testWidgets('typing suggests contacts; Enter adds the highlighted one and empties the field', (
    tester,
  ) async {
    await openCompose(tester);
    expect(suggestions, findsNothing);
    await type(tester, 'e');
    expect(suggestions, findsOneWidget);
    expect(shown(tester), [
      'erik@posteo.de',
      'bob@sealbox.test',
      'carol@proton.me',
      'grace@fairemail.test',
      'heidi@delta.chat',
    ]);
    expect(highlighted(tester, 'erik@posteo.de'), isTrue, reason: 'the best match by default');
    expect(
      find.descendant(of: suggestion('erik@posteo.de'), matching: find.text('encrypted · WKD')),
      findsOneWidget,
    );

    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(pill('erik@posteo.de'), findsOneWidget);
    expect(find.byKey(const ValueKey('recipient-status-encrypted')), findsOneWidget);
    expect(tester.widget<TextField>(toField).controller!.text, isEmpty);
    expect(suggestions, findsNothing);
  });

  testWidgets('arrow keys move the highlight (wrapping); Enter adds that one', (tester) async {
    await openCompose(tester);
    await type(tester, 'e');
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(highlighted(tester, 'bob@sealbox.test'), isTrue);
    expect(highlighted(tester, 'erik@posteo.de'), isFalse);
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
    await tester.pump();
    expect(highlighted(tester, 'heidi@delta.chat'), isTrue, reason: 'up from the first wraps');
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(highlighted(tester, 'erik@posteo.de'), isTrue, reason: 'down from the last wraps');
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(pill('carol@proton.me'), findsOneWidget);
    expect(pill('erik@posteo.de'), findsNothing);
  });

  testWidgets('a tap adds the address and keeps the focus for the next one', (tester) async {
    await openCompose(tester, size: phone);
    await type(tester, 'pro');
    await tester.tap(suggestion('carol@proton.me'));
    await tester.pumpAndSettle();
    expect(pill('carol@proton.me'), findsOneWidget);
    expect(tester.widget<TextField>(toField).controller!.text, isEmpty);
    expect(tester.widget<TextField>(toField).focusNode!.hasFocus, isTrue);

    // The next address: Carol is on the message now, so she is not suggested again.
    await type(tester, 'pro');
    expect(suggestions, findsNothing);
    await type(tester, 'e');
    expect(shown(tester), isNot(contains('carol@proton.me')));
  });

  testWidgets('a complete typed address is taken as typed unless a suggestion is chosen', (
    tester,
  ) async {
    await openCompose(tester);
    // Valid-looking, but erik@posteo.de completes it: highlighted, Enter would take Erik.
    await type(tester, 'erik@posteo.d');
    expect(highlighted(tester, 'erik@posteo.de'), isTrue, reason: 'a suggestion completes it');
    await type(tester, 'rik@posteo.de');
    expect(suggestions, findsOneWidget, reason: 'erik@posteo.de contains it');
    expect(highlighted(tester, 'erik@posteo.de'), isFalse);
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(pill('rik@posteo.de'), findsOneWidget, reason: 'exactly what was typed');
    expect(pill('erik@posteo.de'), findsNothing);

    // The same text, but the user picks the suggestion with the keyboard.
    await type(tester, 'rik@posteo.de');
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(highlighted(tester, 'erik@posteo.de'), isTrue);
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(pill('erik@posteo.de'), findsOneWidget);
  });

  testWidgets('an exact match is highlighted even when the address is complete', (tester) async {
    await openCompose(tester);
    await type(tester, 'bob@sealbox.test');
    expect(shown(tester), ['bob@sealbox.test']);
    expect(highlighted(tester, 'bob@sealbox.test'), isTrue);
  });

  testWidgets('Escape hides the list until the text changes; leaving the field hides it', (
    tester,
  ) async {
    await openCompose(tester);
    await type(tester, 'e');
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    expect(suggestions, findsNothing);
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(pill('erik@posteo.de'), findsNothing, reason: 'nothing highlighted while hidden');
    expect(find.text('"e" is not an email address'), findsOneWidget);

    await type(tester, 'er');
    expect(suggestions, findsOneWidget);
    await tester.tap(find.byKey(const Key('compose-subject')));
    await tester.pumpAndSettle();
    expect(suggestions, findsNothing);
  });

  testWidgets('our own addresses are never suggested', (tester) async {
    await openCompose(tester, core: _OwnInContactsCore());
    await type(tester, 'alice');
    expect(shown(tester), ['alice.b@example.org']);
    expect(
      find.descendant(
        of: suggestion('alice.b@example.org'),
        matching: find.text('guest link · no key yet'),
      ),
      findsOneWidget,
    );
  });

  testWidgets('screen readers: the list announces its size; each row its position', (tester) async {
    final handle = tester.ensureSemantics();
    await openCompose(tester);
    await type(tester, 'pro');
    expect(find.bySemanticsLabel('1 suggested recipient for "pro"'), findsOneWidget);
    expect(
      tester.getSemantics(suggestion('carol@proton.me')),
      isSemantics(
        label: 'carol@proton.me\nencrypted · Sealbox directory',
        hint: 'Suggestion 1 of 1: adds the address as a recipient',
        isSelected: true,
        isButton: true,
        hasTapAction: true,
      ),
    );
    handle.dispose();
  });

  for (final dark in [false, true]) {
    testWidgets('accessibility guidelines with suggestions open (${dark ? 'dark' : 'light'})', (
      tester,
    ) async {
      final handle = tester.ensureSemantics();
      tester.platformDispatcher.platformBrightnessTestValue = dark
          ? Brightness.dark
          : Brightness.light;
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      await openCompose(tester, size: phone);
      await type(tester, 'e');
      expect(suggestions, findsOneWidget);
      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      handle.dispose();
    });
  }
}
