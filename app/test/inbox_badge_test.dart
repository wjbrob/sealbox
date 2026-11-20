import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/widgets/lock_badge.dart';

import 'helpers.dart';

Finder badgeIn(String threadId, EncryptionState state) => find.descendant(
  of: find.byKey(ValueKey('thread-tile-$threadId')),
  matching: find.byKey(ValueKey('lock-badge-${state.name}')),
);

void main() {
  group('LockBadge', () {
    for (final state in EncryptionState.values) {
      testWidgets('renders ${state.name} with icon, key and semantics', (tester) async {
        final semantics = tester.ensureSemantics();
        await tester.pumpWidget(
          MaterialApp(home: Scaffold(body: LockBadge(state: state, showLabel: true))),
        );
        expect(find.byKey(ValueKey('lock-badge-${state.name}')), findsOneWidget);
        expect(find.byIcon(state.icon), findsOneWidget);
        expect(find.text(state.label), findsOneWidget);
        expect(find.byTooltip(state.description), findsOneWidget);
        final node = tester.getSemantics(find.byKey(ValueKey('lock-badge-${state.name}')));
        expect(node.label, contains(state.label));
        semantics.dispose();
      });
    }

    testWidgets('each state has a distinct icon and colour', (tester) async {
      final icons = EncryptionState.values.map((s) => s.icon).toSet();
      final colors = EncryptionState.values.map((s) => s.color).toSet();
      expect(icons, hasLength(EncryptionState.values.length));
      expect(colors, hasLength(EncryptionState.values.length));
    });
  });

  group('unified inbox', () {
    testWidgets('shows one lock badge per thread matching its newest message',
        (tester) async {
      setSurface(tester, const Size(600, 1600));
      await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('inbox-list')), findsOneWidget);
      expect(badgeIn('t-budget', EncryptionState.encrypted), findsOneWidget);
      expect(badgeIn('t-thunderbird', EncryptionState.encrypted), findsOneWidget);
      expect(badgeIn('t-guest-reply', EncryptionState.encrypted), findsOneWidget);
      expect(badgeIn('t-release', EncryptionState.signed), findsOneWidget);
      expect(badgeIn('t-lunch', EncryptionState.plaintext), findsOneWidget);
      expect(badgeIn('t-github', EncryptionState.plaintext), findsOneWidget);

      // Exactly one badge per tile, never two states on the same row.
      final tiles = find.byWidgetPredicate(
        (w) => w.key is ValueKey<String> &&
            (w.key as ValueKey<String>).value.startsWith('thread-tile-'),
      );
      final allBadges = find.byWidgetPredicate(
        (w) => w.key is ValueKey<String> &&
            (w.key as ValueKey<String>).value.startsWith('lock-badge-'),
      );
      expect(tester.widgetList(allBadges).length, tester.widgetList(tiles).length);
    });

    testWidgets('newest first, unread sender in bold, both accounts shown', (tester) async {
      setSurface(tester, const Size(600, 1600));
      await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
      await tester.pumpAndSettle();

      final tiles = tester
          .widgetList<ListTile>(find.byType(ListTile))
          .map((t) => (t.key as ValueKey<String>).value)
          .toList();
      expect(tiles.first, 'thread-tile-t-budget');
      expect(tiles.last, 'thread-tile-t-fastmail');

      final bob = tester.widget<Text>(find.text('Bob Nakamura'));
      expect(bob.style?.fontWeight, FontWeight.w700);
      final gh = tester.widget<Text>(find.text('GitHub'));
      expect(gh.style?.fontWeight, FontWeight.w400);

      expect(find.text('Gmail'), findsWidgets);
      expect(find.text('Fastmail'), findsWidgets);
    });

    testWidgets('desktop: list and detail side by side; thread opens in the detail pane',
        (tester) async {
      setSurface(tester, desktop);
      await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('home-rail')), findsOneWidget);
      expect(find.byKey(const Key('home-bottom-nav')), findsNothing);
      expect(find.byKey(const Key('inbox-list')), findsOneWidget);
      expect(find.text('Select a conversation'), findsOneWidget);

      await tester.tap(find.byKey(const ValueKey('thread-tile-t-budget')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('inbox-list')), findsOneWidget, reason: 'list stays');
      expect(find.byKey(const Key('thread-messages')), findsOneWidget);
      expect(find.byKey(const ValueKey('message-card-m-1')), findsOneWidget);
      expect(find.byKey(const Key('thread-back')), findsNothing);
      // D7: the verified signature names the signer's address; the key id is in the tooltip.
      expect(find.textContaining('signed by bob@sealbox.test'), findsOneWidget);
    });

    testWidgets('phone: stacked; thread replaces the list and has a back button',
        (tester) async {
      setSurface(tester, phone);
      await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('home-bottom-nav')), findsOneWidget);
      expect(find.byKey(const Key('home-rail')), findsNothing);

      await tester.tap(find.byKey(const ValueKey('thread-tile-t-lunch')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('inbox-list')), findsNothing);
      expect(find.byKey(const Key('thread-messages')), findsOneWidget);
      expect(find.byKey(const ValueKey('lock-badge-plaintext')), findsOneWidget);

      await tester.tap(find.byKey(const Key('thread-back')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('inbox-list')), findsOneWidget);
    });
  });
}
