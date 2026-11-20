import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/review_tour.dart';

import 'helpers.dart';

// Review N2 (review/desktop/2026-10-29/REVIEW.md): in the seeded session the tour scrolled
// to Mail handling, then looked for the Key-directory panel by paging *down* through the
// lazy settings list; the panel sits above, so the search ended on the Server card and
// `49-settings-publish.png` equalled `50-settings-server.png`. `revealInList` (behind the
// tour's `_ensureVisible`) now searches from the top.

/// Like the tour's `find_`: any mounted element with `Key(key)`, on screen or not.
BuildContext? byKey(String key) {
  final hits = find.byKey(Key(key), skipOffstage: false).evaluate();
  return hits.isEmpty ? null : hits.first;
}

Future<ScrollPosition> settingsAtBottom(WidgetTester tester) async {
  final list = find.byKey(const Key('settings-list'));
  final scrollable = find.descendant(of: list, matching: find.byType(Scrollable)).first;
  final pos = tester.state<ScrollableState>(scrollable).position;
  pos.jumpTo(pos.maxScrollExtent);
  await tester.pumpAndSettle();
  return pos;
}

void main() {
  testWidgets('N2: the Key-directory panel above the viewport is found and brought into view', (
    tester,
  ) async {
    setSurface(tester, desktop);
    // The seeded review profile has no Sealbox server: the panel's "no server" state.
    final core = FakeCore(latency: Duration.zero)..configuredServer = null;
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings'));
    await tester.pumpAndSettle();
    await settingsAtBottom(tester);
    expect(find.byKey(const Key('settings-server')), findsOneWidget);
    expect(byKey('directory-status'), isNull, reason: 'built lazily: gone once scrolled past');

    final found = await revealInList(
      'directory-status',
      find: byKey,
      frame: () => tester.pump(),
      list: tester.element(find.byKey(const Key('settings-list'))),
      alignment: 0.3,
    );
    await tester.pumpAndSettle();
    expect(found, isTrue);
    final view = tester.getRect(find.byKey(const Key('settings-list')));
    final panel = tester.getRect(find.byKey(const Key('directory-status')));
    expect(view.contains(panel.topCenter), isTrue, reason: 'panel $panel in view $view');
    expect(find.byKey(const ValueKey('directory-state-noServer')).hitTestable(), findsOneWidget);
    expect(find.byKey(const Key('directory-set-server')).hitTestable(), findsOneWidget);
    expect(
      find.byKey(const Key('settings-server')),
      findsNothing,
      reason: 'a different shot than settings-server',
    );
  });

  testWidgets('a target below the viewport is still found; an unknown key reports false', (
    tester,
  ) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/settings'),
    );
    await tester.pumpAndSettle();
    expect(byKey('settings-core-info'), isNull);
    final list = tester.element(find.byKey(const Key('settings-list')));
    expect(
      await revealInList('settings-core-info', find: byKey, frame: () => tester.pump(), list: list),
      isTrue,
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('settings-core-info')).hitTestable(), findsOneWidget);
    expect(
      await revealInList('no-such-key', find: byKey, frame: () => tester.pump(), list: list),
      isFalse,
    );
  });
}
