import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';

import 'helpers.dart';

void main() {
  testWidgets('folder chips: an arrow marks the clipped edge and pages the row (L11)',
      (tester) async {
    setSurface(tester, const Size(390, 844));
    await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero)));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('folder-chips-more-right')), findsOneWidget);
    expect(find.byKey(const Key('folder-chips-more-left')), findsNothing);
    for (var i = 0; i < 6 && find.byKey(const Key('folder-chips-more-right')).evaluate().isNotEmpty; i++) {
      await tester.tap(find.byKey(const Key('folder-chips-more-right')));
      await tester.pumpAndSettle();
    }
    expect(find.byKey(const Key('folder-chips-more-right')), findsNothing);
    expect(find.byKey(const Key('folder-chips-more-left')), findsOneWidget);
    await tester.tap(find.byKey(const Key('folder-chip-all')));
    await tester.pumpAndSettle();
    expect(find.text('All mail'), findsWidgets);
  });

  testWidgets('phone thread: the Reply FAB never covers the last message (L12)', (tester) async {
    setSurface(tester, const Size(412, 915));
    tester.view.padding = const FakeViewPadding(bottom: 48);
    addTearDown(tester.view.resetPadding);
    await tester.pumpWidget(buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/inbox/t/t-budget'));
    await tester.pumpAndSettle();
    await tester.drag(find.byKey(const Key('thread-messages')), const Offset(0, -5000));
    await tester.pumpAndSettle();
    final fab = tester.getRect(find.byType(FloatingActionButton));
    final cards = find.byWidgetPredicate((w) => w.key is ValueKey && '${(w.key as ValueKey).value}'.startsWith('message-card-'));
    final last = tester.getRect(cards.last);
    expect(last.bottom, lessThanOrEqualTo(fab.top), reason: 'last card $last vs FAB $fab');
  });
}
