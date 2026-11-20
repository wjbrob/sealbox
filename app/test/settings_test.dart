import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';

import 'helpers.dart';

void main() {
  testWidgets('settings lists accounts, the key fingerprint, backup and engine info',
      (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/settings'),
    );
    await tester.pumpAndSettle();

    // The account list (and, with two accounts, the "My key" account picker).
    expect(
      find.descendant(
        of: find.byKey(const ValueKey('account-tile-acct-1')),
        matching: find.text('alice.rivera@gmail.com'),
      ),
      findsOneWidget,
    );
    expect(find.textContaining('Gmail · OAuth 2.0'), findsOneWidget);
    expect(find.textContaining('Fastmail · App password'), findsOneWidget);

    final fp = tester.widget<SelectableText>(find.byKey(const Key('my-fingerprint')));
    expect(fp.data!.replaceAll(RegExp(r'\s'), ''), '3A9F1C2B4D5E6F708192A3B4C5D6E7F809A1B2C3');
    expect(find.bySemanticsLabel(RegExp('QR code of your key fingerprint')), findsOneWidget);

    final scrollable = find.byType(Scrollable).first;
    final backupNow = find.byKey(const Key('settings-backup-now'));
    await tester.scrollUntilVisible(backupNow, 200, scrollable: scrollable);
    // Cards built while scrolling (key transparency, directory) settle and grow.
    await tester.pumpAndSettle();
    await tester.ensureVisible(backupNow);
    await tester.pumpAndSettle();
    expect(find.text('Key not backed up'), findsOneWidget);
    expect(find.byKey(const Key('backup-reminder')), findsWidgets);
    // No phrase on this device yet: "Back up now" leads to the show-once screen.
    await tester.tap(backupNow);
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('recovery-create')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('recovery-reveal')), findsOneWidget);
    await tester.tap(find.byKey(const Key('recovery-reveal')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('recovery-wrote-down')));
    await tester.pumpAndSettle();
    const words = FakeCore.createdPhrase;
    for (final n in [3, 7, 11]) {
      await tester.enterText(find.byKey(Key('recovery-confirm-$n')), words[n - 1]);
    }
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('recovery-confirm')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('recovery-done')), findsOneWidget);
    await tester.tap(find.text('Done'));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(backupNow, 200, scrollable: find.byType(Scrollable).first);
    expect(find.text('Encrypted key backup is on'), findsOneWidget);

    await tester.scrollUntilVisible(
      find.byKey(const Key('settings-core-info')),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Rust core 0.0.0-fake'), findsOneWidget);
    expect(find.textContaining('Hello, Flutter! (FakeCore)'), findsOneWidget);
  });

  testWidgets('"Add account" opens onboarding', (tester) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/settings'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('settings-add-account')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-email')), findsOneWidget);
  });
}
