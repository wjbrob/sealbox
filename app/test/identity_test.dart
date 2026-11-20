import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/identity/verify_screen.dart';

import 'helpers.dart';

// G30 identity UI (docs/IDENTITY.md) against FakeCore: key-change banner and
// its two actions, the accepted / verified chips, contact badges and banners,
// the verify screen (manual entry in groups of four, pasted QR payload,
// mismatch refusal), the compose warning and the key-transparency states.

const bob = 'bob@sealbox.test';

void main() {
  _settingsAndComposeTests();
  testWidgets('key-changed banner → Accept new key → "Key changed (accepted)" chip', (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero)..simulateKeyChange(bob, messageId: 'm-1');
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-budget'));
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('key-changed-banner-$bob')), findsOneWidget);
    expect(find.textContaining('key changed'), findsOneWidget);
    expect(find.text('Compare fingerprints'), findsOneWidget);
    expect(find.text('Accept new key'), findsOneWidget);
    expect(find.text('Key changed (accepted)'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('key-changed-accept-$bob')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('key-changed-banner-$bob')), findsNothing);
    expect(find.text('Key changed (accepted)'), findsOneWidget);
    final c = (await core.contacts()).firstWhere((c) => c.address == bob);
    expect(c.keyChangePending, isFalse);
  });

  testWidgets('Compare fingerprints → verify screen (phone: camera scanner offered)', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero)..simulateKeyChange(bob, messageId: 'm-1');
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-budget'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('key-changed-compare-$bob')));
    await tester.pumpAndSettle();
    expect(find.text('Verify $bob'), findsOneWidget);
    expect(find.byKey(const Key('verify-my-qr')), findsOneWidget);
    await tester.scrollUntilVisible(
      find.byKey(const Key('verify-scan')),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.byKey(const Key('verify-paste')), findsNothing);
  });

  testWidgets('desktop verify: a wrong fingerprint is refused, the pasted QR payload verifies and '
      'clears the alert', (tester) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    try {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero)..simulateKeyChange(bob, messageId: 'm-1');
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-budget'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('key-changed-compare-$bob')));
      await tester.pumpAndSettle();
      final list = find.byType(Scrollable).first;
      expect(find.byKey(const Key('verify-scan')), findsNothing);
      await tester.scrollUntilVisible(find.byKey(const Key('verify-paste')), 200, scrollable: list);

      final current = (await core.contacts()).firstWhere((c) => c.address == bob).fingerprint!;

      // Manual entry is grouped in fours as it is typed.
      await tester.scrollUntilVisible(find.byKey(const Key('verify-manual')), 200, scrollable: list);
      await tester.enterText(find.byKey(const Key('verify-manual')), 'a' * 40);
      await tester.pump();
      final typed =
          tester.widget<TextField>(find.byKey(const Key('verify-manual'))).controller!.text;
      expect(typed, groupFingerprint('A' * 40));
      await tester.ensureVisible(find.byKey(const Key('verify-manual-confirm')));
      await tester.tap(find.byKey(const Key('verify-manual-confirm')));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(find.byKey(const Key('verify-error')), 200, scrollable: list);
      expect(find.textContaining('This is not the key Sealbox has'), findsOneWidget);
      expect((await core.contacts()).firstWhere((c) => c.address == bob).verified, isFalse);

      await tester.scrollUntilVisible(find.byKey(const Key('verify-paste')), -200, scrollable: list);
      await tester.enterText(
        find.byKey(const Key('verify-paste')),
        'openpgp4fpr:${current.toLowerCase()}',
      );
      await tester.pump();
      await tester.ensureVisible(find.byKey(const Key('verify-paste-check')));
      await tester.tap(find.byKey(const Key('verify-paste-check')));
      await tester.pumpAndSettle();
      final after = (await core.contacts()).firstWhere((c) => c.address == bob);
      expect(after.verified, isTrue);
      expect(after.keyChangePending, isFalse);
      // Back on the thread: no banner; the message keeps its "accepted" fact.
      expect(find.byKey(const ValueKey('key-changed-banner-$bob')), findsNothing);
      expect(find.text('Key changed (accepted)'), findsOneWidget);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });
}

void _settingsAndComposeTests() {
  test('fingerprint formatter groups upper-case hex in fours, at most 64 digits', () {
    const f = FingerprintGroupsFormatter();
    final v = f.formatEditUpdate(
      TextEditingValue.empty,
      const TextEditingValue(text: '9f4b-2e1c:7a5d zz30'),
    );
    expect(v.text, '9F4B 2E1C 7A5D 30');
    final long = f.formatEditUpdate(TextEditingValue.empty, TextEditingValue(text: 'a' * 80));
    expect(long.text.replaceAll(' ', '').length, 64);
  });

  testWidgets('"✓ Verified" chip on a message signed by the verified key', (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero)
      ..simulateVerified(bob)
      ..markSignerVerified('m-1');
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-budget'));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('message-verified-m-1')), findsOneWidget);
    expect(find.text('Verified'), findsOneWidget);
  });

  testWidgets('contacts list shows ⚠ / ✓ badges; the detail screen shows the banner', (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero)
      ..simulateKeyChange(bob)
      ..simulateVerified('carol@proton.me');
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings'));
    await tester.pumpAndSettle();
    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.byKey(const ValueKey('contact-tile-$bob')),
      200,
      scrollable: scrollable,
    );
    expect(find.byKey(const ValueKey('contact-badge-changed-$bob')), findsOneWidget);
    expect(find.byKey(const ValueKey('contact-badge-verified-carol@proton.me')), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('contact-tile-$bob')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('contact-banner-$bob')), findsOneWidget);
    expect(find.text('Key changed'), findsOneWidget);
    expect(find.text('Previous key'), findsOneWidget);
    await tester.tap(find.byKey(const Key('contact-accept')));
    await tester.pumpAndSettle();
    expect(find.text('Not verified'), findsOneWidget);
  });

  testWidgets('compose warns about a recipient whose key changed recently', (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero)..simulateKeyChange(bob);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-key-changed')), findsNothing);
    await tester.enterText(find.byKey(const Key('compose-to')), '$bob,');
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-key-changed')), findsOneWidget);
    expect(find.textContaining('The key for $bob changed recently'), findsOneWidget);
  });

  for (final (state, key) in [
    (KtState.verified, 'settings-kt-verified'),
    (KtState.alert, 'settings-kt-alert'),
    (KtState.unreachable, 'settings-kt-unreachable'),
    (KtState.unchecked, 'settings-kt-unchecked'),
  ]) {
    testWidgets('key transparency card: ${state.name}', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero)..ktState = state;
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings'));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.byKey(Key(key)),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.byKey(Key(key)), findsOneWidget);
      if (state == KtState.alert) {
        expect(find.text('The log lists a different key for you'), findsOneWidget);
      }
    });
  }

  testWidgets('key transparency card: no server', (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero)..configuredServer = null;
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings'));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.byKey(const Key('settings-kt-noServer')),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Key transparency: not available'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.byKey(const Key('settings-server')),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('No Sealbox server configured'), findsOneWidget);
  });
}
