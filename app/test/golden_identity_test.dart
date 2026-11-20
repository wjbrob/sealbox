import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Identity goldens (G30, docs/IDENTITY.md): test/goldens/identity_<state>_<device>_<theme>.png
//
//   thread_key_changed   (full matrix)  t-budget: Bob's reply came with a new key → amber
//                                       banner with Compare fingerprints / Accept new key
//   thread_key_accepted  (reduced)      the same after "Accept new key": the chip stays
//   thread_verified      (reduced)      t-thunderbird: Carol verified, "✓ Verified" chip
//   contact_key_changed  (reduced)      Settings → contact: the key-changed banner, both keys
//   verify               (full matrix)  the Verify screen: their key, our real QR code,
//                                       scan (phone) / paste (desktop), manual entry
//   compose_key_changed  (reduced)      compose to Bob: the "changed recently" warning
//   settings_kt_alert    (reduced)      Settings → Security: key-transparency SUBSTITUTION alert

const bob = 'bob@sealbox.test';

GoldenCore _changed() => GoldenCore()..simulateKeyChange(bob, messageId: 'm-1');

void main() {
  for (final v in fullMatrix) {
    testVariant('golden identity_thread_key_changed $v', v, (tester) async {
      await pumpSealbox(tester, core: _changed(), initialLocation: '/inbox/t/t-budget');
      expect(find.byKey(const ValueKey('key-changed-banner-$bob')), findsOneWidget);
      await expectGolden(tester, 'identity', 'thread_key_changed', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden identity_thread_key_accepted $v', v, (tester) async {
      final core = _changed();
      await core.acknowledgeKeyChange(bob);
      await pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-budget');
      expect(find.text('Key changed (accepted)'), findsOneWidget);
      await expectGolden(tester, 'identity', 'thread_key_accepted', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden identity_thread_verified $v', v, (tester) async {
      final core = GoldenCore()
        ..simulateVerified('carol@proton.me', at: GoldenCore.keyChangedAt)
        ..markSignerVerified('m-2');
      await pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-thunderbird');
      expect(find.text('Verified'), findsOneWidget);
      await expectGolden(tester, 'identity', 'thread_verified', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden identity_contact_key_changed $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: _changed(),
        initialLocation: '/settings/contact?address=${Uri.encodeQueryComponent(bob)}',
      );
      expect(find.byKey(const ValueKey('contact-banner-$bob')), findsOneWidget);
      await expectGolden(tester, 'identity', 'contact_key_changed', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden identity_verify $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(),
        initialLocation: '/settings/verify?address=${Uri.encodeQueryComponent(bob)}',
      );
      expect(find.byKey(const Key('verify-my-qr')), findsOneWidget);
      await expectGolden(tester, 'identity', 'verify', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden identity_compose_key_changed $v', v, (tester) async {
      await pumpSealbox(tester, core: _changed(), initialLocation: '/compose');
      await tester.enterText(find.byKey(const Key('compose-to')), '$bob,');
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('compose-key-changed')), findsOneWidget);
      await expectGolden(tester, 'identity', 'compose_key_changed', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden identity_settings_kt_alert $v', v, (tester) async {
      final core = GoldenCore()..ktState = KtState.alert;
      await pumpSealbox(tester, core: core, initialLocation: '/settings');
      final card = find.byKey(const Key('settings-kt-alert'));
      await tester.scrollUntilVisible(card, 200, scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      await tester.ensureVisible(card);
      await tester.pumpAndSettle();
      await expectGolden(tester, 'identity', 'settings_kt_alert', v);
    });
  }
}
