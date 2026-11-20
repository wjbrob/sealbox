import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Onboarding goldens: test/goldens/onboarding_<state>_<device>_<theme>.png
//
//   email            (full matrix)  first screen, empty address field
//   error            (reduced)      malformed address rejected inline
//   detecting        (reduced)      spinner while the provider is looked up
//   detected_gmail   (full matrix)  Gmail: IMAP/SMTP rows, OAuth + app-password fallback
//   oauth_google     (reduced)      the "Sign in with Google" step (preview-build notice)
//   app_password_yahoo (reduced)    Yahoo: numbered app-password instructions + help link
//   manual_unknown   (reduced)      unknown domain → manual server settings, pre-filled
//   connecting       (reduced)      spinner while the account is added
//   done             (reduced)      "<address> is ready" with the Open-inbox button
//
// Update policy: docs/UX_TESTING.md ("flutter test --update-goldens" only
// after reviewing the diff under test/failures/).

Future<void> _enterAndContinue(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('onboarding-email')), email);
  await tester.tap(find.byKey(const Key('onboarding-continue')));
}

Future<void> _toYahooAppPassword(WidgetTester tester) async {
  await _enterAndContinue(tester, 'bob.k@yahoo.com');
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('onboarding-app-password')));
  await tester.pumpAndSettle();
}

void main() {
  for (final v in fullMatrix) {
    testVariant('golden onboarding_email $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      expect(find.byKey(const Key('onboarding-email')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'email', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden onboarding_error $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _enterAndContinue(tester, 'alice-at-gmail');
      await tester.pumpAndSettle();
      expect(find.textContaining('Enter a full email address'), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'error', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden onboarding_detecting $v', v, (tester) async {
      // The gate never completes, so the step stays on screen with no timer
      // left behind; 250 ms lets the step transition (200 ms) finish.
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false, detectGate: Completer<void>()),
        initialLocation: '/onboarding',
      );
      await _enterAndContinue(tester, 'alice@gmail.com');
      await tester.pump(const Duration(milliseconds: 250));
      expect(find.byKey(const Key('onboarding-detecting')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'detecting', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden onboarding_detected_gmail $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _enterAndContinue(tester, 'alice@gmail.com');
      await tester.pumpAndSettle();
      expect(find.text('Gmail detected'), findsOneWidget);
      expect(find.byKey(const Key('onboarding-oauth')), findsOneWidget);
      expect(find.byKey(const Key('onboarding-app-password')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'detected_gmail', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden onboarding_oauth_google $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _enterAndContinue(tester, 'alice@gmail.com');
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('onboarding-oauth')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('onboarding-oauth-step')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'oauth_google', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden onboarding_app_password_yahoo $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _toYahooAppPassword(tester);
      expect(find.byKey(const Key('onboarding-app-password-step')), findsOneWidget);
      expect(find.byTooltip('https://help.yahoo.com/kb/SLN15241.html'), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'app_password_yahoo', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden onboarding_manual_unknown $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _enterAndContinue(tester, 'carol@example.org');
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('onboarding-manual-step')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'manual_unknown', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden onboarding_connecting $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false, connectGate: Completer<void>()),
        initialLocation: '/onboarding',
      );
      await _toYahooAppPassword(tester);
      await tester.enterText(find.byKey(const Key('onboarding-secret')), 'abcd efgh ijkl mnop');
      await tester.pump();
      await tester.tap(find.byKey(const Key('onboarding-connect')));
      await tester.pump(const Duration(milliseconds: 250));
      expect(find.byKey(const Key('onboarding-connecting')), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'connecting', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden onboarding_done $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(seeded: false),
        initialLocation: '/onboarding',
      );
      await _toYahooAppPassword(tester);
      await tester.enterText(find.byKey(const Key('onboarding-secret')), 'abcd efgh ijkl mnop');
      await tester.pump();
      await tester.tap(find.byKey(const Key('onboarding-connect')));
      await tester.pumpAndSettle();
      expect(find.text('bob.k@yahoo.com is ready'), findsOneWidget);
      await expectGolden(tester, 'onboarding', 'done', v);
    });
  }
}
