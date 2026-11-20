import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Compose goldens: test/goldens/compose_<state>_<device>_<theme>.png
//
//   empty            (reduced)      no recipient: neutral policy banner
//   encrypted        (reduced)      one recipient with a key: green pill, "End-to-end
//                                   encrypted" banner, protected-subject note
//   mixed            (full matrix)  one pill per status — encrypted (Autocrypt),
//                                   guest link, confirmed plaintext — with the
//                                   guest-passphrase panel and the plaintext warning
//   plaintext_dialog (reduced)      the "Send unencrypted to …?" confirmation dialog
//   guest_sent       (reduced)      after sending a passphrase guest link: the
//                                   passphrase shown once, with copy / share
//   suggestions      (full matrix)  recipient autocomplete: Bob added, "e" typed in To;
//                                   four contacts suggested (Bob is not: already added),
//                                   the best match (erik@, WKD) highlighted, match in bold
//
// There is no attachments row in the compose screen yet (docs/UX_TESTING.md).

Future<void> _addRecipient(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('compose-to')), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

Future<void> _openPlaintextDialog(WidgetTester tester, String email) async {
  await tester.tap(find.byKey(ValueKey('recipient-menu-$email')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('pill-action-plaintext')));
  await tester.pumpAndSettle();
  expect(find.byKey(const Key('plaintext-confirm-dialog')), findsOneWidget);
}

/// bob (key via Autocrypt) · dana (no key → guest link) · ivan (no key, user
/// confirmed plaintext).
Future<void> _mixedRecipients(WidgetTester tester) async {
  await _addRecipient(tester, 'bob@sealbox.test');
  await _addRecipient(tester, 'dana@example.org');
  await _addRecipient(tester, 'ivan.petrov@hotmail.com');
  await _openPlaintextDialog(tester, 'ivan.petrov@hotmail.com');
  await tester.tap(find.byKey(const Key('confirm-plaintext')));
  await tester.pumpAndSettle();
}

void main() {
  for (final v in reducedA) {
    testVariant('golden compose_empty $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      expect(find.byKey(const Key('compose-policy-empty')), findsOneWidget);
      await expectGolden(tester, 'compose', 'empty', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden compose_encrypted $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _addRecipient(tester, 'bob@sealbox.test');
      expect(find.byKey(const Key('compose-policy-encrypted')), findsOneWidget);
      expect(find.byKey(const Key('guest-passphrase-panel')), findsNothing);
      await expectGolden(tester, 'compose', 'encrypted', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden compose_mixed $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _mixedRecipients(tester);
      expect(find.byKey(const ValueKey('recipient-status-encrypted')), findsOneWidget);
      expect(find.byKey(const ValueKey('recipient-status-guestLink')), findsOneWidget);
      expect(find.byKey(const ValueKey('recipient-status-plaintext')), findsOneWidget);
      expect(find.byKey(const Key('guest-passphrase-panel')), findsOneWidget);
      expect(find.byKey(const Key('compose-policy-plaintext')), findsOneWidget);
      await expectGolden(tester, 'compose', 'mixed', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden compose_suggestions $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _addRecipient(tester, 'bob@sealbox.test');
      await tester.enterText(find.byKey(const Key('compose-to')), 'e');
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('recipient-suggestions')), findsOneWidget);
      expect(find.byKey(const ValueKey('recipient-suggestion-bob@sealbox.test')), findsNothing);
      expect(
        tester
            .widget<ListTile>(find.byKey(const ValueKey('recipient-suggestion-erik@posteo.de')))
            .selected,
        isTrue,
      );
      await expectGolden(tester, 'compose', 'suggestions', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden compose_plaintext_dialog $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _addRecipient(tester, 'dana@example.org');
      await _openPlaintextDialog(tester, 'dana@example.org');
      await expectGolden(tester, 'compose', 'plaintext_dialog', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden compose_guest_sent $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _addRecipient(tester, 'dana@example.org');
      await tester.tap(find.byKey(const Key('compose-send')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('guest-sent-dialog')), findsOneWidget);
      await expectGolden(tester, 'compose', 'guest_sent', v);
    });
  }
}
