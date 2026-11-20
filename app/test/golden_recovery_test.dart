import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Recovery goldens (G15, docs/RECOVERY.md): test/goldens/recovery_<state>_<device>_<theme>.png
//
//   phrase_blurred       (reduced)      Settings → Recovery phrase: 12 words blurred until tapped
//   phrase_revealed      (full matrix)  the numbered grid, not selectable, no copy button
//   phrase_confirm       (reduced)      "Type words 3, 7 and 11 …"
//   restore_form         (full matrix)  onboarding → Restore: email, phrase, server
//   restore_error        (reduced)      wrong phrase → the documented 401 string
//   restore_credential   (reduced)      keys restored → the mailbox password step
//   transfer_code        (reduced)      setup message sent: the 36-digit code in nine blocks
//   inbox_reminder       (reduced)      no backup yet: the reminder banner over the inbox

Future<void> _toWords(WidgetTester tester, {bool reveal = false}) async {
  await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/settings/recovery-phrase');
  await tester.tap(find.byKey(const Key('recovery-create')));
  await tester.pumpAndSettle();
  if (reveal) {
    await tester.tap(find.byKey(const Key('recovery-reveal')));
    await tester.pumpAndSettle();
  }
}

Future<void> _restoreFilled(WidgetTester tester, String email, List<String> phrase) async {
  await pumpSealbox(tester, core: GoldenCore(seeded: false), initialLocation: '/restore');
  await tester.enterText(find.byKey(const Key('restore-email')), email);
  await tester.enterText(find.byKey(const Key('restore-phrase')), phrase.join(' '));
  await tester.pumpAndSettle();
}

void main() {
  for (final v in reducedA) {
    testVariant('golden recovery_phrase_blurred $v', v, (tester) async {
      await _toWords(tester);
      expect(find.byKey(const Key('recovery-reveal')), findsOneWidget);
      await expectGolden(tester, 'recovery', 'phrase_blurred', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden recovery_phrase_revealed $v', v, (tester) async {
      await _toWords(tester, reveal: true);
      expect(find.text('orbit'), findsOneWidget);
      await expectGolden(tester, 'recovery', 'phrase_revealed', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden recovery_phrase_confirm $v', v, (tester) async {
      await _toWords(tester, reveal: true);
      await tester.tap(find.byKey(const Key('recovery-wrote-down')));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('recovery-confirm-3')), 'harbor');
      await tester.pumpAndSettle();
      await expectGolden(tester, 'recovery', 'phrase_confirm', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden recovery_restore_form $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(seeded: false), initialLocation: '/restore');
      expect(find.text('Restore your account'), findsOneWidget);
      await expectGolden(tester, 'recovery', 'restore_form', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden recovery_restore_error $v', v, (tester) async {
      await _restoreFilled(tester, 'alice@fastmail.com', FakeCore.createdPhrase);
      await tester.tap(find.byKey(const Key('restore-submit')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('restore-error')), findsOneWidget);
      await expectGolden(tester, 'recovery', 'restore_error', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden recovery_restore_credential $v', v, (tester) async {
      await _restoreFilled(tester, 'alice@fastmail.com', FakeCore.samplePhrase);
      await tester.tap(find.byKey(const Key('restore-submit')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('restore-credential-title')), findsOneWidget);
      await expectGolden(tester, 'recovery', 'restore_credential', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden recovery_transfer_code $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/settings/transfer');
      await tester.tap(find.byKey(const Key('transfer-send')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('transfer-code-display')), findsOneWidget);
      await expectGolden(tester, 'recovery', 'transfer_code', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden recovery_inbox_reminder $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(backupReminder: true));
      expect(find.byKey(const Key('backup-reminder')), findsOneWidget);
      await expectGolden(tester, 'recovery', 'inbox_reminder', v);
    });
  }
}
