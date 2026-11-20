import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Settings goldens: test/goldens/settings_<state>_<device>_<theme>.png
//
//   loaded       (full matrix)  two accounts, "My key" with the QR placeholder and
//                               the grouped fingerprint, backup off, engine info
//                               (phone: the top of the page)
//   backup_on    (reduced)      after "Back up now": the backup card reports the
//                               last backup (phone: scrolled to the backup card)
//   no_accounts  (reduced)      fresh profile: "No accounts yet" + Add account

void main() {
  for (final v in fullMatrix) {
    testVariant('golden settings_loaded $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/settings');
      expect(find.byKey(const Key('my-fingerprint')), findsOneWidget);
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('account-tile-acct-1')),
          matching: find.text('alice.rivera@gmail.com'),
        ),
        findsOneWidget,
      );
      await expectGolden(tester, 'settings', 'loaded', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden settings_backup_on $v', v, (tester) async {
      final core = GoldenCore();
      await core.backupNow();
      await pumpSealbox(tester, core: core, initialLocation: '/settings');
      final backup = find.byKey(const Key('settings-backup'));
      await tester.scrollUntilVisible(backup, 200, scrollable: find.byType(Scrollable).first);
      await tester.pumpAndSettle();
      // Cards built on the way down (key transparency) grow once loaded: settle again.
      await tester.ensureVisible(backup);
      await tester.pumpAndSettle();
      expect(find.text('Encrypted key backup is on'), findsOneWidget);
      await expectGolden(tester, 'settings', 'backup_on', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden settings_no_accounts $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(seeded: false), initialLocation: '/settings');
      expect(find.text('No accounts yet'), findsOneWidget);
      await expectGolden(tester, 'settings', 'no_accounts', v);
    });
  }
}
