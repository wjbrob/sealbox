import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/providers/provider_table.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Inbox goldens: test/goldens/inbox_<state>_<device>_<theme>.png
//
//   loaded      (full matrix)  the sample mailbox: two accounts (provider chips
//                              on every row), encrypted / signed / plaintext
//                              badges, unread rows in bold, newest first; on
//                              desktop the rail, the list and the empty detail
//                              pane ("Select a conversation") side by side
//   empty       (reduced)      no account yet → "Welcome to Sealbox" + Add an account
//   no_threads  (reduced)      one account, nothing synced → "Nothing here yet."
//
// Search / "no results" states are not in the app yet (see docs/UX_TESTING.md).

void main() {
  for (final v in fullMatrix) {
    testVariant('golden inbox_loaded $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore());
      expect(find.byKey(const Key('inbox-list')), findsOneWidget);
      expect(find.byKey(const ValueKey('thread-tile-t-budget')), findsOneWidget);
      expect(find.byKey(const ValueKey('lock-badge-signed')), findsWidgets);
      await expectGolden(tester, 'inbox', 'loaded', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden inbox_empty $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(seeded: false));
      expect(find.byKey(const Key('inbox-add-account')), findsOneWidget);
      await expectGolden(tester, 'inbox', 'empty', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden inbox_no_threads $v', v, (tester) async {
      final core = GoldenCore(seeded: false);
      await core.addAccount(
        const AccountSetup(
          email: 'alice@example.org',
          displayName: 'Alice',
          authMethod: AuthMethod.password,
          imap: ServerSettings('imap.example.org', 993, ConnectionSecurity.tls),
          smtp: ServerSettings('smtp.example.org', 587, ConnectionSecurity.starttls),
          providerName: 'example.org',
        ),
      );
      await pumpSealbox(tester, core: core);
      expect(find.text('Nothing here yet.'), findsOneWidget);
      await expectGolden(tester, 'inbox', 'no_threads', v);
    });
  }
}
