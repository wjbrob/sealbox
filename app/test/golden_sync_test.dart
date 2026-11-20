import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/harness.dart';
import 'support/sync_cores.dart';

// Sync progress goldens: test/goldens/inbox_<state>_<device>_<theme>.png
//
//   syncing   (full matrix)  the automatic first sync mid-way: "Fetching newest mail… 200 of
//                            500 · alice.rivera@gmail.com" under the title, the bar under the
//                            chips 40 % full, the list already showing what is stored
//   backfill  (reduced B)    older mail loading in the background after the first sync:
//                            "Loading older mail… 4,200 of 10,000 · …" under the title, no bar

void main() {
  for (final v in fullMatrix) {
    testVariant('golden inbox_syncing $v', v, (tester) async {
      await pumpSealbox(tester, core: syncingCore());
      expect(find.byKey(const Key('inbox-list')), findsOneWidget);
      expect(
        tester.widget<Text>(find.byKey(const Key('sync-status'))).data,
        'Fetching newest mail… 200 of 500 · alice.rivera@gmail.com',
      );
      final bar = tester.widget<LinearProgressIndicator>(find.byKey(const Key('sync-progress')));
      expect(bar.value, closeTo(0.4, 1e-9));
      await expectGolden(tester, 'inbox', 'syncing', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden inbox_backfill $v', v, (tester) async {
      await pumpSealbox(tester, core: backfillCore());
      expect(
        tester.widget<Text>(find.byKey(const Key('backfill-status'))).data,
        'Loading older mail… 4,200 of 10,000 · alice.rivera@gmail.com',
      );
      expect(find.byKey(const Key('sync-progress')), findsNothing);
      await expectGolden(tester, 'inbox', 'backfill', v);
    });
  }
}
