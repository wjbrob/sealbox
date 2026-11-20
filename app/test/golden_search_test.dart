import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/features/search/search_controller.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Search goldens: test/goldens/search_<state>_<device>_<theme>.png
//
//   results  (full matrix)  "Q4" typed in the search field after the inbox's search
//                           action: the result count and three rows — sender, date,
//                           subject, the body snippet with the matched word in bold (none
//                           in the third, whose body does not mention it), lock badge and
//                           folder tag. Phone: the search screen; desktop: the results in
//                           the list pane, the detail pane waiting for one to open.

void main() {
  for (final v in fullMatrix) {
    testVariant('golden search_results $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore());
      await tester.tap(find.byKey(const Key('inbox-search')));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('search-field')), 'Q4');
      await tester.pump(MailSearchController.debounce);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('search-results')), findsOneWidget);
      expect(find.text('3 results'), findsOneWidget);
      expect(find.byKey(const ValueKey('search-result-m-1')), findsOneWidget);
      await expectGolden(tester, 'search', 'results', v);
    });
  }
}
