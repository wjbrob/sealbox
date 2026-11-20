import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/providers/provider_table.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Review P8: the empty inbox's copy is one line per sentence on a 360 dp phone, a 390 dp phone,
// the 411 dp emulator and the desktop list pane (380 px), so no word is left alone on a last
// line. Pinned on the laid-out paragraph, not on the text alone: the longer "Mail you send from
// Sealbox is encrypted; replies can be too." takes three lines at 360 dp, 390 dp and on desktop.

Future<GoldenCore> _oneAccountNoMail() async {
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
  return core;
}

void main() {
  for (final (name, size) in const [
    ('360 dp phone', Size(360, 800)),
    ('390 dp phone', Size(390, 844)),
    ('411 dp emulator', Size(411, 914)),
    ('desktop list pane', Size(1280, 800)),
  ]) {
    testWidgets('the empty inbox reads one line per sentence: $name', (tester) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      await pumpSealbox(tester, core: await _oneAccountNoMail());
      expect(find.text('Nothing here yet.'), findsOneWidget);
      final copy = find.descendant(
        of: find.byKey(const Key('inbox-empty')),
        matching: find.textContaining('New messages '),
      );
      expect(copy, findsOneWidget);
      final sentences = tester.widget<Text>(copy).data!.split('\n');
      expect(sentences, hasLength(2));
      final paragraph = tester.renderObject<RenderParagraph>(
        find.descendant(of: copy, matching: find.byType(RichText)),
      );
      final line = paragraph.getFullHeightForCaret(const TextPosition(offset: 0));
      expect(
        (paragraph.size.height / line).round(),
        2,
        reason: 'each sentence on one line at $size (${paragraph.size.width} px wide)',
      );
      expect(sentences.last, 'Mail you send is encrypted; replies can be too.');
    });
  }
}
