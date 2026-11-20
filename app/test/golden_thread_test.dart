import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';
import 'support/inline_image_core.dart';

// Thread goldens: test/goldens/thread_<state>_<device>_<theme>.png
//
//   encrypted_verified       (full matrix)  t-budget: our encrypted question plus
//                                           Bob's encrypted, signature-verified reply
//                                           ("signed by bob@…", D7); the subject heads
//                                           the first card, the app bar says "Inbox"
//                                           (D6/B1)
//   encrypted_unknown_signer (reduced)      t-guest-reply: encrypted both ways, no
//                                           verified signer (guest-link reply)
//   signed_only              (reduced)      t-release: cleartext with a valid signature
//   plaintext                (reduced)      t-lunch: ordinary unencrypted mail
//   undecryptable            (reduced A)    t-undecryptable, opened from "All mail": the
//                                           provider's "..." reads "Encrypted message" in
//                                           italics in the row and the header (review N1)
//   signer_mismatch          (reduced B)    t-signer-mismatch, opened from "All mail": Bob's
//                                           mail signed with another address's key, the amber
//                                           "signed by … — but sent by …" chip and the row's
//                                           amber glyph (R4)
//   html                     (full matrix)  t-html-statement: an HTML newsletter rendered by
//                                           MessageBody — heading, table, inline-image and
//                                           remote-image placeholders, the "2 remote images
//                                           blocked · Load images" banner and "Show as text"
//                                           (docs/HTML_MAIL.md). Deterministic because every
//                                           image is blocked: nothing is fetched
//   html_inline_image        (full matrix)  the same newsletter once its logo part carries the
//                                           Content-ID its cid: image names (InlineImageCore):
//                                           the logo renders from the local store, decoded
//                                           before the capture; the two remote images stay
//                                           blocked and counted; the logo is not listed again
//                                           as an attachment chip under the body (review N4;
//                                           in `html` its part names nothing, so it keeps one)
//
// Phone: the thread replaces the list (back button). Desktop: list + detail.

/// Opens [threadId] from the "All mail" chip: FakeCore keeps the review samples outside
/// INBOX, so on desktop the list beside the thread shows (and selects) their row too.
Future<void> _openFromAllMail(WidgetTester tester, String threadId) async {
  final chip = find.byKey(const Key('folder-chip-all'));
  await tester.ensureVisible(chip);
  await tester.pumpAndSettle();
  await tester.tap(chip);
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(ValueKey('thread-tile-$threadId')));
  await tester.pumpAndSettle();
}

void main() {
  for (final v in fullMatrix) {
    testVariant('golden thread_encrypted_verified $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-budget');
      expect(find.byKey(const ValueKey('message-card-m-1')), findsOneWidget);
      expect(find.byKey(const ValueKey('lock-badge-encrypted')), findsWidgets);
      expect(find.textContaining('signed by bob@sealbox.test'), findsOneWidget);
      expect(find.byKey(const Key('thread-subject')), findsOneWidget);
      await expectGolden(tester, 'thread', 'encrypted_verified', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden thread_encrypted_unknown_signer $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-guest-reply');
      expect(find.byKey(const ValueKey('message-card-m-5')), findsOneWidget);
      expect(find.byKey(const ValueKey('lock-badge-encrypted')), findsWidgets);
      expect(find.textContaining('signed by'), findsNothing);
      expect(find.textContaining('signature verified'), findsNothing);
      await expectGolden(tester, 'thread', 'encrypted_unknown_signer', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden thread_signed_only $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-release');
      expect(find.byKey(const ValueKey('lock-badge-signed')), findsWidgets);
      await expectGolden(tester, 'thread', 'signed_only', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden thread_plaintext $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-lunch');
      expect(find.byKey(const ValueKey('lock-badge-plaintext')), findsWidgets);
      await expectGolden(tester, 'thread', 'plaintext', v);
    });
  }

  for (final v in reducedA) {
    testVariant('golden thread_undecryptable $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore());
      await _openFromAllMail(tester, 't-undecryptable');
      expect(tester.widget<Text>(find.byKey(const Key('thread-subject'))).data, 'Encrypted message');
      expect(find.byKey(const ValueKey('lock-badge-undecryptable')), findsWidgets);
      expect(find.text('...'), findsNothing);
      await expectGolden(tester, 'thread', 'undecryptable', v);
    });
  }

  for (final v in reducedB) {
    testVariant('golden thread_signer_mismatch $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore());
      await _openFromAllMail(tester, 't-signer-mismatch');
      expect(
        find.byKey(const ValueKey('message-signer-mismatch-m-signer-mismatch-1')),
        findsOneWidget,
      );
      expect(
        find.text('signed by accounts@nakamura-billing.example — but sent by bob@sealbox.test'),
        findsOneWidget,
      );
      await expectGolden(tester, 'thread', 'signer_mismatch', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden thread_html $v', v, (tester) async {
      await pumpSealbox(
        tester,
        core: GoldenCore(),
        initialLocation: '/inbox/t/t-html-statement',
      );
      expect(find.byKey(ValueKey('message-html-${FakeCore.htmlSampleId}')), findsOneWidget);
      expect(find.byKey(const Key('html-remote-banner')), findsOneWidget);
      expect(find.text('2 remote images blocked'), findsOneWidget);
      expect(find.byKey(const Key('message-show-text')), findsOneWidget);
      // nothing in the capture was fetched from the network
      expect(find.byType(Image), findsNothing);
      // the logo part has no Content-ID here: not shown inline, so it keeps its chip (N4)
      expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsOneWidget);
      await expectGolden(tester, 'thread', 'html', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden thread_html_inline_image $v', v, (tester) async {
      final core = InlineImageCore();
      await pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-html-statement');
      final inline = find.byWidgetPredicate((w) => w is Image && w.image is MemoryImage);
      expect(inline, findsOneWidget);
      // Decode the PNG for real before the capture (image codecs run outside the fake clock).
      await tester.runAsync(
        () => precacheImage(tester.widget<Image>(inline).image, tester.element(inline)),
      );
      await tester.pumpAndSettle();
      expect(find.text('2 remote images blocked'), findsOneWidget);
      expect(find.byKey(const Key('html-blocked-image')), findsNWidgets(2));
      expect(core.reads, ['${FakeCore.htmlSampleId}/0']);
      // shown inline, so not listed again as a chip (review N4)
      expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsNothing);
      await expectGolden(tester, 'thread', 'html_inline_image', v);
    });
  }
}
