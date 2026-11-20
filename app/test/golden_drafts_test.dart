import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';

// Drafts and Cc/Bcc goldens: test/goldens/<screen>_<state>_<device>_<theme>.png
//
//   inbox_drafts (full matrix)  the Drafts chip selected: three drafts saved on this device,
//                               newest first (all at the anchor time, so by id) — a reply to
//                               Carol, a Fastmail draft with no recipient yet and a file, the
//                               lunch plan for Dana — with recipients, subject, the start of
//                               the text and the reply / file / account tags.
//   compose_cc_bcc (full matrix) Bob in To, the Cc and Bcc links used: Dana (no key: guest
//                               link) in Cc and Erik (key from WKD) in Bcc with their pills,
//                               the Bcc field's note (each Bcc recipient gets a copy of their
//                               own), the draft saved 2 s later ("Draft saved 14:05").

Future<GoldenCore> _withDrafts() async {
  final core = GoldenCore();
  final notes = await core.keepDraftAttachment(
    'release-notes.md',
    Uint8List.fromList('# 0.4'.codeUnits),
  );
  await core.saveDraft(
    const DraftInput(
      accountId: 'acct-1',
      to: ['dana@example.org'],
      subject: 'Lunch next week',
      body:
          'How about Tuesday at the Lebanese place near the station? I can book a table '
          'for 12:30.',
    ),
  );
  await core.saveDraft(
    DraftInput(
      accountId: 'acct-2',
      subject: 'Release notes 0.4',
      body: 'Ideas so far: SEIPDv2 by default, local search, saved drafts.',
      attachments: [
        SavedDraftAttachment(path: notes, name: 'release-notes.md', contentType: 'text/markdown'),
      ],
    ),
  );
  await core.saveDraft(
    const DraftInput(
      accountId: 'acct-1',
      inReplyTo: 'm-2',
      quote: true,
      to: ['carol@proton.me'],
      subject: 'Re: keys for the Thunderbird interop test',
      body: 'Proton worked too: the reply came back encrypted.',
    ),
  );
  return core;
}

Future<void> _addRecipient(
  WidgetTester tester,
  String email, {
  bool cc = false,
  bool bcc = false,
}) async {
  await tester.enterText(
    find.byKey(Key(bcc ? 'compose-bcc' : (cc ? 'compose-cc' : 'compose-to'))),
    email,
  );
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

void main() {
  for (final v in fullMatrix) {
    testVariant('golden inbox_drafts $v', v, (tester) async {
      await pumpSealbox(tester, core: await _withDrafts());
      await tester.tap(find.byKey(const Key('folder-chip-drafts')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('drafts-list')), findsOneWidget);
      expect(find.byKey(const ValueKey('draft-tile-3')), findsOneWidget);
      await expectGolden(tester, 'inbox', 'drafts', v);
    });
  }

  for (final v in fullMatrix) {
    testVariant('golden compose_cc_bcc $v', v, (tester) async {
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _addRecipient(tester, 'bob@sealbox.test');
      await tester.tap(find.byKey(const Key('compose-cc-toggle')));
      await tester.pumpAndSettle();
      await _addRecipient(tester, 'dana@example.org', cc: true);
      await tester.tap(find.byKey(const Key('compose-bcc-toggle')));
      await tester.pumpAndSettle();
      await _addRecipient(tester, 'erik@posteo.de', bcc: true);
      await tester.pump(ComposeController.autosaveDelay);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('compose-cc-pills')), findsOneWidget);
      expect(find.byKey(const Key('compose-bcc-pills')), findsOneWidget);
      expect(find.byKey(const Key('compose-bcc-toggle')), findsNothing);
      expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget);
      expect(find.text('Draft saved 14:05'), findsOneWidget);
      await expectGolden(tester, 'compose', 'cc_bcc', v);
    });
  }
}
