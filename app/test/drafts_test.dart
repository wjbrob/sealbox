import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';

import 'helpers.dart';

// Saved drafts in the app: compose saves 2 s after the last edit and when it is left (one
// draft, updated under its id), the Drafts chip lists them, a row resumes compose with
// every field, sending goes through the per-recipient send path and then deletes the draft
// and its file copies, Discard asks first. Plus the Cc field and the P4 title.

FakeCore core() => FakeCore(latency: Duration.zero);

ProviderContainer containerOf(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byType(Scaffold).first));

void go(WidgetTester tester, String location) =>
    GoRouter.of(tester.element(find.byType(Scaffold).first)).go(location);

Future<void> addRecipient(WidgetTester tester, String email, {bool cc = false}) async {
  await tester.enterText(find.byKey(Key(cc ? 'compose-cc' : 'compose-to')), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

/// Lets the autosave run out and the save land.
Future<void> autosave(WidgetTester tester) async {
  await tester.pump(ComposeController.autosaveDelay);
  await tester.pumpAndSettle();
}

Finder pill(String email, {bool cc = false}) => find.descendant(
  of: find.byKey(Key(cc ? 'compose-cc-pills' : 'compose-list')),
  matching: find.byKey(ValueKey('recipient-pill-$email')),
);

/// Scrolls the compose form until the widget with [key] is built and on screen.
Future<Finder> reveal(WidgetTester tester, String key) async {
  final f = find.byKey(Key(key));
  await tester.scrollUntilVisible(
    f,
    200,
    scrollable: find
        .descendant(of: find.byKey(const Key('compose-list')), matching: find.byType(Scrollable))
        .first,
  );
  await tester.pumpAndSettle();
  return f;
}

String fieldText(WidgetTester tester, String key) =>
    tester.widget<TextField>(find.byKey(Key(key))).controller!.text;

/// FakeCore whose key lookups wait for [gate].
class _SlowLookupCore extends FakeCore {
  _SlowLookupCore() : super(latency: Duration.zero);

  Completer<void> gate = Completer<void>();

  @override
  Future<RecipientKeyInfo> lookupRecipientKey(String email) async {
    await gate.future;
    return super.lookupRecipientKey(email);
  }
}

void main() {
  testWidgets('a draft being reopened never leaks into the message compose switched to', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = _SlowLookupCore();
    final d = await c.saveDraft(
      const DraftInput(
        accountId: 'acct-1',
        to: ['bob@sealbox.test', 'carol@proton.me'],
        cc: ['dana@example.org'],
        subject: 'Old one',
      ),
    );
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose?draft=${d.id}'));
    await tester.pump();
    await tester.pump();
    // Resuming waits for Bob's key (then Carol's, Dana's); meanwhile a new message starts.
    go(tester, '/compose');
    await tester.pumpAndSettle();
    c.gate.complete();
    await tester.pumpAndSettle();
    final s = containerOf(tester).read(composeControllerProvider);
    expect(s.allRecipients, isEmpty, reason: 'nothing of the old draft in the new message');
    expect(s.subject, isEmpty);
    expect(s.draftId, isNull);
    expect(tester.takeException(), isNull);
    expect((await c.listDrafts()).single.subject, 'Old one', reason: 'the draft is untouched');
  });

  testWidgets('autosave: nothing before 2 s, then one draft, updated under its id', (tester) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Lunch next week');
    await tester.pump(const Duration(seconds: 1));
    expect(await c.listDrafts(), isEmpty, reason: 'still typing');
    await tester.enterText(find.byKey(const Key('compose-body')), 'How about Tuesday?');
    await tester.pump(const Duration(milliseconds: 1900));
    expect(await c.listDrafts(), isEmpty, reason: 'the delay restarts with every edit');
    await tester.pump(const Duration(milliseconds: 200));
    await tester.pumpAndSettle();
    final first = (await c.listDrafts()).single;
    expect(first.subject, 'Lunch next week');
    expect(first.body, 'How about Tuesday?');
    expect(first.accountId, 'acct-1');
    expect(find.byKey(const Key('compose-draft-status')), findsOneWidget);
    expect(find.textContaining('Draft saved'), findsOneWidget);

    await addRecipient(tester, 'dana@example.org');
    await autosave(tester);
    final again = (await c.listDrafts()).single;
    expect(again.id, first.id, reason: 'the same draft, saved again');
    expect(again.to, ['dana@example.org']);
    expect(again.policy, SendPolicy.guestLink, reason: 'dana has no key: never plaintext');
  });

  testWidgets('leaving compose saves what is unsaved; an untouched compose saves nothing', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), isEmpty);

    go(tester, '/compose');
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Half written');
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect((await c.listDrafts()).single.subject, 'Half written');
  });

  testWidgets('the app going to the background saves at once', (tester) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Before the call');
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pumpAndSettle();
    expect((await c.listDrafts()).single.subject, 'Before the call', reason: 'no 2 s wait');
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
  });

  testWidgets('switching compose to a reply keeps the message started before as a draft', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-body')), 'An idea for later');
    go(tester, '/compose?reply=t-budget');
    await tester.pumpAndSettle();
    expect((await c.listDrafts()).single.body, 'An idea for later');
    expect(fieldText(tester, 'compose-subject'), 'Re: Q4 budget — final numbers');
    expect(fieldText(tester, 'compose-body'), isEmpty, reason: 'the reply starts clean');
  });

  testWidgets('the Drafts chip lists drafts; a row resumes compose with every field', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    final file = await c.keepDraftAttachment('agenda.txt', Uint8List.fromList([1, 2, 3]));
    final saved = await c.saveDraft(
      DraftInput(
        accountId: 'acct-1',
        to: const ['bob@sealbox.test'],
        cc: const ['dana@example.org'],
        subject: 'Offsite agenda',
        body: 'Draft agenda attached.',
        attachments: [
          SavedDraftAttachment(path: file, name: 'agenda.txt', contentType: 'text/plain'),
        ],
        guestMode: GuestMode.oneClick,
      ),
    );
    await tester.pumpWidget(buildApp(core: c));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('folder-chip-drafts')), findsOneWidget);
    await tester.tap(find.byKey(const Key('folder-chip-drafts')));
    await tester.pumpAndSettle();
    expect(find.text('Drafts'), findsWidgets, reason: 'the app bar title');
    final row = find.byKey(ValueKey('draft-tile-${saved.id}'));
    expect(row, findsOneWidget);
    expect(
      find.descendant(of: row, matching: find.text('To bob@sealbox.test, dana@example.org')),
      findsOneWidget,
    );
    expect(find.descendant(of: row, matching: find.text('Offsite agenda')), findsOneWidget);
    expect(find.descendant(of: row, matching: find.text('1 file')), findsOneWidget);

    await tester.tap(row);
    await tester.pumpAndSettle();
    expect(fieldText(tester, 'compose-subject'), 'Offsite agenda');
    expect(fieldText(tester, 'compose-body'), 'Draft agenda attached.');
    expect(find.byKey(const ValueKey('recipient-pill-bob@sealbox.test')), findsOneWidget);
    expect(pill('dana@example.org', cc: true), findsOneWidget, reason: 'Cc stays Cc');
    expect(find.byKey(const Key('compose-cc')), findsOneWidget, reason: 'the Cc field is open');
    expect(
      find.byKey(const ValueKey('attachment-chip-agenda.txt'), skipOffstage: false),
      findsOneWidget,
    );
    expect(find.textContaining('Draft saved'), findsOneWidget);
    final s = containerOf(tester).read(composeControllerProvider);
    expect(s.draftId, saved.id);
    expect(s.guestMode, GuestMode.oneClick);
    expect(s.attachments.single.data, [1, 2, 3]);

    // Back in the list (selecting another chip leaves the Drafts list).
    go(tester, '/inbox');
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('drafts-list')), findsOneWidget);
    await tester.tap(find.byKey(const Key('folder-chip-inbox')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('drafts-list')), findsNothing);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  });

  testWidgets('sending a resumed draft uses the send path, then the draft and its copies go', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    final file = await c.keepDraftAttachment('a.bin', Uint8List.fromList([7]));
    final saved = await c.saveDraft(
      DraftInput(
        accountId: 'acct-1',
        to: const ['bob@sealbox.test'],
        cc: const ['dana@example.org'],
        subject: 'Numbers',
        body: 'See attached.',
        attachments: [SavedDraftAttachment(path: file, name: 'a.bin')],
      ),
    );
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose?draft=${saved.id}'));
    await tester.pumpAndSettle();
    await tester.enterText(await reveal(tester, 'compose-body'), 'See attached, final.');
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
    expect(find.text('Sent: encrypted to 1, guest link for 1'), findsOneWidget);
    final sent = c.sentMessages.single;
    expect(sent.to, ['bob@sealbox.test']);
    expect(sent.cc, ['dana@example.org']);
    expect(sent.body, 'See attached, final.');
    expect(sent.attachments.single.data, [7]);
    expect(await c.listDrafts(), isEmpty, reason: 'a sent draft is deleted');
    expect(c.draftFiles, isEmpty, reason: 'with the copies of its files');
    await tester.pump(ComposeController.autosaveDelay * 2);
    expect(await c.listDrafts(), isEmpty, reason: 'and never saved again');
  });

  testWidgets('Discard asks first: Keep editing keeps the draft, Discard deletes it', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<IconButton>(find.byKey(const Key('compose-discard'))).onPressed,
      isNull,
      reason: 'nothing to discard yet',
    );
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Not this one');
    await autosave(tester);
    expect(await c.listDrafts(), hasLength(1));
    await tester.tap(find.byKey(const Key('compose-discard')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('discard-draft-dialog')), findsOneWidget);
    await tester.tap(find.byKey(const Key('discard-draft-cancel')));
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), hasLength(1));
    expect(fieldText(tester, 'compose-subject'), 'Not this one');

    await tester.tap(find.byKey(const Key('compose-discard')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('discard-draft-confirm')));
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), isEmpty);
    expect(find.text('Draft discarded'), findsOneWidget);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget, reason: 'compose closed');
    await tester.pump(ComposeController.autosaveDelay * 2);
    expect(await c.listDrafts(), isEmpty, reason: 'leaving did not save it again');
  });

  testWidgets('erasing everything deletes the draft', (tester) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-subject')), 'x');
    await autosave(tester);
    expect(await c.listDrafts(), hasLength(1));
    await tester.enterText(find.byKey(const Key('compose-subject')), '');
    await autosave(tester);
    expect(await c.listDrafts(), isEmpty);
  });

  testWidgets('a file is copied when the draft is saved and released once removed', (tester) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    final ctl = containerOf(tester).read(composeControllerProvider.notifier);
    ctl.addAttachments([
      DraftAttachment(
        name: 'q4.csv',
        contentType: 'text/csv',
        data: Uint8List.fromList('q,4'.codeUnits),
      ),
    ]);
    await autosave(tester);
    final d = (await c.listDrafts()).single;
    final path = d.attachments.single.path;
    expect(path, startsWith(FakeCore.draftFilePrefix));
    expect(d.attachments.single.blobId, isNotNull, reason: 'a stored copy, not a file path');
    expect(c.draftFiles.keys, [path]);
    expect(
      containerOf(tester).read(composeControllerProvider).attachments.single.storedPath,
      path,
      reason: 'not copied again by the next save',
    );
    await tester.enterText(find.byKey(const Key('compose-subject')), 'with a file');
    await autosave(tester);
    expect(c.draftFiles.keys, [path]);
    await reveal(tester, 'compose-attachments');
    await tester.tap(find.byTooltip('Remove q4.csv'));
    await autosave(tester);
    expect((await c.listDrafts()).single.attachments, isEmpty);
    expect(c.draftFiles, isEmpty);
  });

  testWidgets('a resumed draft whose file is gone opens with a note', (tester) async {
    setSurface(tester, desktop);
    final c = core();
    final saved = await c.saveDraft(
      const DraftInput(
        accountId: 'acct-1',
        subject: 'Report',
        attachments: [SavedDraftAttachment(path: '/nowhere/report.pdf')],
      ),
    );
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose?draft=${saved.id}'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-notice')), findsOneWidget);
    expect(find.textContaining('report.pdf'), findsOneWidget);
    expect(containerOf(tester).read(composeControllerProvider).attachments, isEmpty);
  });

  testWidgets('Cc: the link opens the field; Cc recipients are decided and sent as Cc', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-cc')), findsNothing);
    await addRecipient(tester, 'bob@sealbox.test');
    await tester.tap(find.byKey(const Key('compose-cc-toggle')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-cc-toggle')), findsNothing);
    await addRecipient(tester, 'dana@example.org', cc: true);
    expect(pill('dana@example.org', cc: true), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget);
    // An address already on the message is not added twice.
    await addRecipient(tester, 'bob@sealbox.test', cc: true);
    expect(pill('bob@sealbox.test', cc: true), findsNothing);
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Hello');
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
    expect(find.text('Sent: encrypted to 1, guest link for 1'), findsOneWidget);
    expect(c.sentMessages.single.to, ['bob@sealbox.test']);
    expect(c.sentMessages.single.cc, ['dana@example.org']);
  });

  testWidgets('the Cc field closes again while it is empty', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(buildApp(core: core(), initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('compose-cc-toggle')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('compose-cc-hide')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-cc')), findsNothing);
    expect(find.byKey(const Key('compose-cc-toggle')), findsOneWidget);
  });

  testWidgets('P4: "Compose" on a phone, Attach and Discard in its menu; "New message" wide', (
    tester,
  ) async {
    setSurface(tester, phone);
    final c = core();
    await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    expect(
      find.descendant(of: find.byType(AppBar), matching: find.text('Compose')),
      findsOneWidget,
    );
    expect(find.byKey(const Key('compose-attach')), findsNothing);
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Phone draft');
    await tester.pump();
    await tester.tap(find.byKey(const Key('compose-more')));
    await tester.pumpAndSettle();
    expect(find.text('Attach files'), findsOneWidget);
    await tester.tap(find.byKey(const Key('compose-discard')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('discard-draft-confirm')));
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), isEmpty);

    setSurface(tester, desktop);
    go(tester, '/compose');
    await tester.pumpAndSettle();
    final appBar = find.byType(AppBar);
    expect(find.descendant(of: appBar, matching: find.text('New message')), findsOneWidget);
    expect(find.byKey(const Key('compose-attach')), findsOneWidget);
  });

  testWidgets('the Drafts list: empty state, swipe to discard after a confirmation', (
    tester,
  ) async {
    setSurface(tester, phone);
    final c = core();
    final d = await c.saveDraft(
      const DraftInput(accountId: 'acct-2', subject: 'Swipe me', body: 'x'),
    );
    await tester.pumpWidget(buildApp(core: c));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('folder-chip-drafts')));
    await tester.pumpAndSettle();
    final row = find.byKey(ValueKey('draft-tile-${d.id}'));
    expect(find.descendant(of: row, matching: find.text('No recipients yet')), findsOneWidget);
    await tester.drag(row, const Offset(-500, 0));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('discard-draft-dialog')), findsOneWidget);
    await tester.tap(find.byKey(const Key('discard-draft-confirm')));
    await tester.pumpAndSettle();
    expect(await c.listDrafts(), isEmpty);
    expect(find.byKey(const Key('drafts-empty')), findsOneWidget);
    expect(find.text('Drafts'), findsWidgets, reason: 'the title and the chip');
  });

  for (final (name, size) in [('phone', phone), ('desktop', desktop)]) {
    testWidgets('accessibility on $name: the Drafts list and compose with Cc', (tester) async {
      final handle = tester.ensureSemantics();
      setSurface(tester, size);
      final c = core();
      await c.saveDraft(
        const DraftInput(
          accountId: 'acct-1',
          to: ['bob@sealbox.test'],
          subject: 'Offsite',
          body: 'Agenda',
        ),
      );
      await tester.pumpWidget(buildApp(core: c));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('folder-chip-drafts')));
      await tester.pumpAndSettle();
      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      if (size == phone) await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      go(tester, '/compose');
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('compose-cc-toggle')));
      await tester.pumpAndSettle();
      await addRecipient(tester, 'dana@example.org', cc: true);
      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      if (size == phone) await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      handle.dispose();
    });
  }
}
