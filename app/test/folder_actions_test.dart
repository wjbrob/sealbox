import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/inbox/inbox_list_pane.dart' show threadSubjectKey;

import 'helpers.dart';

// Folder chips by special-use role (first-open sync, honest empty states,
// refresh) and the conversation actions (swipe, thread menu, spam sheet),
// against FakeCore: Gmail folder names on acct-1, generic ones on acct-2.

/// Counts `syncFolder` calls; [failRole] makes that role's sync report an error.
class _Core extends FakeCore {
  _Core({this.failRole}) : super(latency: Duration.zero);

  final FolderRole? failRole;
  final syncs = <String>[];

  @override
  Future<SyncOutcome> syncFolder(FolderRole role, {String? accountId}) async {
    syncs.add('${role.name}:$accountId');
    if (role == failRole) {
      return SyncOutcome([
        AccountSyncOutcome(
          account: accountId ?? '*',
          error: 'IMAP: connect to 127.0.0.1:1 failed: refused',
        ),
      ]);
    }
    return super.syncFolder(role, accountId: accountId);
  }
}

Finder tileOf(String subject) => find.byKey(threadSubjectKey(subject));

Finder snack(String text) =>
    find.descendant(of: find.byKey(const Key('thread-action-snackbar')), matching: find.text(text));

Future<void> openChip(WidgetTester tester, MailFolder f) async {
  final chip = find.byKey(Key('folder-chip-${f.name}'));
  await tester.ensureVisible(chip);
  await tester.pumpAndSettle();
  await tester.tap(chip);
  await tester.pumpAndSettle();
}

String? titleOf(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const Key('thread-title'))).data;

Future<void> openMenu(WidgetTester tester, String itemKey) async {
  await tester.tap(find.byKey(const Key('thread-more')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(Key(itemKey)));
  await tester.pumpAndSettle();
}

const lunch = 'Lunch Thursday?';
const scam = 'Congratulations!!! You have won a 1,000 € gift card';

void main() {
  group('folder chips by role', () {
    testWidgets('Spam syncs itself once per account per session and lists the junk', (
      tester,
    ) async {
      setSurface(tester, desktop);
      final core = _Core();
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      expect(core.syncs, isEmpty, reason: 'INBOX comes with syncAll, no folder sync');
      expect(tileOf(scam), findsNothing);

      await openChip(tester, MailFolder.spam);
      expect(core.syncs, ['junk:acct-1', 'junk:acct-2']);
      expect(tileOf(scam), findsOneWidget);
      expect(tileOf(lunch), findsNothing);

      await openChip(tester, MailFolder.inbox);
      await openChip(tester, MailFolder.spam);
      expect(core.syncs, hasLength(2), reason: 'opened before in this session');

      // The refresh button syncs the current role again.
      await tester.tap(find.byKey(const Key('inbox-sync')));
      await tester.pumpAndSettle();
      expect(core.syncs, hasLength(4));
      expect(find.byKey(const Key('inbox-sync-snackbar')), findsOneWidget);
    });

    testWidgets('an empty synced folder says the server has nothing there', (tester) async {
      setSurface(tester, desktop);
      final core = _Core();
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await openChip(tester, MailFolder.trash);
      expect(core.syncs, ['trash:acct-1', 'trash:acct-2']);
      expect(find.byKey(const Key('folder-empty-synced')), findsOneWidget);
      expect(find.text('Nothing in Trash on the server.'), findsOneWidget);
      expect(
        find.textContaining('[Gmail]/Trash'),
        findsOneWidget,
        reason: 'names the folders checked',
      );
    });

    testWidgets('a failed folder sync is "not synced yet" with the error and Sync now', (
      tester,
    ) async {
      setSurface(tester, phone);
      final core = _Core(failRole: FolderRole.archive);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await openChip(tester, MailFolder.archive);
      expect(find.byKey(const Key('folder-empty-not-synced')), findsOneWidget);
      expect(find.text('Archive is not synced yet.'), findsOneWidget);
      expect(find.textContaining('The last attempt failed: IMAP: connect'), findsOneWidget);
      final calls = core.syncs.length;
      await openChip(tester, MailFolder.inbox);
      await openChip(tester, MailFolder.archive);
      expect(core.syncs, hasLength(calls), reason: 'no automatic retry loop');
      await tester.tap(find.byKey(const Key('folder-sync-now')));
      await tester.pumpAndSettle();
      expect(core.syncs.length, greaterThan(calls));
    });
  });

  group('swipe actions', () {
    testWidgets('swipe right archives; the snackbar names the destination folder', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await tester.drag(tileOf(lunch), const Offset(320, 0));
      await tester.pumpAndSettle();
      expect(snack('Archived to [Gmail]/All Mail'), findsOneWidget);
      expect(tileOf(lunch), findsNothing);
      expect((await core.listThreadsIn(MailFolder.archive)).map((t) => t.id), contains('t-lunch'));
    });

    testWidgets('swipe left asks before deleting; Cancel keeps the row', (tester) async {
      setSurface(tester, phone);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await tester.drag(tileOf(lunch), const Offset(-380, 0));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('thread-delete-dialog')), findsOneWidget);
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(tileOf(lunch), findsOneWidget);
      expect(tester.takeException(), isNull);

      await tester.drag(tileOf(lunch), const Offset(-380, 0));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('thread-delete-confirm')));
      await tester.pumpAndSettle();
      expect(snack('Moved to [Gmail]/Trash'), findsOneWidget);
      expect(tileOf(lunch), findsNothing);
      await openChip(tester, MailFolder.trash);
      expect(tileOf(lunch), findsOneWidget, reason: 'in Trash after its sync');
    });

    testWidgets('long press offers the same actions (and Mark unread)', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await tester.longPress(tileOf(lunch));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('thread-row-action-archive')), findsOneWidget);
      expect(find.byKey(const ValueKey('thread-row-action-delete')), findsOneWidget);
      await tester.tap(find.byKey(const ValueKey('thread-row-action-markUnread')));
      await tester.pumpAndSettle();
      expect(snack('Marked as unread'), findsOneWidget);
      expect(
        find.descendant(of: tileOf(lunch), matching: find.byKey(const ValueKey('thread-unread'))),
        findsOneWidget,
      );
    });
  });

  group('thread menu', () {
    testWidgets('mark as spam moves it to the junk folder; Not spam brings it back', (
      tester,
    ) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-lunch'));
      await tester.pumpAndSettle();
      expect(titleOf(tester), 'Inbox');
      await openMenu(tester, 'thread-spam');
      expect(snack('Marked as spam · moved to [Gmail]/Spam'), findsOneWidget);
      expect(find.byKey(const Key('thread-messages')), findsNothing, reason: 'back to the list');
      expect(tileOf(lunch), findsNothing);

      await openChip(tester, MailFolder.spam);
      await tester.tap(tileOf(lunch));
      await tester.pumpAndSettle();
      expect(titleOf(tester), 'Spam');
      await tester.tap(find.byKey(const Key('thread-more')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('thread-spam')), findsNothing);
      expect(find.text('Why is this spam?'), findsOneWidget);
      await tester.tap(find.byKey(const Key('thread-not-spam')));
      await tester.pumpAndSettle();
      expect(snack('Marked as not spam · moved to INBOX'), findsOneWidget);
      await openChip(tester, MailFolder.inbox);
      expect(tileOf(lunch), findsOneWidget);
    });

    testWidgets('archive, then Move to Inbox from Archive', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-budget'));
      await tester.pumpAndSettle();
      await openMenu(tester, 'thread-archive');
      expect(snack('Archived 2 messages to [Gmail]/All Mail'), findsOneWidget);
      expect(find.byKey(const ValueKey('thread-tile-t-budget')), findsNothing);

      await openChip(tester, MailFolder.archive);
      await tester.tap(find.byKey(const ValueKey('thread-tile-t-budget')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('thread-more')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('thread-archive')),
        findsNothing,
        reason: 'nothing left in INBOX',
      );
      await tester.tap(find.byKey(const Key('thread-move-inbox')));
      await tester.pumpAndSettle();
      // Bob's mail goes back to INBOX; our own message (m-0) to Sent.
      expect(find.byKey(const Key('thread-action-snackbar')), findsOneWidget);
      expect(find.textContaining('Moved 2 messages to'), findsOneWidget);
      final budget = await core.getThread('t-budget');
      expect(
        {for (final m in budget!.messages) m.id: m.folder},
        {'m-0': '[Gmail]/Sent Mail', 'm-1': 'INBOX'},
      );
    });

    testWidgets('mark unread returns to the list with the row unread', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-thunderbird'));
      await tester.pumpAndSettle();
      expect((await core.getMessage('m-2'))!.unread, isFalse, reason: 'opening marks it seen');
      await openMenu(tester, 'thread-mark-unread');
      expect(snack('Marked as unread'), findsOneWidget);
      expect((await core.getMessage('m-2'))!.unread, isTrue);
      expect(find.byKey(const Key('thread-messages')), findsNothing);
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('thread-tile-t-thunderbird')),
          matching: find.byKey(const ValueKey('thread-unread')),
        ),
        findsOneWidget,
      );
    });

    testWidgets('in Trash, Delete becomes Delete forever (asks first)', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await core.moveMessage('m-3', FolderRole.trash);
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/t-lunch'));
      await tester.pumpAndSettle();
      expect(find.byTooltip('Delete forever'), findsOneWidget);
      await tester.tap(find.byKey(const Key('thread-delete')));
      await tester.pumpAndSettle();
      expect(find.text('Delete this message forever?'), findsOneWidget);
      await tester.tap(find.byKey(const Key('thread-delete-confirm')));
      await tester.pumpAndSettle();
      expect(snack('Deleted forever'), findsOneWidget);
      expect(await core.getThread('t-lunch'), isNull);
    });

    testWidgets('Forward opens compose with the forwarded message', (tester) async {
      setSurface(tester, desktop);
      await tester.pumpWidget(
        buildApp(
          core: FakeCore(latency: Duration.zero),
          initialLocation: '/inbox/t/t-release',
        ),
      );
      await tester.pumpAndSettle();
      await openMenu(tester, 'thread-forward');
      expect(find.text('Forward'), findsWidgets);
      final subject = tester.widget<TextField>(find.byKey(const Key('compose-subject')));
      expect(subject.controller!.text, 'Fwd: sealbox-crypto 0.3 release notes (signed)');
      final preview = tester.widget<SelectableText>(find.byKey(const Key('compose-preview-text')));
      expect(preview.data, contains('-------- Forwarded Message --------'));
    });
  });

  group('why is this spam?', () {
    testWidgets('label, reasons with weights, SPF/DKIM/DMARC, filters; Not spam', (tester) async {
      setSurface(tester, desktop);
      final core = FakeCore(latency: Duration.zero);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      await openChip(tester, MailFolder.spam);
      await tester.tap(tileOf(scam));
      await tester.pumpAndSettle();
      await openMenu(tester, 'thread-spam-explain');
      expect(find.byKey(const Key('spam-explain-sheet')), findsOneWidget);
      expect(find.text('Spam · 99 %'), findsOneWidget);
      for (final code in ['scam_language', 'dmarc_fail', 'spf_fail', 'raw_ip_url']) {
        expect(find.byKey(ValueKey('spam-reason-$code')), findsOneWidget, reason: code);
      }
      expect(find.text('+2.5'), findsOneWidget, reason: 'the DMARC weight');
      expect(find.text('SPF fail'), findsOneWidget);
      expect(find.text('DKIM none'), findsOneWidget);
      expect(find.text('DMARC fail'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.byKey(const Key('spam-explain-filters')),
        120,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('spam-explain-sheet')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      expect(find.text('No rule matches this message.'), findsOneWidget);
      await tester.tap(find.byKey(const Key('spam-explain-not-spam')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('spam-explain-sheet')), findsNothing);
      expect(snack('Marked as not spam · moved to INBOX'), findsOneWidget);
      expect((await core.getMessage(FakeCore.junkSampleId))!.folder, 'INBOX');
    });

    testWidgets('a signed inbox message: not spam, and the Finance rule would star it', (
      tester,
    ) async {
      setSurface(tester, desktop);
      await tester.pumpWidget(
        buildApp(
          core: FakeCore(latency: Duration.zero),
          initialLocation: '/inbox/t/t-budget',
        ),
      );
      await tester.pumpAndSettle();
      await openMenu(tester, 'thread-spam-explain');
      expect(find.text('Spam check'), findsOneWidget);
      expect(find.text('Not spam · 0 %'), findsOneWidget);
      expect(find.byKey(const ValueKey('spam-reason-signed_by_contact')), findsOneWidget);
      expect(find.text('Would star it (rule: Finance).'), findsOneWidget);
      expect(find.byKey(const Key('spam-explain-mark-spam')), findsOneWidget);
    });
  });
}
