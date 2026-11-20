import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';

import 'helpers.dart';

// Drafts hygiene (c): a draft saved from the CLI could carry Bcc that the app only noted and
// never sent. Compose now has a Bcc field (behind its link, like Cc). Bcc recipients are
// decided per recipient like To/Cc, and each gets a copy of their own through the same
// per-recipient send path, addressed to them alone: neither the visible recipients nor the
// other Bcc recipients can tell (one OpenPGP message encrypted to a Bcc key would show that
// key's id to everyone). Bob (bob@sealbox.test) and Erik (erik@posteo.de) have keys in
// FakeCore; Dana (dana@example.org) has none (guest link).

/// FakeCore whose send fails for messages addressed to [failFor].
class FailingSendCore extends FakeCore {
  FailingSendCore() : super(latency: Duration.zero);

  String? failFor;

  @override
  Future<SendReceipt> send(DraftMessage draft) {
    if (failFor != null && draft.to.contains(failFor)) {
      return Future.error(StateError('SMTP: 451 try again later'));
    }
    return super.send(draft);
  }
}

ProviderContainer containerOf(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byType(Scaffold).first));

Future<void> addRecipient(WidgetTester tester, String email, {String field = 'compose-to'}) async {
  await tester.enterText(find.byKey(Key(field)), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

Future<void> openBcc(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('compose-bcc-toggle')));
  await tester.pumpAndSettle();
}

Finder bccPill(String email) => find.descendant(
  of: find.byKey(const Key('compose-bcc-pills')),
  matching: find.byKey(ValueKey('recipient-pill-$email')),
);

Future<void> send(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('compose-send')));
  await tester.pumpAndSettle();
  if (find.byKey(const Key('guest-sent-done')).evaluate().isNotEmpty) {
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
  }
}

Future<FakeCore> composeOn(WidgetTester tester, FakeCore c, {String at = '/compose'}) async {
  setSurface(tester, desktop);
  await tester.pumpWidget(buildApp(core: c, initialLocation: at));
  await tester.pumpAndSettle();
  return c;
}

void main() {
  testWidgets('Bcc recipients are decided per recipient and each sent a copy of their own', (
    tester,
  ) async {
    final c = await composeOn(tester, FakeCore(latency: Duration.zero));
    expect(find.byKey(const Key('compose-bcc')), findsNothing, reason: 'behind its link');
    await addRecipient(tester, 'bob@sealbox.test');
    await openBcc(tester);
    expect(find.byKey(const Key('compose-bcc-toggle')), findsNothing);
    expect(find.byKey(const Key('compose-cc-toggle')), findsOneWidget, reason: 'Cc still offered');
    expect(
      find.text('Each Bcc recipient gets a copy of their own, addressed to them alone.'),
      findsOneWidget,
    );
    await addRecipient(tester, 'dana@example.org', field: 'compose-bcc');
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    expect(bccPill('dana@example.org'), findsOneWidget);
    expect(bccPill('erik@posteo.de'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget, reason: 'Dana');
    // Below the fold of the lazy list (the guest-link panel came in between).
    containerOf(tester).read(composeControllerProvider.notifier)
      ..setSubject('Offsite')
      ..setBody('Tuesday, 10:00.');
    await tester.pumpAndSettle();
    await send(tester);

    expect(find.text('Sent: encrypted to 2, guest link for 1'), findsOneWidget);
    final sent = c.sentMessages;
    expect(
      [for (final m in sent) m.to],
      [
        ['bob@sealbox.test'],
        ['dana@example.org'],
        ['erik@posteo.de'],
      ],
      reason: 'the visible message first, then one copy per Bcc recipient',
    );
    for (final m in sent) {
      expect(m.cc, isEmpty);
      expect(m.subject, 'Offsite');
      expect(m.body, 'Tuesday, 10:00.');
    }
  });

  testWidgets('a message with Bcc recipients only sends nothing visible: a copy to each', (
    tester,
  ) async {
    final c = await composeOn(tester, FakeCore(latency: Duration.zero));
    await openBcc(tester);
    await addRecipient(tester, 'bob@sealbox.test', field: 'compose-bcc');
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Quiet note');
    await send(tester);
    expect(
      [for (final m in c.sentMessages) m.to],
      [
        ['bob@sealbox.test'],
        ['erik@posteo.de'],
      ],
    );
    expect(find.text('Sent: encrypted to 2'), findsOneWidget);
  });

  testWidgets('a draft saved with Bcc (the CLI) opens with its Bcc field and sends them', (
    tester,
  ) async {
    final core = FakeCore(latency: Duration.zero);
    final d = await core.saveDraft(
      const DraftInput(
        accountId: 'acct-1',
        to: ['bob@sealbox.test'],
        bcc: ['erik@posteo.de'],
        subject: 'Numbers',
        body: 'See below.',
      ),
    );
    await composeOn(tester, core, at: '/compose?draft=${d.id}');
    expect(bccPill('erik@posteo.de'), findsOneWidget);
    expect(find.byKey(const Key('compose-notice')), findsNothing, reason: 'no "cannot send" note');
    await send(tester);
    expect(
      [for (final m in core.sentMessages) m.to],
      [
        ['bob@sealbox.test'],
        ['erik@posteo.de'],
      ],
    );
    expect(await core.listDrafts(), isEmpty, reason: 'a sent draft is deleted');
  });

  testWidgets('Bcc is saved with the draft; an address is on one line only', (tester) async {
    final c = await composeOn(tester, FakeCore(latency: Duration.zero));
    await addRecipient(tester, 'bob@sealbox.test');
    await openBcc(tester);
    await addRecipient(tester, 'bob@sealbox.test', field: 'compose-bcc');
    expect(bccPill('bob@sealbox.test'), findsNothing, reason: 'already in To');
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await addRecipient(tester, 'not an address', field: 'compose-bcc');
    expect(find.text('"not an address" is not an email address'), findsOneWidget);
    await tester.pump(ComposeController.autosaveDelay);
    await tester.pumpAndSettle();
    final saved = (await c.listDrafts()).single;
    expect(saved.to, ['bob@sealbox.test']);
    expect(saved.bcc, ['erik@posteo.de']);

    // Removing the pill empties Bcc; the empty field can be closed again.
    await tester.tap(find.byKey(const ValueKey('recipient-menu-erik@posteo.de')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('pill-action-remove')).last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-bcc')), '');
    await tester.tap(find.byKey(const Key('compose-bcc-hide')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-bcc')), findsNothing);
    expect(find.byKey(const Key('compose-bcc-toggle')), findsOneWidget);
  });

  testWidgets('plaintext accepted for a Bcc recipient applies to their copy only', (tester) async {
    final c = await composeOn(tester, FakeCore(latency: Duration.zero));
    await addRecipient(tester, 'bob@sealbox.test');
    await openBcc(tester);
    await addRecipient(tester, 'dana@example.org', field: 'compose-bcc');
    await tester.tap(find.byKey(const ValueKey('recipient-menu-dana@example.org')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('pill-action-plaintext')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm-plaintext')));
    await tester.pumpAndSettle();
    await send(tester);
    final byTo = {for (final m in c.sentMessages) m.to.single: m};
    expect(byTo['dana@example.org']!.plaintextConfirmedFor, {'dana@example.org'});
    expect(byTo['bob@sealbox.test']!.plaintextConfirmedFor.contains('bob@sealbox.test'), isFalse);
    expect(find.text('Sent: encrypted to 1, plaintext to 1'), findsOneWidget);
  });

  testWidgets('a Bcc copy that fails after the rest went out: only its recipient stays', (
    tester,
  ) async {
    final c = FailingSendCore()..failFor = 'erik@posteo.de';
    await composeOn(tester, c);
    await addRecipient(tester, 'bob@sealbox.test');
    await openBcc(tester);
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Report');
    await send(tester);

    expect(find.byKey(const Key('compose-partial-snackbar')), findsOneWidget);
    expect(
      find.textContaining(
        'Sent: encrypted to 1 (bob@sealbox.test), but not to erik@posteo.de: SMTP: 451',
      ),
      findsOneWidget,
    );
    expect(
      [for (final m in c.sentMessages) m.to],
      [
        ['bob@sealbox.test'],
      ],
    );
    final s = containerOf(tester).read(composeControllerProvider);
    expect(s.recipients, isEmpty, reason: 'Bob got it: sending again must not repeat it');
    expect([for (final r in s.bccRecipients) r.email], ['erik@posteo.de']);
    await tester.pumpAndSettle();
    final saved = (await c.listDrafts()).single;
    expect(saved.to, isEmpty, reason: 'the draft follows');
    expect(saved.bcc, ['erik@posteo.de'], reason: 'Erik is still to be sent his copy');

    c.failFor = null;
    await send(tester);
    expect(
      [for (final m in c.sentMessages) m.to],
      [
        ['bob@sealbox.test'],
        ['erik@posteo.de'],
      ],
      reason: 'Erik once, Bob not again',
    );
    expect(await c.listDrafts(), isEmpty);
  });

  testWidgets('To does not suggest someone already in Bcc (picking them would do nothing)', (
    tester,
  ) async {
    await composeOn(tester, FakeCore(latency: Duration.zero));
    await openBcc(tester);
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await tester.enterText(find.byKey(const Key('compose-to')), 'e');
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('recipient-suggestions')), findsOneWidget);
    expect(find.byKey(const ValueKey('recipient-suggestion-erik@posteo.de')), findsNothing);
  });
}
