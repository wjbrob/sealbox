import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';
import 'package:sealbox_app/src/policy/encryption_policy.dart' show RecipientStatus;
import 'package:sealbox_app/src/rust/api/engine.dart' as frb;

import 'helpers.dart';
import 'support/fake_frb_engine.dart';

// A group send that fails midway never duplicates mail. One message goes out as up to three
// engine sends (encrypted to those with a key, a guest link for those without — one per
// recipient for email-code links — plaintext to those the user confirmed), then a copy per
// Bcc recipient. When one fails after another went out, those who got it are named
// (PartialSendException), leave the message and its saved draft, and Send again sends only to
// the rest. Bob (bob@sealbox.test), Carol (carol@proton.me) and Erik (erik@posteo.de) have
// keys; Dana (dana@example.org) and Ivan (ivan.petrov@hotmail.com) have none.

/// The bridge engine under `FrbCore.send`: Bob, Carol and Erik have keys. Every `sendWith` is
/// recorded in [calls]; the one with [failPolicy], or to [failTo], fails with [error].
class _SendEngine extends FakeFrbEngine {
  static const _keys = {'bob@sealbox.test', 'carol@proton.me', 'erik@posteo.de'};

  frb.SendPolicy? failPolicy;
  String? failTo;
  final StateError error = StateError('server unreachable');

  /// `auto → bob@sealbox.test`, `guestLink → dana@example.org (failed)`, oldest first.
  final List<String> calls = [];
  int _sent = 0;

  @override
  Future<frb.RecipientStatus> resolveRecipient({
    required String address,
    required bool replyToEncrypted,
  }) async {
    final known = _keys.contains(address.toLowerCase());
    return frb.RecipientStatus(
      address: address,
      recommendation: known ? frb.Recommendation.encrypt : frb.Recommendation.disable,
      fingerprint: known ? '9F4B2E1C7A5D30186B2F4E9C1D7A3B5F0E6C8D2A' : null,
      source: known ? frb.KeySource.autocrypt : frb.KeySource.none,
      hasKey: known,
    );
  }

  @override
  Future<frb.SendReport> sendWith({
    required String accountEmail,
    required frb.Draft draft,
    required frb.ComposeOptions opts,
  }) async {
    final fails = draft.policy == failPolicy || [...draft.to, ...draft.cc].contains(failTo);
    calls.add(
      '${draft.policy.name} → ${draft.to.join(', ')}'
      '${draft.cc.isEmpty ? '' : ' cc ${draft.cc.join(', ')}'}${fails ? ' (failed)' : ''}',
    );
    if (fails) throw error;
    final n = ++_sent;
    final guest = draft.policy == frb.SendPolicy.guestLink;
    return frb.SendReport(
      messageId: 'm$n@sealbox.test',
      mode: guest
          ? frb.SendMode.guestLink
          : draft.policy == frb.SendPolicy.allowPlaintext
          ? frb.SendMode.plaintext
          : frb.SendMode.encrypted,
      encrypted: draft.policy != frb.SendPolicy.allowPlaintext,
      recipients: const [],
      guest: guest
          ? frb.GuestLinkInfo(
              url: 'https://guest.sealbox.test/m/g$n',
              passphrase: 'amber-$n-lotus-quartz-tidal',
              mode: draft.guestMode,
              expiresAt: 1784073600,
              secretInLink: draft.guestMode != frb.GuestMode.passphrase,
              recipientVerification: draft.guestMode == frb.GuestMode.emailCode,
            )
          : null,
      sentCopyAppended: true,
    );
  }
}

/// FakeCore for every screen, the real `FrbCore.send` (over [_SendEngine]) for sending.
class _FrbSendCore extends FakeCore {
  _FrbSendCore(this.engine) : super(latency: Duration.zero);

  final _SendEngine engine;
  late final FrbCore _frb = FrbCore(engine);

  @override
  Future<SendReceipt> send(DraftMessage draft) => _frb.send(draft);
}

DraftMessage _draft({
  required List<String> to,
  List<String> cc = const [],
  Set<String> plaintext = const {},
  GuestMode mode = GuestMode.passphrase,
}) => DraftMessage(
  accountId: 'alice@sealbox.test',
  to: to,
  cc: cc,
  subject: 'Offsite',
  body: 'Tuesday, 10:00.',
  guestMode: mode,
  plaintextConfirmedFor: plaintext,
);

Future<PartialSendException> _partial(Future<SendReceipt> send) async {
  try {
    await send;
  } on PartialSendException catch (e) {
    return e;
  }
  fail('expected a PartialSendException');
}

ProviderContainer containerOf(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byType(Scaffold).first));

ComposeState composeState(WidgetTester tester) =>
    containerOf(tester).read(composeControllerProvider);

List<String> emails(List<RecipientEntry> list) => [for (final r in list) r.email];

Future<void> addRecipient(WidgetTester tester, String email, {String field = 'compose-to'}) async {
  await tester.enterText(find.byKey(Key(field)), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

Future<void> subject(WidgetTester tester, String text) async {
  containerOf(tester).read(composeControllerProvider.notifier).setSubject(text);
  await tester.pumpAndSettle();
}

Future<void> confirmPlaintext(WidgetTester tester, String email) async {
  await tester.tap(find.byKey(ValueKey('recipient-menu-$email')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('pill-action-plaintext')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('confirm-plaintext')));
  await tester.pumpAndSettle();
}

/// Taps Send; a guest-link dialog that opens is acknowledged.
Future<void> tapSend(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('compose-send')));
  await tester.pumpAndSettle();
  if (find.byKey(const Key('guest-sent-done')).evaluate().isNotEmpty) {
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
  }
}

Future<T> composeOn<T extends FakeCore>(WidgetTester tester, T c, {Size size = desktop}) async {
  setSurface(tester, size);
  await tester.pumpWidget(buildApp(core: c, initialLocation: '/compose'));
  await tester.pumpAndSettle();
  return c;
}

Finder partialSnackbar(String text) => find.descendant(
  of: find.byKey(const Key('compose-partial-snackbar')),
  matching: find.text(text),
);

void main() {
  group('FrbCore.send', () {
    test('everything out: one receipt for the three sends, as before', () async {
      final engine = _SendEngine();
      final r = await FrbCore(engine).send(
        _draft(
          to: ['bob@sealbox.test', 'dana@example.org', 'ivan.petrov@hotmail.com'],
          cc: ['carol@proton.me'],
          plaintext: {'ivan.petrov@hotmail.com'},
        ),
      );
      expect(engine.calls, [
        'auto → bob@sealbox.test cc carol@proton.me',
        'guestLink → dana@example.org',
        'allowPlaintext → ivan.petrov@hotmail.com',
      ]);
      expect(r.encryptedTo, ['bob@sealbox.test', 'carol@proton.me']);
      expect(r.guestLinkTo, ['dana@example.org']);
      expect(r.plaintextTo, ['ivan.petrov@hotmail.com']);
      expect(r.messageId, 'm1@sealbox.test');
      expect(r.guestLinks.single.recipients, ['dana@example.org']);
    });

    test('the encrypted group out, the guest link failing: who got it and who did not', () async {
      final engine = _SendEngine()..failPolicy = frb.SendPolicy.guestLink;
      final e = await _partial(
        FrbCore(engine).send(
          _draft(
            to: ['bob@sealbox.test', 'dana@example.org', 'ivan.petrov@hotmail.com'],
            cc: ['carol@proton.me'],
            plaintext: {'ivan.petrov@hotmail.com'},
          ),
        ),
      );
      expect(engine.calls, [
        'auto → bob@sealbox.test cc carol@proton.me',
        'guestLink → dana@example.org (failed)',
      ], reason: 'the plaintext group is not tried after a failure');
      expect(e.sent.encryptedTo, ['bob@sealbox.test', 'carol@proton.me']);
      expect(e.sent.guestLinkTo, isEmpty);
      expect(e.sent.plaintextTo, isEmpty);
      expect(e.sent.guestLinks, isEmpty);
      expect(e.sent.messageId, 'm1@sealbox.test');
      expect(e.notSentTo, [
        'dana@example.org',
        'ivan.petrov@hotmail.com',
      ], reason: 'the failed group and the one not tried');
      expect(e.reason, 'server unreachable');
    });

    test('nothing out: the original error, unchanged', () async {
      final engine = _SendEngine()..failPolicy = frb.SendPolicy.auto;
      await expectLater(
        FrbCore(engine).send(_draft(to: ['bob@sealbox.test', 'dana@example.org'])),
        throwsA(same(engine.error)),
      );
      expect(engine.calls, ['auto → bob@sealbox.test (failed)']);
    });

    test('email-code links: batch 1 out, batch 2 failing leaves only batch 2', () async {
      final engine = _SendEngine()..failTo = 'ivan.petrov@hotmail.com';
      final e = await _partial(
        FrbCore(engine).send(
          _draft(to: ['dana@example.org', 'ivan.petrov@hotmail.com'], mode: GuestMode.emailCode),
        ),
      );
      expect(engine.calls, [
        'guestLink → dana@example.org',
        'guestLink → ivan.petrov@hotmail.com (failed)',
      ]);
      expect(e.sent.guestLinkTo, ['dana@example.org']);
      expect(e.notSentTo, ['ivan.petrov@hotmail.com']);
      final link = e.sent.guestLinks.single;
      expect(link.recipients, ['dana@example.org']);
      expect(link.mode, GuestMode.emailCode);
      expect(link.recipientVerification, isTrue);
    });

    test('a delivered guest link is reported with its passphrase when plaintext fails', () async {
      final engine = _SendEngine()..failPolicy = frb.SendPolicy.allowPlaintext;
      final e = await _partial(
        FrbCore(engine).send(
          _draft(
            to: ['bob@sealbox.test', 'dana@example.org', 'ivan.petrov@hotmail.com'],
            plaintext: {'ivan.petrov@hotmail.com'},
          ),
        ),
      );
      expect(e.sent.encryptedTo, ['bob@sealbox.test']);
      expect(e.sent.guestLinkTo, ['dana@example.org']);
      final link = e.sent.guestLinks.single;
      expect(link.url, 'https://guest.sealbox.test/m/g2');
      expect(link.passphrase, 'amber-2-lotus-quartz-tidal', reason: 'shown only once: not lost');
      expect(link.recipients, ['dana@example.org']);
      expect(e.notSentTo, ['ivan.petrov@hotmail.com']);
    });
  });

  testWidgets('the encrypted group out, the guest link failing (FrbCore.send): the screen says '
      'who got it, only Dana stays, and Send again sends to her alone', (tester) async {
    final engine = _SendEngine()..failPolicy = frb.SendPolicy.guestLink;
    final c = await composeOn(tester, _FrbSendCore(engine));
    await addRecipient(tester, 'bob@sealbox.test');
    await addRecipient(tester, 'dana@example.org');
    await subject(tester, 'Offsite');
    await tapSend(tester);

    expect(find.byKey(const Key('compose-error-snackbar')), findsNothing);
    expect(
      partialSnackbar(
        'Sent: encrypted to 1 (bob@sealbox.test), but not to dana@example.org: server '
        'unreachable. Still on the message: Send again to send it to them.',
      ),
      findsOneWidget,
    );
    expect(engine.calls, ['auto → bob@sealbox.test', 'guestLink → dana@example.org (failed)']);
    expect(emails(composeState(tester).recipients), ['dana@example.org'], reason: 'Bob got it');
    expect(find.byKey(const ValueKey('recipient-pill-bob@sealbox.test')), findsNothing);
    expect(find.byKey(const ValueKey('recipient-pill-dana@example.org')), findsOneWidget);
    await tester.pumpAndSettle();
    final draft = (await c.listDrafts()).single;
    expect(draft.to, ['dana@example.org'], reason: 'the saved draft follows');
    expect(draft.subject, 'Offsite');

    engine
      ..failPolicy = null
      ..calls.clear();
    await tapSend(tester);
    expect(engine.calls, ['guestLink → dana@example.org'], reason: 'Dana once, Bob not again');
    expect(await c.listDrafts(), isEmpty, reason: 'all sent: the draft goes');
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  });

  testWidgets('the To/Cc message partly out: its Bcc copy waits with the rest, then goes once', (
    tester,
  ) async {
    final c = await composeOn(
      tester,
      FakeCore(latency: Duration.zero)..failSendPolicy = SendPolicy.guestLink,
    );
    await addRecipient(tester, 'bob@sealbox.test');
    await addRecipient(tester, 'dana@example.org');
    await tester.tap(find.byKey(const Key('compose-bcc-toggle')));
    await tester.pumpAndSettle();
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await subject(tester, 'Report');
    await tapSend(tester);

    expect(
      find.textContaining(
        'Sent: encrypted to 1 (bob@sealbox.test), but not to dana@example.org, erik@posteo.de: '
        'server unreachable.',
      ),
      findsOneWidget,
    );
    expect(
      ['${c.sendWithCalls[0]}', '${c.sendWithCalls[1]}'],
      ['auto → bob@sealbox.test', 'guestLink → dana@example.org (failed)'],
    );
    expect(c.sendWithCalls, hasLength(2), reason: "Erik's copy is not tried after a failure");
    final s = composeState(tester);
    expect(emails(s.recipients), ['dana@example.org']);
    expect(emails(s.bccRecipients), ['erik@posteo.de']);
    await tester.pumpAndSettle();
    final draft = (await c.listDrafts()).single;
    expect(draft.to, ['dana@example.org']);
    expect(draft.bcc, ['erik@posteo.de']);

    c.failSendPolicy = null;
    await tapSend(tester);
    expect(
      [for (final call in c.sendWithCalls.skip(2)) '$call'],
      ['guestLink → dana@example.org', 'auto → erik@posteo.de'],
      reason: 'Dana and Erik once, Bob not again',
    );
    expect(
      c.sendWithCalls.where((call) => call.recipients.contains('bob@sealbox.test')),
      hasLength(1),
    );
    expect(await c.listDrafts(), isEmpty);
  });

  testWidgets('nothing out: the original error, every recipient and the draft unchanged', (
    tester,
  ) async {
    final c = await composeOn(tester, FakeCore(latency: Duration.zero));
    await addRecipient(tester, 'bob@sealbox.test');
    await addRecipient(tester, 'dana@example.org');
    await subject(tester, 'Offsite');
    await tester.pump(ComposeController.autosaveDelay);
    await tester.pumpAndSettle();
    final before = (await c.listDrafts()).single;
    expect(before.to, ['bob@sealbox.test', 'dana@example.org']);

    c.failSendPolicy = SendPolicy.auto;
    await tapSend(tester);
    expect(find.byKey(const Key('compose-partial-snackbar')), findsNothing);
    expect(find.text('Could not send: server unreachable'), findsOneWidget);
    expect(['${c.sendWithCalls.single}'], ['auto → bob@sealbox.test (failed)']);
    expect(c.sentMessages, isEmpty);
    expect(emails(composeState(tester).recipients), ['bob@sealbox.test', 'dana@example.org']);
    await tester.pumpAndSettle();
    final after = (await c.listDrafts()).single;
    expect(after.id, before.id);
    expect(after.to, ['bob@sealbox.test', 'dana@example.org']);
  });

  testWidgets('email-code links: batch 1 out, batch 2 failing leaves only batch 2', (tester) async {
    final c = await composeOn(
      tester,
      FakeCore(latency: Duration.zero)..failSendTo = 'ivan.petrov@hotmail.com',
    );
    await addRecipient(tester, 'dana@example.org');
    await addRecipient(tester, 'ivan.petrov@hotmail.com');
    await tester.tap(find.byKey(const Key('guest-mode-emailCode')));
    await tester.pumpAndSettle();
    await subject(tester, 'Offsite');
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();

    // Dana's link went out: it is shown (for her alone), then what did not.
    expect(find.byKey(const Key('guest-sent-dialog')), findsOneWidget);
    expect(find.textContaining('dana@example.org received a link.'), findsOneWidget);
    expect(find.textContaining('ivan.petrov@hotmail.com received'), findsNothing);
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
    expect(
      find.textContaining(
        'Sent: guest link for 1 (dana@example.org), but not to ivan.petrov@hotmail.com: server '
        'unreachable.',
      ),
      findsOneWidget,
    );
    expect(
      [for (final call in c.sendWithCalls) '$call'],
      ['guestLink → dana@example.org', 'guestLink → ivan.petrov@hotmail.com (failed)'],
    );
    expect(emails(composeState(tester).recipients), ['ivan.petrov@hotmail.com']);
    await tester.pumpAndSettle();
    expect((await c.listDrafts()).single.to, ['ivan.petrov@hotmail.com']);

    c.failSendTo = null;
    await tapSend(tester);
    expect(
      [for (final call in c.sendWithCalls.skip(2)) '$call'],
      ['guestLink → ivan.petrov@hotmail.com'],
      reason: 'Ivan once, Dana not again',
    );
    expect(await c.listDrafts(), isEmpty);
  });

  testWidgets('the guest link of a delivered batch is shown once, its passphrase too, when the '
      'plaintext send fails after it', (tester) async {
    final c = await composeOn(
      tester,
      FakeCore(latency: Duration.zero)..failSendPolicy = SendPolicy.allowPlaintext,
    );
    await addRecipient(tester, 'dana@example.org');
    await addRecipient(tester, 'ivan.petrov@hotmail.com');
    await confirmPlaintext(tester, 'ivan.petrov@hotmail.com');
    await subject(tester, 'Offsite');
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('guest-sent-dialog')), findsOneWidget);
    expect(
      find.textContaining('dana@example.org received a link that needs this passphrase'),
      findsOneWidget,
    );
    final shown = tester.widget<SelectableText>(find.byKey(const Key('guest-passphrase'))).data!;
    expect(shown.split('-'), hasLength(5));
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
    expect(
      find.textContaining(
        'Sent: guest link for 1 (dana@example.org), but not to ivan.petrov@hotmail.com: server '
        'unreachable.',
      ),
      findsOneWidget,
    );
    final s = composeState(tester);
    expect(emails(s.recipients), ['ivan.petrov@hotmail.com']);
    expect(
      s.statusOf('ivan.petrov@hotmail.com'),
      RecipientStatus.plaintext,
      reason: 'still confirmed',
    );

    c.failSendPolicy = null;
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-sent-dialog')), findsNothing, reason: 'no second link');
    expect(find.byKey(const Key('guest-passphrase')), findsNothing);
    expect(
      [for (final call in c.sendWithCalls.skip(2)) '$call'],
      ['allowPlaintext → ivan.petrov@hotmail.com'],
      reason: 'Ivan once, Dana not again',
    );
  });

  testWidgets('a recipient who got it leaves with their plaintext consent: added again, they are '
      'asked again', (tester) async {
    await composeOn(tester, FakeCore(latency: Duration.zero)..failSendTo = 'erik@posteo.de');
    await addRecipient(tester, 'ivan.petrov@hotmail.com');
    await confirmPlaintext(tester, 'ivan.petrov@hotmail.com');
    await tester.tap(find.byKey(const Key('compose-bcc-toggle')));
    await tester.pumpAndSettle();
    await addRecipient(tester, 'erik@posteo.de', field: 'compose-bcc');
    await subject(tester, 'Offsite');
    await tapSend(tester);
    expect(
      find.textContaining(
        'Sent: plaintext to 1 (ivan.petrov@hotmail.com), but not to erik@posteo.de: server '
        'unreachable.',
      ),
      findsOneWidget,
    );
    expect(composeState(tester).confirmedPlaintext, isEmpty);

    await addRecipient(tester, 'ivan.petrov@hotmail.com');
    expect(
      composeState(tester).statusOf('ivan.petrov@hotmail.com'),
      RecipientStatus.guestLink,
      reason: 'never plaintext again without a new confirmation',
    );
  });

  for (final (name, size) in [('phone', phone), ('desktop', desktop)]) {
    testWidgets('accessibility on $name: compose after a partial send', (tester) async {
      final handle = tester.ensureSemantics();
      await composeOn(
        tester,
        FakeCore(latency: Duration.zero)..failSendPolicy = SendPolicy.guestLink,
        size: size,
      );
      await addRecipient(tester, 'bob@sealbox.test');
      await addRecipient(tester, 'dana@example.org');
      await subject(tester, 'Offsite');
      await tapSend(tester);
      expect(find.byKey(const Key('compose-partial-snackbar')), findsOneWidget);
      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      if (size == phone) await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      handle.dispose();
    });
  }
}
