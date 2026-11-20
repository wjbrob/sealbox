import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

Future<void> addRecipient(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('compose-to')), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

Finder statusOf(String email, String status) => find.descendant(
  of: find.byKey(ValueKey('recipient-pill-$email')),
  matching: find.byKey(ValueKey('recipient-status-$status')),
);

void main() {
  testWidgets('per-recipient pills: key known ⇒ encrypted, no key ⇒ guest link + passphrase',
      (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-policy-empty')), findsOneWidget);

    await addRecipient(tester, 'bob@sealbox.test');
    expect(statusOf('bob@sealbox.test', 'encrypted'), findsOneWidget);
    expect(find.textContaining('encrypted · Autocrypt'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-encrypted')), findsOneWidget);
    expect(find.byKey(const Key('guest-passphrase-panel')), findsNothing);
    expect(find.text('Send encrypted'), findsOneWidget);

    await addRecipient(tester, 'dana@example.org');
    expect(statusOf('dana@example.org', 'guestLink'), findsOneWidget);
    expect(statusOf('bob@sealbox.test', 'encrypted'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget);
    expect(find.byKey(const Key('guest-link-panel')), findsOneWidget);
    expect(find.byKey(const Key('guest-passphrase-panel')), findsOneWidget);
    // No passphrase before sending: the engine creates it at send time.
    expect(find.byKey(const Key('guest-passphrase')), findsNothing);
    expect(find.text('Send encrypted'), findsOneWidget);
  });

  testWidgets('guest-link modes: honest explanations, passphrase panel only for Passphrase, '
      'passphrase shown once after send', (tester) async {
    setSurface(tester, phone);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();
    await addRecipient(tester, 'dana@example.org');

    expect(find.textContaining('Share the passphrase by another channel'), findsOneWidget);
    expect(
      find.text('Anyone with the link can read it — protects against the server and the network only.'),
      findsOneWidget,
    );
    expect(find.textContaining('confirms their address'), findsOneWidget);

    await tester.tap(find.byKey(const Key('guest-mode-oneClick')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-passphrase-panel')), findsNothing);
    await tester.tap(find.byKey(const Key('guest-mode-emailCode')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-passphrase-panel')), findsNothing);
    await tester.tap(find.byKey(const Key('guest-mode-passphrase')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-passphrase-panel')), findsOneWidget);

    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-sent-dialog')), findsOneWidget);
    final p = tester.widget<SelectableText>(find.byKey(const Key('guest-passphrase')));
    expect(p.data!.split('-'), hasLength(5));
    expect(find.byKey(const Key('guest-passphrase-copy')), findsOneWidget);
    expect(find.byKey(const Key('guest-passphrase-share')), findsOneWidget);
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-sent-dialog')), findsNothing);
    expect(find.byKey(const Key('guest-passphrase')), findsNothing);
  });

  testWidgets('an engine without G29 offers only one-click; the default is never silently weakened',
      (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero)..guestModes = {GuestMode.oneClick};
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await addRecipient(tester, 'dana@example.org');
    await tester.enterText(find.byKey(const Key('compose-subject')), 'hi');
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('guest-mode-passphrase-soon')), findsOneWidget);
    expect(find.byKey(const Key('guest-mode-emailCode-soon')), findsOneWidget);
    expect(find.byKey(const Key('guest-mode-unavailable')), findsOneWidget);
    expect(tester.widget<ButtonStyleButton>(find.byKey(const Key('compose-send'))).onPressed, isNull);

    await tester.tap(find.byKey(const Key('guest-mode-oneClick')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('guest-mode-unavailable')), findsNothing);
    expect(tester.widget<ButtonStyleButton>(find.byKey(const Key('compose-send'))).onPressed, isNotNull);
  });

  testWidgets('plaintext only after explicit confirmation, and only for that recipient',
      (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();

    await addRecipient(tester, 'dana@example.org');
    expect(statusOf('dana@example.org', 'guestLink'), findsOneWidget);

    // Cancelling the warning keeps the guest link.
    await tester.tap(find.byKey(const ValueKey('recipient-menu-dana@example.org')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('pill-action-plaintext')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('plaintext-confirm-dialog')), findsOneWidget);
    await tester.tap(find.text('Keep the guest link'));
    await tester.pumpAndSettle();
    expect(statusOf('dana@example.org', 'guestLink'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget);

    // Confirming switches exactly this recipient to plaintext.
    await tester.tap(find.byKey(const ValueKey('recipient-menu-dana@example.org')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('pill-action-plaintext')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm-plaintext')));
    await tester.pumpAndSettle();
    expect(statusOf('dana@example.org', 'plaintext'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-plaintext')), findsOneWidget);
    expect(find.text('Send (plaintext)'), findsOneWidget);

    // A second key-less recipient does not inherit the confirmation.
    await addRecipient(tester, 'ivan.petrov@hotmail.com');
    expect(statusOf('ivan.petrov@hotmail.com', 'guestLink'), findsOneWidget);
    expect(statusOf('dana@example.org', 'plaintext'), findsOneWidget);

    // And it can be reverted to a guest link.
    await tester.tap(find.byKey(const ValueKey('recipient-menu-dana@example.org')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('pill-action-guest-link')));
    await tester.pumpAndSettle();
    expect(statusOf('dana@example.org', 'guestLink'), findsOneWidget);
    expect(find.byKey(const Key('compose-policy-guestLink')), findsOneWidget);
  });

  testWidgets('sending reports what happened and returns to the inbox', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();

    await addRecipient(tester, 'bob@sealbox.test');
    await addRecipient(tester, 'dana@example.org');
    await tester.enterText(find.byKey(const Key('compose-subject')), 'Hello');
    await tester.enterText(find.byKey(const Key('compose-body')), 'Body');
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('guest-sent-done')));
    await tester.pumpAndSettle();

    expect(find.text('Sent: encrypted to 1, guest link for 1'), findsOneWidget);
    expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  });

  testWidgets('reply pre-fills the sender and subject; the engine quotes (preview)', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(
        core: FakeCore(latency: Duration.zero),
        initialLocation: '/compose?reply=t-budget',
      ),
    );
    await tester.pumpAndSettle();

    expect(statusOf('bob@sealbox.test', 'encrypted'), findsOneWidget);
    final subject = tester.widget<TextField>(find.byKey(const Key('compose-subject')));
    expect(subject.controller!.text, 'Re: Q4 budget — final numbers');
    // No quote in the editor any more: ComposeOptions.reply() lets the engine quote,
    // and the Preview (open for replies) shows exactly what goes out.
    final body = tester.widget<TextField>(find.byKey(const Key('compose-body')));
    expect(body.controller!.text, isEmpty);
    final preview = tester.widget<SelectableText>(find.byKey(const Key('compose-preview-text')));
    expect(preview.data, contains('wrote:\n> Alice,'));
    expect(preview.data, contains('-- \nAlice Rivera'), reason: 'the account signature, above the quote');
  });

  testWidgets('a non-address is rejected with an inline error', (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();
    await addRecipient(tester, 'bob');
    expect(find.text('"bob" is not an email address'), findsOneWidget);
    expect(find.byKey(const ValueKey('recipient-pill-bob')), findsNothing);
  });

  testWidgets('/compose → /compose?reply=… starts a clean reply draft (no setState during build)',
      (tester) async {
    setSurface(tester, desktop);
    await tester.pumpWidget(
      buildApp(core: FakeCore(latency: Duration.zero), initialLocation: '/compose'),
    );
    await tester.pumpAndSettle();
    final ctx = tester.element(find.byType(Scaffold).last);
    final container = ProviderScope.containerOf(ctx);
    await container.read(composeControllerProvider.notifier).addRecipient('guest@example.org');
    await tester.pumpAndSettle();
    GoRouter.of(ctx).go('/compose?reply=t-budget');
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(
      container.read(composeControllerProvider).recipients.map((r) => r.email),
      ['bob@sealbox.test'],
    );
  });
}
