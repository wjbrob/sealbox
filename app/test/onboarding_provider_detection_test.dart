import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

Future<void> enterEmailAndContinue(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('onboarding-email')), email);
  await tester.tap(find.byKey(const Key('onboarding-continue')));
}

void main() {
  testWidgets('Gmail: shows "detecting", then IMAP/SMTP + OAuth with app-password fallback',
      (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: const Duration(milliseconds: 300), seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();

    await enterEmailAndContinue(tester, 'alice@gmail.com');
    await tester.pump();
    expect(find.byKey(const Key('onboarding-detecting')), findsOneWidget);
    expect(find.text('Detecting provider…'), findsOneWidget);

    await tester.pump(const Duration(milliseconds: 400));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('onboarding-detected')), findsOneWidget);
    expect(find.text('Gmail detected'), findsOneWidget);
    expect(find.textContaining('imap.gmail.com:993 (TLS)'), findsOneWidget);
    expect(find.textContaining('smtp.gmail.com:465 (TLS)'), findsOneWidget);
    expect(find.text('OAuth 2.0'), findsOneWidget);
    expect(find.byKey(const Key('onboarding-oauth')), findsOneWidget);
    expect(find.text('Continue with Google'), findsOneWidget);
    expect(find.byKey(const Key('onboarding-app-password')), findsOneWidget);

    // App-password instructions carry the provider's help link (behind the open button,
    // as its tooltip, and the copy action — P10: no longer printed as raw text).
    await tester.tap(find.byKey(const Key('onboarding-app-password')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-app-password-step')), findsOneWidget);
    expect(find.textContaining('2-Step Verification'), findsWidgets);
    expect(
      find.byTooltip('https://support.google.com/accounts/answer/185833'),
      findsOneWidget,
    );
  });

  testWidgets('Outlook.com: OAuth only, no app-password button', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();

    await enterEmailAndContinue(tester, 'ivan@hotmail.com');
    await tester.pumpAndSettle();

    expect(find.text('Outlook.com / Hotmail detected'), findsOneWidget);
    expect(find.textContaining('outlook.office365.com:993'), findsOneWidget);
    expect(find.textContaining('smtp.office365.com:587 (STARTTLS)'), findsOneWidget);
    expect(find.text('Continue with Microsoft'), findsOneWidget);
    expect(find.byKey(const Key('onboarding-app-password')), findsNothing);
  });

  testWidgets('Yahoo: app-password flow end to end, then the inbox opens', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();

    await enterEmailAndContinue(tester, 'bob.k@yahoo.com');
    await tester.pumpAndSettle();
    expect(find.text('Yahoo Mail detected'), findsOneWidget);
    expect(find.textContaining('imap.mail.yahoo.com:993'), findsOneWidget);
    expect(find.text('App password'), findsOneWidget);
    expect(find.byKey(const Key('onboarding-oauth')), findsNothing);

    await tester.tap(find.byKey(const Key('onboarding-app-password')));
    await tester.pumpAndSettle();
    expect(find.byTooltip('https://help.yahoo.com/kb/SLN15241.html'), findsOneWidget);

    // Connect stays disabled until the value is plausible (L5).
    FilledButton connect() => tester.widget<FilledButton>(find.byKey(const Key('onboarding-connect')));
    expect(connect().onPressed, isNull);
    await tester.enterText(find.byKey(const Key('onboarding-secret')), 'short');
    await tester.pump();
    expect(connect().onPressed, isNull);

    await tester.enterText(find.byKey(const Key('onboarding-secret')), 'abcd efgh ijkl mnop');

    await tester.pump();
    await tester.tap(find.byKey(const Key('onboarding-connect')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-done')), findsOneWidget);
    expect(find.text('bob.k@yahoo.com is ready'), findsOneWidget);

    await tester.tap(find.byKey(const Key('onboarding-open-inbox')));
    await tester.pumpAndSettle();
    expect(find.text('Inbox'), findsWidgets);
    expect((await core.listAccounts()).single.email, 'bob.k@yahoo.com');
  });

  testWidgets('unknown domain falls back to manual settings, pre-filled from the domain',
      (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();

    await enterEmailAndContinue(tester, 'carol@example.org');
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('onboarding-manual-step')), findsOneWidget);
    expect(find.textContaining('could not find example.org'), findsOneWidget);
    final imapHost = tester.widget<TextField>(find.byKey(const Key('manual-imap-host')));
    expect(imapHost.controller!.text, 'imap.example.org');
    final smtpHost = tester.widget<TextField>(find.byKey(const Key('manual-smtp-host')));
    expect(smtpHost.controller!.text, 'smtp.example.org');
  });

  testWidgets('a malformed address is rejected before detection', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();

    await enterEmailAndContinue(tester, 'alice-at-gmail');
    await tester.pumpAndSettle();
    expect(find.textContaining('Enter a full email address'), findsOneWidget);
    expect(find.byKey(const Key('onboarding-detected')), findsNothing);
  });

  testWidgets('first run: positioning hero with the three steps', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();
    expect(find.text('Private email, without changing your email address.'), findsOneWidget);
    expect(find.text('Connect your existing email account.'), findsOneWidget);
    expect(find.text('Compose and send encrypted messages as usual.'), findsOneWidget);
    expect(find.textContaining('secure guest link'), findsOneWidget);
    expect(find.text('Welcome to Sealbox'), findsOneWidget);
  });

  for (final encrypted in [false, true]) {
    testWidgets('app-password copy claims encryption only when the engine reports it ($encrypted)',
        (tester) async {
      setSurface(tester, phone);
      final core = FakeCore(latency: Duration.zero, seeded: false)
        ..profileKey = encrypted
            ? const ProfileKeyStatus(source: 'raw', wrappedRows: 3)
            : const ProfileKeyStatus.unknown();
      await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
      await tester.pumpAndSettle();
      await enterEmailAndContinue(tester, 'bob.k@yahoo.com');
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('onboarding-app-password')));
      await tester.pumpAndSettle();
      final copy = tester.widget<Text>(find.byKey(const Key('onboarding-app-password-storage'))).data!;
      expect(copy.contains('keystore'), isFalse);
      expect(copy.contains('stored encrypted in your Sealbox profile'), encrypted);
      if (!encrypted) expect(copy, contains('stored only in your Sealbox profile on this device'));
    });
  }

  testWidgets('Gmail app password: 16 letters, spaces stripped, 16/16 counter (L5)', (tester) async {
    setSurface(tester, phone);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();
    await enterEmailAndContinue(tester, 'alice@gmail.com');
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('onboarding-app-password')));
    await tester.pumpAndSettle();
    FilledButton connect() => tester.widget<FilledButton>(find.byKey(const Key('onboarding-connect')));
    await tester.enterText(find.byKey(const Key('onboarding-secret')), 'abcd efgh ijkl mno');
    await tester.pump();
    expect(find.text('15/16'), findsOneWidget);
    expect(connect().onPressed, isNull);
    await tester.enterText(find.byKey(const Key('onboarding-secret')), 'abcd efgh ijkl mnop');
    await tester.pump();
    expect(find.text('16/16'), findsOneWidget);
    expect(connect().onPressed, isNotNull);
    await tester.tap(find.byKey(const Key('onboarding-connect')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-done')), findsOneWidget);
  });

  testWidgets('keyboard open: Connect on the manual step can be scrolled above it (Android S1)',
      (tester) async {
    setSurface(tester, const Size(412, 915));
    tester.view.viewInsets = const FakeViewPadding(bottom: 330);
    tester.view.padding = const FakeViewPadding(bottom: 48);
    addTearDown(tester.view.resetViewInsets);
    addTearDown(tester.view.resetPadding);
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();
    await enterEmailAndContinue(tester, 'me@example.org');
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-manual-step')), findsOneWidget);
    await tester.showKeyboard(find.byKey(const Key('manual-secret')));
    await tester.pumpAndSettle();
    await tester.drag(find.byKey(const Key('onboarding-scroll')), const Offset(0, -2000));
    await tester.pumpAndSettle();
    final button = tester.getRect(find.byKey(const Key('manual-connect')));
    final visibleBottom = 915 - 330.0;
    expect(button.bottom, lessThanOrEqualTo(visibleBottom),
        reason: 'Connect ($button) must sit fully above the keyboard (top at $visibleBottom)');
    await tester.tap(find.byKey(const Key('manual-connect')));
    await tester.pump();
  });
}
