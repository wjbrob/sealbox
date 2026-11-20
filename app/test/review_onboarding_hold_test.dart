import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/features/onboarding/onboarding_controller.dart';
import 'package:sealbox_app/src/providers/provider_table.dart';

import 'helpers.dart';

// Review P5: the fresh review session never captured "Detecting provider…" or "Connecting
// to …" — the real engine answers within milliseconds, so those shots equal the next state.
// The fake session now holds both with FakeCore's review gates (holdDetect / holdConnect)
// until they are captured. These tests pin what the tour relies on: a held call keeps the
// state on screen for as long as it is held, and a gate completed with an error fails the
// connection like the fresh session's refused one.

OnboardingController controllerOf(WidgetTester tester) =>
    ProviderScope.containerOf(tester.element(find.byType(Scaffold).first))
        .read(onboardingControllerProvider.notifier);

void main() {
  testWidgets('a held detection keeps "Detecting provider…" on screen until released', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();
    final gate = core.holdDetect = Completer<void>();
    unawaited(controllerOf(tester).detect('dana@review.invalid'));
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(seconds: 1));
    }
    expect(find.byKey(const Key('onboarding-detecting')), findsOneWidget, reason: 'held 5 s');
    expect(find.text('Detecting provider…'), findsOneWidget);
    core.holdDetect = null;
    gate.complete();
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-detecting')), findsNothing);
    expect(
      find.byKey(const Key('onboarding-manual-step')),
      findsOneWidget,
      reason: 'unknown domain',
    );
  });

  testWidgets('a held connection shows "Connecting to …"; an error release fails it', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
    await tester.pumpAndSettle();
    final ctl = controllerOf(tester);
    await ctl.detect('dana@review.invalid');
    await tester.pumpAndSettle();
    final accounts = (await core.listAccounts()).length;
    final gate = core.holdConnect = Completer<void>();
    unawaited(
      ctl.connectManual(
        imap: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
        smtp: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
        username: 'dana',
        secret: 'wrong',
      ),
    );
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(seconds: 1));
    }
    expect(find.byKey(const Key('onboarding-connecting')), findsOneWidget, reason: 'held 5 s');
    expect(find.text('Connecting to 127.0.0.1…'), findsOneWidget);
    core.holdConnect = null;
    gate.completeError(StateError('IMAP: connect to 127.0.0.1:1 failed: Connection refused'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('onboarding-connecting')), findsNothing);
    expect(
      find.textContaining('Could not connect: IMAP: connect to 127.0.0.1:1 failed'),
      findsOneWidget,
    );
    expect((await core.listAccounts()).length, accounts, reason: 'no account added');
  });
}
