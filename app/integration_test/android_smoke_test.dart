// Sealbox on-device smoke test — gate G19 (scripts/review_android.sh, scripts/gate_g19.sh).
//
// Runs the REAL app (`main()` from lib/main.dart: RustLib.init, the Rust keygen self-check,
// the router) on the emulator and walks every screen that exists today, taking a Flutter
// screenshot of each. Only stable things are relied upon: the app starts, the first screen
// renders, and the visible texts / widget keys of the current UI (bottom navigation
// Inbox · Compose · Settings, `onboarding-email`, `onboarding-continue`,
// `settings-add-account`, `compose-to`, …). Optional steps never fail the test; the
// required ones are: the app renders, and (when accounts exist) inbox, compose and
// settings are reachable — or (fresh profile) onboarding renders.
//
// Screenshots reach the host through test_driver/integration_test.dart as NN-<screen>.png.
// The last two replace the real app with ReviewTour's FakeCore (states the real loop cannot
// provoke): the key-changed banner and the HTML newsletter's inline cid: logo.
// Start modes:
//   * accounts exist (today: the seeded FakeCore) → the app opens on the inbox;
//   * no accounts (fresh engine)                   → it opens on onboarding; the test then
//     adds u06@sealbox.test manually against GreenMail on the host (10.0.2.2 is the
//     emulator's alias for the host loopback; IMAP 3143 / SMTP 3025 without TLS, exactly
//     as gate G17's wiring test does) and carries on if that succeeds.
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sealbox_app/main.dart' as app;
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/review_tour.dart';
import 'package:sealbox_app/src/features/compose/compose_screen.dart' show ComposeScreen;
import 'package:sealbox_app/src/router.dart';

const _hostLoopback = '10.0.2.2';
// GreenMail users u06–u10 belong to the Android loop (docs/GATES.md allocation).
const _smokeUser = 'u06@sealbox.test';
const _smokeLogin = 'u06'; // GreenMail logins are the local part
const _smokePassword = 'u06pw';
// An offline provider-table hit, so the "detected" step renders without any network.
const _detectEmail = 'u06@gmail.com';

typedef Shot = Future<void> Function(String name);

/// The PIN the smoke test sets / enters on the device under test.
const _smokePin = '135790';

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  binding.framePolicy = LiveTestWidgetsFlutterBindingFramePolicy.fullyLive;

  testWidgets('launch → inbox → thread → compose → settings → onboarding', (
    tester,
  ) async {
    final shots = <String>[];
    final steps = <Map<String, Object?>>[];
    var mode = 'unknown';
    var n = 0;

    Future<void> shot(String name) async {
      n += 1;
      final file = '${n.toString().padLeft(2, '0')}-$name';
      await dismissKeyboard(tester);
      await settle(tester, const Duration(milliseconds: 700));
      await binding.takeScreenshot(file);
      shots.add(file);
      debugPrint('[smoke] screenshot $file');
    }

    Future<bool> step(
      String name,
      Future<void> Function() body, {
      bool required = false,
    }) async {
      final t0 = DateTime.now();
      try {
        await body();
        steps.add({
          'step': name,
          'ok': true,
          'ms': DateTime.now().difference(t0).inMilliseconds,
        });
        debugPrint('[smoke] ok   $name');
        return true;
      } catch (e, st) {
        steps.add({
          'step': name,
          'ok': false,
          'required': required,
          'error': '$e',
          'ms': DateTime.now().difference(t0).inMilliseconds,
        });
        debugPrint('[smoke] FAIL $name: $e\n$st');
        if (required) rethrow;
        return false;
      }
    }

    final inboxReady = <Finder>[
      find.byKey(const Key('inbox-list')),
      find.text('Nothing here yet.'),
      find.byKey(const Key('inbox-add-account')),
    ];
    final settingsReady = <Finder>[
      find.byKey(const Key('settings-add-account')),
      find.byKey(const Key('my-fingerprint')),
      find.byKey(const Key('settings-core-info')),
    ];

    try {
      await step('launch: main() + first frame', required: true, () async {
        // main() returns only after the app lock was passed, so it is not awaited.
        unawaited(app.main());
        await waitFor(tester, find.byType(MaterialApp), const Duration(seconds: 30));
        // Android: the Flutter surface must be converted before takeScreenshot.
        await binding.convertFlutterSurfaceToImage();
      });
      await shot('launch');

      // App lock: PIN setup on a fresh install, unlock otherwise (same smoke PIN).
      final lockScreen = find.byKey(const Key('lock-screen'));
      await waitForAny(tester, [lockScreen, find.byKey(const Key('onboarding-email')), find.byKey(const Key('home-bottom-nav'))],
          const Duration(seconds: 30));
      if (lockScreen.evaluate().isNotEmpty) {
        await step('app lock: set or enter the PIN', required: true, () async {
          final setup = find.byKey(const Key('lock-pin-confirm')).evaluate().isNotEmpty;
          await shot(setup ? 'lock-setup' : 'lock-unlock');
          await tester.enterText(find.byKey(const Key('lock-pin')), _smokePin);
          if (setup) {
            await tester.enterText(find.byKey(const Key('lock-pin-confirm')), _smokePin);
          }
          await dismissKeyboard(tester);
          await tester.tap(find.byKey(const Key('lock-submit')));
          await waitForAny(
            tester,
            [find.byKey(const Key('onboarding-email')), find.byKey(const Key('home-bottom-nav'))],
            const Duration(seconds: 60),
          );
        });
      }

      final onboarding = find.byKey(const Key('onboarding-email'));
      final shell = find.byWidgetPredicate(
        (w) =>
            w.key == const Key('home-bottom-nav') ||
            w.key == const Key('home-rail'),
      );
      await step('first screen: onboarding or the home shell', required: true, () async {
        await waitForAny(tester, [onboarding, shell], const Duration(seconds: 30));
      });

      if (onboarding.evaluate().isNotEmpty) {
        mode = 'fresh';
        await step('onboarding renders (fresh profile)', required: true, () async {
          expect(find.byKey(const Key('onboarding-hero')), findsOneWidget);
        });
        await shot('onboarding-email');
        final added = await step(
          'add $_smokeUser manually via GreenMail on the host',
          () => addAccountManually(tester, shot),
        );
        if (!added) {
          // Nothing beyond onboarding is reachable without an account; the host-side
          // gate decides from the manifest whether that is acceptable.
          await shot('onboarding-after-connect-attempt');
          return;
        }
      } else {
        mode = 'accounts';
      }

      await step('inbox', required: true, () async {
        await navTo(tester, 'Inbox');
        await waitForAny(tester, inboxReady, const Duration(seconds: 20));
        // Give the first sync a moment, then refresh once so seeded mail shows up.
        await settle(tester, const Duration(seconds: 4));
        final refresh = find.byTooltip('Refresh');
        if (refresh.evaluate().isNotEmpty) {
          await tester.tap(refresh.first, warnIfMissed: false);
          await settle(tester, const Duration(seconds: 3));
        }
      });
      await shot('inbox');

      await step('open the first thread and come back', () async {
        final tile = find.byWidgetPredicate(
          (w) =>
              w.key is ValueKey<String> &&
              (w.key! as ValueKey<String>).value.startsWith('thread-tile-'),
        );
        await waitFor(tester, tile, const Duration(seconds: 10));
        await tester.tap(tile.first, warnIfMissed: false);
        await waitFor(
          tester,
          find.byKey(const Key('thread-messages')),
          const Duration(seconds: 15),
        );
        await shot('thread');
        final back = find.byKey(const Key('thread-back'));
        if (back.evaluate().isNotEmpty) {
          await tester.tap(back.first, warnIfMissed: false);
        } else {
          await navTo(tester, 'Inbox');
        }
        await waitForAny(tester, inboxReady, const Duration(seconds: 10));
      });

      await step('compose', required: true, () async {
        await navTo(tester, 'Compose');
        await waitFor(
          tester,
          find.byKey(const Key('compose-to')),
          const Duration(seconds: 15),
        );
      });
      await shot('compose');

      await step('compose: recipient pill, subject, body (nothing is sent)', () async {
        await tester.enterText(
          find.byKey(const Key('compose-to')),
          'u07@sealbox.test',
        );
        await tester.testTextInput.receiveAction(TextInputAction.done);
        await settle(tester, const Duration(seconds: 2)); // recipient key lookup → pill
        // A key-less recipient opens the guest-link panel, which pushes Subject and
        // Message below the fold of the (lazily built) compose list.
        final composeList = find.descendant(
          of: find.byType(ComposeScreen),
          matching: find.byType(Scrollable),
        ).first;
        await tester.scrollUntilVisible(find.byKey(const Key('compose-subject')), 200,
            scrollable: composeList);
        await tester.enterText(
          find.byKey(const Key('compose-subject')),
          'Smoke test from the Android loop',
        );
        await tester.scrollUntilVisible(find.byKey(const Key('compose-body')), 200,
            scrollable: composeList);
        await tester.enterText(
          find.byKey(const Key('compose-body')),
          'Hello from sealbox_api35. This draft is never sent.',
        );
        await settle(tester, const Duration(seconds: 1));
        await shot('compose-filled');
      });

      await step('settings', required: true, () async {
        await navTo(tester, 'Settings');
        await waitForAny(tester, settingsReady, const Duration(seconds: 20));
        await settle(tester, const Duration(seconds: 3)); // keygen for the fingerprint card
      });
      await shot('settings');

      // G30/G15 on the real engine: the key-transparency card, the verify screen with the
      // real OPENPGP4FPR QR, the recovery phrase (throw-away smoke profile), the restore form.
      await step('identity + recovery screens (real engine)', () async {
        GoRouter router() => GoRouter.of(tester.element(find.byType(Scaffold).first));
        final card = find.byKey(const Key('settings-identity-recovery'));
        await tester.scrollUntilVisible(card, 300,
            scrollable: find.byType(Scrollable).first, maxScrolls: 40);
        await shot('settings-security-recovery');
        router().go('/settings/verify?address=${Uri.encodeQueryComponent('u07@sealbox.test')}');
        await waitFor(tester, find.byKey(const Key('verify-my-qr')), const Duration(seconds: 15));
        await shot('verify-qr');
        router().go('/settings/recovery-phrase');
        await waitFor(tester, find.byKey(const Key('recovery-create')), const Duration(seconds: 10));
        await tester.tap(find.byKey(const Key('recovery-create')), warnIfMissed: false);
        await waitFor(tester, find.byKey(const Key('recovery-reveal')), const Duration(seconds: 10));
        await shot('recovery-phrase-blurred');
        await tester.tap(find.byKey(const Key('recovery-reveal')), warnIfMissed: false);
        await shot('recovery-phrase-revealed');
        router().go('/restore');
        await waitFor(tester, find.byKey(const Key('restore-email')), const Duration(seconds: 10));
        await shot('restore');
        router().go('/settings');
        await waitForAny(tester, settingsReady, const Duration(seconds: 15));
      });

      {
        // Both modes: the detected / app-password steps are only reachable this way.
        await step('onboarding via Settings → Add account', () async {
          final add = find.byKey(const Key('settings-add-account'));
          await waitFor(tester, add, const Duration(seconds: 10));
          await tryEnsureVisible(tester, add);
          await tester.tap(add.first, warnIfMissed: false);
          await waitFor(tester, onboarding, const Duration(seconds: 10));
          await shot('onboarding-email');

          await tester.enterText(onboarding, _detectEmail);
          await tester.tap(
            find.byKey(const Key('onboarding-continue')),
            warnIfMissed: false,
          );
          await waitForAny(tester, [
            find.byKey(const Key('onboarding-detected')),
            find.byKey(const Key('onboarding-manual-step')),
          ], const Duration(seconds: 30));
          await shot('onboarding-detected');

          final appPw = find.byKey(const Key('onboarding-app-password'));
          if (appPw.evaluate().isNotEmpty) {
            await tester.tap(appPw.first, warnIfMissed: false);
            await waitFor(
              tester,
              find.byKey(const Key('onboarding-app-password-step')),
              const Duration(seconds: 10),
            );
            await shot('onboarding-app-password');
          }

          // Leave onboarding: back to the email step, then the close button.
          for (var i = 0; i < 3; i++) {
            final back = find.byKey(const Key('onboarding-back'));
            if (back.evaluate().isEmpty) break;
            await tester.tap(back.first, warnIfMissed: false);
            await settle(tester, const Duration(milliseconds: 500));
          }
          final close = find.byIcon(Icons.close);
          if (close.evaluate().isNotEmpty) {
            await tester.tap(close.first, warnIfMissed: false);
          }
          await waitForAny(tester, settingsReady, const Duration(seconds: 10));
        });
      }

      await step('back to the inbox', () async {
        await navTo(tester, 'Inbox');
        await waitForAny(tester, inboxReady, const Duration(seconds: 15));
      });
      await shot('inbox-final');

      // Last, because it replaces the real app's widget tree: the key-changed banner on
      // FakeCore's sample mailbox (the real loop cannot make a correspondent's key change).
      await step('fake: key-changed banner (FakeCore)', () async {
        await tester.pumpWidget(
          ProviderScope(
            overrides: [
              coreApiProvider.overrideWithValue(ReviewTour.fakeCore()),
              initialLocationProvider.overrideWithValue('/inbox/t/t-budget'),
            ],
            child: const SealboxApp(),
          ),
        );
        await waitFor(
          tester,
          find.byKey(const ValueKey('key-changed-banner-bob@sealbox.test')),
          const Duration(seconds: 15),
        );
        await shot('fake-thread-key-changed');
      });

      // The desktop loop's last fake shot at phone size: the HTML newsletter once its logo part
      // carries the Content-ID its cid: image names (ReviewFakeCore's switch, as
      // ReviewTour._fakeInlineImage). The logo renders from the store, the two remote images stay
      // blocked and counted, and the logo is not listed again as a chip (review N4). A fresh
      // tree (its own key), so the router starts on the newsletter.
      await step('fake: inline cid: image (FakeCore)', () async {
        final core = ReviewTour.fakeCore() as ReviewFakeCore;
        core.inlineImage = true;
        await tester.pumpWidget(
          ProviderScope(
            key: const ValueKey('smoke-fake-inline-image'),
            overrides: [
              coreApiProvider.overrideWithValue(core),
              initialLocationProvider.overrideWithValue('/inbox/t/t-html-statement'),
            ],
            child: const SealboxApp(),
          ),
        );
        await waitFor(
          tester,
          find.byKey(const Key('html-inline-image')),
          const Duration(seconds: 15),
        );
        await shot('fake-thread-html-inline-image');
      });
    } finally {
      // Merge, never replace: takeScreenshot() has been appending the PNG bytes to
      // reportData['screenshots'], which is how they travel to the host driver.
      (binding.reportData ??= <String, dynamic>{}).addAll(<String, dynamic>{
        'mode': mode,
        'screens': shots,
        'steps': steps,
      });
    }
  });
}

/// Fresh-profile path: fill the manual server step against GreenMail on the host.
Future<void> addAccountManually(WidgetTester tester, Shot shot) async {
  final email = find.byKey(const Key('onboarding-email'));
  await tester.enterText(email, _smokeUser);
  await tester.tap(find.byKey(const Key('onboarding-continue')), warnIfMissed: false);
  final manual = find.byKey(const Key('onboarding-manual-step'));
  final detected = find.byKey(const Key('onboarding-detected'));
  await waitForAny(tester, [manual, detected], const Duration(seconds: 60));
  if (detected.evaluate().isNotEmpty) {
    await shot('onboarding-detected');
    await tester.tap(find.byKey(const Key('onboarding-manual')), warnIfMissed: false);
    await waitFor(tester, manual, const Duration(seconds: 10));
  }
  await shot('onboarding-manual');

  Future<void> fill(String key, String value) async {
    final f = find.byKey(Key(key));
    await waitFor(tester, f, const Duration(seconds: 5));
    await tester.enterText(f, value);
  }

  await fill('manual-imap-host', _hostLoopback);
  await fill('manual-imap-port', '3143'); // GreenMail IMAP, no TLS (as gate G17)
  await selectDropdownEntry(tester, 'manual-imap-security', 'None (plain)');
  await fill('manual-smtp-host', _hostLoopback);
  await fill('manual-smtp-port', '3025'); // GreenMail SMTP, no TLS
  await selectDropdownEntry(tester, 'manual-smtp-security', 'None (plain)');
  await fill('manual-username', _smokeLogin);
  await fill('manual-secret', _smokePassword);
  // With the soft keyboard open the Connect button sits (clipped) at the very edge of the
  // shrunken viewport — see review/android/<date>/REVIEW.md. Close the keyboard first, then
  // tap; if the step did not move on, submit the password field (its onSubmitted connects).
  final connect = find.byKey(const Key('manual-connect'));
  await dismissKeyboard(tester);
  await settle(tester, const Duration(milliseconds: 800));
  await tryEnsureVisible(tester, connect);
  await tester.tap(connect, warnIfMissed: false);
  await settle(tester, const Duration(seconds: 2));
  if (manual.evaluate().isNotEmpty &&
      find.byKey(const Key('onboarding-connecting')).evaluate().isEmpty) {
    await tester.showKeyboard(find.byKey(const Key('manual-secret')));
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await settle(tester, const Duration(seconds: 1));
  }
  final open = find.byKey(const Key('onboarding-open-inbox'));
  final done = find.byKey(const Key('onboarding-done'));
  await waitForAny(tester, [done, open], const Duration(seconds: 90));
  await shot('onboarding-done');
  if (open.evaluate().isNotEmpty) {
    await tester.tap(open.first, warnIfMissed: false);
  }
  await settle(tester, const Duration(seconds: 1));
}

Future<void> selectDropdownEntry(WidgetTester tester, String key, String label) async {
  final dd = find.byKey(Key(key));
  await tryEnsureVisible(tester, dd);
  await tester.tap(dd, warnIfMissed: false);
  await settle(tester, const Duration(milliseconds: 600));
  final entries = find.text(label);
  if (entries.evaluate().isEmpty) return;
  await tester.tap(entries.last, warnIfMissed: false); // the popup entry, not the button
  await settle(tester, const Duration(milliseconds: 600));
}

/// Tap a destination of the bottom navigation bar (phones) or the rail (wide).
Future<void> navTo(WidgetTester tester, String label) async {
  final bottom = find.byKey(const Key('home-bottom-nav'));
  final rail = find.byKey(const Key('home-rail'));
  await waitForAny(tester, [bottom, rail], const Duration(seconds: 10));
  final container = bottom.evaluate().isNotEmpty ? bottom : rail;
  final dest = find.descendant(of: container, matching: find.text(label));
  await waitFor(tester, dest, const Duration(seconds: 5));
  await tester.tap(dest.first, warnIfMissed: false);
  await settle(tester, const Duration(milliseconds: 800));
}

/// Drop focus so the platform hides the soft keyboard and the viewport grows back.
Future<void> dismissKeyboard(WidgetTester tester) async {
  FocusManager.instance.primaryFocus?.unfocus();
  await tester.pump();
}

Future<void> tryEnsureVisible(WidgetTester tester, Finder f) async {
  try {
    await tester.ensureVisible(f.first);
    await settle(tester, const Duration(milliseconds: 300));
  } catch (_) {
    // Not inside a Scrollable (or already visible): nothing to do.
  }
}

/// Real-time wait: keep pumping frames until [finder] matches or [timeout] elapses.
Future<void> waitFor(WidgetTester tester, Finder finder, Duration timeout) =>
    waitForAny(tester, [finder], timeout);

Future<void> waitForAny(
  WidgetTester tester,
  List<Finder> finders,
  Duration timeout,
) async {
  final end = DateTime.now().add(timeout);
  while (true) {
    await tester.pump();
    if (finders.any((f) => f.evaluate().isNotEmpty)) return;
    if (DateTime.now().isAfter(end)) {
      throw TimeoutException(
        'timed out after ${timeout.inSeconds}s waiting for any of: '
        '${finders.map((f) => f.describeMatch(Plurality.one)).join(' | ')}',
      );
    }
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}

/// Pump frames for a fixed real-time span (the app's own async work keeps running).
Future<void> settle(WidgetTester tester, Duration total) async {
  final end = DateTime.now().add(total);
  while (DateTime.now().isBefore(end)) {
    await tester.pump();
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  await tester.pump();
}
