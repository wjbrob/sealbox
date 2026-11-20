import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../test/support/golden_core.dart';
import '../test/support/harness.dart';

// End-to-end UX flow (gate G20): the real widget tree, router and controllers
// on Linux desktop, driven like a user would, against the deterministic
// GoldenCore (FakeCore + a simulated first sync). The core is injected through
// the hook the app already exposes — the `coreApiProvider` /
// `initialLocationProvider` overrides that main.dart itself uses — so nothing
// in lib/ is special-cased for tests and no `--dart-define` is needed.
//
//   fresh start → onboarding (alice@gmail.com → Gmail detected → app-password
//   path → connecting → ready) → inbox → open the encrypted thread → Reply →
//   recipient pill shows "encrypted", the Preview shows the engine's quote → send →
//   inbox shows the receipt and the refreshed thread → swipe a row to archive it →
//   the Spam chip syncs itself and says what the server holds → Settings shows the
//   key fingerprint → Settings → Filters → add a rule.
//
// Runs twice: at the desktop window size (1280×720, rail + split view) and in a
// narrow 480×900 window (phone layout: bottom bar, stacked list/detail).
//
//   cd app && flutter test -d linux integration_test/ux_flow_test.dart
//   (headless: scripts/gate_g20.sh starts Xvfb)
//
// Every step prints `FLOW_STEP <variant> <n>: <what was verified>` (17 per
// variant); the gate
// counts those lines. With SEALBOX_FLOW_SHOTS_DIR set, a PNG of each step is
// written to <dir>/<variant>/<nn>_<slug>.png for the visual review loop.

const _settleTimeout = Duration(seconds: 20);

class _Flow {
  _Flow(this.tester, this.variant);

  final WidgetTester tester;
  final String variant;
  int _n = 0;

  /// Records a verified step (and a screenshot when enabled).
  Future<void> step(String what) async {
    _n++;
    debugPrint('FLOW_STEP $variant $_n: $what');
    await _screenshot('${_n.toString().padLeft(2, '0')}_${_slug(what)}');
  }

  int get count => _n;

  /// Taps [target] and waits for [expected]; if nothing appears within a short window the tap
  /// is repeated (an animating or not-yet-laid-out control swallows a single tap). Fails only
  /// when [expected] never shows up within the settle timeout.
  Future<void> tapUntil(
    Finder target,
    Finder expected, {
    required String what,
    int attempts = 6,
  }) async {
    final deadline = DateTime.now().add(_settleTimeout);
    for (var attempt = 1; ; attempt++) {
      await tester.ensureVisible(target);
      await tester.pump(const Duration(milliseconds: 150));
      await tester.tap(target, warnIfMissed: false);
      final retryAt = DateTime.now().add(const Duration(seconds: 3));
      while (expected.evaluate().isEmpty && DateTime.now().isBefore(retryAt)) {
        await tester.pump(const Duration(milliseconds: 100));
      }
      if (expected.evaluate().isNotEmpty) break;
      if (attempt >= attempts || DateTime.now().isAfter(deadline)) {
        fail('timed out waiting for $what after $attempt tap(s)');
      }
      debugPrint(
        'FLOW_RETRY $variant: $what not up after tap $attempt, tapping again',
      );
    }
    await tester.pumpAndSettle(
      const Duration(milliseconds: 100),
      EnginePhase.sendSemanticsUpdate,
      _settleTimeout,
    );
  }

  /// Live-binding friendly settle: the fake core answers after a real delay
  /// during which no frame is scheduled, so a plain `pumpAndSettle` would
  /// return too early. Poll until [finder] matches, then let animations end.
  Future<void> waitFor(Finder finder, {String? what}) async {
    final deadline = DateTime.now().add(_settleTimeout);
    while (finder.evaluate().isEmpty) {
      if (DateTime.now().isAfter(deadline)) {
        fail('timed out waiting for ${what ?? finder.toString()}');
      }
      await tester.pump(const Duration(milliseconds: 100));
    }
    await tester.pumpAndSettle(
      const Duration(milliseconds: 100),
      EnginePhase.sendSemanticsUpdate,
      _settleTimeout,
    );
  }

  Future<void> _screenshot(String name) async {
    final dir = Platform.environment['SEALBOX_FLOW_SHOTS_DIR'];
    if (dir == null || dir.isEmpty) return;
    final boundary = tester.renderObject<RenderRepaintBoundary>(
      find.byKey(goldenRootKey),
    );
    final image = await boundary.toImage();
    final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
    if (bytes == null) return;
    File('$dir/$variant/$name.png')
      ..createSync(recursive: true)
      ..writeAsBytesSync(bytes.buffer.asUint8List());
  }

  static String _slug(String s) {
    final t = s
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
        .replaceAll(RegExp(r'^_|_$'), '');
    return t.length <= 40 ? t : t.substring(0, 40);
  }
}

Future<void> _runFlow(WidgetTester tester, String variant, Size window) async {
  final flow = _Flow(tester, variant);
  final narrow = window.width < 840;

  tester.view.physicalSize = window;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final core = GoldenCore(
    seeded: false,
    syncOnAddAccount: true,
    latency: const Duration(milliseconds: 400),
  );
  await tester.pumpWidget(
    buildSealbox(core: core, initialLocation: '/onboarding'),
  );
  await flow.waitFor(
    find.byKey(const Key('onboarding-email')),
    what: 'onboarding',
  );
  expect(find.byKey(const Key('home-bottom-nav')), findsNothing);
  await flow.step('fresh start: no account, onboarding is the first screen');

  await tester.enterText(
    find.byKey(const Key('onboarding-email')),
    'alice@gmail.com',
  );
  await tester.tap(find.byKey(const Key('onboarding-continue')));
  await tester.pump();
  expect(find.byKey(const Key('onboarding-detecting')), findsOneWidget);
  await flow.step('address entered, provider detection running');

  await flow.waitFor(
    find.byKey(const Key('onboarding-detected')),
    what: 'detection result',
  );
  expect(find.text('Gmail detected'), findsOneWidget);
  expect(find.textContaining('imap.gmail.com:993'), findsOneWidget);
  expect(find.byKey(const Key('onboarding-oauth')), findsOneWidget);
  expect(find.byKey(const Key('onboarding-app-password')), findsOneWidget);
  await flow.step(
    'Gmail detected: IMAP/SMTP shown, OAuth offered, app-password fallback offered',
  );

  await tester.tap(find.byKey(const Key('onboarding-app-password')));
  await flow.waitFor(
    find.byKey(const Key('onboarding-app-password-step')),
    what: 'app-password step',
  );
  expect(find.textContaining('2-Step Verification'), findsWidgets);
  // The help URL is no longer printed as raw text (review P10): the "Open Google
  // help" button carries it as its tooltip and "Copy link" puts it on the clipboard.
  expect(
    find.byTooltip('https://support.google.com/accounts/answer/185833'),
    findsOneWidget,
  );
  expect(find.text('Copy link'), findsOneWidget);
  await flow.step('app-password path: Google instructions and help link shown');

  await tester.enterText(
    find.byKey(const Key('onboarding-secret')),
    'abcd efgh ijkl mnop',
  );
  await tester.pump();
  await tester.tap(find.byKey(const Key('onboarding-connect')));
  await tester.pump();
  expect(find.byKey(const Key('onboarding-connecting')), findsOneWidget);
  expect(find.textContaining('Connecting to imap.gmail.com'), findsOneWidget);
  await flow.step('connecting to imap.gmail.com');

  await flow.waitFor(
    find.byKey(const Key('onboarding-done')),
    what: 'account added',
  );
  expect(find.text('alice@gmail.com is ready'), findsOneWidget);
  await flow.step('account ready');

  await tester.tap(find.byKey(const Key('onboarding-open-inbox')));
  await flow.waitFor(
    find.byKey(const ValueKey('thread-tile-t-budget')),
    what: 'synced inbox',
  );
  expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  expect(
    find.byKey(narrow ? const Key('home-bottom-nav') : const Key('home-rail')),
    findsOneWidget,
  );
  expect(find.byKey(const ValueKey('lock-badge-encrypted')), findsWidgets);
  expect(find.byKey(const ValueKey('lock-badge-plaintext')), findsWidgets);
  expect(find.byKey(const ValueKey('lock-badge-signed')), findsWidgets);
  await flow.step(
    'inbox after first sync: ${narrow ? 'phone' : 'desktop'} layout, mixed lock badges',
  );

  await tester.tap(find.byKey(const ValueKey('thread-tile-t-budget')));
  await flow.waitFor(
    find.byKey(const ValueKey('message-card-m-1')),
    what: 'thread view',
  );
  expect(find.byKey(const Key('thread-messages')), findsOneWidget);
  // D7: the verified signature names its signer.
  expect(find.textContaining('signed by bob@sealbox.test'), findsWidgets);
  expect(
    find.descendant(
      of: find.byKey(const ValueKey('message-card-m-1')),
      matching: find.byKey(const ValueKey('lock-badge-encrypted')),
    ),
    findsOneWidget,
  );
  if (narrow) expect(find.byKey(const Key('inbox-list')), findsNothing);
  await flow.step(
    'encrypted thread opened: decrypted body, verified signature badge',
  );

  await tester.tap(find.widgetWithText(FloatingActionButton, 'Reply'));
  await flow.waitFor(
    find.descendant(
      of: find.byKey(const ValueKey('recipient-pill-bob@sealbox.test')),
      matching: find.byKey(const ValueKey('recipient-status-encrypted')),
    ),
    what: 'reply pre-filled with an encrypted recipient',
  );
  expect(find.text('Reply'), findsWidgets);
  expect(find.byKey(const Key('compose-policy-encrypted')), findsOneWidget);
  expect(find.textContaining('encrypted · Autocrypt'), findsOneWidget);
  final subject = tester.widget<TextField>(
    find.byKey(const Key('compose-subject')),
  );
  expect(subject.controller!.text, 'Re: Q4 budget — final numbers');
  final body = tester.widget<TextField>(find.byKey(const Key('compose-body')));
  expect(
    body.controller!.text,
    isEmpty,
    reason: 'the engine quotes (ComposeOptions.reply)',
  );
  expect(find.text('Send encrypted'), findsOneWidget);
  // The Preview (open for replies) shows what goes out: signature, then the quote.
  await tester.scrollUntilVisible(
    find.byKey(const Key('compose-preview')),
    200,
    scrollable: find
        .descendant(
          of: find.byKey(const Key('compose-list')),
          matching: find.byType(Scrollable),
        )
        .first,
  );
  await flow.waitFor(
    find.textContaining('> Alice,'),
    what: "the engine's quote in the preview",
  );
  expect(find.text('Reply with quote'), findsOneWidget);
  await flow.step(
    'reply: recipient resolves to encrypted (Autocrypt key), subject pre-filled, the Preview shows the quote',
  );

  await tester.enterText(
    find.byKey(const Key('compose-body')),
    'Thanks Bob — the numbers look right, sending them on to legal.\n',
  );
  await tester.pump();
  final send = tester.widget<FilledButton>(
    find.byKey(const Key('compose-send')),
  );
  expect(
    send.onPressed,
    isNotNull,
    reason: 'send is enabled once the recipient resolved',
  );
  await tester.tap(find.byKey(const Key('compose-send')));
  await flow.waitFor(
    find.textContaining('Sent: encrypted to 1'),
    what: 'send receipt',
  );
  expect(find.byKey(const Key('inbox-list')), findsOneWidget);
  await flow.step(
    'sent: back on the inbox with the receipt "Sent: encrypted to 1"',
  );

  await flow.waitFor(
    find.descendant(
      of: find.byKey(const ValueKey('thread-tile-t-budget')),
      matching: find.textContaining('Thanks Bob'),
    ),
    what: 'inbox row refreshed with the sent copy',
  );
  expect(
    find.descendant(
      of: find.byKey(const ValueKey('thread-tile-t-budget')),
      matching: find.byKey(const ValueKey('lock-badge-encrypted')),
    ),
    findsOneWidget,
  );
  await flow.step(
    'inbox refreshed after send: the thread row previews our encrypted reply',
  );

  await tester.tap(find.byKey(const ValueKey('thread-tile-t-budget')));
  await flow.waitFor(
    find.byKey(const ValueKey('message-card-sent-1')),
    what: 'thread with the sent copy',
  );
  expect(
    find.descendant(
      of: find.byKey(const ValueKey('message-card-sent-1')),
      matching: find.byKey(const ValueKey('lock-badge-encrypted')),
    ),
    findsOneWidget,
  );
  expect(
    find.descendant(
      of: find.byKey(const ValueKey('message-card-sent-1')),
      matching: find.textContaining('Thanks Bob'),
    ),
    findsOneWidget,
  );
  await flow.step(
    'thread re-opened: the Sent copy is the newest card, encrypted',
  );

  if (narrow) {
    await tester.tap(find.byKey(const Key('thread-back')));
    await flow.waitFor(
      find.byKey(const Key('inbox-list')),
      what: 'back to the list',
    );
  }
  await tester.tap(find.byKey(const Key('inbox-sync')));
  await flow.waitFor(
    find.byKey(const Key('inbox-sync-snackbar')),
    what: 'sync outcome',
  );
  await flow.step('manual fetch: sync ran and reported its outcome');

  // Swipe right archives; the snackbar names the destination folder.
  final lunch = find.byKey(const ValueKey('thread-tile-t-lunch'));
  await flow.waitFor(lunch, what: 'the lunch row');
  await tester.drag(lunch, Offset(narrow ? 420 : 330, 0));
  await flow.waitFor(
    find.text('Archived to [Gmail]/All Mail'),
    what: 'archive snackbar',
  );
  await flow.waitFor(
    find.byKey(const Key('inbox-list')),
    what: 'the list after the swipe',
  );
  expect(lunch, findsNothing);
  await flow.step(
    'swipe right: the conversation is archived to [Gmail]/All Mail and leaves the inbox',
  );

  // Spam: the first open of the chip fetches that folder, then says what the server holds.
  await tester.tap(find.byKey(const Key('folder-chip-spam')));
  await flow.waitFor(
    find.byKey(const Key('folder-empty-synced')),
    what: 'the synced Spam folder',
  );
  expect(find.text('Nothing in Spam on the server.'), findsOneWidget);
  await flow.step(
    'Spam chip: synced on first open, "Nothing in Spam on the server."',
  );
  await tester.tap(find.byKey(const Key('folder-chip-inbox')));
  await flow.waitFor(
    find.byKey(const Key('inbox-list')),
    what: 'back to the inbox',
  );

  if (narrow) {
    expect(find.byKey(const Key('home-bottom-nav')), findsOneWidget);
  }
  await tester.tap(find.text('Settings'));
  await flow.waitFor(find.byKey(const Key('my-fingerprint')), what: 'settings');
  final identity = await core.myIdentity();
  final shown = tester.widget<SelectableText>(
    find.byKey(const Key('my-fingerprint')),
  );
  expect(shown.data!.replaceAll(RegExp(r'\s'), ''), identity.fingerprint);
  expect(find.text('alice@gmail.com'), findsOneWidget);
  expect(find.textContaining('Gmail · App password'), findsOneWidget);
  await flow.step(
    'settings: the account and the OpenPGP fingerprint ${identity.grouped}',
  );

  // Settings → Mail handling → Filters: add a rule; the engine stores it, the list shows it.
  final filtersTile = find.byWidgetPredicate(
    (w) =>
        w.key is ValueKey &&
        '${(w.key as ValueKey).value}'.startsWith('settings-filters-'),
  );
  await tester.scrollUntilVisible(
    filtersTile,
    200,
    scrollable: find.byType(Scrollable).first,
  );
  await tester.pump(const Duration(milliseconds: 200));
  await flow.tapUntil(
    filtersTile,
    find.byKey(const Key('filters-empty')),
    what: 'the filters screen',
  );
  // The FAB scales in while the fake core's first answer is still pending, so a tap that lands
  // during the entrance animation is dropped (seen once in the narrow variant). Tap on a
  // condition, not on a timing: re-tap until the editor sheet is up.
  await flow.tapUntil(
    find.byKey(const Key('filters-add')),
    find.byKey(const Key('filter-editor')),
    what: 'the rule editor',
  );
  await tester.enterText(find.byKey(const Key('filter-value')), 'newsletter');
  await tester.enterText(find.byKey(const Key('filter-folder')), 'Lists');
  await tester.ensureVisible(find.byKey(const Key('filter-save')));
  await tester.pump(const Duration(milliseconds: 200));
  await tester.tap(find.byKey(const Key('filter-save')));
  await flow.waitFor(
    find.text('Subject contains "newsletter": move to Lists'),
    what: 'the new rule',
  );
  await flow.step(
    'Settings → Filters: a rule added in the editor is stored and listed',
  );

  debugPrint('FLOW_DONE $variant ${flow.count} steps');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('UX flow, desktop window 1280×720', (tester) async {
    await _runFlow(tester, 'desktop', const Size(1280, 720));
  });

  testWidgets('UX flow, narrow window 480×900 (phone layout on desktop)', (
    tester,
  ) async {
    await _runFlow(tester, 'narrow', const Size(480, 900));
  });
}
