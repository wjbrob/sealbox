import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart'
    show LiveUpdatesController, liveUpdatesProvider;
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/search/search_controller.dart';
import 'package:sealbox_app/src/widgets/lock_badge.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';
import 'support/sync_cores.dart';

// Accessibility suite (gate G20, docs/UX_TESTING.md). Fixtures include the UI wave:
// the Spam folder, the thread menu and the spam explanation, the Spam / Filters screens
// and the rule editor, Settings → key directory / Mail handling / Server, a reply preview,
// and the review residuals: an undecryptable thread (N1) and a signer ≠ sender one (R4).
//
// For every screen fixture below, in light and dark theme:
//   phone   (390×844 @3×, Android):  textContrastGuideline, androidTapTargetGuideline,
//                                    iOSTapTargetGuideline, labeledTapTargetGuideline
//   desktop (1280×800 @1×, Linux):   textContrastGuideline, labeledTapTargetGuideline
//            (tap-target sizes are a touch-platform rule; Material shrinks targets
//             on desktop by design, so the two size guidelines are phone-only)
// plus semantics checks that lock badges and recipient pills read sensibly.
//
// Every assertion prints `A11Y_ASSERT <id> PASS` or `A11Y_ASSERT <id> SKIP FINDING-n`
// (the gate counts both). A SKIP is never silent: the guideline still runs, every
// failing node must match the finding's signature, and the test FAILS if the
// recorded violation has gone away — so each FINDING entry below must be removed
// (and the finding closed) the moment the app is fixed.

class _Fixture {
  const _Fixture(
    this.id,
    this.location, {
    this.seeded = true,
    this.arrange,
    this.core,
    this.overrides = const [],
  });

  final String id;
  final String location;
  final bool seeded;
  final Future<void> Function(WidgetTester tester)? arrange;

  /// A prepared core instead of `GoldenCore(seeded: seeded)`.
  final GoldenCore Function()? core;

  /// Provider overrides for this fixture (see `settings_server`).
  final List<Override> overrides;
}

/// Live updates pinned off: with the default on (2026-10-29) the Settings watcher status line
/// shifts the list so the "Theme" row straddles the viewport's top edge after scrolling to the
/// server field, and the contrast guideline samples the clipped text against the background
/// (a 1.23:1 false reading). The switch and its status line are covered by the settings goldens.
class _LiveUpdatesOff extends LiveUpdatesController {
  @override
  bool build() => false;
}

Future<void> _enterAndContinue(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('onboarding-email')), email);
  await tester.tap(find.byKey(const Key('onboarding-continue')));
  await tester.pumpAndSettle();
}

Future<void> _addRecipient(WidgetTester tester, String email) async {
  await tester.enterText(find.byKey(const Key('compose-to')), email);
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

/// bob (key) · dana (guest link) · ivan (confirmed plaintext) — one pill per status.
Future<void> _mixedRecipients(WidgetTester tester) async {
  await _addRecipient(tester, 'bob@sealbox.test');
  await _addRecipient(tester, 'dana@example.org');
  await _addRecipient(tester, 'ivan.petrov@hotmail.com');
  await tester.tap(find.byKey(const ValueKey('recipient-menu-ivan.petrov@hotmail.com')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('pill-action-plaintext')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('confirm-plaintext')));
  await tester.pumpAndSettle();
}

final List<_Fixture> _fixtures = [
  const _Fixture('onboarding_email', '/onboarding', seeded: false),
  _Fixture(
    'onboarding_detected_gmail',
    '/onboarding',
    seeded: false,
    arrange: (t) => _enterAndContinue(t, 'alice@gmail.com'),
  ),
  _Fixture(
    'onboarding_app_password_yahoo',
    '/onboarding',
    seeded: false,
    arrange: (t) async {
      await _enterAndContinue(t, 'bob.k@yahoo.com');
      await t.tap(find.byKey(const Key('onboarding-app-password')));
      await t.pumpAndSettle();
    },
  ),
  _Fixture(
    'onboarding_manual_unknown',
    '/onboarding',
    seeded: false,
    arrange: (t) => _enterAndContinue(t, 'carol@example.org'),
  ),
  const _Fixture('inbox_loaded', '/inbox'),
  const _Fixture('thread_encrypted_verified', '/inbox/t/t-budget'),
  _Fixture('compose_mixed', '/compose', arrange: _mixedRecipients),
  const _Fixture('settings_loaded', '/settings'),
  _Fixture(
    'identity_thread_key_changed',
    '/inbox/t/t-budget',
    core: () => GoldenCore()..simulateKeyChange('bob@sealbox.test', messageId: 'm-1'),
  ),
  const _Fixture('identity_verify', '/settings/verify?address=bob%40sealbox.test'),
  _Fixture(
    'recovery_phrase_revealed',
    '/settings/recovery-phrase',
    arrange: (t) async {
      await t.tap(find.byKey(const Key('recovery-create')));
      await t.pumpAndSettle();
      await t.tap(find.byKey(const Key('recovery-reveal')));
      await t.pumpAndSettle();
    },
  ),
  const _Fixture('recovery_restore_form', '/restore', seeded: false),
  // -- the UI wave: folders by role, actions, spam & filters, directory, server, preview --
  _Fixture(
    'inbox_spam_folder',
    '/inbox',
    arrange: (t) async {
      await t.tap(find.byKey(const Key('folder-chip-spam')));
      await t.pumpAndSettle();
    },
  ),
  _Fixture(
    'thread_menu',
    '/inbox/t/t-budget',
    arrange: (t) async {
      await t.tap(find.byKey(const Key('thread-more')));
      await t.pumpAndSettle();
    },
  ),
  _Fixture(
    'spam_explain',
    '/inbox/t/t-junk-prize',
    arrange: (t) async {
      await t.tap(find.byKey(const Key('thread-more')));
      await t.pumpAndSettle();
      await t.tap(find.byKey(const Key('thread-spam-explain')));
      await t.pumpAndSettle();
    },
  ),
  const _Fixture('spam_settings', '/settings/spam?account=acct-1'),
  const _Fixture('filters_list', '/settings/filters?account=acct-1'),
  _Fixture(
    'filters_editor',
    '/settings/filters?account=acct-1',
    arrange: (t) async {
      await t.tap(find.byKey(const Key('filters-add')));
      await t.pumpAndSettle();
    },
  ),
  _Fixture(
    'settings_directory_and_mail_handling',
    '/settings',
    arrange: (t) => _scrollTo(t, find.byKey(const Key('settings-mail-handling'))),
  ),
  _Fixture(
    'settings_server',
    '/settings?section=server',
    arrange: (t) => _scrollTo(t, find.byKey(const Key('server-url-field'))),
    overrides: [liveUpdatesProvider.overrideWith(_LiveUpdatesOff.new)],
  ),
  const _Fixture('compose_reply_preview', '/compose?reply=t-budget'),
  // -- review residuals: N1 "Encrypted message" title, R4 signer ≠ sender warning --
  const _Fixture('thread_undecryptable', '/inbox/t/t-undecryptable'),
  const _Fixture('thread_signer_mismatch', '/inbox/t/t-signer-mismatch'),
  // -- search (results with the matched words in bold) ------------------------------------
  _Fixture(
    'search_results',
    '/search',
    arrange: (t) async {
      await t.enterText(find.byKey(const Key('search-field')), 'Q4');
      await t.pump(MailSearchController.debounce);
      await t.pumpAndSettle();
    },
  ),
  // -- saved drafts: the Drafts chip's list, and compose with a Cc recipient -----------------
  _Fixture('inbox_drafts', '/inbox', core: _coreWithDrafts, arrange: _openDrafts),
  _Fixture(
    'compose_cc',
    '/compose',
    arrange: (t) async {
      await _addRecipient(t, 'bob@sealbox.test');
      await t.tap(find.byKey(const Key('compose-cc-toggle')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('compose-cc')), 'dana@example.org');
      await t.testTextInput.receiveAction(TextInputAction.done);
      await t.pumpAndSettle();
    },
  ),
  // -- Bcc: its own field, with its note; each Bcc recipient gets a copy of their own --------
  _Fixture(
    'compose_cc_bcc',
    '/compose',
    arrange: (t) async {
      await _addRecipient(t, 'bob@sealbox.test');
      await t.tap(find.byKey(const Key('compose-cc-toggle')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('compose-cc')), 'dana@example.org');
      await t.testTextInput.receiveAction(TextInputAction.done);
      await t.pumpAndSettle();
      await t.tap(find.byKey(const Key('compose-bcc-toggle')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('compose-bcc')), 'erik@posteo.de');
      await t.testTextInput.receiveAction(TextInputAction.done);
      await t.pumpAndSettle();
    },
  ),
  // -- sync progress: a first sync mid-way (status line + bar), older mail loading behind it --
  const _Fixture('inbox_syncing', '/inbox', core: syncingCore),
  const _Fixture('inbox_backfill', '/inbox', core: backfillCore),
];

/// A reply draft to Carol and a draft with no recipient yet (second account), saved at the
/// GoldenCore anchor. GoldenCore answers at once, so both are stored before the app pumps.
GoldenCore _coreWithDrafts() {
  final core = GoldenCore();
  core.saveDraft(
    const DraftInput(
      accountId: 'acct-1',
      inReplyTo: 'm-2',
      to: ['carol@proton.me'],
      subject: 'Re: keys for the Thunderbird interop test',
      body: 'Proton worked too.',
    ),
  );
  core.saveDraft(
    const DraftInput(accountId: 'acct-2', subject: 'Release notes 0.4', body: 'Ideas'),
  );
  return core;
}

Future<void> _openDrafts(WidgetTester t) async {
  await t.tap(find.byKey(const Key('folder-chip-drafts')));
  await t.pumpAndSettle();
  expect(find.byKey(const Key('drafts-list')), findsOneWidget);
}

Future<void> _scrollTo(WidgetTester tester, Finder f) async {
  await tester.scrollUntilVisible(f, 200, scrollable: find.byType(Scrollable).first);
  await tester.pumpAndSettle();
  await tester.ensureVisible(f);
  await tester.pumpAndSettle();
}

typedef _Check = (String name, AccessibilityGuideline guideline);

const List<_Check> _phoneChecks = [
  ('contrast', textContrastGuideline),
  ('android_tap', androidTapTargetGuideline),
  ('ios_tap', iOSTapTargetGuideline),
  ('labeled', labeledTapTargetGuideline),
];

const List<_Check> _desktopChecks = [
  ('contrast', textContrastGuideline),
  ('labeled', labeledTapTargetGuideline),
];

/// A recorded violation: the finding number and a substring that every
/// failing node of that assertion must contain (so a *new* violation on the
/// same screen still fails the test).
typedef _Finding = ({String id, String signature});

/// Known violations — assertion id → finding. Each one is a defect in app
/// code this suite must not change, recorded with file/line and a proposed
/// fix in review/ux-findings-2026-10-27.md. The assertion keeps running; see
/// `_checkGuideline`.
const Map<String, _Finding> _knownFindings = {
  // FINDING-1 (help link), FINDING-2 (From dropdown arrow) and FINDING-4
  // (show/hide password) were fixed on 2026-10-27; see review/ux-findings-2026-10-27.md.
};

/// One failing node per guideline message; used to count failures in an
/// [Evaluation.reason] and to check they all carry the finding's signature.
const _failureMarkers = [
  'Expected contrast ratio',
  'expected tap target size',
  'expected tappable node to have semantic label',
];

int _count(String haystack, String needle) =>
    needle.isEmpty ? 0 : needle.allMatches(haystack).length;

/// Runs [guideline] and returns a failure description, or null when it
/// passed (or failed exactly as a recorded finding says it should).
Future<String?> _checkGuideline(
  WidgetTester tester,
  String id,
  AccessibilityGuideline guideline,
) async {
  final finding = _knownFindings[id];
  if (finding == null) {
    try {
      await expectLater(tester, meetsGuideline(guideline));
    } on TestFailure catch (e) {
      return '$id: ${e.message}';
    }
    debugPrint('A11Y_ASSERT $id PASS');
    return null;
  }
  // FINDING skip: still evaluated, so the skip expires with the defect, and
  // every failing node must be the recorded one.
  final Evaluation result = await guideline.evaluate(tester);
  if (result.passed) {
    return '$id: ${finding.id} no longer reproduces — remove it from '
        '_knownFindings and close the finding in review/ux-findings-*.md';
  }
  final reason = result.reason ?? '';
  final failures = _failureMarkers.fold<int>(0, (n, m) => n + _count(reason, m));
  final known = _count(reason, finding.signature);
  if (failures != known) {
    return '$id: ${finding.id} covers "${finding.signature}" only, but the '
        'guideline reported $failures failure(s) of which $known match:\n$reason';
  }
  debugPrint('A11Y_ASSERT $id SKIP ${finding.id}');
  return null;
}

/// Asserts every guideline in [checks]; all failures are reported together
/// so one broken guideline never hides another.
Future<void> _assertGuidelines(
  WidgetTester tester,
  String prefix,
  List<_Check> checks,
) async {
  final failures = <String>[];
  for (final (name, guideline) in checks) {
    final failure = await _checkGuideline(tester, '$prefix/$name', guideline);
    if (failure != null) failures.add(failure);
  }
  if (failures.isNotEmpty) {
    fail(failures.join('\n\n'));
  }
}

/// Every label and tooltip in the semantics tree, depth first.
List<String> _semanticsStrings(WidgetTester tester) {
  final out = <String>[];
  void visit(SemanticsNode node) {
    final data = node.getSemanticsData();
    if (data.label.isNotEmpty) out.add(data.label);
    if (data.tooltip.isNotEmpty) out.add(data.tooltip);
    node.visitChildren((child) {
      visit(child);
      return true;
    });
  }

  for (final view in tester.binding.renderViews) {
    visit(view.owner!.semanticsOwner!.rootSemanticsNode!);
  }
  return out;
}

void main() {
  group('guidelines', () {
    for (final f in _fixtures) {
      for (final theme in GoldenTheme.values) {
        for (final device in GoldenDevice.values) {
          final checks = device == GoldenDevice.phone ? _phoneChecks : _desktopChecks;
          final variant = Variant(device, theme);
          testVariant('${f.id} $variant', variant, (tester) async {
            final semantics = tester.ensureSemantics();
            await pumpSealbox(
              tester,
              core: f.core?.call() ?? GoldenCore(seeded: f.seeded),
              initialLocation: f.location,
              overrides: f.overrides,
            );
            await f.arrange?.call(tester);
            await _assertGuidelines(tester, '${f.id}/$variant', checks);
            semantics.dispose();
          });
        }
      }
    }
  });

  group('semantics', () {
    const v = Variant(GoldenDevice.phone, GoldenTheme.light);

    testVariant('inbox lock badges read as Encrypted / Signed / Not encrypted', v, (tester) async {
      final semantics = tester.ensureSemantics();
      await pumpSealbox(tester, core: GoldenCore());
      final lines = _semanticsStrings(tester).expand((s) => s.split('\n')).toList();
      for (final label in ['Encrypted', 'Signed', 'Not encrypted']) {
        expect(lines, contains(label), reason: 'a thread row should announce "$label"');
      }
      debugPrint('A11Y_ASSERT semantics/inbox_lock_badges PASS');
      semantics.dispose();
    });

    testVariant('thread lock badge carries its label and description', v, (tester) async {
      final semantics = tester.ensureSemantics();
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-budget');
      final strings = _semanticsStrings(tester);
      expect(strings.expand((s) => s.split('\n')), contains('Encrypted'));
      expect(
        strings.any((s) => s.contains('End-to-end encrypted with OpenPGP')),
        isTrue,
        reason: 'the badge tooltip explains what "Encrypted" means',
      );
      debugPrint('A11Y_ASSERT semantics/thread_lock_badge PASS');
      semantics.dispose();
    });

    const pills = {
      'bob@sealbox.test': 'encrypted · Autocrypt',
      'dana@example.org': 'guest link',
      'ivan.petrov@hotmail.com': 'plaintext',
    };

    testVariant('recipient pills announce address, status and a labelled menu', v, (tester) async {
      final semantics = tester.ensureSemantics();
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _mixedRecipients(tester);
      final strings = _semanticsStrings(tester);
      final lines = strings.expand((s) => s.split('\n')).toList();
      for (final MapEntry(key: email, value: status) in pills.entries) {
        final at = lines.indexOf(email);
        expect(at, isNonNegative, reason: '$email is announced');
        expect(lines.skip(at + 1).firstOrNull, status, reason: '$email is followed by "$status"');
        expect(strings, contains('Options for $email'), reason: 'the pill menu is labelled');
      }
      debugPrint('A11Y_ASSERT semantics/recipient_pills PASS');
      semantics.dispose();
    });

    // FINDING-5 (fixed 2026-10-27): every RecipientPill is its own semantics
    // node ("address\nstatus"), with the pill menu as a labelled child.
    testVariant('each recipient pill is ONE semantic node (address + status, nothing else)', v, (tester) async {
      final semantics = tester.ensureSemantics();
      await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/compose');
      await _mixedRecipients(tester);
      final strings = _semanticsStrings(tester);
      bool ownNode(String email) => strings.any(
        (s) =>
            s.contains(email) &&
            s.contains(pills[email]!) &&
            pills.keys.where((other) => other != email).every((other) => !s.contains(other)),
      );
      final perPill = {for (final email in pills.keys) email: ownNode(email)};
      expect(perPill.values.every((ok) => ok), isTrue, reason: 'one node per pill: $perPill');
      debugPrint('A11Y_ASSERT semantics/recipient_pill_own_node PASS');
      semantics.dispose();
    });
  });

  // The lock badge (thread view, 12 sp w600 label on a 12 % tint) and the
  // recipient pill status (11 sp w600 on a 10 % tint) use LockColors, fixed
  // colours with a fixed meaning in both themes. Their text merges into the
  // card / pill semantics node, so textContrastGuideline never measures it
  // (find.text on the merged label matches nothing); this measures the same
  // WCAG ratio directly, against the theme surface each tint sits on.
  group('lock colours', () {
    const minRatio = 4.5; // normal text (< 18 pt, < 14 pt bold)
    const tints = {'badge': 0.12, 'pill': 0.10};

    for (final theme in GoldenTheme.values) {
      final palette = LockColors.of(theme.brightness);
      final colours = {
        'encrypted': palette.encrypted,
        'signed': palette.signed,
        'plaintext': palette.plaintext,
        'guestLink': palette.guestLink,
      };
      for (final MapEntry(key: name, value: colour) in colours.entries) {
        for (final MapEntry(key: where, value: alpha) in tints.entries) {
          final id = 'lock_colours/$where/$name/${theme.name}';
          test(id, () {
            final surface = buildTheme(theme.brightness).colorScheme.surface;
            final background = Color.alphaBlend(colour.withValues(alpha: alpha), surface);
            final lum = [colour.computeLuminance(), background.computeLuminance()]..sort();
            final ratio = (lum[1] + 0.05) / (lum[0] + 0.05);
            final finding = _knownColourFindings[id];
            if (ratio >= minRatio) {
              expect(finding, isNull,
                  reason: '$finding no longer reproduces ($id is ${ratio.toStringAsFixed(2)}:1) — remove it');
              debugPrint('A11Y_ASSERT $id PASS');
              return;
            }
            expect(finding, isNotNull,
                reason: '$id: ${ratio.toStringAsFixed(2)}:1 is below $minRatio:1 — '
                    'record a finding or fix LockColors');
            debugPrint('A11Y_ASSERT $id SKIP $finding (${ratio.toStringAsFixed(2)}:1)');
          });
        }
      }
    }
  });
}

/// FINDING-3 (fixed 2026-10-27): LockColors is resolved per brightness
/// (`LockColors.of(brightness)`), so every text/background pair below must
/// reach 4.5:1 and no entry is skipped any more.
const Map<String, String> _knownColourFindings = {};
