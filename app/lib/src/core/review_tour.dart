// The tour is review tooling that drives the live app from outside the widget
// tree; it deliberately holds the root navigator context across awaits.
// ignore_for_file: use_build_context_synchronously

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../features/compose/compose_controller.dart';
import '../features/compose/compose_screen.dart' show showPlaintextConfirmDialog;
import '../features/compose/drafts.dart' show draftsChipProvider;
import '../features/onboarding/onboarding_controller.dart';
import '../features/settings/settings_screen.dart' show showImportKeyDialog;
import '../features/spam/spam_explain_sheet.dart' show showSpamExplanation;
import '../providers/provider_table.dart';
import '../router.dart';
import '../lock/app_lock.dart';
import '../lock/lock_providers.dart';
import 'core_providers.dart';
import 'fake_core.dart';
import 'models.dart';

/// The scripted screen tour behind `scripts/review_desktop.sh`.
///
/// Started with `SEALBOX_REVIEW=fresh` (empty profile: onboarding states, empty
/// inbox) or `SEALBOX_REVIEW=seeded` (a profile with real GreenMail mail: inbox,
/// threads, compose with every recipient status, settings, dark theme, then a
/// narrow window). After each state settles it prints
/// `[review] screen=<NN-name>` on stdout; the script captures a PNG per line.
/// `[review] resize=WxH` asks the script to resize the window; `[review] done`
/// ends the tour, after which the tour keeps cycling screens so a soak run can
/// go on for as long as the script likes.
class ReviewTour {
  ReviewTour(
    this.container, {
    required this.mode,
    this.settle = const Duration(milliseconds: 1400),
    int shotsBefore = 0,
  }) {
    _n += shotsBefore;
  }

  /// The PIN the tour sets on a review profile (profiles are throw-away).
  static const reviewPin = '246810';

  /// Before the engine opens: captures the lock screen (PIN setup on a fresh
  /// profile, then the unlock screen) and unlocks with [reviewPin]. Returns
  /// the number of screenshots taken, for the numbering of the main tour.
  static Future<int> driveLock(AppLockController lock) async {
    // Under Xvfb "system" resolves to dark: like [run] for the app, the tour chooses Light,
    // stored where the lock screen reads it, so the lock shots match the app (review P6).
    await ThemePreference.of(lock.store).set(ThemeMode.light);
    final t = _LockShots();
    if (lock.phase == LockPhase.setup) {
      await t.shot('lock-setup');
      await lock.setPin(reviewPin);
      lock.lock();
    }
    await t.shot('lock-unlock');
    if (!await lock.unlockWithPin(reviewPin)) {
      debugPrint('[review] error the review profile has a PIN other than the tour\'s');
    }
    return t.n;
  }

  final ProviderContainer container;
  final String mode;
  final Duration settle;

  /// Screenshot numbering continues across sessions (`SEALBOX_REVIEW_START`).
  int _n = int.tryParse(Platform.environment['SEALBOX_REVIEW_START'] ?? '') ?? 0;

  GoRouter get _router => container.read(routerProvider);

  BuildContext? get _context => _router.routerDelegate.navigatorKey.currentContext;

  Future<void> run() async {
    try {
      // Under Xvfb "system" resolves to dark; the light set must really be light.
      container.read(themeModeProvider.notifier).set(ThemeMode.light);
      if (mode == 'fresh') {
        await _fresh();
      } else if (mode == 'fake') {
        await _fake();
      } else {
        await _seeded();
      }
      _log('done');
      await _soak();
    } catch (e, st) {
      _log('error $e');
      debugPrintStack(stackTrace: st);
    }
  }

  void _log(String msg) => debugPrint('[review] $msg');

  /// Directory where the capture script acknowledges each shot (`<name>.ack`);
  /// without it the tour just pauses briefly after every marker.
  final String? _ackDir = Platform.environment['SEALBOX_REVIEW_ACK_DIR'];

  /// [quick] skips the settle wait for transient states (spinners) that would
  /// be over by the time the frame settled.
  Future<void> _shot(String name, {bool quick = false}) async {
    if (!quick) await _wait(settle);
    _n++;
    await _announce(_n, name, _ackDir);
  }

  /// The first element with `Key(key)` in the live tree, if any.
  BuildContext? find_(String key) {
    BuildContext? hit;
    void visit(Element e) {
      if (hit != null) return;
      if (e.widget.key == Key(key)) {
        hit = e;
        return;
      }
      e.visitChildElements(visit);
    }

    WidgetsBinding.instance.rootElement?.visitChildElements(visit);
    return hit;
  }

  Future<void> _wait(Duration d) => Future<void>.delayed(d);

  Future<void> _go(String location) async {
    _router.go(location);
    await _wait(const Duration(milliseconds: 300));
  }

  Future<T> _until<T>(T? Function() probe, {Duration timeout = const Duration(seconds: 60)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      final v = probe();
      if (v != null) return v;
      await _wait(const Duration(milliseconds: 150));
    }
    throw TimeoutException('review tour: condition not met within $timeout');
  }

  /// Type into the TextField with `Key(key)` the way a user would (fires onChanged).
  void _type(String key, String text) {
    final el = find_(key);
    if (el == null) throw StateError('review tour: no field $key');
    final tf = el.widget as TextField;
    tf.controller!.text = text;
    tf.onChanged?.call(text);
  }

  /// Press the button / tap target with `Key(key)`.
  void _press(String key) {
    final el = find_(key);
    final w = el?.widget;
    if (w is ButtonStyleButton && w.onPressed != null) {
      w.onPressed!();
    } else if (w is GestureDetector && w.onTap != null) {
      w.onTap!();
    } else if (w is ListTile && w.onTap != null) {
      w.onTap!();
    } else if (w is FloatingActionButton && w.onPressed != null) {
      w.onPressed!();
    } else if (w is IconButton && w.onPressed != null) {
      w.onPressed!();
    } else {
      throw StateError('review tour: $key is not pressable (${w.runtimeType})');
    }
  }

  /// Opens the PopupMenuButton with `Key(key)` (the thread's overflow menu).
  void _openMenu(String key) {
    final el = find_(key);
    if (el is StatefulElement && el.state is PopupMenuButtonState) {
      (el.state as PopupMenuButtonState).showButtonMenu();
    } else {
      throw StateError('review tour: $key is not a popup menu');
    }
  }

  /// Closes the topmost dialog, sheet or menu.
  Future<void> _dismiss() async {
    final ctx = _context;
    if (ctx != null) Navigator.of(ctx, rootNavigator: true).maybePop();
    await _wait(const Duration(milliseconds: 300));
  }

  /// Brings `Key(key)` into view inside the lazy list under `Key(listKey)` ([revealInList]).
  Future<void> _ensureVisible(String key, {double alignment = 0.05, String? listKey}) async {
    await revealInList(
      key,
      find: find_,
      frame: () => _wait(const Duration(milliseconds: 80)),
      list: listKey == null ? null : find_(listKey),
      alignment: alignment,
    );
  }

  /// The FakeCore of `SEALBOX_REVIEW=fake`: Bob's key changed (message m-1), Carol
  /// verified with a message signed by her verified key, Erik's change already
  /// accepted, and a key-transparency alert for the own address.
  static FakeCore fakeCore() {
    final core = ReviewFakeCore()
      ..simulateKeyChange('bob@sealbox.test', messageId: 'm-1')
      ..simulateVerified('carol@proton.me')
      ..markSignerVerified('m-2')
      ..simulateKeyChange('erik@posteo.de', messageId: 'm-4');
    core.ktState = KtState.alert;
    return core;
  }

  // --- fake core: identity states the real loop cannot provoke ----------------

  Future<void> _fake() async {
    final core = container.read(coreApiProvider);
    if (core is FakeCore) await core.acknowledgeKeyChange('erik@posteo.de');
    await _go('/inbox/t/t-budget');
    await _until(() => find_('key-changed-banner-bob@sealbox.test') != null ? true : null);
    await _shot('fake-thread-key-changed');
    await _go('/inbox/t/t-release');
    await _shot('fake-thread-key-changed-accepted');
    await _go('/inbox/t/t-thunderbird');
    await _shot('fake-thread-verified');
    await _go('/settings/contact?address=${Uri.encodeQueryComponent('bob@sealbox.test')}');
    await _shot('fake-contact-key-changed');
    await _go('/settings/verify?address=${Uri.encodeQueryComponent('bob@sealbox.test')}');
    await _shot('fake-verify');
    _type('verify-manual', '9F4B 2E1C 7A5D 3018 6B2F 4E9C 1D7A 3B5F 0E6C 8D2A');
    await _wait(const Duration(milliseconds: 200));
    _press('verify-manual-confirm');
    await _wait(const Duration(milliseconds: 400));
    // The error sits below the fold of the lazy list: scroll to the end so it is built.
    final confirm = find_('verify-manual-confirm');
    if (confirm != null) {
      final pos = Scrollable.of(confirm).position;
      pos.jumpTo(pos.maxScrollExtent);
    }
    await _until(() => find_('verify-error') != null ? true : null);
    await _ensureVisible('verify-error', alignment: 0.9);
    await _shot('fake-verify-mismatch');
    await _go('/compose');
    await _wait(const Duration(milliseconds: 300));
    final compose = container.read(composeControllerProvider.notifier);
    await compose.addRecipient('bob@sealbox.test');
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('fake-compose-key-changed');
    await _go('/settings');
    await _until(() => container.read(accountsProvider).hasValue ? true : null);
    await _ensureVisible('settings-identity-recovery', alignment: 0.1, listKey: 'settings-list');
    await _shot('fake-settings-kt-alert');
    await _go('/settings/recovery-phrase');
    await _wait(const Duration(milliseconds: 300));
    _press('recovery-create');
    await _until(() => find_('recovery-reveal') != null ? true : null);
    _press('recovery-reveal');
    await _shot('fake-recovery-phrase-revealed');
    _router.go('/settings/transfer');
    await _wait(const Duration(milliseconds: 300));
    _press('transfer-send');
    await _until(() => find_('transfer-code-display') != null ? true : null);
    await _shot('fake-transfer-code');
    await _fakeMailHandling();
    container.read(themeModeProvider.notifier).set(ThemeMode.dark);
    await _go('/inbox/t/t-budget');
    await _shot('fake-thread-key-changed-dark');
    await _go('/settings/verify?address=${Uri.encodeQueryComponent('bob@sealbox.test')}');
    await _shot('fake-verify-dark');
    container.read(themeModeProvider.notifier).set(ThemeMode.light);
    _log('resize=480x900');
    await _wait(const Duration(seconds: 2));
    await _go('/inbox/t/t-budget');
    await _shot('fake-narrow-thread-key-changed');
    await _go('/settings/verify?address=${Uri.encodeQueryComponent('bob@sealbox.test')}');
    await _shot('fake-narrow-verify');
    _log('resize=1280x800');
    await _wait(const Duration(seconds: 2));
    await _fakeResiduals();
    await _fakeSearchAndDrafts();
    await _fakeOnboardingTransients();
    await _fakeInlineImage();
  }

  /// [_fakeInlineImage] on its own, for its widget test.
  @visibleForTesting
  Future<void> fakeInlineImageStep() => _fakeInlineImage();

  /// The HTML newsletter once its logo part carries the Content-ID its `cid:` image names
  /// (docs/HTML_MAIL.md, "Inline images"): the logo renders from the store, the two remote
  /// images stay blocked. Last in the fake session, so the numbers of the shots before stay.
  Future<void> _fakeInlineImage() async {
    final core = container.read(coreApiProvider);
    if (core is! ReviewFakeCore) return;
    core.inlineImage = true;
    container.invalidate(threadProvider);
    await _go('/inbox');
    container.read(folderProvider.notifier).set(MailFolder.all);
    await _until(() => find_('thread-tile-t-html-statement') != null ? true : null);
    await _go('/inbox/t/t-html-statement');
    await _until(() => find_('html-inline-image') != null ? true : null);
    await _shot('fake-thread-html-inline-image');
    container.read(folderProvider.notifier).set(MailFolder.inbox);
  }

  /// The two transient onboarding states the fresh session cannot hold (review P5): the real
  /// engine refuses `.invalid` and a closed port within milliseconds, so its
  /// `onboarding-detecting` / `onboarding-connecting` shots show the next state. Here
  /// FakeCore's gates keep "Detecting provider…" and "Connecting to 127.0.0.1…" (the fresh
  /// session's input) on screen until each is captured; the connection then fails like the
  /// fresh one. Last in the fake session, so the numbers of the shots before stay.
  Future<void> _fakeOnboardingTransients() async {
    final core = container.read(coreApiProvider);
    if (core is! FakeCore) return;
    OnboardingController ctl() => container.read(onboardingControllerProvider.notifier);
    OnboardingStep step() => container.read(onboardingControllerProvider).step;
    await _go('/onboarding');
    await _until(() => find_('onboarding-email') != null ? true : null);

    final detecting = core.holdDetect = Completer<void>();
    unawaited(ctl().detect('dana@review.invalid'));
    await _until(() => step() == OnboardingStep.detecting ? true : null);
    await _shot('fake-onboarding-detecting');
    core.holdDetect = null;
    detecting.complete();
    await _until(() => step() == OnboardingStep.manual ? true : null);

    final connecting = core.holdConnect = Completer<void>();
    unawaited(
      ctl().connectManual(
        imap: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
        smtp: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
        username: 'dana',
        secret: 'wrong',
      ),
    );
    await _until(() => step() == OnboardingStep.connecting ? true : null);
    await _shot('fake-onboarding-connecting');
    core.holdConnect = null;
    connecting.completeError(StateError('IMAP: connect to 127.0.0.1:1 failed: Connection refused'));
    await _until(() => container.read(onboardingControllerProvider).error != null ? true : null);
    await _go('/inbox');
  }

  /// Search and saved drafts (last in the fake session, so the numbers of the shots before
  /// stay): "Q4" typed after the inbox's search action, the results in the list pane with
  /// the matched words in bold; then a message started in compose and left, listed under
  /// the Drafts chip.
  Future<void> _fakeSearchAndDrafts() async {
    await _go('/inbox');
    _press('inbox-search');
    await _until(() => find_('search-field') != null ? true : null);
    _type('search-field', 'Q4');
    await _until(() => find_('search-results') != null ? true : null);
    await _shot('fake-search');
    _press('search-close');
    await _wait(const Duration(milliseconds: 300));
    await _go('/compose');
    await _until(() => find_('compose-subject') != null ? true : null);
    final compose = container.read(composeControllerProvider.notifier);
    await compose.addRecipient('dana@example.org');
    compose.setSubject('Lunch next week');
    compose.setBody('How about Tuesday at the Lebanese place near the station? 12:30 works.');
    await _go('/inbox'); // leaving compose saves the draft
    container.read(draftsChipProvider.notifier).set(true);
    await _until(() => find_('drafts-list') != null ? true : null);
    await _shot('fake-drafts');
    container.read(draftsChipProvider.notifier).set(false);
  }

  /// FakeCore's review samples (folder "Review samples", listed under "All mail" only):
  /// the undecryptable conversation titled "Encrypted message" (review N1), Bob's mail
  /// signed with another address's key, amber "signed by … — but sent by …" (R4), and the
  /// HTML newsletter with its remote images blocked and then loaded. Last in the fake
  /// session, so the numbers of the shots before stay as they were.
  Future<void> _fakeResiduals() async {
    await _go('/inbox');
    container.read(folderProvider.notifier).set(MailFolder.all);
    await _until(() => find_('thread-tile-t-signer-mismatch') != null ? true : null);
    await _go('/inbox/t/t-undecryptable');
    await _until(() => find_('thread-subject') != null ? true : null);
    await _shot('fake-thread-undecryptable');
    await _go('/inbox/t/t-signer-mismatch');
    await _until(
      () => find_('message-signer-mismatch-${FakeCore.signerMismatchSampleId}') != null ? true : null,
    );
    await _shot('fake-thread-signer-mismatch');
    // HTML mail (docs/HTML_MAIL.md): the sanitized newsletter with both remote images
    // blocked, then the same message after "Load images".
    await _go('/inbox/t/t-html-statement');
    await _until(() => find_('message-html-${FakeCore.htmlSampleId}') != null ? true : null);
    await _shot('fake-thread-html');
    if (find_('html-load-images') != null) {
      _press('html-load-images');
      await _until(() => find_('html-remote-banner') == null ? true : null);
      await _shot('fake-thread-html-images-loaded');
    }
    container.read(folderProvider.notifier).set(MailFolder.inbox);
  }

  /// FakeCore states of the UI wave the real loop cannot show: a Spam folder with a
  /// scam and its explanation, a filter dry run, the directory walking unpublished →
  /// awaiting verification → published, an invalid server URL, a forward preview.
  Future<void> _fakeMailHandling() async {
    await _go('/inbox');
    container.read(folderProvider.notifier).set(MailFolder.spam);
    await _until(() => find_('thread-tile-t-junk-prize') != null ? true : null);
    await _shot('fake-inbox-spam');
    await _go('/inbox/t/t-junk-prize');
    await _until(() => find_('thread-more') != null ? true : null);
    _openMenu('thread-more');
    await _shot('fake-thread-menu-spam');
    await _dismiss();
    final ctx = _context;
    if (ctx != null) {
      unawaited(showSpamExplanation(ctx, messageId: FakeCore.junkSampleId, accountId: 'acct-1'));
      await _until(() => find_('spam-explain-label') != null ? true : null);
      await _shot('fake-spam-explain');
      await _dismiss();
    }
    container.read(folderProvider.notifier).set(MailFolder.inbox);
    await _go('/settings/spam?account=acct-1');
    await _shot('fake-settings-spam');
    await _go('/settings/filters?account=acct-1');
    await _until(() => find_('filter-rule-1') != null ? true : null);
    await _shot('fake-settings-filters');
    _press('filters-test');
    await _until(() => find_('filter-test-pick-m-1') != null ? true : null);
    _press('filter-test-pick-m-1');
    await _until(() => find_('filters-test-report') != null ? true : null);
    await _shot('fake-filters-test-report');
    await _go('/settings');
    await _until(() => find_('directory-publish') != null ? true : null);
    await _ensureVisible('directory-status', alignment: 0.3, listKey: 'settings-list');
    await _shot('fake-publish-unpublished');
    _press('directory-publish');
    await _until(() => find_('directory-complete') != null ? true : null);
    await _ensureVisible('directory-status', alignment: 0.3, listKey: 'settings-list');
    await _shot('fake-publish-awaiting');
    _press('directory-complete');
    await _until(() => find_('directory-state-published') != null ? true : null);
    await _ensureVisible('directory-status', alignment: 0.3, listKey: 'settings-list');
    await _shot('fake-publish-published');
    await _go('/settings?section=server');
    await _until(() => find_('server-url-field') != null ? true : null);
    _type('server-url-field', 'ftp://keys.example.org');
    _press('server-url-save');
    await _wait(const Duration(milliseconds: 400));
    await _ensureVisible('settings-server', alignment: 0.2, listKey: 'settings-list');
    await _shot('fake-server-invalid');
    await _go('/compose?forward=m-4');
    await _until(() => container.read(composeControllerProvider).subject.startsWith('Fwd:') ? true : null);
    await _ensureVisible('compose-preview', alignment: 0.2, listKey: 'compose-list');
    await _shot('fake-compose-forward-preview');
  }

  // --- fresh profile: onboarding --------------------------------------------

  Future<void> _fresh() async {
    await _go('/onboarding');
    await _shot('onboarding-email');

    // Restore from recovery phrase: live validation, then a real restore attempt against an
    // unreachable server (the documented error path; this run has no backup server).
    await _go('/restore');
    await _wait(const Duration(milliseconds: 300));
    await _shot('restore');
    _type('restore-email', 'u05@sealbox.test');
    _type('restore-phrase', List.filled(12, 'abandon').join(' '));
    if ((find_('restore-server')?.widget as TextField?)?.controller?.text.isEmpty ?? false) {
      _type('restore-server', 'http://127.0.0.1:9');
    }
    await _wait(const Duration(milliseconds: 300));
    await _shot('restore-phrase-checksum');
    _type('restore-phrase', '${List.filled(11, 'abandon').join(' ')} about');
    await _wait(const Duration(milliseconds: 300));
    _press('restore-submit');
    await _until(() => find_('restore-error') != null ? true : null);
    await _shot('restore-error');
    await _go('/onboarding');
    await _wait(const Duration(milliseconds: 300));
    OnboardingController ctl() => container.read(onboardingControllerProvider.notifier);

    // A table provider: instant detection → detected card with OAuth + app password.
    unawaited(ctl().detect('alice.rivera@gmail.com'));
    await _until(() => container.read(onboardingControllerProvider).step == OnboardingStep.detected ? true : null);
    await _shot('onboarding-detected-gmail');
    ctl().chooseOAuth();
    await _shot('onboarding-oauth');
    ctl().chooseAppPassword();
    await _shot('onboarding-app-password');
    ctl().back();
    ctl().back();

    // Unknown domain: the engine's network discovery runs → "Detecting…", then manual.
    unawaited(ctl().detect('dana@review.invalid'));
    await _wait(const Duration(milliseconds: 120));
    await _shot('onboarding-detecting', quick: true);
    await _until(() => container.read(onboardingControllerProvider).step == OnboardingStep.manual ? true : null,
        timeout: const Duration(seconds: 90));
    await _shot('onboarding-manual');

    // Failed connection → inline error on the manual form.
    unawaited(ctl().connectManual(
      imap: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
      smtp: const ServerSettings('127.0.0.1', 1, ConnectionSecurity.plain),
      username: 'dana',
      secret: 'wrong',
    ));
    await _wait(const Duration(milliseconds: 60));
    await _shot('onboarding-connecting', quick: true);
    await _until(() => container.read(onboardingControllerProvider).error != null ? true : null);
    await _shot('onboarding-error');

    // A real GreenMail account → done → empty inbox.
    ctl().back();
    unawaited(ctl().detect('u05@sealbox.test'));
    await _until(() => container.read(onboardingControllerProvider).step == OnboardingStep.manual ? true : null,
        timeout: const Duration(seconds: 90));
    unawaited(ctl().connectManual(
      imap: const ServerSettings('127.0.0.1', 3143, ConnectionSecurity.plain),
      smtp: const ServerSettings('127.0.0.1', 3025, ConnectionSecurity.plain),
      username: 'u05',
      secret: 'u05pw',
    ));
    await _until(() => container.read(onboardingControllerProvider).step == OnboardingStep.done ? true : null);
    await _shot('onboarding-done');
    await _go('/inbox');
    await _until(() => container.read(threadsProvider).hasValue ? true : null);
    await _shot('inbox-empty');
    await _go('/settings');
    await _shot('settings-one-account');
  }

  // --- seeded profile: everything else --------------------------------------

  Future<void> _seeded() async {
    await _go('/inbox');
    await _until(() => container.read(accountsProvider).hasValue ? true : null);
    // Fetch mail so the list shows real GreenMail content, then capture.
    await container.read(syncControllerProvider.notifier).syncNow();
    final threads = await _until(() {
      final t = container.read(threadsProvider).value;
      return (t != null && t.isNotEmpty) ? t : null;
    });
    await _shot('inbox');
    container.read(folderProvider.notifier).set(MailFolder.sent);
    await _until(() => container.read(threadsProvider).hasValue ? true : null);
    await _shot('inbox-sent-folder');
    // Spam / Trash: the first open fetches the role's folder; then the honest state.
    final accounts = container.read(accountsProvider).value ?? const <Account>[];
    for (final (chip, role, shot) in const [
      (MailFolder.spam, FolderRole.junk, 'inbox-spam-folder'),
      (MailFolder.trash, FolderRole.trash, 'inbox-trash-folder'),
    ]) {
      container.read(folderProvider.notifier).set(chip);
      await container.read(folderSyncProvider.notifier).ensureSynced(role, accounts);
      await _until(() => container.read(threadsProvider).hasValue ? true : null);
      await _shot(shot);
    }
    container.read(folderProvider.notifier).set(MailFolder.inbox);
    await _until(() => container.read(threadsProvider).hasValue ? true : null);

    MailThread? pick(EncryptionState s) => threads
        .where((t) => t.messages.any((m) => m.state == s && !m.isSent))
        .firstOrNull;
    final encrypted = pick(EncryptionState.encrypted) ?? threads.first;
    final plain = pick(EncryptionState.plaintext) ?? threads.last;
    await _go('/inbox/t/${encrypted.id}');
    await _until(() => container.read(threadProvider(encrypted.id)).hasValue ? true : null);
    await _shot('thread-encrypted');
    _openMenu('thread-more');
    await _shot('thread-menu');
    await _dismiss();
    if (plain.id != encrypted.id) {
      await _go('/inbox/t/${plain.id}');
      await _until(() => container.read(threadProvider(plain.id)).hasValue ? true : null);
      await _shot('thread-plaintext');
    }

    // Compose: empty → encrypted recipient → guest link → plaintext (confirmed).
    await _go('/compose');
    await _wait(const Duration(milliseconds: 400));
    await _shot('compose-empty');
    ComposeController compose() => container.read(composeControllerProvider.notifier);
    final contacts = container.read(contactsProvider).value ?? await container.read(coreApiProvider).contacts();
    final withKey = contacts.where((c) => c.hasKey).firstOrNull?.address ?? 'u04@sealbox.test';
    compose().setSubject('Review: encrypted draft');
    compose().setBody('Hello from the review tour.');
    await compose().addRecipient(withKey);
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('compose-encrypted');
    compose().addAttachments([
      DraftAttachment(
        name: 'q4-numbers.csv',
        contentType: 'text/csv',
        data: Uint8List.fromList('quarter,headcount\nQ4,42\n'.codeUnits),
      ),
    ]);
    await _shot('compose-attachment');
    await compose().addRecipient('guest@example.org');
    await _until(() {
      final s = container.read(composeControllerProvider);
      return (!s.anyResolving && s.plan.needsPassphrase) ? true : null;
    });
    await _shot('compose-guest-link');
    final ctx = _context;
    if (ctx != null) {
      unawaited(showPlaintextConfirmDialog(ctx, 'guest@example.org'));
      await _shot('compose-plaintext-confirm');
      Navigator.of(ctx, rootNavigator: true).pop(false);
      await _wait(const Duration(milliseconds: 200));
    }
    compose().confirmPlaintext('guest@example.org');
    await _shot('compose-plaintext');

    // Reply flow (pre-filled quote).
    await _go('/compose?reply=${encrypted.id}');
    await _until(() => container.read(composeControllerProvider).recipients.isNotEmpty ? true : null);
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('compose-reply');
    // The engine's quote and the signature, as the Preview shows them (open for replies).
    await _ensureVisible('compose-preview', alignment: 0.1, listKey: 'compose-list');
    await _until(() => find_('compose-preview-text') != null || find_('compose-preview-error') != null ? true : null);
    await _shot('compose-reply-preview');

    await _go('/settings');
    await _until(() => container.read(identityProvider).hasValue && container.read(contactsProvider).hasValue ? true : null);
    await _shot('settings');
    final ctx2 = _context;
    if (ctx2 != null) {
      unawaited(showImportKeyDialog(ctx2));
      await _shot('settings-import-key');
      Navigator.of(ctx2, rootNavigator: true).pop();
      await _wait(const Duration(milliseconds: 200));
    }
    // Settings → App lock, then "Lock now" covers the app with the lock screen.
    final lockSection = find_('settings-app-lock');
    if (lockSection != null) {
      await Scrollable.ensureVisible(lockSection, alignment: 0.1);
      await _shot('settings-app-lock');
    }
    final lock = container.read(appLockProvider);
    if (lock != null) {
      lock.lock();
      await _shot('lock-now');
      await lock.unlockWithPin(reviewPin);
    }

    final firstAccount = container.read(accountsProvider).value?.firstOrNull?.id;
    // Identity + recovery on the real engine: key-transparency card, a contact, the verify
    // screen with the real OPENPGP4FPR QR, the recovery phrase (throw-away review profile),
    // and the setup-message transfer (mailed to the account itself on GreenMail).
    await _go('/settings');
    await _wait(const Duration(milliseconds: 400));
    await _ensureVisible('settings-identity-recovery', alignment: 0.1, listKey: 'settings-list');
    await _shot('settings-security-recovery');
    final enc = Uri.encodeQueryComponent(withKey);
    await _go('/settings/contact?address=$enc');
    await _shot('contact-detail');
    await _go('/settings/verify?address=$enc');
    await _until(() => find_('verify-my-qr') != null ? true : null);
    await _shot('verify-qr');
    if (firstAccount != null) {
      final q = Uri.encodeQueryComponent(firstAccount);
      await _go('/settings/recovery-phrase?account=$q');
      await _wait(const Duration(milliseconds: 300));
      await _shot('recovery-phrase-intro');
      _press('recovery-create');
      await _until(() => find_('recovery-reveal') != null ? true : null);
      await _shot('recovery-phrase-blurred');
      _press('recovery-reveal');
      await _shot('recovery-phrase-revealed');
      _press('recovery-wrote-down');
      await _shot('recovery-phrase-confirm');
      await _go('/settings/transfer?account=$q');
      await _wait(const Duration(milliseconds: 300));
      _press('transfer-send');
      await _until(() => find_('transfer-code-display') != null || find_('transfer-error') != null ? true : null);
      await _shot('transfer-setup-code');
    }
    if (firstAccount != null) {
      final q = Uri.encodeQueryComponent(firstAccount);
      await _go('/settings/signature?account=$q');
      await _until(() => container.read(signatureProvider(firstAccount)).hasValue ? true : null);
      await _shot('settings-signature');
      await _go('/settings/autoreply?account=$q');
      await _until(() => container.read(autoReplyProvider(firstAccount)).hasValue ? true : null);
      await _shot('settings-out-of-office');
      await _go('/settings');
      await _wait(const Duration(milliseconds: 400));
      await _ensureVisible('settings-mail-handling', alignment: 0.1, listKey: 'settings-list');
      await _shot('settings-mail-handling');
      await _ensureVisible('directory-status', alignment: 0.3, listKey: 'settings-list');
      await _shot('settings-publish');
      await _go('/settings?section=server');
      await _until(() => find_('server-url-field') != null ? true : null);
      await _shot('settings-server');
      await _go('/settings/spam?account=$q');
      await _until(() => container.read(spamSettingsProvider(firstAccount)).hasValue ? true : null);
      await _shot('settings-spam');
      await _go('/settings/filters?account=$q');
      await _until(() => container.read(filterRulesProvider(firstAccount)).hasValue ? true : null);
      await _until(() => find_('filters-empty') != null || find_('filters-list') != null ? true : null);
      await _shot('settings-filters');
      _press('filters-add');
      await _until(() => find_('filter-editor') != null ? true : null);
      await _shot('settings-filter-editor');
      await _dismiss();
    }

    // Dark theme.
    container.read(themeModeProvider.notifier).set(ThemeMode.dark);
    await _go('/inbox');
    await _shot('inbox-dark');
    await _go('/inbox/t/${encrypted.id}');
    await _shot('thread-dark');
    await _go('/compose');
    await _wait(const Duration(milliseconds: 300));
    compose().setSubject('Dark theme');
    await compose().addRecipient(withKey);
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('compose-dark');
    await _go('/settings');
    await _shot('settings-dark');
    container.read(themeModeProvider.notifier).set(ThemeMode.light);

    // Narrow (phone-like) window: bottom navigation, stacked list/detail.
    _log('resize=480x900');
    await _wait(const Duration(seconds: 2));
    await _go('/inbox');
    await _shot('narrow-inbox');
    await _go('/inbox/t/${encrypted.id}');
    await _shot('narrow-thread');
    await _go('/compose');
    await _wait(const Duration(milliseconds: 300));
    await compose().addRecipient(withKey);
    await compose().addRecipient('guest@example.org');
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('narrow-compose');
    await _go('/settings');
    await _shot('narrow-settings');
    container.read(themeModeProvider.notifier).set(ThemeMode.dark);
    await _go('/inbox');
    await _shot('narrow-inbox-dark');
    await _go('/inbox/t/${encrypted.id}');
    await _shot('narrow-thread-dark');
    await _go('/compose');
    await _wait(const Duration(milliseconds: 300));
    await compose().addRecipient(withKey);
    await _until(() => container.read(composeControllerProvider).anyResolving ? null : true);
    await _shot('narrow-compose-dark');
    await _go('/settings');
    await _shot('narrow-settings-dark');
    container.read(themeModeProvider.notifier).set(ThemeMode.light);
    _log('resize=1280x800');
    await _wait(const Duration(seconds: 2));
    await _go('/inbox');
  }

  /// Keeps navigating until the process is killed (soak run for the gate).
  Future<void> _soak() async {
    const stops = ['/inbox', '/compose', '/settings'];
    var i = 0;
    while (true) {
      await _wait(const Duration(seconds: 3));
      await _go(stops[i++ % stops.length]);
      if (i % 3 == 0) {
        await container.read(syncControllerProvider.notifier).syncNow();
      }
    }
  }
}

/// Brings the element with `Key(key)` into view at [alignment] inside the lazy list
/// [list] (a `ListView` builds only what is near its viewport, so the element may not
/// exist yet).
///
/// When [find] cannot see it, the first Scrollable under [list] jumps to its top and pages
/// down until the element is built: from the top, because it may lie above the viewport as
/// well as below it (review N2: searching only downwards from Mail handling never met the
/// Key-directory panel above it, so the seeded `settings-publish` shot was the Server card).
/// [frame] lets the list lay out between steps. Returns whether the element was found.
Future<bool> revealInList(
  String key, {
  required BuildContext? Function(String key) find,
  required Future<void> Function() frame,
  BuildContext? list,
  double alignment = 0.05,
}) async {
  if (find(key) == null && list is Element) {
    ScrollableState? scrollable;
    void visit(Element e) {
      if (scrollable != null) return;
      if (e is StatefulElement && e.state is ScrollableState) {
        scrollable = e.state as ScrollableState;
        return;
      }
      e.visitChildElements(visit);
    }

    visit(list);
    final pos = scrollable?.position;
    if (pos != null) {
      pos.jumpTo(pos.minScrollExtent);
      await frame();
      while (find(key) == null && pos.pixels < pos.maxScrollExtent) {
        pos.jumpTo((pos.pixels + 300).clamp(pos.minScrollExtent, pos.maxScrollExtent));
        await frame();
      }
    }
  }
  final el = find(key);
  if (el == null || !el.mounted) return false;
  await Scrollable.ensureVisible(el, alignment: alignment);
  return true;
}

/// Prints the capture marker for shot [n] and holds the frame until the
/// script captured it (it writes `<id>.ack`), so a slow `import` under load
/// can never drift one state behind the tour.
Future<void> _announce(int n, String name, String? ackDir) async {
  final id = '${n.toString().padLeft(2, '0')}-$name';
  debugPrint('[review] screen=$id');
  if (ackDir != null && ackDir.isNotEmpty) {
    final ack = File('$ackDir/$id.ack');
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (!ack.existsSync() && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  } else {
    await Future<void>.delayed(const Duration(milliseconds: 700));
  }
}

/// Shot counter for the lock phase (before a container exists).
class _LockShots {
  int n = 0;
  final int _start = int.tryParse(Platform.environment['SEALBOX_REVIEW_START'] ?? '') ?? 0;

  Future<void> shot(String name) async {
    await Future<void>.delayed(const Duration(milliseconds: 1400));
    n++;
    await _announce(_start + n, name, Platform.environment['SEALBOX_REVIEW_ACK_DIR']);
  }
}

/// The fake session's [FakeCore] with one review switch: [inlineImage] gives the HTML sample's
/// logo part the Content-ID its `cid:` image names and a real PNG behind it — what the engine
/// serves for an inline image since it keeps Content-IDs. Off until the tour's last step, so
/// every earlier shot (and FakeCore itself, which the goldens use) keeps the placeholder.
class ReviewFakeCore extends FakeCore {
  ReviewFakeCore() : super(latency: Duration.zero);

  bool inlineImage = false;

  static const inlineCid = 'logo@statements.example';

  /// A 180×48 PNG "bank logo" (421 bytes).
  static final Uint8List inlineLogoPng = base64Decode(
    'iVBORw0KGgoAAAANSUhEUgAAALQAAAAwCAYAAAC47FD8AAABbElEQVR42u3dMU7DMBSAYdvqGRhBXAPORefOcC56DURHLgFLI4SaVlUSBz/3+9YyUOfPw46A5nTB/dPrd4LGHPbbfO61LGR6CruImajGWi1ipqeoi5jpKeoiZnqKulgKelLWns6f7y9WnWpTOq8V9FjID89vrgKLqh70NRNZ2Cy25Whhe2EbQtMTek6gpjXNBL3kpBU2/xZ0zS1DjbBtcdqz1HWeFfSaYSzxhoXcf9glShxipMqEbiGsKXexG+I2pvQmYhDD9+LgyOSgxUNXQV87rcfCr/31MPtQCIIOetAgznUyobGHjn73e4TX70/QjcXDHhoEDYIGe+hLPnZfrvrR4+7OhBaz9RC0i2ddBA2CRtAgaCd669KkfGv/edThsO+bPOSfYA2m/E6GSW3LAYIGQYOg4VdOyWes0IfDfptNaPrbclz6qFmIMp3/7KFFTfSYTw6FoiZyzCdBi5rIMad0fMpxjqcfRAl58AP0vpWRG3NAbwAAAABJRU5ErkJggg==',
  );

  Message _withInline(Message m) {
    if (!inlineImage || m.id != FakeCore.htmlSampleId) return m;
    return m.copyWith(
      attachments: [
        for (final a in m.attachments)
          a.contentType.startsWith('image/')
              ? AttachmentMeta(
                  index: a.index,
                  filename: a.filename,
                  contentType: a.contentType,
                  size: inlineLogoPng.length,
                  contentId: inlineCid,
                )
              : a,
      ],
    );
  }

  @override
  Future<MailThread?> getThread(String threadId) async {
    final t = await super.getThread(threadId);
    if (t == null || !inlineImage) return t;
    return MailThread(
      id: t.id,
      subject: t.subject,
      accountId: t.accountId,
      messages: [for (final m in t.messages) _withInline(m)],
    );
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    final m = await super.getMessage(messageId);
    return m == null ? null : _withInline(m);
  }

  @override
  Future<AttachmentBytes> getAttachment(String messageId, int index) async {
    final meta = (await getMessage(messageId))?.attachments.where((a) => a.index == index).firstOrNull;
    if (meta != null && meta.contentId == inlineCid) {
      return AttachmentBytes(meta: meta, data: inlineLogoPng);
    }
    return super.getAttachment(messageId, index);
  }
}
