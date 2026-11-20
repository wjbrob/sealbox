// G17 — app ↔ core wiring, end to end against the local GreenMail server.
//
// Run by scripts/gate_g17.sh:
//   flutter test integration_test/core_wiring_test.dart -d linux \
//     --dart-define=SEALBOX_PROFILE=<empty dir for the app (u01)> \
//     --dart-define=SEALBOX_CLI=<path to the sealbox binary> \
//     --dart-define=SEALBOX_PEER_PROFILE=<dir for the CLI peer (u02)>
//
// The app adds u01 through the onboarding UI (manual GreenMail servers); the
// `sealbox` CLI plays u02: it sends a first-contact plaintext mail and an
// encrypted one, the app syncs, shows both with the right badges, decrypts and
// verifies the encrypted one, composes an encrypted reply, and the CLI confirms
// u02 received it encrypted and could decrypt it. Finally the Sent copy is
// readable in the app. G30: u01 verifies u02 on the Verify screen with the CLI's
// real `OPENPGP4FPR:` payload (a wrong one is refused first), and u02's next
// signed mail shows "Verified" (signer_verified). G15 (no backup server here):
// the engine's phrase passes its own validation, the reminder/phrase bookkeeping
// updates, and a real setup message is exported. Reference threading: a reply with
// In-Reply-To and a changed subject joins its conversation, two unrelated mails with the
// same subject stay apart. Folders by role: the plaintext thread is deleted (moved to Trash)
// from the UI, leaves the Inbox and is in Trash after that folder's first-open sync; the
// encrypted thread is marked unread from the thread menu. With SEALBOX_TEST_SERVER (a local
// sealbox-server mailing through GreenMail) the key is published from Settings → My key and
// the directory's verification mail completes it. Then the IDLE watch stream arms.
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart'
    show AsyncValueExtensions, ProviderContainer;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sealbox_app/main.dart' as app;
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/core/threading.dart';
import 'package:sealbox_app/src/features/identity/identity_widgets.dart'
    show verifyRoute;
import 'package:sealbox_app/src/features/inbox/inbox_list_pane.dart'
    show threadSubjectKey;
import 'package:sealbox_app/src/features/recovery/recovery_copy.dart';
import 'package:sealbox_app/src/router.dart';

const String profileDir = String.fromEnvironment('SEALBOX_PROFILE');
const String cli = String.fromEnvironment('SEALBOX_CLI');
const String peerProfile = String.fromEnvironment('SEALBOX_PEER_PROFILE');
const String imapSpec = String.fromEnvironment(
  'SEALBOX_IMAP',
  defaultValue: '127.0.0.1:3143:plain',
);
const String smtpSpec = String.fromEnvironment(
  'SEALBOX_SMTP',
  defaultValue: '127.0.0.1:3025:plain',
);

/// A local sealbox-server (scripts/gate_g17.sh starts one): the publish steps run only
/// when it is given.
const String testServer = String.fromEnvironment('SEALBOX_TEST_SERVER');

const me = 'u01@sealbox.test';
const mePassword = 'u01pw';
const peer = 'u02@sealbox.test';
const peerPassword = 'u02pw';

Future<String> runCli(List<String> args) async {
  final r = await Process.run(
    cli,
    ['--profile', peerProfile, ...args],
    environment: const {'SEALBOX_LOG': 'warn'},
  );
  if (r.exitCode != 0) {
    throw TestFailure(
      'sealbox ${args.join(' ')} exited ${r.exitCode}\n--- stdout\n${r.stdout}\n--- stderr\n${r.stderr}',
    );
  }
  return r.stdout as String;
}

/// Pumps real frames until [condition] holds (spinners keep `pumpAndSettle`
/// from ever settling while the engine talks to the server).
Future<void> pumpUntil(
  WidgetTester tester,
  bool Function() condition, {
  Duration timeout = const Duration(seconds: 45),
  String what = 'condition',
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    await tester.pump(const Duration(milliseconds: 120));
    if (condition()) return;
  }
  throw TestFailure('timed out after $timeout waiting for $what');
}

Future<void> pumpUntilFound(
  WidgetTester tester,
  Finder f, {
  Duration timeout = const Duration(seconds: 45),
}) => pumpUntil(
  tester,
  () => f.evaluate().isNotEmpty,
  timeout: timeout,
  what: '$f',
);

/// Waits for [condition] while re-triggering a sync whenever the engine is idle: mail that lands
/// a moment after a single sync tap (or a tap swallowed by an in-flight auto-refresh) would
/// otherwise never show up, which made this gate flaky. The condition decides, not the timing.
Future<void> syncUntil(
  WidgetTester tester,
  ProviderContainer container,
  bool Function() condition, {
  Duration timeout = const Duration(seconds: 90),
  Duration every = const Duration(seconds: 8),
  String what = 'condition',
}) async {
  final deadline = DateTime.now().add(timeout);
  var nextSync = DateTime.now();
  while (DateTime.now().isBefore(deadline)) {
    if (condition()) {
      return;
    }
    final idle = !container.read(syncControllerProvider).running;
    if (idle && !DateTime.now().isBefore(nextSync)) {
      final button = find.byKey(const Key('inbox-sync'));
      if (button.evaluate().isNotEmpty) {
        await tester.ensureVisible(button);
        await tester.tap(button, warnIfMissed: false);
      }
      nextSync = DateTime.now().add(every);
    }
    await tester.pump(const Duration(milliseconds: 150));
  }
  final state = await describeMailState(container);
  throw TestFailure(
    'timed out after $timeout waiting for $what\n--- state at the timeout\n$state',
  );
}

/// What the inbox and the engine hold when a sync-driven wait gives up: the sync
/// controller, the selected chip, the conversation rows in the widget tree, the
/// engine's conversations (folders + UIDs) and one direct `syncAll` with its outcome —
/// enough to tell a sync that missed mail from a list that did not refresh.
Future<String> describeMailState(
  ProviderContainer container, {
  bool directSync = true,
}) async {
  final b = StringBuffer();
  final sync = container.read(syncControllerProvider);
  b.writeln(
    'sync controller: running=${sync.running} ranOnce=${sync.ranOnce} '
    'lastAt=${sync.lastAt?.toIso8601String()} '
    'last=${sync.last?.summary.replaceAll('\n', ' / ')}',
  );
  for (final a in sync.last?.accounts ?? const <AccountSyncOutcome>[]) {
    b.writeln(
      '  ${a.account}: new=${a.newMessages} decrypted=${a.decrypted} '
      'failed=${a.failed} error=${a.error}',
    );
  }
  b.writeln('selected chip: ${container.read(folderProvider)}');
  final threads = container.read(threadsProvider);
  b.writeln(
    'threadsProvider: loading=${threads.isLoading} '
    '${threads.hasError ? 'error=${threads.error}' : 'rows=${threads.value?.length}'}',
  );
  const prefix = 'thread-subject-';
  final keys = find
      .byWidgetPredicate(
        (w) =>
            w is KeyedSubtree &&
            w.key is ValueKey<String> &&
            (w.key as ValueKey<String>).value.startsWith(prefix),
      )
      .evaluate()
      .map(
        (e) =>
            (e.widget.key as ValueKey<String>).value.substring(prefix.length),
      )
      .toList();
  b.writeln('rows in the widget tree (${keys.length}): $keys');
  final core = container.read(coreApiProvider);
  try {
    final all = await core.listThreadsIn(MailFolder.all);
    final sorted = [...all]
      ..sort((x, y) => y.latest.date.compareTo(x.latest.date));
    b.writeln('engine conversations (${all.length}, newest first, up to 40):');
    for (final t in sorted.take(40)) {
      b.writeln(
        '  ${t.subject} · ${t.messages.length} msg · '
        '${t.latest.date.toIso8601String()} · '
        'folders ${t.messages.map((m) => m.folder).toSet().join(',')} · '
        'uids ${t.messages.map((m) => m.uid).join(',')} · id ${t.id}',
      );
    }
    if (directSync) {
      final o = await core.syncAll();
      b.writeln('direct core.syncAll(): ${o.summary.replaceAll('\n', ' / ')}');
      final after = await core.listThreadsIn(MailFolder.all);
      b.writeln('engine conversations after it: ${after.length}');
    }
  } catch (e) {
    b.writeln('engine query failed: $e');
  }
  return b.toString();
}

Future<void> tapVisible(WidgetTester tester, Finder f) async {
  await tester.ensureVisible(f);
  await tester.pump(const Duration(milliseconds: 100));
  await tester.tap(f);
  await tester.pump(const Duration(milliseconds: 200));
}

Future<void> pickSecurity(
  WidgetTester tester,
  String keyPrefix,
  String label,
) async {
  final dropdown = find.byKey(Key('$keyPrefix-security'));
  await tapVisible(tester, dropdown);
  await tester.pumpAndSettle();
  await tester.tap(find.text(label).last);
  await tester.pumpAndSettle();
}

/// The list row of a conversation by its subject. Conversation ids follow the engine's
/// reference threading (`MessageSummary.thread_id`), so tests address rows by subject.
Finder tileOf(String subject) => find.byKey(threadSubjectKey(subject));

Finder badgeIn(String subject, EncryptionState state) => find.descendant(
  of: tileOf(subject),
  matching: find.byKey(ValueKey('lock-badge-${state.name}')),
);

/// The conversation (all folders) whose normalised subject is [subject].
Future<MailThread?> threadBySubject(CoreApi core, String subject) async {
  final want = normalizeSubject(subject);
  for (final t in await core.listThreadsIn(MailFolder.all)) {
    if (normalizeSubject(t.subject) == want) return core.getThread(t.id);
  }
  return null;
}

/// Settings is a lazy list: from the top, step down until [f] is on screen (no
/// pumpAndSettle: spinners on the way would keep it from settling).
Future<void> scrollSettingsTo(WidgetTester tester, Finder f) async {
  final list = find
      .descendant(
        of: find.byKey(const Key('settings-list')),
        matching: find.byType(Scrollable),
      )
      .first;
  final pos = tester.state<ScrollableState>(list).position;
  pos.jumpTo(0);
  final deadline = DateTime.now().add(const Duration(seconds: 45));
  while (f.evaluate().isEmpty && DateTime.now().isBefore(deadline)) {
    await tester.pump(const Duration(milliseconds: 150));
    if (f.evaluate().isNotEmpty) break;
    if (pos.pixels < pos.maxScrollExtent) {
      pos.jumpTo((pos.pixels + 250).clamp(0, pos.maxScrollExtent));
    }
  }
  if (f.evaluate().isEmpty) throw TestFailure('not found in Settings: $f');
  await tester.ensureVisible(f);
  await tester.pump(const Duration(milliseconds: 200));
}

/// Taps a folder chip (scrolling the chip row first).
Future<void> openChip(WidgetTester tester, MailFolder f) async {
  final chip = find.byKey(Key('folder-chip-${f.name}'));
  await tester.ensureVisible(chip);
  await tester.pump(const Duration(milliseconds: 200));
  await tester.tap(chip);
  await tester.pump(const Duration(milliseconds: 200));
}

/// Inside the open conversation (the desktop layout keeps the list pane — and
/// its snippets and badges — visible next to it).
Finder inThread(Finder f) =>
    find.descendant(of: find.byKey(const Key('thread-messages')), matching: f);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('onboarding → sync → decrypt + verify → encrypted reply → Sent copy', (
    tester,
  ) async {
    expect(profileDir, isNotEmpty, reason: '--dart-define=SEALBOX_PROFILE');
    expect(cli, isNotEmpty, reason: '--dart-define=SEALBOX_CLI');
    expect(
      peerProfile,
      isNotEmpty,
      reason: '--dart-define=SEALBOX_PEER_PROFILE',
    );
    expect(File(cli).existsSync(), isTrue, reason: 'CLI binary at $cli');
    final nonce = DateTime.now().millisecondsSinceEpoch.toRadixString(36);
    final imap = imapSpec.split(':');
    final smtp = smtpSpec.split(':');

    // --- u02 lives in the CLI ------------------------------------------------
    await runCli([
      'account',
      'add',
      '--email',
      peer,
      '--password',
      peerPassword,
      '--imap',
      imapSpec,
      '--smtp',
      smtpSpec,
    ]);

    // --- the app boots on an empty profile → onboarding ----------------------
    // G27: the profile is opened with a raw 32-byte key exactly like the app
    // does after the lock screen (ProfileKeySource::Raw); a fresh random key
    // per run, since the profile is fresh too.
    final rnd = Random.secure();
    final key = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));
    final core = await app.bootstrapCore(
      profileDir: profileDir,
      profileKey: key,
    );
    final status = await core.profileKeyStatus();
    expect(status.source, 'raw', reason: 'the app-lock key keys the profile');
    final container = await app.runSealbox(core);
    await pumpUntilFound(tester, find.byKey(const Key('onboarding-email')));

    await tester.enterText(find.byKey(const Key('onboarding-email')), me);
    await tapVisible(tester, find.byKey(const Key('onboarding-continue')));
    // sealbox.test is not a known provider: the engine's network discovery
    // runs (ISPDB, autoconfig, SRV, MX, probes) and gives up → manual settings.
    await pumpUntilFound(
      tester,
      find.byKey(const Key('onboarding-manual-step')),
      timeout: const Duration(seconds: 120),
    );
    await tester.enterText(find.byKey(const Key('manual-imap-host')), imap[0]);
    await tester.enterText(find.byKey(const Key('manual-imap-port')), imap[1]);
    await pickSecurity(tester, 'manual-imap', 'None (plain)');
    await tester.enterText(find.byKey(const Key('manual-smtp-host')), smtp[0]);
    await tester.enterText(find.byKey(const Key('manual-smtp-port')), smtp[1]);
    await pickSecurity(tester, 'manual-smtp', 'None (plain)');
    await tester.enterText(find.byKey(const Key('manual-username')), 'u01');
    await tester.enterText(find.byKey(const Key('manual-secret')), mePassword);
    await tapVisible(tester, find.byKey(const Key('manual-connect')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('onboarding-done')),
      timeout: const Duration(seconds: 90),
    );
    expect(find.text('$me is ready'), findsOneWidget);
    final accounts = await core.listAccounts();
    expect(accounts.map((a) => a.email), [me]);
    expect(accounts.single.fingerprint, isNotNull);
    expect(
      accounts.single.fingerprint!.length,
      40,
      reason: 'a real v4 OpenPGP key',
    );

    // --- u02 → u01: first contact (plaintext) and an encrypted mail ----------
    // u02 needs u01's key for the encrypted one: export it from the app's
    // engine and import it in the CLI profile (what a key directory would do).
    final armored = await core.exportPublicKey(me);
    expect(armored, contains('BEGIN PGP PUBLIC KEY BLOCK'));
    final keyFile = File('$peerProfile/u01.asc')..writeAsStringSync(armored);
    await runCli(['key', 'import', '--address', me, '--file', keyFile.path]);
    await runCli([
      'send',
      '--from',
      peer,
      '--to',
      me,
      '--subject',
      'hello $nonce',
      '--body',
      'first contact $nonce',
      '--policy',
      'plaintext',
    ]);
    await runCli([
      'send',
      '--from',
      peer,
      '--to',
      me,
      '--subject',
      'secret $nonce',
      '--body',
      'secret body $nonce',
      '--policy',
      'auto',
    ]);

    // --- inbox: sync from the UI, both mails with the right badges -----------
    await tapVisible(tester, find.byKey(const Key('onboarding-open-inbox')));
    await pumpUntilFound(tester, find.byKey(const Key('inbox-sync')));
    expect(find.byKey(const Key('folder-chip-inbox')), findsOneWidget);
    await pumpUntil(
      tester,
      () => !container.read(syncControllerProvider).running,
      what: 'the automatic first sync to finish',
    );
    await tapVisible(tester, find.byKey(const Key('inbox-sync')));
    final plainSubject = 'hello $nonce';
    final secretSubject = 'secret $nonce';
    await pumpUntilFound(
      tester,
      tileOf(secretSubject),
      timeout: const Duration(seconds: 90),
    );
    await pumpUntilFound(tester, tileOf(plainSubject));
    expect(badgeIn(plainSubject, EncryptionState.plaintext), findsOneWidget);
    expect(badgeIn(secretSubject, EncryptionState.encrypted), findsOneWidget);
    expect(
      find.text('secret $nonce'),
      findsWidgets,
      reason: 'protected Subject restored',
    );
    // Reference threading: the conversation id is the engine's thread key, not the subject.
    final secretConversation = (await threadBySubject(core, secretSubject))!;
    expect(secretConversation.id, isNot(threadIdOf(me, secretSubject)));
    expect(secretConversation.messages.single.engineThreadId, isNotEmpty);

    // --- open the encrypted one: plaintext body + verified signature ---------
    await tapVisible(tester, tileOf(secretSubject));
    await pumpUntilFound(tester, find.byKey(const Key('thread-messages')));
    await pumpUntilFound(
      tester,
      inThread(find.textContaining('secret body $nonce')),
    );
    // D7: the chip names the signer's address (the key id is in its tooltip).
    expect(inThread(find.textContaining('signed by $peer')), findsOneWidget);
    expect(
      inThread(find.byKey(const ValueKey('lock-badge-encrypted'))),
      findsOneWidget,
    );
    expect(
      inThread(find.byKey(const Key('thread-subject'))),
      findsOneWidget,
      reason: 'D6: subject header',
    );

    // --- encrypted reply from the UI -------------------------------------------
    await tapVisible(tester, find.byKey(const Key('thread-reply')));
    await pumpUntilFound(
      tester,
      find.descendant(
        of: find.byKey(const ValueKey('recipient-pill-$peer')),
        matching: find.byKey(const ValueKey('recipient-status-encrypted')),
      ),
    );
    expect(find.byKey(const Key('compose-policy-encrypted')), findsOneWidget);
    expect(find.text('Send encrypted'), findsOneWidget);
    // The engine quotes the original (ComposeOptions.reply()): the editor starts empty.
    expect(
      tester
          .widget<TextField>(find.byKey(const Key('compose-body')))
          .controller!
          .text,
      isEmpty,
    );
    await tester.enterText(
      find.byKey(const Key('compose-body')),
      'reply body $nonce',
    );
    await tapVisible(tester, find.byKey(const Key('compose-send')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('compose-sent-snackbar')),
      timeout: const Duration(seconds: 90),
    );
    expect(find.text('Sent: encrypted to 1'), findsOneWidget);

    // --- u02 receives it encrypted and decrypts it (CLI) ------------------------
    await runCli(['sync']);
    final listing =
        jsonDecode(await runCli(['--json', 'list'])) as List<dynamic>;
    final reply = listing.cast<Map<String, dynamic>>().where(
      (m) => m['subject'] == 'Re: secret $nonce',
    );
    expect(
      reply,
      hasLength(1),
      reason: 'u02 inbox lists the reply once:\n$listing',
    );
    final detail = jsonDecode(
      await runCli(['--json', 'read', '${reply.single['id']}']),
    ) as Map<String, dynamic>;
    expect(detail['was_encrypted'], isTrue);
    expect(detail['decrypted'], isTrue);
    expect(detail['was_signed'], isTrue);
    expect((detail['signature'] as Map)['status'], 'good');
    expect(
      detail['protected_subject'],
      isTrue,
      reason: 'subject travelled inside the encrypted part',
    );
    expect(detail['text'], contains('reply body $nonce'));
    expect(
      detail['text'],
      contains('> secret body $nonce'),
      reason: 'the engine quoted the original',
    );

    // --- the Sent copy is readable in the app ----------------------------------
    await pumpUntilFound(tester, find.byKey(const Key('inbox-list')));
    await pumpUntil(
      tester,
      () => !container.read(syncControllerProvider).running,
      what: 'sync idle',
    );
    await tapVisible(tester, find.byKey(const Key('inbox-sync')));
    // The list defaults to INBOX; the conversation itself spans INBOX + Sent.
    var sentSynced = false;
    final deadline = DateTime.now().add(const Duration(seconds: 90));
    while (!sentSynced && DateTime.now().isBefore(deadline)) {
      await tester.pump(const Duration(milliseconds: 250));
      final t = await threadBySubject(core, secretSubject);
      sentSynced = t != null && t.messages.any((m) => m.isSent);
    }
    expect(
      sentSynced,
      isTrue,
      reason: 'the Sent copy was synced into the conversation',
    );
    final withReply = (await threadBySubject(core, secretSubject))!;
    expect(
      withReply.id,
      secretConversation.id,
      reason: 'the reply joined by In-Reply-To',
    );
    // And the Sent chip lists it as an outgoing conversation.
    await openChip(tester, MailFolder.sent);
    await pumpUntilFound(tester, tileOf(secretSubject));
    // GreenMail keeps u01's Sent folder across gate runs, so scope to this thread's row.
    expect(
      find.descendant(
        of: tileOf(secretSubject),
        matching: find.textContaining('To $peer'),
      ),
      findsOneWidget,
      reason: 'outgoing rows name the recipient',
    );
    await openChip(tester, MailFolder.inbox);
    await pumpUntilFound(tester, tileOf(secretSubject));
    await tapVisible(tester, tileOf(secretSubject));
    await pumpUntilFound(
      tester,
      inThread(find.textContaining('reply body $nonce')),
    );
    expect(inThread(find.textContaining('in Sent')), findsOneWidget);
    expect(
      inThread(find.byKey(const ValueKey('lock-badge-encrypted'))),
      findsNWidgets(2),
      reason: 'the received mail and our Sent copy are both decrypted',
    );
    expect(inThread(find.textContaining('signed by $peer')), findsOneWidget);
    expect(
      inThread(find.textContaining('signed by $me')),
      findsOneWidget,
      reason: 'our own Sent copy is signed by our key too',
    );

    // --- G30: verify u02 from the Verify screen with the CLI's real QR payload -----
    final router = container.read(routerProvider);
    final qr = jsonDecode(
      await runCli(['--json', 'key', 'qr', '--account', peer]),
    ) as Map<String, dynamic>;
    final peerPayload = qr['payload'] as String;
    expect(peerPayload, startsWith('OPENPGP4FPR:'));
    router.go(verifyRoute(peer));
    await pumpUntilFound(tester, find.byKey(const Key('verify-my-qr')));
    final myPayload = await core.fingerprintQrPayload(me);
    expect(myPayload, 'OPENPGP4FPR:${accounts.single.fingerprint}');
    // A wrong fingerprint is refused by the engine and explained.
    await tester.enterText(
      find.byKey(const Key('verify-paste')),
      'OPENPGP4FPR:${'A' * 40}',
    );
    await tester.pump();
    await tapVisible(tester, find.byKey(const Key('verify-paste-check')));
    await pumpUntilFound(tester, find.byKey(const Key('verify-error')));
    expect(
      (await core.contacts()).firstWhere((c) => c.address == peer).verified,
      isFalse,
    );
    // A second enterText into the same field does not replace its text under the live
    // integration binding (observed); set it the way typing would.
    final pasteField = tester.widget<TextField>(
      find.byKey(const Key('verify-paste')),
    );
    pasteField.controller!.text = peerPayload;
    pasteField.onChanged?.call(peerPayload);
    await tester.pump();
    await tapVisible(tester, find.byKey(const Key('verify-paste-check')));
    final closeBy = DateTime.now().add(const Duration(seconds: 20));
    while (find.byKey(const Key('verify-paste')).evaluate().isNotEmpty &&
        DateTime.now().isBefore(closeBy)) {
      await tester.pump(const Duration(milliseconds: 200));
    }
    if (find.byKey(const Key('verify-paste')).evaluate().isNotEmpty) {
      final err = find.descendant(
        of: find.byKey(const Key('verify-error')),
        matching: find.byType(Text),
      );
      final c = (await core.contacts()).firstWhere((c) => c.address == peer);
      String direct;
      try {
        direct =
            'direct verify ok: ${(await core.verifyContact(peer, qr['fingerprint'] as String)).verified}';
      } catch (e) {
        direct = 'direct verify error: $e';
      }
      final field = tester
          .widget<TextField>(find.byKey(const Key('verify-paste')))
          .controller!
          .text;
      fail(
        'verify did not succeed ($direct; field "$field"; was verified before: ${c.verified}): '
        '${err.evaluate().map((e) => (e.widget as Text).data).join()} · contact key ${c.fingerprint} '
        '· CLI key ${qr['fingerprint']} · source ${c.source}',
      );
    }
    final verified = (await core.contacts()).firstWhere(
      (c) => c.address == peer,
    );
    expect(verified.verified, isTrue);
    expect(verified.fingerprint, qr['fingerprint']);
    // The next signed mail from u02 carries signer_verified → "✓ Verified" chip.
    await runCli([
      'send',
      '--from',
      peer,
      '--to',
      me,
      '--subject',
      'verified $nonce',
      '--body',
      'signed by the verified key $nonce',
      '--policy',
      'auto',
    ]);
    router.go('/inbox');
    await pumpUntilFound(tester, find.byKey(const Key('inbox-sync')));
    await pumpUntil(
      tester,
      () => !container.read(syncControllerProvider).running,
      what: 'sync idle',
    );
    final verifiedSubject = 'verified $nonce';
    await syncUntil(
      tester,
      container,
      () => tileOf(verifiedSubject).evaluate().isNotEmpty,
      timeout: const Duration(seconds: 90),
      what: 'the verified-signer mail',
    );
    await tapVisible(tester, tileOf(verifiedSubject));
    await pumpUntilFound(
      tester,
      inThread(find.textContaining('signed by the verified key')),
    );
    expect(
      inThread(find.text('Verified')),
      findsOneWidget,
      reason: 'SignatureSummary.signer_verified',
    );

    // --- reference threading: In-Reply-To with a changed subject joins; same subject
    //     without references stays apart -------------------------------------------------
    final parentSend = jsonDecode(
      await runCli([
        '--json',
        'send',
        '--from',
        peer,
        '--to',
        me,
        '--subject',
        'thread $nonce',
        '--body',
        'first in thread $nonce',
        '--policy',
        'auto',
      ]),
    ) as Map<String, dynamic>;
    final firstId = parentSend['message_id'] as String;
    expect(firstId, isNotEmpty);
    await runCli([
      'send',
      '--from',
      peer,
      '--to',
      me,
      '--subject',
      'moved on $nonce',
      '--body',
      'second in thread $nonce',
      '--policy',
      'auto',
      '--in-reply-to',
      firstId,
    ]);
    for (final n in [1, 2]) {
      await runCli([
        'send',
        '--from',
        peer,
        '--to',
        me,
        '--subject',
        'same $nonce',
        '--body',
        'unrelated $n $nonce',
        '--policy',
        'auto',
      ]);
    }
    router.go('/inbox');
    await pumpUntilFound(tester, find.byKey(const Key('inbox-sync')));
    await pumpUntil(
      tester,
      () => !container.read(syncControllerProvider).running,
      what: 'sync idle',
    );
    await syncUntil(
      tester,
      container,
      () =>
          tileOf('same $nonce').evaluate().length == 2 &&
          tileOf('thread $nonce').evaluate().isNotEmpty,
      timeout: const Duration(seconds: 90),
      what: 'the threading mails',
    );
    expect(
      tileOf('moved on $nonce'),
      findsNothing,
      reason: 'the reply is in its parent\'s row',
    );
    final joined = (await threadBySubject(core, 'thread $nonce'))!;
    expect(joined.messages.map((m) => m.subject).toSet(), {
      'thread $nonce',
      'moved on $nonce',
    }, reason: 'In-Reply-To joined the changed subject');
    final same = [
      for (final t in await core.listThreads())
        if (normalizeSubject(t.subject) == 'same $nonce') t,
    ];
    expect(
      same,
      hasLength(2),
      reason: 'same subject, no references: two conversations',
    );
    expect(same.every((t) => t.messages.length == 1), isTrue);
    await tapVisible(tester, tileOf('thread $nonce'));
    await pumpUntilFound(
      tester,
      inThread(find.textContaining('second in thread $nonce')),
    );
    expect(
      inThread(find.textContaining('first in thread $nonce')),
      findsOneWidget,
    );

    // --- folders by role: delete (= move to Trash) the plaintext thread from the UI ----
    router.go('/inbox');
    await pumpUntilFound(tester, tileOf(plainSubject));
    await tapVisible(tester, tileOf(plainSubject));
    await pumpUntilFound(
      tester,
      inThread(find.textContaining('first contact $nonce')),
    );
    await tapVisible(tester, find.byKey(const Key('thread-delete')));
    await pumpUntilFound(tester, find.byKey(const Key('thread-delete-dialog')));
    await tapVisible(tester, find.byKey(const Key('thread-delete-confirm')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('thread-action-snackbar')),
    );
    expect(
      find.textContaining('Moved to Trash'),
      findsOneWidget,
      reason: 'names the destination',
    );
    await pumpUntil(
      tester,
      () => tileOf(plainSubject).evaluate().isEmpty,
      what: 'the row leaving the inbox',
    );
    await openChip(tester, MailFolder.trash);
    // First open of Trash in this session: the role's folder is fetched, then listed.
    await pumpUntilFound(
      tester,
      tileOf(plainSubject),
      timeout: const Duration(seconds: 60),
    );
    expect(badgeIn(plainSubject, EncryptionState.plaintext), findsOneWidget);
    final trashed = (await threadBySubject(core, plainSubject))!;
    expect(
      MailFolder.trash.matches(trashed.messages.single.folder),
      isTrue,
      reason: 'now in ${trashed.messages.single.folder}',
    );

    // --- mark the encrypted thread unread from the thread menu → unread row ----------
    await openChip(tester, MailFolder.inbox);
    await pumpUntilFound(tester, tileOf(secretSubject));
    expect(
      find.descendant(
        of: tileOf(secretSubject),
        matching: find.byKey(const ValueKey('thread-unread')),
      ),
      findsNothing,
    );
    await tapVisible(tester, tileOf(secretSubject));
    await pumpUntilFound(tester, find.byKey(const Key('thread-more')));
    await tapVisible(tester, find.byKey(const Key('thread-more')));
    await pumpUntilFound(tester, find.byKey(const Key('thread-mark-unread')));
    await tapVisible(tester, find.byKey(const Key('thread-mark-unread')));
    await pumpUntilFound(
      tester,
      find.descendant(
        of: tileOf(secretSubject),
        matching: find.byKey(const ValueKey('thread-unread')),
      ),
    );
    final unread = (await threadBySubject(core, secretSubject))!;
    expect(
      unread.messages.where((m) => !m.isSent).single.unread,
      isTrue,
      reason: 'Seen removed on the server',
    );

    // --- publish to the key directory (local sealbox-server, mail through GreenMail) ---
    if (testServer.isNotEmpty) {
      router.go('/settings?section=server');
      await pumpUntilFound(tester, find.byKey(const Key('server-url-field')));
      await tester.enterText(
        find.byKey(const Key('server-url-field')),
        testServer,
      );
      await tapVisible(tester, find.byKey(const Key('server-url-save')));
      await pumpUntilFound(
        tester,
        find.byKey(const Key('server-url-snackbar')),
      );
      expect(await core.serverUrlSource(), ServerUrlSource.settings);
      await scrollSettingsTo(
        tester,
        find.byKey(const ValueKey('directory-state-unpublished')),
      );
      // Built but possibly scrolled just out of view after a tap: look past the viewport.
      Finder any(Key k) => find.byKey(k, skipOffstage: false);
      String? panelError() {
        final e = any(const Key('directory-error'));
        return e.evaluate().isEmpty ? null : tester.widget<Text>(e).data;
      }

      await tapVisible(tester, find.byKey(const Key('directory-publish')));
      await pumpUntil(
        tester,
        () =>
            any(const ValueKey('directory-state-awaitingVerification'))
                .evaluate()
                .isNotEmpty ||
            panelError() != null,
        what: 'the publish result',
      );
      expect(panelError(), isNull, reason: 'publish refused');
      // The engine's directory status says "unpublished" until the address is verified;
      // the panel remembers the mailed challenge and offers Complete verification. The mail
      // travels server → GreenMail SMTP → u01's INBOX; completing syncs and follows its link
      // ("awaiting" until it is there).
      final until = DateTime.now().add(const Duration(seconds: 90));
      while (any(const ValueKey('directory-state-published'))
              .evaluate()
              .isEmpty &&
          DateTime.now().isBefore(until)) {
        final complete = any(const Key('directory-complete'));
        if (complete.evaluate().isNotEmpty) await tapVisible(tester, complete);
        await pumpUntil(
          tester,
          () => tester
              .widgetList<FilledButton>(complete)
              .every((b) => b.onPressed != null),
          what: 'the verification attempt',
        );
        expect(panelError(), isNull, reason: 'complete verification refused');
        await tester.pump(const Duration(seconds: 1));
      }
      expect(any(const ValueKey('directory-state-published')), findsOneWidget);
      expect((await core.directoryStatus(me)).state, DirectoryState.published);
    } else {
      debugPrint(
        '[g17] SEALBOX_TEST_SERVER not set: publish to the directory left to the widget tests',
      );
    }

    // --- G15 (no backup server in this gate): phrase, status, setup message --------
    final status15 = await core.recoveryStatus(me);
    expect(status15.backedUp, isFalse);
    expect(
      status15.reminder,
      isNotNull,
      reason: 'no backup yet → engine reminder',
    );
    router.go('/settings/recovery-phrase');
    await pumpUntilFound(tester, find.byKey(const Key('recovery-create')));
    await tapVisible(tester, find.byKey(const Key('recovery-create')));
    await pumpUntilFound(tester, find.byKey(const Key('recovery-reveal')));
    final words = await core.recoveryPhraseValidate(
      (await core.recoveryPhraseCreate(me)).join(' '),
    );
    expect(words.words, hasLength(12));
    expect(
      words.checksumOk,
      isTrue,
      reason: 'a phrase from the engine passes its own BIP39 check',
    );
    expect((await core.recoveryStatus(me)).phraseCreatedAt, isNotNull);
    router.go('/settings/transfer');
    await pumpUntilFound(tester, find.byKey(const Key('transfer-send')));
    await tapVisible(tester, find.byKey(const Key('transfer-send')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('transfer-code-display')),
      timeout: const Duration(seconds: 60),
    );
    expect(find.text(RecoveryCopy.transferInstruction), findsOneWidget);
    router.go('/settings');
    // Settings keeps its scroll position (it was left at the key directory): from the top.
    await pumpUntilFound(tester, find.byKey(const Key('settings-list')));
    await scrollSettingsTo(
      tester,
      find.byKey(const Key('settings-add-account')),
    );
    // The setup message landed in u01's INBOX: fetch it, so the IDLE check below starts
    // from a synced mailbox (its first event must be `idle`, not `newMail`).
    await container.read(syncControllerProvider.notifier).syncNow();

    // --- the IDLE watch stream arms and stops on cancel --------------------------
    final first = await core
        .watch(me)
        .first
        .timeout(const Duration(seconds: 45));
    expect(first.kind, MailEventKind.idle);
  });
}
