// Search and saved drafts, end to end against the local GreenMail server (GreenMail users
// u66 = the app, u67 and u68 = `sealbox` CLI peers; docs/GATES.md allocation "app").
//
// Run like scripts/gate_g17.sh runs core_wiring_test.dart (private Xvfb, fresh profiles):
//   flutter test integration_test/search_drafts_test.dart -d linux \
//     --dart-define=SEALBOX_PROFILE=<empty dir for the app (u66)> \
//     --dart-define=SEALBOX_CLI=<path to the sealbox binary> \
//     --dart-define=SEALBOX_PEER_PROFILE=<empty dir for the CLI peers (u67, u68)>
//
// The app adds u66 through onboarding (manual GreenMail servers). The CLI peers send three
// mails with distinct body words — two from u67 (one of them encrypted to u66's key, so the
// word is only searchable after decryption) and one from u68 — and the app syncs them. The
// search screen finds exactly the right mail by a body word (the encrypted one), exactly the
// u68 mail by its sender's name, says "No results" for a word nobody wrote, and opens a
// result's conversation. Then a message started in compose, with a file attached, is left
// (saved as a draft; the file kept as a sealed copy in the engine's store, a `blob:<id>`
// handle — its bytes are in no profile file in the clear; the save also pushed it to u66's
// Drafts folder, whose own sync then lists no message for it, and a drafts sync imports
// nothing new), the Drafts chip lists it,
// reopening it restores subject, text and the file, it is sent encrypted to u67, the CLI
// decrypts it and gets the file byte for byte, and the draft and the stored copy are gone. The peers' profiles are passphrase-keyed (no
// OS keyring entries); the app's profile uses a fresh raw key, like the app lock.
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart' show ProviderContainer;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sealbox_app/main.dart' as app;
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_controller.dart';
import 'package:sealbox_app/src/features/inbox/inbox_list_pane.dart' show threadSubjectKey;
import 'package:sealbox_app/src/features/search/search_controller.dart';

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

const me = 'u66@sealbox.test';
const mePassword = 'u66pw';
const peer = 'u67@sealbox.test';
const other = 'u68@sealbox.test';

/// Passphrase for the peers' passphrase-keyed CLI profiles (fresh per run).
final String peerPassphrase = base64Url.encode(
  List.generate(18, (_) => Random.secure().nextInt(256)),
);

String peerDir(String address) =>
    '$peerProfile${Platform.pathSeparator}${address.split('@').first}';

/// Runs the CLI on [address]'s peer profile.
Future<String> runCli(String address, List<String> args) async {
  final r = await Process.run(
    cli,
    ['--profile', peerDir(address), ...args],
    environment: {
      'SEALBOX_LOG': 'warn',
      'SEALBOX_PROFILE_KEY': 'passphrase',
      'SEALBOX_PROFILE_PASSPHRASE': peerPassphrase,
    },
  );
  if (r.exitCode != 0) {
    throw TestFailure(
      'sealbox ${args.join(' ')} ($address) exited ${r.exitCode}\n--- stdout\n${r.stdout}\n'
      '--- stderr\n${r.stderr}',
    );
  }
  return r.stdout as String;
}

/// Pumps real frames until [condition] holds (spinners keep `pumpAndSettle` from settling
/// while the engine talks to the server).
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
}) => pumpUntil(tester, () => f.evaluate().isNotEmpty, timeout: timeout, what: '$f');

/// Waits for [condition] while re-triggering a sync whenever the engine is idle (mail that
/// lands a moment after one sync would otherwise never show up).
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
    if (condition()) return;
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
  final sync = container.read(syncControllerProvider);
  throw TestFailure(
    'timed out after $timeout waiting for $what (last sync: ${sync.last?.summary})',
  );
}

/// Whether [needle] occurs in [hay].
bool holds(List<int> hay, List<int> needle) {
  for (var i = 0; i + needle.length <= hay.length; i++) {
    var j = 0;
    while (j < needle.length && hay[i + j] == needle[j]) {
      j++;
    }
    if (j == needle.length) return true;
  }
  return false;
}

Future<void> tapVisible(WidgetTester tester, Finder f) async {
  await tester.ensureVisible(f);
  await tester.pump(const Duration(milliseconds: 100));
  await tester.tap(f);
  await tester.pump(const Duration(milliseconds: 200));
}

Future<void> pickSecurity(WidgetTester tester, String keyPrefix, String label) async {
  await tapVisible(tester, find.byKey(Key('$keyPrefix-security')));
  await tester.pumpAndSettle();
  await tester.tap(find.text(label).last);
  await tester.pumpAndSettle();
}

Finder tileOf(String subject) => find.byKey(threadSubjectKey(subject));

Finder get searchField => find.byKey(const Key('search-field'));

/// The result rows on screen.
List<String> resultKeys() => find
    .byWidgetPredicate(
      (w) =>
          w.key is ValueKey<String> &&
          (w.key as ValueKey<String>).value.startsWith('search-result-'),
    )
    .evaluate()
    .map((e) => (e.widget.key as ValueKey<String>).value)
    .toList();

/// Types [text] into the search field and waits for the answer to it.
Future<void> searchFor(WidgetTester tester, ProviderContainer container, String text) async {
  // A second enterText into the same field does not always replace its text under the live
  // binding (core_wiring_test.dart); set it the way typing does.
  final field = tester.widget<TextField>(searchField);
  field.controller!.text = text;
  field.onChanged?.call(text);
  await tester.pump(MailSearchController.debounce);
  await pumpUntil(tester, () {
    final s = container.read(mailSearchProvider);
    return !s.loading && s.resultsFor == text && (s.results != null || s.error != null);
  }, what: 'the search for "$text"');
  await tester.pump(const Duration(milliseconds: 200));
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('search finds the right mail (body word, sender); a draft is saved, reopened, sent', (
    tester,
  ) async {
    expect(profileDir, isNotEmpty, reason: '--dart-define=SEALBOX_PROFILE');
    expect(cli, isNotEmpty, reason: '--dart-define=SEALBOX_CLI');
    expect(peerProfile, isNotEmpty, reason: '--dart-define=SEALBOX_PEER_PROFILE');
    expect(File(cli).existsSync(), isTrue, reason: 'CLI binary at $cli');
    final nonce = DateTime.now().millisecondsSinceEpoch.toRadixString(36);
    final imap = imapSpec.split(':');
    final smtp = smtpSpec.split(':');
    // The run's nonce in every name and word: mail left in GreenMail by earlier runs never
    // matches.
    final peerName = 'Uma Peer $nonce';
    final otherName = 'Otto Sender $nonce';

    // --- the peers live in the CLI -----------------------------------------------------------
    for (final (address, name) in [(peer, peerName), (other, otherName)]) {
      final local = address.split('@').first;
      await runCli(address, [
        'account',
        'add',
        '--email',
        address,
        '--name',
        name,
        '--password',
        '${local}pw',
        '--imap',
        imapSpec,
        '--smtp',
        smtpSpec,
      ]);
    }

    // --- the app boots on an empty profile → onboarding (manual GreenMail servers) ---------
    final rnd = Random.secure();
    final key = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));
    final core = await app.bootstrapCore(profileDir: profileDir, profileKey: key);
    final container = await app.runSealbox(core);
    await pumpUntilFound(tester, find.byKey(const Key('onboarding-email')));
    await tester.enterText(find.byKey(const Key('onboarding-email')), me);
    await tapVisible(tester, find.byKey(const Key('onboarding-continue')));
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
    await tester.enterText(find.byKey(const Key('manual-username')), 'u66');
    await tester.enterText(find.byKey(const Key('manual-secret')), mePassword);
    await tapVisible(tester, find.byKey(const Key('manual-connect')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('onboarding-done')),
      timeout: const Duration(seconds: 90),
    );
    expect((await core.listAccounts()).map((a) => a.email), [me]);

    // --- three mails with distinct body words; the first is encrypted to u66 --------------
    // u67 needs u66's key for the encrypted one: exported from the app's engine.
    final keyFile = File('${peerDir(peer)}/u66.asc')
      ..writeAsStringSync(await core.exportPublicKey(me));
    await runCli(peer, ['key', 'import', '--address', me, '--file', keyFile.path]);
    final secretWord = 'kumquat$nonce';
    final plainWord = 'rutabaga$nonce';
    final otherWord = 'persimmon$nonce';
    final secretSubject = 'orchard $nonce';
    final plainSubject = 'garden $nonce';
    final otherSubject = 'market $nonce';
    Future<void> send(String from, String subject, String body, String policy) => runCli(from, [
      'send',
      '--from',
      from,
      '--to',
      me,
      '--subject',
      subject,
      '--body',
      body,
      '--policy',
      policy,
    ]);
    await send(peer, secretSubject, 'The $secretWord tree fruits in winter.', 'auto');
    await send(peer, plainSubject, 'Plant the $plainWord before the frost.', 'plaintext');
    await send(other, otherSubject, 'Fresh $otherWord at the Saturday stall.', 'plaintext');

    // --- the app syncs all three ------------------------------------------------------------
    await tapVisible(tester, find.byKey(const Key('onboarding-open-inbox')));
    await pumpUntilFound(tester, find.byKey(const Key('inbox-sync')));
    await syncUntil(
      tester,
      container,
      () =>
          [secretSubject, plainSubject, otherSubject].every((s) => tileOf(s).evaluate().isNotEmpty),
      timeout: const Duration(seconds: 120),
      what: 'the three mails',
    );

    // --- search: a body word of the encrypted mail finds exactly that mail -----------------
    await tapVisible(tester, find.byKey(const Key('inbox-search')));
    await pumpUntilFound(tester, searchField);
    await searchFor(tester, container, secretWord);
    var results = container.read(mailSearchProvider).results!;
    expect(results.map((r) => r.message.subject), [secretSubject]);
    final secret = results.single;
    expect(secret.message.state, EncryptionState.encrypted);
    expect(secret.matchedTerms.map((t) => t.toLowerCase()), contains(secretWord));
    expect(resultKeys(), ['search-result-${secret.message.id}']);
    expect(find.text('1 result'), findsOneWidget);

    // By the sender's name: exactly the u68 mail.
    await searchFor(tester, container, 'Otto $nonce');
    results = container.read(mailSearchProvider).results!;
    expect(results.map((r) => r.message.subject), [otherSubject]);
    expect(results.single.message.from.email, other);
    expect(find.text(otherName), findsOneWidget);

    // A word nobody wrote: says so.
    await searchFor(tester, container, 'zebracorn$nonce');
    expect(find.byKey(const Key('search-empty')), findsOneWidget);

    // Back to the body word; the result opens its conversation (beside the results).
    await searchFor(tester, container, secretWord);
    await tapVisible(tester, find.byKey(ValueKey('search-result-${secret.message.id}')));
    final thread = find.byKey(const Key('thread-messages'));
    await pumpUntilFound(
      tester,
      find.descendant(of: thread, matching: find.textContaining(secretWord)),
    );
    expect(
      find.byKey(const Key('search-results')),
      findsOneWidget,
      reason: 'results stay beside it',
    );
    await tapVisible(tester, find.byKey(const Key('search-close')));
    await pumpUntilFound(tester, find.byKey(const Key('inbox-list')));

    // --- drafts: start a message, leave it, find it under Drafts ----------------------------
    final draftSubject = 'draft $nonce';
    final draftBody = 'Half written on purpose, $nonce.';
    await tapVisible(
      tester,
      find.descendant(of: find.byKey(const Key('home-rail')), matching: find.text('Compose')),
    );
    await pumpUntilFound(tester, find.byKey(const Key('compose-subject')));
    await tester.enterText(find.byKey(const Key('compose-subject')), draftSubject);
    await tester.enterText(find.byKey(const Key('compose-body')), draftBody);
    // A file as the picker hands it over (the native picker cannot be driven from a test).
    final fileName = 'notes-$nonce.txt';
    final fileBytes = utf8.encode('attached to the draft $nonce\n');
    container.read(composeControllerProvider.notifier).addAttachments([
      DraftAttachment(
        name: fileName,
        contentType: 'text/plain',
        data: Uint8List.fromList(fileBytes),
      ),
    ]);
    await tester.pump(const Duration(milliseconds: 200));
    // Leave before the autosave: leaving saves.
    await tapVisible(
      tester,
      find.descendant(of: find.byKey(const Key('home-rail')), matching: find.text('Inbox')),
    );
    await pumpUntilFound(tester, find.byKey(const Key('folder-chip-drafts')));
    var saved = await core.listDrafts();
    for (var i = 0; i < 50 && saved.isEmpty; i++) {
      await tester.pump(const Duration(milliseconds: 200));
      saved = await core.listDrafts();
    }
    expect(saved.map((d) => d.subject), [draftSubject], reason: 'leaving compose saved it');
    expect(saved.single.body, draftBody);
    // The file: a sealed copy in the engine's store behind a `blob:<id>` handle (threat-model
    // R16), never a plain file in the profile.
    final stored = saved.single.attachments.single;
    expect(stored.blobId, isNotNull, reason: 'a stored copy, not a file path: ${stored.path}');
    expect(await core.readDraftAttachment(stored.path), fileBytes);
    expect(stored.name, fileName);
    expect(Directory('$profileDir/draft-attachments').existsSync(), isFalse);
    final marker = utf8.encode('attached to the draft $nonce');
    for (final f in Directory(profileDir).listSync(recursive: true).whereType<File>()) {
      expect(holds(f.readAsBytesSync(), marker), isFalse, reason: '${f.path}: file in the clear');
    }
    // On the server too: FrbCore pushes every save in the background (push_draft), so the
    // draft's copy sits in u66's Drafts folder, encrypted to u66's own key.
    DraftServerState? server;
    for (var i = 0; i < 150 && server?.onServer != true; i++) {
      await tester.pump(const Duration(milliseconds: 200));
      server = await core.draftServerInfo(saved.single.id);
    }
    expect(server?.onServer, isTrue, reason: 'the save pushed the draft to the server');
    // The Drafts folder's own sync stores that copy, but no message shows for it.
    final draftsSync = await core.syncFolder(FolderRole.drafts, accountId: me);
    expect(draftsSync.errors, isEmpty, reason: 'Drafts folder sync');
    expect(
      await core.listThreadsInRole(FolderRole.drafts, accountId: me),
      isEmpty,
      reason: 'a draft\'s server copy is no message',
    );
    // A drafts sync brings in nothing new: the one draft there is this device's.
    final draftSync = await core.syncDrafts();
    expect(draftSync.failures, isEmpty);
    expect(draftSync.imported, 0);
    expect((await core.listDrafts()).length, 1);
    await tapVisible(tester, find.byKey(const Key('folder-chip-drafts')));
    final row = find.byKey(ValueKey('draft-tile-${saved.single.id}'));
    await pumpUntilFound(tester, row);
    expect(find.descendant(of: row, matching: find.text(draftSubject)), findsOneWidget);
    expect(find.descendant(of: row, matching: find.text('No recipients yet')), findsOneWidget);

    // --- reopen: subject and text are back; add u67 and send encrypted -------------------
    await tapVisible(tester, row);
    await pumpUntil(
      tester,
      () =>
          find.byKey(const Key('compose-subject')).evaluate().isNotEmpty &&
          tester.widget<TextField>(find.byKey(const Key('compose-subject'))).controller!.text ==
              draftSubject,
      what: 'the draft reopened in compose',
    );
    expect(
      tester.widget<TextField>(find.byKey(const Key('compose-body'))).controller!.text,
      draftBody,
    );
    expect(container.read(composeControllerProvider).attachments.map((a) => a.name), [
      fileName,
    ], reason: 'the file is back');
    await tester.enterText(find.byKey(const Key('compose-to')), peer);
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await pumpUntilFound(
      tester,
      find.descendant(
        of: find.byKey(const ValueKey('recipient-pill-$peer')),
        matching: find.byKey(const ValueKey('recipient-status-encrypted')),
      ),
    );
    await tapVisible(tester, find.byKey(const Key('compose-send')));
    await pumpUntilFound(
      tester,
      find.byKey(const Key('compose-sent-snackbar')),
      timeout: const Duration(seconds: 90),
    );
    expect(find.text('Sent: encrypted to 1'), findsOneWidget);
    expect(await core.listDrafts(), isEmpty, reason: 'the sent draft is gone');
    await expectLater(
      core.readDraftAttachment(stored.path),
      throwsA(isA<Object>()),
      reason: 'and the stored copy of its file',
    );

    // --- u67 receives it encrypted and decrypts it ----------------------------------------
    Map<String, dynamic>? received;
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (received == null && DateTime.now().isBefore(deadline)) {
      await runCli(peer, ['sync']);
      final listing = (jsonDecode(await runCli(peer, ['--json', 'list'])) as List<dynamic>)
          .cast<Map<String, dynamic>>();
      received = listing.where((m) => m['subject'] == draftSubject).firstOrNull;
      if (received == null) await tester.pump(const Duration(seconds: 1));
    }
    expect(received, isNotNull, reason: 'u67 got the mail sent from the draft');
    final detail = jsonDecode(
      await runCli(peer, ['--json', 'read', '${received!['id']}']),
    ) as Map<String, dynamic>;
    expect(detail['was_encrypted'], isTrue);
    expect(detail['decrypted'], isTrue);
    expect(detail['text'], contains(draftBody));
    final files = (detail['attachments'] as List<dynamic>).cast<Map<String, dynamic>>();
    expect(files.map((a) => a['filename']), [fileName]);
    final out = File('${peerDir(peer)}/$fileName');
    await runCli(peer, ['attachment', 'save', '${received['id']}', '0', out.path]);
    expect(out.readAsBytesSync(), fileBytes, reason: 'the file arrived byte for byte');

    // --- and the Drafts chip has nothing left ----------------------------------------------
    await pumpUntilFound(tester, find.byKey(const Key('folder-chip-drafts')));
    await tapVisible(tester, find.byKey(const Key('folder-chip-drafts')));
    await pumpUntilFound(tester, find.byKey(const Key('drafts-empty')));
  });
}
