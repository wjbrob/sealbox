import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/core_api.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'support/golden_core.dart';

// The core API of the UI wave (folders by role, compose preview, spam, filter
// rules, key directory, runtime server URL): the model mappings, the CoreApiOps
// defaults for doubles without the operations, and the FakeCore behaviour the
// screens and goldens are built on. Pure Dart (no engine); FrbCore's side of
// the same API is exercised through the bridge's own tests (app/rust).

FakeCore fake() => FakeCore(latency: Duration.zero);

const alice = 'acct-1'; // Gmail account of the sample mailbox
const fastmail = 'acct-2';

/// Implements nothing but the base seam: every new op falls back to the
/// extension defaults.
class _BareCore implements CoreApi {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

DraftMessage draft({
  String account = alice,
  String body = 'See you there.',
  String? inReplyTo,
  ComposeOptions compose = const ComposeOptions(),
}) => DraftMessage(
  accountId: account,
  to: const ['bob@sealbox.test'],
  subject: 'Lunch',
  body: body,
  inReplyTo: inReplyTo,
  compose: compose,
);

void main() {
  group('models', () {
    test('every inbox chip but "All mail" has a role, and the role maps back to it', () {
      for (final f in MailFolder.values) {
        final role = f.role;
        if (f == MailFolder.all) {
          expect(role, isNull);
        } else {
          expect(role, isNotNull, reason: '$f');
          expect(role!.mailFolder, f);
        }
      }
      expect(FolderRole.junk.mailFolder, MailFolder.spam);
      expect(FolderRole.all.mailFolder, MailFolder.archive);
      expect(FolderRole.drafts.mailFolder, isNull);
      expect(FolderRole.flagged.mailFolder, isNull);
      expect(FolderRole.junk.label, 'Spam');
    });

    test('directory states parse the engine spelling; publish result state', () {
      expect(DirectoryState.parse('published'), DirectoryState.published);
      expect(DirectoryState.parse('other_key'), DirectoryState.otherKey);
      expect(DirectoryState.parse('unpublished'), DirectoryState.unpublished);
      expect(DirectoryState.parse('awaiting_verification'), DirectoryState.awaitingVerification);
      expect(DirectoryState.parse('pending'), DirectoryState.awaitingVerification);
      expect(DirectoryState.parse('verification_failed'), DirectoryState.verificationFailed);
      expect(DirectoryState.parse('something new'), DirectoryState.unknown);
      const issued = PublishResult(accountId: 'a', fingerprint: 'F', serverUrl: 's', tokenIssued: true);
      expect(issued.state, DirectoryState.awaitingVerification);
      const done = PublishResult(accountId: 'a', fingerprint: 'F', serverUrl: 's');
      expect(done.state, DirectoryState.published);
    });

    test('filter rule summary uses the engine spelling', () {
      const r = FilterRule(
        condition: FilterCondition(field: FilterField.subject, op: FilterOp.contains, value: '[newsletter]'),
        action: FilterAction.moveTo('Newsletters'),
      );
      expect(r.summary, 'subject contains "[newsletter]" → move:Newsletters');
      const h = FilterRule(
        condition: FilterCondition(
          field: FilterField.header,
          headerName: 'X-Mailer',
          op: FilterOp.regex,
          value: 'bulk',
          caseInsensitive: false,
        ),
        action: FilterAction.addFlag(r'$Bulk'),
        stop: true,
      );
      expect(h.summary, r'header:X-Mailer regex "bulk" (case-sensitive) → flag:$Bulk [stop]');
      expect(const FilterAction.markRead().code, 'read');
      expect(const FilterAction.star().code, 'star');
    });

    test('Message.copyWith keeps the threading fields and can relocate', () {
      final m = Message(
        id: '1',
        threadId: 't',
        accountId: 'a',
        from: const Contact(email: 'x@y.z'),
        to: const [],
        subject: 's',
        body: 'b',
        date: DateTime.utc(2026),
        state: EncryptionState.plaintext,
        inReplyTo: const ['p@y.z'],
        references: const ['r@y.z', 'p@y.z'],
        engineThreadId: 'r@y.z',
      );
      final moved = m.copyWith(folder: 'Trash', unread: true);
      expect(moved.folder, 'Trash');
      expect(moved.inReplyTo, ['p@y.z']);
      expect(moved.references, ['r@y.z', 'p@y.z']);
      expect(moved.engineThreadId, 'r@y.z');
      expect(m.copyWith(body: 'x').folder, 'INBOX');
    });
  });

  group('CoreApiOps defaults (a double without the new ops)', () {
    test('reads are inert, actions say "not available"', () async {
      final CoreApi core = _BareCore();
      expect(await core.folderRoles('a'), isEmpty);
      expect((await core.syncFolder(FolderRole.junk)).accounts, isEmpty);
      expect(await core.spamSettings('a'), isA<SpamSettings>());
      expect((await core.spamStatus()).accounts, isEmpty);
      expect(await core.filterRules('a'), isEmpty);
      expect(await core.signaturePreview('a', ComposeKind.newMessage), isNull);
      final p = await core.composePreview(draft(inReplyTo: '7'));
      expect((p.kind, p.text, p.signatureApplied), (ComposeKind.reply, 'See you there.', false));
      expect((await core.directoryStatus('a')).state, DirectoryState.unknown);
      expect(await core.serverUrlSource(), ServerUrlSource.none);
      await expectLater(core.moveMessage('1', FolderRole.trash), throwsUnsupportedError);
      await expectLater(core.spamLearn('1', isSpam: true), throwsUnsupportedError);
      await expectLater(core.publishKey('a'), throwsUnsupportedError);
      await expectLater(core.setServerUrl('https://x.example'), throwsUnsupportedError);
    });
  });

  group('FakeCore: folders by role', () {
    test('roles: Gmail names on the gmail.com account, generic ones elsewhere', () async {
      final core = fake();
      final gmail = {for (final r in await core.folderRoles(alice)) r.role: r};
      expect(gmail.length, FolderRole.values.length);
      expect(gmail[FolderRole.junk]!.folder, '[Gmail]/Spam');
      expect(gmail[FolderRole.trash]!.folder, '[Gmail]/Trash');
      expect(gmail[FolderRole.junk]!.learned, isTrue);
      expect(gmail[FolderRole.drafts]!.learned, isFalse);
      final other = {for (final r in await core.folderRoles(fastmail)) r.role: r};
      expect(other[FolderRole.junk]!.folder, 'Junk');
      expect(other[FolderRole.archive]!.folder, 'Archive');
      await expectLater(core.folderRoles('nobody'), throwsArgumentError);
    });

    test('the Spam chip shows the prize scam; the inbox does not', () async {
      final core = fake();
      final inbox = await core.listThreadsIn(MailFolder.inbox);
      expect(inbox.map((t) => t.id), isNot(contains('t-junk-prize')));
      expect(inbox, hasLength(8));
      final spam = await core.listThreadsIn(MailFolder.spam);
      expect(spam.map((t) => t.id), ['t-junk-prize']);
      final byRole = await core.listThreadsInRole(FolderRole.junk, accountId: alice);
      expect(byRole.single.latest.id, FakeCore.junkSampleId);
      expect(await core.listThreadsInRole(FolderRole.junk, accountId: fastmail), isEmpty);
      expect((await core.getThread('t-junk-prize'))!.messages.single.folder, '[Gmail]/Spam');
      expect((await core.getMessage(FakeCore.junkSampleId))!.unread, isTrue);
      final all = await core.listThreadsIn(MailFolder.all);
      expect(all.map((t) => t.id), contains('t-junk-prize'));
    });

    test('moving relocates the message and keeps its conversation', () async {
      final core = fake();
      final mv = await core.moveMessage('m-3', FolderRole.trash);
      expect((mv.fromFolder, mv.toFolder, mv.method, mv.moved), ('INBOX', '[Gmail]/Trash', MoveMethod.move, true));
      expect((await core.listThreadsIn(MailFolder.inbox)).map((t) => t.id), isNot(contains('t-lunch')));
      expect((await core.listThreadsIn(MailFolder.trash)).map((t) => t.id), contains('t-lunch'));
      expect((await core.listThreadsInRole(FolderRole.trash)).single.latest.id, 'm-3');
      expect((await core.getThread('t-lunch'))!.messages.single.folder, '[Gmail]/Trash');
      final again = await core.moveMessage('m-3', FolderRole.trash);
      expect(again.moved, isFalse);
      await core.moveMessage('m-3', FolderRole.inbox);
      final back = await core.listThreadsIn(MailFolder.inbox);
      expect(back.map((t) => t.id), contains('t-lunch'));
      expect(await core.listThreadsIn(MailFolder.trash), isEmpty);
      // One message of a two-message conversation: the rest stays in the inbox.
      await core.moveMessage('m-1', FolderRole.archive);
      final budget = (await core.listThreadsIn(MailFolder.inbox)).firstWhere((t) => t.id == 't-budget');
      expect(budget.messages.map((m) => m.id), ['m-0']);
      expect((await core.getThread('t-budget'))!.messages.map((m) => m.id), ['m-0', 'm-1']);
      await expectLater(core.moveMessage('nope', FolderRole.trash), throwsArgumentError);
      expect((await core.syncFolder(FolderRole.trash)).accounts, hasLength(2));
    });

    test('GoldenCore keeps the inbox goldens: same eight threads, Spam visible', () async {
      final core = GoldenCore();
      final inbox = await core.listThreadsIn(MailFolder.inbox);
      expect(inbox, hasLength(8));
      expect(inbox.first.id, (await core.listThreads()).first.id);
      expect((await core.listThreadsIn(MailFolder.spam)).map((t) => t.id), ['t-junk-prize']);
    });
  });

  group('FakeCore: compose preview and signature', () {
    test('a new message gets the fake signature after a blank line', () async {
      final core = fake();
      final p = await core.composePreview(draft());
      expect(p.kind, ComposeKind.newMessage);
      expect(p.signatureApplied, isTrue);
      expect(p.text, 'See you there.\n\n-- \nAlice Rivera\nSent with Sealbox — end-to-end encrypted\n');
      final sig = await core.signaturePreview(alice, ComposeKind.newMessage);
      expect(sig!.text, startsWith('-- \nAlice Rivera'));
      final none = await core.composePreview(draft(compose: const ComposeOptions(skipSignature: true)));
      expect((none.text, none.signatureApplied), ('See you there.', false));
    });

    test('reply quoting follows the signature placement; a stored signature wins', () async {
      final core = fake();
      final above = await core.composePreview(
        draft(body: 'Works for me.', inReplyTo: 'm-3', compose: const ComposeOptions.reply()),
      );
      expect(above.kind, ComposeKind.reply);
      final sigAt = above.text.indexOf('-- \n');
      final quoteAt = above.text.indexOf('wrote:\n> The Lebanese place');
      expect(sigAt > 0 && quoteAt > sigAt, isTrue, reason: above.text);
      expect(above.text, contains(', Dana Whitfield <dana@example.org> wrote:'));
      await core.setSignature(
        alice,
        const SignatureSettings(enabled: true, text: 'A.', placement: SignaturePlacement.belowQuote),
      );
      final below = await core.composePreview(
        draft(body: 'Works for me.', inReplyTo: 'm-3', compose: const ComposeOptions.reply()),
      );
      expect(below.text.indexOf('-- \nA.\n') > below.text.indexOf('> The Lebanese place'), isTrue);
      await core.setSignature(alice, const SignatureSettings(enabled: false, text: 'A.'));
      expect(await core.signaturePreview(alice, ComposeKind.newMessage), isNull);
      expect((await core.composePreview(draft())).signatureApplied, isFalse);
    });

    test('forwarding names the original; unknown originals are refused', () async {
      final core = fake();
      final f = await core.composePreview(draft(body: 'FYI', compose: const ComposeOptions.forward('m-4')));
      expect(f.kind, ComposeKind.forward);
      expect(f.text, contains('-------- Forwarded Message --------\nSubject: sealbox-crypto 0.3 release notes'));
      expect(f.text, contains('From: Erik Lindqvist <erik@posteo.de>'));
      await expectLater(
        core.composePreview(draft(compose: const ComposeOptions.forward('missing'))),
        throwsArgumentError,
      );
      await expectLater(
        core.composePreview(draft(inReplyTo: 'missing', compose: const ComposeOptions.reply())),
        throwsArgumentError,
      );
    });
  });

  group('FakeCore: spam', () {
    test('the prize scam explains itself', () async {
      final core = fake();
      final e = await core.spamExplain(FakeCore.junkSampleId);
      expect((e.accountId, e.folder), (alice, '[Gmail]/Spam'));
      expect(e.verdict.label, SpamLabel.spam);
      expect(e.verdict.spamProbability, greaterThan(0.9));
      expect(e.stored.label, SpamLabel.spam);
      expect(e.verdict.reasons.map((r) => r.code), containsAll(['dmarc_fail', 'raw_ip_url', 'scam_language']));
      expect(e.features.urls, ['http://203.0.113.7/claim']);
      expect((e.features.spf, e.features.dmarc), (SpamAuthResult.fail, SpamAuthResult.fail));
      final ham = await core.spamExplain('m-1');
      expect(ham.verdict.label, SpamLabel.ham);
      expect(ham.verdict.reasons.single.code, 'signed_by_contact');
      expect(ham.filters.star, isTrue, reason: 'the seeded Finance rule stars bob@sealbox.test');
    });

    test('learning moves the message between the junk folder and the inbox', () async {
      final core = fake();
      final notSpam = await core.spamLearn(FakeCore.junkSampleId, isSpam: false);
      expect((notSpam.learned, notSpam.movedTo, notSpam.messageId), (SpamLabel.ham, 'INBOX', FakeCore.junkSampleId));
      expect((await core.listThreadsIn(MailFolder.inbox)).map((t) => t.id), contains('t-junk-prize'));
      expect(await core.listThreadsIn(MailFolder.spam), isEmpty);
      final spam = await core.spamLearn('m-3', isSpam: true);
      expect((spam.learned, spam.movedTo), (SpamLabel.spam, '[Gmail]/Spam'));
      expect(spam.verdict.reasons.first.code, 'user_feedback');
      expect((await core.getMessage('m-3'))!.unread, isFalse);
      final again = await core.spamLearn('m-3', isSpam: true);
      expect((again.movedTo, again.previouslyLearned), (null, SpamLabel.spam));
      final status = await core.spamStatus();
      final a = status.accounts.firstWhere((s) => s.accountId == alice);
      expect(a.spamCount, 1);
      expect(a.spamFolder, '[Gmail]/Spam');
      expect(a.filterRuleCount, 2);
    });

    test('settings are validated and normalised like the engine', () async {
      final core = fake();
      expect((await core.spamSettings(alice)).spamThreshold, 0.9);
      final s = await core.setSpamSettings(
        alice,
        const SpamSettings(spamThreshold: 0.95, allowlist: ['@Friend.Example', 'friend.example']),
      );
      expect(s.spamThreshold, 0.95);
      expect(s.allowlist, ['friend.example']);
      await expectLater(core.setSpamSettings(alice, const SpamSettings(unsureThreshold: 0.99)), throwsArgumentError);
      await expectLater(core.setSpamSettings(alice, const SpamSettings(moveToFolder: 'inbox')), throwsArgumentError);
      var l = await core.spamBlock(alice, 'friend.example');
      expect(l.allowlist, isEmpty);
      expect(l.blocklist, ['friend.example']);
      l = await core.spamAllow(alice, 'friend.example');
      expect(l.allowlist, ['friend.example']);
      expect(l.blocklist, isEmpty);
      l = await core.spamAllow(alice, 'friend.example', add: false);
      expect(l.allowlist, isEmpty);
    });
  });

  group('FakeCore: filter rules', () {
    test('two seeded rules; dry run; validation; edit, reorder, remove', () async {
      final core = fake();
      final rules = await core.filterRules(alice);
      expect(rules.map((r) => r.name), ['Newsletters', 'Finance']);
      expect(await core.filterRules(fastmail), isEmpty);
      final t = await core.testFilterRules(alice, 'm-1');
      expect(t.outcome.matchedRuleIds, [2]);
      expect((t.outcome.star, t.outcome.moveTo), (true, null));
      expect(t.rules.map((r) => (r.ruleId, r.matched)), [(1, false), (2, true)]);
      await expectLater(core.testFilterRules(fastmail, 'm-1'), throwsArgumentError);

      const noHeader = FilterRule(
        condition: FilterCondition(field: FilterField.header, op: FilterOp.contains, value: 'x'),
        action: FilterAction.star(),
      );
      await expectLater(core.addFilterRule(alice, noHeader), throwsArgumentError);
      await expectLater(
        core.addFilterRule(
          alice,
          const FilterRule(
            condition: FilterCondition(field: FilterField.subject, op: FilterOp.contains, value: 'x'),
            action: FilterAction.addFlag('two words'),
          ),
        ),
        throwsArgumentError,
      );
      final added = await core.addFilterRule(
        alice,
        const FilterRule(
          name: 'Lunch',
          condition: FilterCondition(field: FilterField.subject, op: FilterOp.contains, value: 'lunch'),
          action: FilterAction.markRead(),
        ),
      );
      expect((added.id > 2, added.order), (true, 30));
      expect((await core.testFilterRules(alice, 'm-3')).outcome.markRead, isTrue);
      final off = await core.setFilterRuleEnabled(alice, added.id, false);
      expect(off.enabled, isFalse);
      expect((await core.testFilterRules(alice, 'm-3')).outcome.markRead, isFalse);
      await core.updateFilterRule(alice, off.copyWith(name: 'Lunch (off)'));
      final replaced = await core.setFilterRules(alice, (await core.filterRules(alice)).reversed.toList());
      expect(replaced.map((r) => r.order), [10, 20, 30]);
      expect(replaced.first.name, 'Lunch (off)');
      expect(await core.removeFilterRule(alice, replaced.first.id), isTrue);
      expect(await core.removeFilterRule(alice, replaced.first.id), isFalse);
      expect(await core.filterRules(alice), hasLength(2));
    });
  });

  group('FakeCore: server URL and key directory', () {
    test('the directory walks unpublished → awaiting verification → published', () async {
      final core = fake();
      expect((await core.directoryStatus(alice)).state, DirectoryState.unpublished);
      expect((await core.directoryStatus(alice)).state, DirectoryState.awaitingVerification);
      final published = await core.directoryStatus(alice);
      expect((published.state, published.fingerprintMatches), (DirectoryState.published, true));
      expect((await core.directoryStatus(alice)).state, DirectoryState.published, reason: 'sticks');
      final again = await core.publishKey(alice);
      expect((again.tokenIssued, again.state), (false, DirectoryState.published));
    });

    test('publish → complete verification; no server → refused / noServer', () async {
      final core = fake();
      final p = await core.publishKey(alice);
      expect((p.tokenIssued, p.addressStates['alice.rivera@gmail.com']), (true, 'pending'));
      expect((await core.completeDirectoryVerification(alice)).state, DirectoryState.published);
      core.configuredServer = null;
      expect((await core.directoryStatus(alice)).state, DirectoryState.noServer);
      await expectLater(
        core.publishKey(alice),
        throwsA(predicate((e) => '$e'.contains('server set-url'))),
      );
      expect(await core.serverUrlSource(), ServerUrlSource.none);
    });

    test('a runtime server URL wins over the environment until cleared', () async {
      final core = fake();
      expect(await core.serverUrlSource(), ServerUrlSource.environment);
      expect(await core.setServerUrl('https://keys.example.org/'), 'https://keys.example.org');
      expect(await core.serverUrl(), 'https://keys.example.org');
      expect(await core.serverUrlSource(), ServerUrlSource.settings);
      await expectLater(core.setServerUrl('ftp://keys.example.org'), throwsArgumentError);
      expect(await core.setServerUrl(null), 'https://sealbox.example');
      expect(await core.serverUrlSource(), ServerUrlSource.environment);
    });
  });
}
