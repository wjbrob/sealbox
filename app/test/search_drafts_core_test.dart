import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/core_api.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/core/models.dart';

// Search and saved drafts in the core seam: the engine snippet split into spans, the
// CoreApiOps defaults for doubles without the operations, and FakeCore's search and
// in-memory drafts (what the widget tests and goldens are built on). FrbCore's side is
// exercised against the real engine by app/rust (`search_and_drafts_*`) and by
// integration_test/search_drafts_test.dart.

const s0 = snippetMatchStart;
const s1 = snippetMatchEnd;

FakeCore fake({DateTime Function()? clock}) => FakeCore(latency: Duration.zero, clock: clock);

/// Implements nothing but the base seam.
class _BareCore implements CoreApi {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  group('parseSnippet', () {
    test('splits on the engine markers; the markers never reach the text', () {
      final spans = parseSnippet('the ${s0}zebra$s1 grazes near the ${s0}Zebra${s1}s');
      expect(spans, const [
        SnippetSpan('the '),
        SnippetSpan('zebra', isMatch: true),
        SnippetSpan(' grazes near the '),
        SnippetSpan('Zebra', isMatch: true),
        SnippetSpan('s'),
      ]);
      expect(spans.map((s) => s.text).join(), 'the zebra grazes near the Zebras');
      expect(spans.any((s) => s.text.contains(s0) || s.text.contains(s1)), isFalse);
    });

    test('plain text, empty text, a match at either end', () {
      expect(parseSnippet('no match here'), const [SnippetSpan('no match here')]);
      expect(parseSnippet(''), isEmpty);
      expect(parseSnippet('${s0}start$s1 and ${s0}end$s1'), const [
        SnippetSpan('start', isMatch: true),
        SnippetSpan(' and '),
        SnippetSpan('end', isMatch: true),
      ]);
    });

    test('robust to malformed input: stray end, nested start, unclosed match, empty match', () {
      expect(parseSnippet('a${s1}b'), const [SnippetSpan('ab')]);
      expect(parseSnippet('$s0${s0}x$s1'), const [SnippetSpan('x', isMatch: true)]);
      expect(parseSnippet('a ${s0}open to the end'), const [
        SnippetSpan('a '),
        SnippetSpan('open to the end', isMatch: true),
      ]);
      expect(parseSnippet('a$s0${s1}b'), const [
        SnippetSpan('ab'),
      ], reason: 'empty runs merge away');
      expect(parseSnippet('${s0}one$s1$s0 two$s1'), const [SnippetSpan('one two', isMatch: true)]);
    });

    test('non-BMP characters survive the split', () {
      final spans = parseSnippet('🔐 ${s0}clé$s1 ✓');
      expect(spans.map((s) => s.text).join(), '🔐 clé ✓');
      expect(spans[1], const SnippetSpan('clé', isMatch: true));
    });

    test('SearchResult keeps the spans, the flat text and the matched terms', () {
      final r = SearchResult.fromRaw(
        message: Message(
          id: '1',
          threadId: 't',
          accountId: 'a',
          from: const Contact(email: 'b@x'),
          to: const [],
          subject: 's',
          body: '',
          date: DateTime(2026),
          state: EncryptionState.plaintext,
        ),
        snippet: '… meet at the ${s0}station$s1 at ${s0}noon$s1 …',
        rank: 2.5,
      );
      expect(r.snippetText, '… meet at the station at noon …');
      expect(r.matchedTerms, ['station', 'noon']);
      expect(r.rank, 2.5);
    });
  });

  group('CoreApiOps defaults (a double without search / drafts)', () {
    test('search says it is unavailable instead of claiming "no results"', () async {
      final core = _BareCore();
      await expectLater(core.search('anything'), throwsA(isA<UnsupportedError>()));
      expect((await core.warmSearchIndex()).documents, 0);
    });

    test('drafts: none listed, saving is unavailable, nothing to delete', () async {
      final core = _BareCore();
      expect(core.supportsDrafts, isFalse);
      expect(await core.listDrafts(), isEmpty);
      expect(await core.deleteDraft(1), isFalse);
      await expectLater(
        core.saveDraft(const DraftInput(accountId: 'a')),
        throwsA(isA<UnsupportedError>()),
      );
      await expectLater(core.sendDraft(1), throwsA(isA<UnsupportedError>()));
      await core.releaseDraftAttachment('/etc/passwd'); // a no-op, never a delete
      expect(fake().supportsDrafts, isTrue);
    });
  });

  group('FakeCore search', () {
    test('every word must match, case-insensitively, in subject, people or body', () async {
      final core = fake();
      // m-1 has both words in its subject; m-0 has "budget" there and "final" in its body.
      final budget = await core.search('BUDGET final');
      expect(budget.map((r) => r.message.id), ['m-1', 'm-0']);
      expect(budget.first.rank, greaterThan(budget.last.rank));
      expect(await core.search('budget nonsense'), isEmpty);
      // By sender name and by address.
      expect((await core.search('nakamura')).map((r) => r.message.id), contains('m-1'));
      expect((await core.search('posteo')).map((r) => r.message.id), ['m-4']);
      // Text without a letter or digit finds nothing.
      expect(await core.search('  --  '), isEmpty);
    });

    test('ranks subject above body, newest first on ties, and honours the limit', () async {
      final core = fake();
      // "thunderbird" is in m-2's subject and body; m-1's body does not have it.
      final r = await core.search('thunderbird');
      expect(r.first.message.id, 'm-2');
      expect(r.first.rank, greaterThan(0));
      final all = await core.search('alice');
      expect(all.length, greaterThan(2));
      expect(await core.search('alice', limit: 2), hasLength(2));
      for (var i = 1; i < all.length; i++) {
        final a = all[i - 1], b = all[i];
        expect(
          a.rank > b.rank || (a.rank == b.rank && !a.message.date.isBefore(b.message.date)),
          isTrue,
          reason: 'best first, then newest',
        );
      }
    });

    test('narrows to an account and a folder; searches parked mail too', () async {
      final core = fake();
      expect(
        (await core.search(
          'alice',
          accountId: 'acct-2',
        )).every((r) => r.message.accountId == 'acct-2'),
        isTrue,
      );
      final spam = await core.search('gift card');
      expect(spam.map((r) => r.message.id), [FakeCore.junkSampleId]);
      expect(await core.search('gift card', folder: 'INBOX'), isEmpty);
      expect(await core.search('gift card', folder: '[gmail]/spam'), hasLength(1));
      expect(await core.search('gift card', folder: '*'), hasLength(1));
    });

    test('the snippet marks the matched words around the first body match', () async {
      final core = fake();
      final r = (await core.search('renegotiation')).single;
      expect(r.matchedTerms, ['renegotiation']);
      expect(r.snippetText, startsWith('… line drops 8% after the renegotiation.'));
      // Only the subject matched: the start of the body, nothing marked.
      final subjectOnly = (await core.search('autocrypt meetup')).single;
      expect(subjectOnly.matchedTerms, isEmpty);
      expect(subjectOnly.snippetText, startsWith('Encrypted to both of you'));
      expect(FakeCore.fakeSnippet('', ['x']), '');
      final long = List.generate(40, (i) => 'w$i').join(' ');
      expect(FakeCore.fakeSnippet(long, ['w20']), startsWith('… w15'));
      expect(FakeCore.fakeSnippet(long, ['w20']), endsWith('w30 …'));
    });

    test('warming the index reports what it holds', () async {
      final info = await fake().warmSearchIndex();
      expect(info.documents, greaterThan(5));
      expect(info.memoryBytes, greaterThan(0));
    });
  });

  group('FakeCore drafts', () {
    test('save creates, saving with the id replaces; ids are never reused', () async {
      var now = DateTime.utc(2026, 6, 15, 12);
      final core = fake(clock: () => now);
      final first = await core.saveDraft(
        const DraftInput(accountId: 'acct-1', to: ['bob@sealbox.test'], subject: 'Plan'),
      );
      expect(first.id, 1);
      expect(first.kind, ComposeKind.newMessage);
      expect(first.createdAt, now);
      now = now.add(const Duration(minutes: 5));
      final again = await core.saveDraft(
        DraftInput(
          id: first.id,
          accountId: 'acct-1',
          to: const ['bob@sealbox.test'],
          subject: 'Plan B',
        ),
      );
      expect(again.id, first.id);
      expect(again.createdAt, first.createdAt);
      expect(again.updatedAt, now);
      expect((await core.listDrafts()).single.subject, 'Plan B');
      final second = await core.saveDraft(const DraftInput(accountId: 'acct-2', body: 'x'));
      expect(second.id, 2);
      expect(await core.deleteDraft(second.id), isTrue);
      expect(await core.deleteDraft(second.id), isFalse);
      final third = await core.saveDraft(const DraftInput(accountId: 'acct-2', body: 'y'));
      expect(third.id, 3, reason: 'a deleted id is not handed out again');
    });

    test('list: newest first, per account; get; unknown ids and accounts', () async {
      var now = DateTime.utc(2026, 6, 15, 12);
      final core = fake(clock: () => now);
      final a = await core.saveDraft(const DraftInput(accountId: 'acct-1', subject: 'a'));
      now = now.add(const Duration(minutes: 1));
      final b = await core.saveDraft(const DraftInput(accountId: 'acct-2', subject: 'b'));
      expect((await core.listDrafts()).map((d) => d.id), [b.id, a.id]);
      expect((await core.listDrafts(accountId: 'acct-1')).map((d) => d.id), [a.id]);
      expect((await core.getDraft(a.id)).subject, 'a');
      await expectLater(core.getDraft(99), throwsA(isA<ArgumentError>()));
      await expectLater(
        core.saveDraft(const DraftInput(accountId: 'nobody')),
        throwsA(isA<ArgumentError>()),
      );
      await expectLater(core.listDrafts(accountId: 'nobody'), throwsA(isA<ArgumentError>()));
    });

    test('kind follows the reply / forward reference, like the engine', () async {
      final core = fake();
      expect(
        (await core.saveDraft(const DraftInput(accountId: 'acct-1', inReplyTo: 'm-1'))).kind,
        ComposeKind.reply,
      );
      expect(
        (await core.saveDraft(const DraftInput(accountId: 'acct-1', forwardOf: 'm-4'))).kind,
        ComposeKind.forward,
      );
      await expectLater(
        core.saveDraft(const DraftInput(accountId: 'acct-1', inReplyTo: 'm-1', forwardOf: 'm-4')),
        throwsA(isA<ArgumentError>()),
      );
      await expectLater(
        core.saveDraft(const DraftInput(accountId: 'acct-1', kind: ComposeKind.reply)),
        throwsA(isA<ArgumentError>()),
      );
      await expectLater(
        core.saveDraft(
          const DraftInput(accountId: 'acct-1', kind: ComposeKind.forward, inReplyTo: 'm-1'),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('attachment copies: kept, read back, released with the draft', () async {
      final core = fake();
      final path = await core.keepDraftAttachment('notes.txt', Uint8List.fromList([1, 2, 3]));
      expect(path, startsWith(FakeCore.draftFilePrefix));
      expect(SavedDraftAttachment.blobIdOf(path), isNotNull, reason: 'a stored-copy handle');
      expect(await core.readDraftAttachment(path), [1, 2, 3]);
      final d = await core.saveDraft(
        DraftInput(
          accountId: 'acct-1',
          subject: 'with a file',
          attachments: [
            SavedDraftAttachment(path: path, name: 'notes.txt', contentType: 'text/plain'),
          ],
        ),
      );
      expect(d.attachments.single.displayName, 'notes.txt');
      expect(await core.deleteDraft(d.id), isTrue);
      expect(core.draftFiles, isEmpty, reason: 'the copy goes with the draft');
      await expectLater(core.readDraftAttachment(path), throwsA(isA<StateError>()));
      // A path the app did not create is never touched.
      await core.releaseDraftAttachment('/home/someone/report.pdf');
    });

    test('stored copies, like the engine: the kept name is the default, a gone one is refused', () async {
      final core = fake();
      final handle = await core.keepDraftAttachment('plan.pdf', Uint8List.fromList([4]));
      final d = await core.saveDraft(
        DraftInput(
          accountId: 'acct-1',
          subject: 'unnamed attachment',
          attachments: [SavedDraftAttachment(path: handle)],
        ),
      );
      final a = d.attachments.single;
      expect((a.path, a.blobId, a.name), (handle, SavedDraftAttachment.blobIdOf(handle), 'plan.pdf'));
      await core.releaseDraftAttachment(handle);
      await expectLater(
        core.saveDraft(
          DraftInput(
            accountId: 'acct-1',
            subject: 'gone',
            attachments: [SavedDraftAttachment(path: handle)],
          ),
        ),
        throwsA(isA<ArgumentError>()),
      );
      // Handles and paths: only `blob:<positive id>` is a handle.
      expect(SavedDraftAttachment.blobHandle(12), 'blob:12');
      for (final p in ['blob:0', 'blob:x', '/tmp/blob:3', 'blob:', 'mem://draft-attachments/1/a']) {
        expect(SavedDraftAttachment.blobIdOf(p), isNull, reason: p);
      }
      expect(const SavedDraftAttachment(path: 'blob:9').displayName, 'attachment');
    });

    test('sendDraft sends through the send path (To and Cc) and deletes the draft', () async {
      final core = fake();
      final path = await core.keepDraftAttachment('a.bin', Uint8List.fromList([9]));
      final d = await core.saveDraft(
        DraftInput(
          accountId: 'acct-1',
          to: const ['bob@sealbox.test'],
          cc: const ['dana@example.org'],
          subject: 'Hi',
          body: 'Body',
          attachments: [SavedDraftAttachment(path: path, name: 'a.bin')],
        ),
      );
      final receipt = await core.sendDraft(d.id);
      expect(receipt.encryptedTo, ['bob@sealbox.test']);
      expect(receipt.guestLinkTo, ['dana@example.org'], reason: 'Cc decided per recipient too');
      final sent = core.sentMessages.single;
      expect(sent.cc, ['dana@example.org']);
      expect(sent.attachments.single.data, [9]);
      expect(await core.listDrafts(), isEmpty);
      expect(core.draftFiles, isEmpty);
    });
  });

  test('FrbCore keeps a picked file under a safe name', () {
    expect(FrbCore.safeAttachmentFileName('report.pdf'), 'report.pdf');
    expect(FrbCore.safeAttachmentFileName('../../etc/passwd'), '.._.._etc_passwd');
    expect(FrbCore.safeAttachmentFileName('a\\b\u0000c'), 'a_b_c');
    expect(FrbCore.safeAttachmentFileName('  '), 'attachment');
    expect(FrbCore.safeAttachmentFileName('..'), 'attachment');
    final long = '${'x' * 200}.pdf';
    expect(FrbCore.safeAttachmentFileName(long), hasLength(120));
    expect(FrbCore.safeAttachmentFileName(long), endsWith('.pdf'));
  });
}
