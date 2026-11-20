import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/rust/api/engine.dart' as frb;

import 'support/fake_frb_engine.dart';

// Draft attachments are sealed engine blobs (docs/THREAT_MODEL.md R16): FrbCore keeps a picked
// file with `put_draft_blob` and hands compose a `blob:<id>` handle, saved drafts carry the blob
// id, and reading, releasing, sending and deleting work on handles. A copy kept for another
// account is moved to the draft's account when the draft is saved (the engine lets only that
// account's drafts reference it). Plain copies of earlier builds under
// `<profile>/draft-attachments/` keep working. The start-up sweep runs the engine's for every
// account.

typedef _Blob = ({String account, String name, Uint8List data});

const _ep = frb.Endpoint(host: '127.0.0.1', port: 3143, security: frb.Security.plain);

/// The engine's draft and draft-blob calls in memory, with its rules: a blob only for drafts
/// of the account that stored it, the blob's name as an attachment's default, and a draft's
/// blobs deleted with it.
class _Engine extends FakeFrbEngine {
  _Engine(this.dir, this.accounts);

  final Directory dir;
  final List<String> accounts;
  final Map<int, _Blob> blobs = {};
  final Map<int, frb.SavedDraft> drafts = {};
  final List<String> sweeps = [];
  bool failSave = false;
  var _nextBlob = 1;
  var _nextDraft = 1;

  @override
  String profileDir() => dir.path;

  @override
  Future<List<frb.AccountInfo>> listAccounts() async => [
    for (final (i, a) in accounts.indexed)
      frb.AccountInfo(
        id: i + 1,
        email: a,
        displayName: '',
        imap: _ep,
        smtp: _ep,
        authKind: frb.AuthKind.password,
        login: a,
        createdAt: 0,
      ),
  ];

  @override
  Future<int> putDraftBlob({
    required String accountEmail,
    required String filename,
    required String contentType,
    required List<int> data,
  }) async {
    if (!accounts.contains(accountEmail)) throw StateError('account not found: $accountEmail');
    final id = _nextBlob++;
    blobs[id] = (
      account: accountEmail,
      name: filename.isEmpty ? 'attachment' : filename,
      data: Uint8List.fromList(data),
    );
    return id;
  }

  frb.DraftBlobInfo _info(int id, _Blob b) => frb.DraftBlobInfo(
    id: id,
    account: b.account,
    filename: b.name,
    contentType: '',
    size: b.data.length,
    createdAt: 0,
  );

  @override
  Future<frb.DraftBlob> getDraftBlob({required int id}) async {
    final b = blobs[id] ?? (throw StateError('invalid input: no draft blob $id'));
    return frb.DraftBlob(info: _info(id, b), data: b.data);
  }

  @override
  Future<bool> deleteDraftBlob({required int id}) async => blobs.remove(id) != null;

  @override
  Future<List<frb.DraftBlobInfo>> listDraftBlobs({required String accountEmail}) async => [
    for (final e in blobs.entries)
      if (e.value.account == accountEmail) _info(e.key, e.value),
  ];

  @override
  Future<int> sweepDraftBlobs({required String accountEmail}) async {
    sweeps.add(accountEmail);
    return 1;
  }

  @override
  Future<frb.SavedDraft> saveDraft({required frb.DraftInput input}) async {
    if (failSave) throw StateError('store: disk full');
    final attachments = [
      for (final a in input.attachments)
        if (a.blobId case final int id)
          blobs[id]?.account == input.account
              ? frb.DraftAttachment(
                  path: '',
                  blobId: id,
                  name: a.name.isEmpty ? blobs[id]!.name : a.name,
                  contentType: a.contentType,
                )
              : throw StateError('invalid input: draft attachment: no stored blob $id')
        else
          a,
    ];
    final id = input.id ?? _nextDraft++;
    return drafts[id] = frb.SavedDraft(
      id: id,
      account: input.account,
      kind: input.kind,
      quote: input.quote,
      references: const [],
      to: input.to,
      cc: input.cc,
      bcc: input.bcc,
      subject: input.subject,
      bodyText: input.bodyText,
      attachments: attachments,
      policy: input.policy,
      guestMode: input.guestMode,
      noSignature: input.noSignature,
      createdAt: 1781500000,
      updatedAt: 1781500000,
      origin: frb.DraftOrigin.local,
      remoteFiles: 0,
    );
  }

  @override
  Future<List<frb.SavedDraft>> listDrafts({String? account}) async => [
    for (final d in drafts.values)
      if (account == null || d.account == account) d,
  ];

  @override
  Future<frb.SavedDraft> getDraft({required int id}) async =>
      drafts[id] ?? (throw StateError('invalid input: no draft $id'));

  @override
  Future<bool> deleteDraft({required int id}) async {
    final d = drafts.remove(id);
    for (final a in d?.attachments ?? const <frb.DraftAttachment>[]) {
      if (a.blobId case final int b) blobs.remove(b);
    }
    return d != null;
  }
}

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('sealbox-draft-blobs-'));
  tearDown(() => tmp.deleteSync(recursive: true));

  DraftInput input(String account, List<String> handles, {int? id}) => DraftInput(
    id: id,
    accountId: account,
    subject: 'Plan',
    attachments: [for (final h in handles) SavedDraftAttachment(path: h)],
  );

  test('a kept file is a sealed engine blob behind a handle, never a file in the profile', () async {
    final engine = _Engine(tmp, ['a@sealbox.test']);
    final core = FrbCore(engine);
    final handle = await core.keepDraftAttachment('notes.txt', Uint8List.fromList([1, 2, 3]));
    final id = SavedDraftAttachment.blobIdOf(handle);
    expect(handle, SavedDraftAttachment.blobHandle(id!));
    expect(engine.blobs[id]?.account, 'a@sealbox.test');
    expect(Directory(core.draftAttachmentDir).existsSync(), isFalse, reason: 'no plain copy');
    expect(await core.readDraftAttachment(handle), [1, 2, 3]);

    final saved = await core.saveDraft(input('a@sealbox.test', [handle]));
    final att = saved.attachments.single;
    expect((att.path, att.blobId, att.displayName), (handle, id, 'notes.txt'));
    final stored = engine.drafts[saved.id]!.attachments.single;
    expect((stored.blobId, stored.path), (id, ''), reason: 'the engine gets the blob id');
    expect((await core.getDraft(saved.id)).attachments.single.path, handle);
    expect((await core.listDrafts()).single.attachments.single.blobId, id);

    // Deleting the draft deletes the blob (in the engine); releasing the handle later is harmless.
    expect(await core.deleteDraft(saved.id), isTrue);
    expect(engine.blobs, isEmpty);
    await core.releaseDraftAttachment(handle);
    await expectLater(core.readDraftAttachment(handle), throwsA(isA<StateError>()));

    // A released handle deletes its blob.
    final other = await core.keepDraftAttachment('b.bin', Uint8List.fromList([4]));
    await core.releaseDraftAttachment(other);
    expect(engine.blobs, isEmpty);
  });

  test('a copy kept for another account moves to the draft account when saved', () async {
    final engine = _Engine(tmp, ['a@sealbox.test', 'b@sealbox.test']);
    final core = FrbCore(engine);
    // Nothing saved yet: kept for the first account.
    final handle = await core.keepDraftAttachment('plan.pdf', Uint8List.fromList([7, 7]));
    final first = SavedDraftAttachment.blobIdOf(handle)!;
    expect(engine.blobs[first]?.account, 'a@sealbox.test');

    final saved = await core.saveDraft(input('b@sealbox.test', [handle]));
    final moved = saved.attachments.single.blobId!;
    expect(moved, isNot(first));
    expect(engine.blobs.keys, [moved], reason: 'the first copy is nobody\'s now');
    expect(engine.blobs[moved]?.account, 'b@sealbox.test');
    expect(saved.attachments.single.displayName, 'plan.pdf');
    // Compose still holds the first handle: reads and saves follow the move, no new copy.
    expect(await core.readDraftAttachment(handle), [7, 7]);
    final again = await core.saveDraft(input('b@sealbox.test', [handle], id: saved.id));
    expect(again.attachments.single.blobId, moved);
    expect(engine.blobs.keys, [moved]);
    // Releasing the first handle (what compose does once the draft names the copy) keeps it.
    await core.releaseDraftAttachment(handle);
    expect(engine.blobs.keys, [moved]);
    // The next copy is kept for the account of the draft saved last.
    final next = await core.keepDraftAttachment('more.txt', Uint8List.fromList([1]));
    expect(engine.blobs[SavedDraftAttachment.blobIdOf(next)!]?.account, 'b@sealbox.test');

    // A save that fails leaves no moved copy behind, and the kept copy as it was.
    final stray = await core.keepDraftAttachment('x.bin', Uint8List.fromList([2]));
    final strayId = SavedDraftAttachment.blobIdOf(stray)!;
    engine.failSave = true;
    await expectLater(core.saveDraft(input('a@sealbox.test', [stray])), throwsA(isA<StateError>()));
    expect(engine.blobs.keys.toSet(), {moved, SavedDraftAttachment.blobIdOf(next), strayId});
    expect(engine.blobs[strayId]?.account, 'b@sealbox.test');
  });

  test('plain copies of earlier builds under the profile still read, release and go', () async {
    final engine = _Engine(tmp, ['a@sealbox.test']);
    final core = FrbCore(engine);
    final legacy = File('${core.draftAttachmentDir}/a1/old.pdf')
      ..createSync(recursive: true)
      ..writeAsBytesSync([5, 5]);
    final outside = File('${tmp.path}/mine.pdf')..writeAsBytesSync([6]);
    expect(SavedDraftAttachment.blobIdOf(legacy.path), isNull);
    expect(await core.readDraftAttachment(legacy.path), [5, 5]);
    final saved = await core.saveDraft(input('a@sealbox.test', [legacy.path, outside.path]));
    expect([for (final a in saved.attachments) a.path], [legacy.path, outside.path]);
    expect(await core.deleteDraft(saved.id), isTrue);
    expect(legacy.existsSync(), isFalse, reason: 'our old copy goes with its draft');
    expect(outside.existsSync(), isTrue, reason: 'a file the app did not copy is never touched');
  });

  test('the start-up sweep runs the engine sweep for every account', () async {
    final engine = _Engine(tmp, ['a@sealbox.test', 'b@sealbox.test']);
    expect(await FrbCore(engine).sweepDraftBlobs(), 2);
    expect(engine.sweeps, ['a@sealbox.test', 'b@sealbox.test']);
  });
}
