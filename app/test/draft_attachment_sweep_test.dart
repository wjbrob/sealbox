import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/draft_attachment_sweep.dart';
import 'package:sealbox_app/src/features/compose/drafts.dart';

// Drafts hygiene (b): copies of files attached to drafts live under
// <profile>/draft-attachments/<one dir per copy>/. When the app dies between copying a file
// and storing its draft, or an account is removed with its drafts, nobody refers to the copy
// any more. A sweep at start-up deletes those (older than kOrphanedCopyMinAge, so a save in
// flight is never raced) and logs how many.

final _old = DateTime.now().subtract(const Duration(hours: 2));

/// `<root>/<dir>/<name>` with [content], last written [at] (default: two hours ago).
File copy(Directory root, String dir, String name, {DateTime? at, String content = 'x'}) {
  final f = File('${root.path}/$dir/$name')
    ..createSync(recursive: true)
    ..writeAsStringSync(content);
  f.setLastModifiedSync(at ?? _old);
  return f;
}

SavedDraft draftNaming(int id, List<String> paths) => SavedDraft(
  id: id,
  accountId: 'acct-1',
  attachments: [for (final p in paths) SavedDraftAttachment(path: p)],
  createdAt: _old,
  updatedAt: _old,
);

/// FakeCore counting `listDrafts` calls (one per sweep).
class CountingCore extends FakeCore {
  CountingCore() : super(latency: Duration.zero);

  int listCalls = 0;

  @override
  Future<List<SavedDraft>> listDrafts({String? accountId}) {
    listCalls++;
    return super.listDrafts(accountId: accountId);
  }
}

void main() {
  late Directory tmp;
  late Directory root;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('sealbox-sweep-');
    root = Directory('${tmp.path}/profile/draft-attachments')..createSync(recursive: true);
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  test('deletes old copies no draft names, keeps the rest', () async {
    final kept = copy(root, 'a1', 'minutes.pdf');
    final orphan = copy(root, 'a2', 'budget.xlsx');
    final orphan2 = copy(root, 'a3', 'photo.jpg');
    final fresh = copy(root, 'a4', 'just-copied.txt', at: DateTime.now());
    // Named through another path to the same file (a symlinked profile directory).
    final alias = Link('${tmp.path}/alias')..createSync(root.path);
    final viaAlias = copy(root, 'a5', 'agenda.md');
    // A link inside the copies: never followed, never deleted, nor its target.
    final outside = File('${tmp.path}/outside/secret.txt')
      ..createSync(recursive: true)
      ..writeAsStringSync('not ours');
    outside.setLastModifiedSync(_old);
    final link = Link('${root.path}/a6/secret.txt')..createSync(outside.path, recursive: true);

    final n = await sweepOrphanedDraftAttachments(
      root: root,
      listDrafts: () async => [
        draftNaming(1, [kept.path, '${tmp.path}/elsewhere/gone.txt', 'blob:5']),
        draftNaming(2, ['${alias.path}/a5/agenda.md']),
      ],
    );

    expect(n, 2);
    expect(orphan.existsSync(), isFalse);
    expect(orphan2.existsSync(), isFalse);
    expect(Directory('${root.path}/a2').existsSync(), isFalse, reason: 'its directory went too');
    expect(Directory('${root.path}/a3').existsSync(), isFalse);
    expect(kept.existsSync(), isTrue, reason: 'named by a draft');
    expect(viaAlias.existsSync(), isTrue, reason: 'named by a draft through a link');
    expect(fresh.existsSync(), isTrue, reason: 'younger than kOrphanedCopyMinAge: in flight');
    expect(link.existsSync(), isTrue, reason: 'links are left alone');
    expect(outside.readAsStringSync(), 'not ours');
  });

  test('when the drafts cannot be listed nothing is deleted', () async {
    final orphan = copy(root, 'a1', 'budget.xlsx');
    await expectLater(
      sweepOrphanedDraftAttachments(
        root: root,
        listDrafts: () async => throw StateError('database is locked'),
      ),
      throwsStateError,
    );
    expect(orphan.existsSync(), isTrue);
  });

  test('no copies directory, or nothing old enough: nothing to do', () async {
    expect(
      await sweepOrphanedDraftAttachments(
        root: Directory('${tmp.path}/none'),
        listDrafts: () async => throw StateError('not asked'),
      ),
      0,
    );
    copy(root, 'a1', 'new.txt', at: DateTime.now());
    expect(
      await sweepOrphanedDraftAttachments(
        root: root,
        listDrafts: () async => throw StateError('not asked: no candidate'),
      ),
      0,
    );
  });

  group('at start-up', () {
    ProviderContainer containerFor(FakeCore core, Directory? dir) => ProviderContainer(
      overrides: [
        coreApiProvider.overrideWithValue(core),
        draftCopiesDirProvider.overrideWithValue(dir),
      ],
    );

    test('the Drafts chip (built by every inbox) starts the sweep, once per run', () async {
      final core = CountingCore();
      final kept = copy(root, 'a1', 'minutes.pdf');
      final orphan = copy(root, 'a2', 'budget.xlsx');
      await core.saveDraft(
        DraftInput(
          accountId: 'acct-1',
          subject: 'Minutes',
          attachments: [SavedDraftAttachment(path: kept.path)],
        ),
      );
      final c = containerFor(core, root);
      addTearDown(c.dispose);
      expect(c.read(draftsChipProvider), isFalse); // what the inbox does, nothing more
      for (var i = 0; i < 200 && orphan.existsSync(); i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(orphan.existsSync(), isFalse, reason: 'swept without anyone asking for the sweep');
      expect(kept.existsSync(), isTrue);
      expect(await c.read(draftCopiesSweepProvider.future), 1);
      expect(core.listCalls, 1);

      // Once per run: the chip used again does not sweep again (a later orphan waits).
      final later = copy(root, 'a3', 'later.txt');
      c.read(draftsChipProvider.notifier).set(true);
      c.read(draftsChipProvider.notifier).set(false);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(core.listCalls, 1);
      expect(later.existsSync(), isTrue);
    });

    test('the engine sweep of stored copies runs too, once per run, beside the file sweep', () async {
      final core = CountingCore();
      copy(root, 'a2', 'budget.xlsx'); // an old orphaned plain copy
      var blobSweeps = 0;
      final c = ProviderContainer(
        overrides: [
          coreApiProvider.overrideWithValue(core),
          draftCopiesDirProvider.overrideWithValue(root),
          draftBlobSweepProvider.overrideWithValue(() async {
            blobSweeps++;
            return 2;
          }),
        ],
      );
      addTearDown(c.dispose);
      c.read(draftsChipProvider);
      expect(await c.read(draftCopiesSweepProvider.future), 3, reason: '1 file + 2 stored copies');
      c.read(draftsChipProvider.notifier).set(true);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(blobSweeps, 1);
    });

    test('a failing sweep of stored copies keeps the file sweep and its count', () async {
      final core = CountingCore();
      final orphan = copy(root, 'a2', 'budget.xlsx');
      final c = ProviderContainer(
        overrides: [
          coreApiProvider.overrideWithValue(core),
          draftCopiesDirProvider.overrideWithValue(root),
          draftBlobSweepProvider.overrideWithValue(() async => throw StateError('locked')),
        ],
      );
      addTearDown(c.dispose);
      expect(await c.read(draftCopiesSweepProvider.future), 1);
      expect(orphan.existsSync(), isFalse);
    });

    test('a core without copies on disk (FakeCore) sweeps nothing', () async {
      final c = ProviderContainer(
        overrides: [coreApiProvider.overrideWithValue(FakeCore(latency: Duration.zero))],
      );
      addTearDown(c.dispose);
      expect(c.read(draftCopiesDirProvider), isNull);
      expect(c.read(draftBlobSweepProvider), isNull);
      c.read(draftsChipProvider);
      expect(await c.read(draftCopiesSweepProvider.future), 0);
    });
  });
}
