import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/frb_core.dart' show FrbCore;
import '../../core/models.dart';

/// How old a copy no draft refers to must be before the sweep deletes it. A copy is written
/// just before the draft that names it is stored, so a younger one may belong to a save that
/// is still in flight (this run's compose, at start-up).
const kOrphanedCopyMinAge = Duration(minutes: 10);

/// Deletes the attachment copies under [root] (`<profile>/draft-attachments`, one directory
/// per copy) that no saved draft refers to and that were last written more than [minAge]
/// ago; returns how many it deleted. Builds before the engine sealed draft attachments kept
/// their copies there as plain files (docs/THREAT_MODEL.md R16); they are left behind when
/// the app died between copying a file and storing its draft, or when an account was removed
/// with its drafts. (New copies are sealed engine blobs, swept by the engine:
/// [draftBlobSweepProvider].)
///
/// Only regular files inside [root] are candidates: links are neither followed nor deleted.
/// A copy's directory goes with it once empty. [listDrafts] failing deletes nothing.
Future<int> sweepOrphanedDraftAttachments({
  required Directory root,
  required Future<List<SavedDraft>> Function() listDrafts,
  Duration minAge = kOrphanedCopyMinAge,
  DateTime Function() clock = DateTime.now,
}) async {
  if (!await root.exists()) return 0;
  final rootReal = await root.resolveSymbolicLinks();
  final cutoff = clock().subtract(minAge);
  // The copies first, the drafts second: a copy written after this listing is no candidate,
  // and one written before it is either named by a draft listed below or older than minAge.
  final candidates = <String>[];
  await for (final e in Directory(rootReal).list(recursive: true, followLinks: false)) {
    if (e is! File) continue;
    if ((await e.stat()).modified.isBefore(cutoff)) candidates.add(e.path);
  }
  if (candidates.isEmpty) return 0;
  final referenced = <String>{};
  for (final d in await listDrafts()) {
    for (final a in d.attachments) {
      if (a.blobId != null) continue; // a stored copy, not a file
      try {
        final f = File(a.path);
        if (await f.exists()) referenced.add(await f.resolveSymbolicLinks());
      } on FileSystemException {
        // Not there: nothing of ours to keep for it.
      }
    }
  }
  var removed = 0;
  for (final path in candidates) {
    if (referenced.contains(path)) continue;
    try {
      await File(path).delete();
      removed++;
    } on FileSystemException catch (e) {
      debugPrint('[sealbox] draft attachments: could not remove a copy: ${friendlyError(e)}');
      continue;
    }
    final dir = File(path).parent;
    if (dir.parent.path != rootReal) continue;
    try {
      if (await dir.list().isEmpty) await dir.delete();
    } on FileSystemException {
      // Kept: an empty directory is harmless.
    }
  }
  return removed;
}

/// Where this app keeps its copies of files attached to drafts (`FrbCore.draftAttachmentDir`,
/// on disk under the profile); null for a core that keeps them elsewhere (FakeCore holds them
/// in memory: nothing outlives the run).
final draftCopiesDirProvider = Provider<Directory?>((ref) {
  final core = ref.watch(coreApiProvider);
  return core is FrbCore ? Directory(core.draftAttachmentDir) : null;
});

/// The engine's sweep of stored draft copies (sealed blobs no saved draft references, more
/// than ten minutes old, every account; `FrbCore.sweepDraftBlobs`); null for a core that
/// keeps them elsewhere (FakeCore holds them in memory: nothing outlives the run).
final draftBlobSweepProvider = Provider<Future<int> Function()?>((ref) {
  final core = ref.watch(coreApiProvider);
  return core is FrbCore ? core.sweepDraftBlobs : null;
});

/// The start-up sweep of draft attachment copies no saved draft refers to: the plain file
/// copies of earlier builds ([sweepOrphanedDraftAttachments]) and the engine's stored copies
/// ([draftBlobSweepProvider]). Once per run (keep-alive), started by the Drafts chip's
/// controller, which every inbox builds; logs how many copies each removed and completes
/// with their sum. When the drafts cannot be listed no file is deleted; either sweep failing
/// leaves the other's count.
final draftCopiesSweepProvider = FutureProvider<int>((ref) async {
  final root = ref.watch(draftCopiesDirProvider);
  final sweepBlobs = ref.watch(draftBlobSweepProvider);
  final core = ref.watch(coreApiProvider);
  var removed = 0;
  if (root != null) {
    try {
      final n = await sweepOrphanedDraftAttachments(root: root, listDrafts: core.listDrafts);
      debugPrint('[sealbox] draft attachments: $n orphaned ${n == 1 ? 'copy' : 'copies'} removed');
      removed += n;
    } catch (e) {
      debugPrint('[sealbox] draft attachments: sweep skipped: ${friendlyError(e)}');
    }
  }
  if (sweepBlobs != null) {
    try {
      final n = await sweepBlobs();
      debugPrint('[sealbox] draft attachments: $n unreferenced stored ${n == 1 ? 'copy' : 'copies'} removed');
      removed += n;
    } catch (e) {
      debugPrint('[sealbox] draft attachments: stored-copy sweep skipped: ${friendlyError(e)}');
    }
  }
  return removed;
});
