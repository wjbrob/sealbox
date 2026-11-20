import 'dart:async';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart' show Int64List;
import 'package:sealbox_app/src/rust/api/engine.dart' as frb;

/// The bridge's `frb.Engine` without the native library, for unit tests of `FrbCore`'s own
/// logic (mapping, grouping, what it asks the engine for). Only the members those tests
/// call are implemented; anything else fails loudly.
class FakeFrbEngine implements frb.Engine {
  /// What `listMessages` serves: every summary for `folder: '*'`, those whose folder is
  /// `INBOX` / `Sent` for the inbox / sent role.
  final List<frb.MessageSummary> summaries = [];

  /// Bodies by message id, for `getMessage`.
  final Map<int, frb.MessageDetail> details = {};

  /// Every `getMessage` id, in order.
  final List<int> getMessageCalls = [];

  /// Every sync / backfill call: `sync <email>`, `backfill <email> <max|all>`.
  final List<String> runs = [];

  /// The stream a sync / backfill call returns (a test-built one, or an empty run).
  Stream<frb.SyncEvent> Function(String email)? onSync;
  Stream<frb.SyncEvent> Function(String email, int? max)? onBackfill;

  @override
  Future<List<frb.MessageSummary>> listMessages({required frb.ListQuery query}) async {
    bool keep(frb.MessageSummary s) => switch (query.folderRole) {
      frb.FolderRole.inbox => s.folder == 'INBOX',
      frb.FolderRole.sent => s.folder == 'Sent',
      null => query.folder == '*' || s.folder == (query.folder ?? 'INBOX'),
      _ => false,
    };
    return [
      for (final s in summaries)
        if ((query.account == null || s.account == query.account) && keep(s)) s,
    ];
  }

  @override
  Future<frb.MessageDetail> getMessage({required int id}) async {
    getMessageCalls.add(id);
    final d = details[id];
    if (d == null) throw StateError('message not found: $id');
    return d;
  }

  @override
  Stream<frb.SyncEvent> syncAccountWithProgress({required String email}) {
    runs.add('sync $email');
    return onSync?.call(email) ?? Stream.value(done(report(email)));
  }

  @override
  Stream<frb.SyncEvent> backfillWithProgress({required String email, int? maxMessages}) {
    runs.add('backfill $email ${maxMessages ?? 'all'}');
    return onBackfill?.call(email, maxMessages) ?? Stream.value(done(report(email)));
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnimplementedError('FakeFrbEngine does not implement ${invocation.memberName}');

  // -- fixtures ---------------------------------------------------------------------------

  /// A summary as the engine lists it (plain, unread, own conversation unless [threadId]).
  static frb.MessageSummary summary(
    int id, {
    String account = 'alice@sealbox.test',
    String folder = 'INBOX',
    String subject = 'Hello',
    int date = 1781500000,
    String? threadId,
    String? snippet,
    bool wasEncrypted = false,
    bool decrypted = false,
    String? decryptError,
  }) => frb.MessageSummary(
    id: id,
    account: account,
    folder: folder,
    uid: id,
    messageId: 'm$id@sealbox.test',
    from: const frb.Address(name: 'Bob', address: 'bob@sealbox.test'),
    to: [frb.Address(address: account)],
    cc: const [],
    subject: subject,
    date: date,
    receivedAt: date,
    flags: const [],
    seen: false,
    wasEncrypted: wasEncrypted,
    decrypted: decrypted,
    wasSigned: false,
    signature: const frb.SignatureSummary(
      status: frb.SigState.none,
      keyChanged: false,
      signerVerified: false,
    ),
    protectedSubject: false,
    attachmentCount: 0,
    rawSize: 100,
    decryptError: decryptError,
    inReplyTo: const [],
    references: const [],
    threadId: threadId ?? 'm$id@sealbox.test',
    snippet: snippet,
  );

  /// `getMessage`'s answer for [s] with [text] as its body.
  static frb.MessageDetail detail(frb.MessageSummary s, {String? text}) => frb.MessageDetail(
    summary: s,
    text: text,
    attachments: const [],
    inReplyTo: s.inReplyTo,
    references: s.references,
  );

  static frb.SyncEvent progress(frb.SyncProgress p) =>
      frb.SyncEvent(kind: frb.SyncEventKind.progress, progress: p);

  static frb.SyncEvent done(frb.SyncReport r) =>
      frb.SyncEvent(kind: frb.SyncEventKind.done, report: r);

  static frb.SyncReport report(
    String email, {
    int newMessages = 0,
    List<frb.FolderSync> folders = const [],
  }) => frb.SyncReport(
    account: email,
    new_: newMessages,
    decrypted: 0,
    failed: 0,
    folders: folders,
    newIds: Int64List(0),
  );
}
