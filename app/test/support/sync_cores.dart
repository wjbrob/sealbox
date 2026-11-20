import 'dart:async';

import 'package:sealbox_app/src/core/models.dart';

import 'golden_core.dart';

// Deterministic sync states for goldens and the accessibility fixtures: GoldenCore with its
// `syncScript` / `backfillScript` hooks set so the inbox's automatic first sync (or the
// background backfill after it) stops mid-way and stays there.

const _gmail = 'acct-1';
const _gmailAddress = 'alice.rivera@gmail.com';

/// A run that has stored [event]'s batch and holds (never finishes).
Stream<SyncEvent> _holding(SyncEvent event) {
  late final StreamController<SyncEvent> c;
  c = StreamController<SyncEvent>(onListen: () => c.add(event));
  return c.stream;
}

/// The automatic first sync of the Gmail account mid-way: the first 200 of its newest 500
/// stored (10,000 on the server).
GoldenCore syncingCore() => GoldenCore()
  ..syncScript = (_) => _holding(
    const SyncEvent.progress(
      SyncProgress(
        account: _gmailAddress,
        folder: 'INBOX',
        phase: SyncPhase.initial,
        fetched: 200,
        stored: 200,
        planned: 500,
        totalKnown: 10000,
        local: 200,
        moreToBackfill: true,
      ),
    ),
  );

/// After a first sync that left older Gmail mail on the server: the background backfill has
/// stored 4,200 of the 10,000.
GoldenCore backfillCore() {
  final core = GoldenCore();
  core.syncScript = (id) => Stream.value(
    SyncEvent.done(
      AccountSyncOutcome(
        account: id == _gmail ? _gmailAddress : id,
        newMessages: id == _gmail ? 500 : 0,
        moreToBackfill: id == _gmail,
      ),
    ),
  );
  core.backfillScript = (_, _) => _holding(
    const SyncEvent.progress(
      SyncProgress(
        account: _gmailAddress,
        folder: 'INBOX',
        phase: SyncPhase.backfill,
        fetched: 200,
        stored: 200,
        planned: 1000,
        totalKnown: 10000,
        local: 4200,
        moreToBackfill: true,
      ),
    ),
  );
  return core;
}
