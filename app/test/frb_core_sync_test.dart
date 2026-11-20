import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/core_api.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/rust/api/engine.dart' as frb;

import 'support/fake_frb_engine.dart';

// The sync progress API (docs/PERFORMANCE.md, "What the app does with it"): `FrbCore` maps the
// bridge's `SyncEvent` stream onto `CoreMailOps.syncAccount` / `backfill`, and a `CoreApi`
// without the engine ops gets inert defaults.

/// A `CoreApi` with none of the op interfaces (only the base seam).
class _BareCore implements CoreApi {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

frb.SyncProgress _batch({
  frb.SyncPhase phase = frb.SyncPhase.initial,
  int fetched = 200,
  int planned = 500,
  int local = 200,
  bool more = true,
}) => frb.SyncProgress(
  account: 'alice@sealbox.test',
  folder: 'INBOX',
  phase: phase,
  fetched: fetched,
  stored: fetched,
  planned: planned,
  totalKnown: 10000,
  local: local,
  moreToBackfill: more,
);

void main() {
  test('syncAccount: a progress event per stored batch, then the outcome', () async {
    final engine = FakeFrbEngine()
      ..onSync = (email) => Stream.fromIterable([
        FakeFrbEngine.progress(_batch()),
        FakeFrbEngine.progress(_batch(fetched: 400, local: 400)),
        FakeFrbEngine.done(
          FakeFrbEngine.report(
            email,
            newMessages: 500,
            folders: const [
              frb.FolderSync(
                name: 'INBOX',
                new_: 500,
                uidvalidityReset: false,
                moreToBackfill: true,
                olderPending: 9500,
                removed: 0,
                flagsChanged: 0,
              ),
              frb.FolderSync(
                name: 'Sent',
                new_: 0,
                uidvalidityReset: false,
                moreToBackfill: false,
                olderPending: 0,
                removed: 0,
                flagsChanged: 0,
              ),
            ],
          ),
        ),
      ]);
    final events = await FrbCore(engine).syncAccount('alice@sealbox.test').toList();
    expect(engine.runs, ['sync alice@sealbox.test']);
    expect(events, hasLength(3));
    final p = events[1].progress!;
    expect(
      (p.account, p.folder, p.phase, p.fetched, p.stored, p.planned, p.totalKnown, p.local),
      ('alice@sealbox.test', 'INBOX', SyncPhase.initial, 400, 400, 500, 10000, 400),
    );
    expect(p.moreToBackfill, isTrue);
    expect(events.take(2).every((e) => !e.isDone), isTrue);
    final o = events.last.outcome!;
    expect((o.account, o.newMessages, o.ok), ('alice@sealbox.test', 500, true));
    expect(o.moreToBackfill, isTrue, reason: 'INBOX still has older mail');
    expect(o.olderPending, 9500, reason: 'summed over the folders that counted');
  });

  test('backfill passes the bound through and maps the backfill phase', () async {
    final engine = FakeFrbEngine()
      ..onBackfill = (email, max) => Stream.fromIterable([
        FakeFrbEngine.progress(
          _batch(phase: frb.SyncPhase.backfill, fetched: 200, planned: 1000, local: 700),
        ),
        FakeFrbEngine.done(
          FakeFrbEngine.report(
            email,
            newMessages: 1000,
            folders: const [
              frb.FolderSync(
                name: 'INBOX',
                new_: 1000,
                uidvalidityReset: false,
                moreToBackfill: false,
                olderPending: 0,
                removed: 0,
                flagsChanged: 0,
              ),
            ],
          ),
        ),
      ]);
    final core = FrbCore(engine);
    final events = await core.backfill('alice@sealbox.test', max: 1000).toList();
    await core.backfill('alice@sealbox.test').drain<void>();
    expect(engine.runs, ['backfill alice@sealbox.test 1000', 'backfill alice@sealbox.test all']);
    expect(events.first.progress!.phase, SyncPhase.backfill);
    expect(events.first.progress!.local, 700);
    final o = events.last.outcome!;
    expect((o.newMessages, o.moreToBackfill, o.olderPending), (1000, false, 0));
  });

  test('an engine failure is the stream error; a malformed event fails it too', () async {
    final engine = FakeFrbEngine()
      ..onSync = (_) => Stream.error(Exception('IMAP: connection refused'));
    final core = FrbCore(engine);
    await expectLater(
      core.syncAccount('alice@sealbox.test'),
      emitsError(isA<Exception>().having((e) => '$e', 'message', contains('connection refused'))),
    );
    engine.onSync = (_) => Stream.value(const frb.SyncEvent(kind: frb.SyncEventKind.done));
    await expectLater(core.syncAccount('alice@sealbox.test'), emitsError(isA<StateError>()));
  });

  test('syncAll carries the backfill state of every account', () async {
    final engine = _SyncAllEngine();
    final outcome = await FrbCore(engine).syncAll();
    expect(outcome.accounts, hasLength(2));
    expect(outcome.accounts[0].moreToBackfill, isTrue);
    expect(outcome.accounts[0].olderPending, 120);
    expect(outcome.accounts[1].ok, isFalse);
    expect(outcome.accounts[1].moreToBackfill, isFalse);
  });

  test('a core without the engine ops: a sync and a backfill store nothing', () async {
    final CoreApi core = _BareCore();
    final sync = await core.syncAccount('a@x').toList();
    final backfill = await core.backfill('a@x', max: 10).toList();
    for (final events in [sync, backfill]) {
      expect(events, hasLength(1));
      expect(events.single.outcome!.account, 'a@x');
      expect(events.single.outcome!.moreToBackfill, isFalse);
    }
  });
}

class _SyncAllEngine extends FakeFrbEngine {
  @override
  Future<List<frb.AccountSyncResult>> syncAll() async => [
    frb.AccountSyncResult(
      account: 'alice@sealbox.test',
      report: FakeFrbEngine.report(
        'alice@sealbox.test',
        newMessages: 3,
        folders: const [
          frb.FolderSync(
            name: 'INBOX',
            new_: 3,
            uidvalidityReset: false,
            moreToBackfill: true,
            olderPending: 120,
            removed: 0,
            flagsChanged: 0,
          ),
        ],
      ),
    ),
    const frb.AccountSyncResult(account: 'bob@sealbox.test', error: 'IMAP: login rejected'),
  ];
}
