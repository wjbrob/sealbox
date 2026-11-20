import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/core/signer_mismatch.dart';
import 'package:sealbox_app/src/widgets/lock_badge.dart';

import 'helpers.dart';

// R4 (docs/THREAT_MODEL.md §6): a good signature by a key that belongs to another address
// than From is an amber "signed by X — but sent by Y" with an explanation, never the green
// "signed by X". FakeCore's sample (FakeCore.signerMismatchSampleId, "Review samples",
// listed under "All mail") is Bob's mail signed with accounts@nakamura-billing.example's key.

const bob = Contact(email: 'bob@sealbox.test', name: 'Bob Nakamura');
const me = Contact(email: 'alice.rivera@gmail.com', name: 'Alice Rivera');
const carolFingerprint = '2C7D9A1F4E6B8035C1D2E3F4A5B6C7D8E9F0A1B2';

Message signed({
  String id = 'x',
  Contact from = bob,
  String? signerAddress = 'bob@sealbox.test',
  String? signer = '9F4B2E1C7A5D30186B2F4E9C1D7A3B5F0E6C8D2A',
  SignatureState signature = SignatureState.good,
  EncryptionState state = EncryptionState.encrypted,
  bool signerVerified = false,
  String folder = 'INBOX',
}) => Message(
  id: id,
  threadId: 't-$id',
  accountId: 'acct-1',
  from: from,
  to: const [me],
  subject: 'Subject $id',
  body: 'Body of $id.',
  date: DateTime.now().subtract(const Duration(minutes: 30)),
  state: state,
  signer: signer,
  signerAddress: signerAddress,
  signatureState: signature,
  signerVerified: signerVerified,
  folder: folder,
);

/// FakeCore plus a few INBOX conversations of the test's own.
class _Core extends FakeCore {
  _Core(this.extra) : super(latency: Duration.zero);

  final List<Message> extra;

  List<MailThread> get _extraThreads => [
    for (final m in extra)
      MailThread(id: m.threadId, subject: m.subject, accountId: m.accountId, messages: [m]),
  ];

  @override
  Future<List<MailThread>> listThreads() async => [
    ...await super.listThreads(),
    ..._extraThreads,
  ]..sort((a, b) => b.latest.date.compareTo(a.latest.date));

  @override
  Future<MailThread?> getThread(String threadId) async {
    for (final t in _extraThreads) {
      if (t.id == threadId) return t;
    }
    return super.getThread(threadId);
  }
}

StatusChip chipOf(WidgetTester tester, String messageId) =>
    tester.widget<StatusChip>(find.byKey(ValueKey('message-signature-$messageId')));

Future<void> openThread(WidgetTester tester, FakeCore core, String threadId) async {
  setSurface(tester, phone);
  await tester.pumpWidget(buildApp(core: core, initialLocation: '/inbox/t/$threadId'));
  await tester.pumpAndSettle();
}

void main() {
  group('signerMismatch()', () {
    test('the key of the From address: none (case and spaces do not matter)', () {
      expect(signerMismatch(signed()), isNull);
      expect(signerMismatch(signed(signerAddress: '  Bob@Sealbox.TEST ')), isNull);
    });

    test('another address\'s key: signer, sender, the chip label and its explanation', () {
      final x = signerMismatch(signed(signerAddress: 'mallory@example.net'))!;
      expect((x.signer, x.sender), ('mallory@example.net', 'bob@sealbox.test'));
      expect(x.label, 'signed by mallory@example.net — but sent by bob@sealbox.test');
      expect(
        x.explanation,
        contains('a key that belongs to mallory@example.net, not to the sender bob@sealbox.test'),
      );
      expect(x.explanation, contains('does not show that bob@sealbox.test wrote this message'));
    });

    test('only good signatures; bad and unknown-key ones keep their own chips', () {
      for (final s in [SignatureState.bad, SignatureState.unknownKey, SignatureState.none]) {
        final m = signed(signerAddress: 'mallory@example.net', signature: s);
        expect(signerMismatch(m), isNull, reason: '$s');
      }
    });

    test('a key the engine knows no address for: unchanged', () {
      expect(signerMismatch(signed(signerAddress: null)), isNull);
      expect(signerMismatch(signed(signerAddress: '   ')), isNull);
    });

    test('a key the user verified for another address counts as that address\'s key', () {
      const carol = ContactKey(
        address: 'carol@proton.me',
        hasKey: true,
        source: KeySource.directory,
        fingerprint: '2C7D 9A1F 4E6B 8035 C1D2 E3F4 A5B6 C7D8 E9F0 A1B2',
        verified: true,
      );
      final m = signed(signerAddress: null, signer: carolFingerprint);
      expect(
        signerMismatch(m, contacts: const [carol])?.label,
        'signed by carol@proton.me — but sent by bob@sealbox.test',
      );
      // Even where the engine maps the key to the From address.
      final mapped = signed(signer: carolFingerprint);
      expect(signerMismatch(mapped, contacts: const [carol])?.signer, 'carol@proton.me');
      // Not verified: the engine's address decides alone.
      final unverified = ContactKey(
        address: carol.address,
        hasKey: true,
        source: carol.source,
        fingerprint: carol.fingerprint,
      );
      expect(signerMismatch(m, contacts: [unverified]), isNull);
    });

    test('the key the user verified for this sender, and the user\'s own addresses: none', () {
      expect(signerMismatch(signed(signerAddress: 'bob@old.example', signerVerified: true)), isNull);
      final own = {'alice.rivera@gmail.com', 'alice@fastmail.com'};
      final sentCopy = signed(
        from: const Contact(email: 'alice@fastmail.com'),
        signerAddress: 'alice.rivera@gmail.com',
        folder: 'Sent',
      );
      expect(signerMismatch(sentCopy, own: own), isNull);
      // Somebody else's mail signed with our key is still a mismatch.
      final ours = signed(signerAddress: 'alice.rivera@gmail.com');
      expect(signerMismatch(ours, own: own)?.signer, 'alice.rivera@gmail.com');
    });
  });

  group('thread view', () {
    testWidgets('good signature by the sender\'s key: the green "signed by" chip', (tester) async {
      await openThread(tester, FakeCore(latency: Duration.zero), 't-budget');
      final chip = chipOf(tester, 'm-1');
      expect(chip.label, 'signed by bob@sealbox.test');
      expect(chip.icon, Icons.verified_outlined);
      expect(chip.color, LockPalette.light.encrypted);
      expect(find.byKey(const ValueKey('message-signer-mismatch-m-1')), findsNothing);
    });

    testWidgets('signed with another address\'s key: amber chip with the explanation as tooltip', (
      tester,
    ) async {
      await openThread(tester, FakeCore(latency: Duration.zero), 't-signer-mismatch');
      const id = FakeCore.signerMismatchSampleId;
      expect(find.byKey(const ValueKey('message-signer-mismatch-$id')), findsOneWidget);
      final chip = chipOf(tester, id);
      expect(chip.label, 'signed by accounts@nakamura-billing.example — but sent by bob@sealbox.test');
      expect(chip.icon, Icons.gpp_maybe_outlined);
      expect(chip.color, LockPalette.light.plaintext, reason: 'amber, the key-change warning tone');
      const why = SignerMismatch(
        signer: 'accounts@nakamura-billing.example',
        sender: 'bob@sealbox.test',
      );
      expect(chip.tooltip, startsWith(why.explanation));
      expect(chip.tooltip, contains('Key …6C8B0E42'));
      expect(find.byTooltip(chip.tooltip!), findsOneWidget);
      // No green chip, no "Verified", and the lock badge still says "Encrypted".
      expect(find.textContaining('signed by accounts@nakamura-billing.example'), findsOneWidget);
      expect(find.text('signed by accounts@nakamura-billing.example'), findsNothing);
      expect(find.byKey(ValueKey('message-verified-$id')), findsNothing);
      expect(find.byKey(const ValueKey('lock-badge-encrypted')), findsOneWidget);
    });

    testWidgets('unknown key: unchanged ("signed by an unknown key")', (tester) async {
      final core = _Core([
        signed(
          id: 'unknown',
          signature: SignatureState.unknownKey,
          state: EncryptionState.plaintext,
          signer: '1A2B3C4D5E6F7081',
          signerAddress: null,
        ),
      ]);
      await openThread(tester, core, 't-unknown');
      final chip = chipOf(tester, 'unknown');
      expect(chip.label, 'signed by an unknown key');
      expect(chip.icon, Icons.help_outline);
      expect(find.byKey(const ValueKey('message-signer-mismatch-unknown')), findsNothing);
    });

    testWidgets('signed-only mail signed by someone else: "Not encrypted" + the amber chip', (
      tester,
    ) async {
      final core = _Core([
        signed(
          id: 'release',
          from: const Contact(email: 'erik@posteo.de', name: 'Erik Lindqvist'),
          state: EncryptionState.signed,
          signerAddress: 'release-bot@builds.example',
        ),
      ]);
      await openThread(tester, core, 't-release');
      expect(find.byKey(const ValueKey('lock-badge-plaintext')), findsOneWidget);
      expect(
        find.byKey(const ValueKey('lock-badge-signed')),
        findsNothing,
        reason: '"Signed" means by the sender',
      );
      expect(
        chipOf(tester, 'release').label,
        'signed by release-bot@builds.example — but sent by erik@posteo.de',
      );
    });

    testWidgets('a key verified for Carol signing Bob\'s mail: amber even without an engine address', (
      tester,
    ) async {
      final core = _Core([signed(id: 'carolkey', signerAddress: null, signer: carolFingerprint)])
        ..simulateVerified('carol@proton.me');
      await openThread(tester, core, 't-carolkey');
      expect(
        chipOf(tester, 'carolkey').label,
        'signed by carol@proton.me — but sent by bob@sealbox.test',
      );
    });
  });

  group('inbox row', () {
    testWidgets('the row\'s signature glyph follows the chip; the lock badge keeps its meaning', (
      tester,
    ) async {
      setSurface(tester, desktop);
      final core = _Core([
        signed(
          id: 'release',
          from: const Contact(email: 'erik@posteo.de', name: 'Erik Lindqvist'),
          state: EncryptionState.signed,
          signerAddress: 'release-bot@builds.example',
        ),
      ]);
      await tester.pumpWidget(buildApp(core: core));
      await tester.pumpAndSettle();
      Finder inRow(String threadId, Finder f) =>
          find.descendant(of: find.byKey(ValueKey('thread-tile-$threadId')), matching: f);

      // Signed-only: "Not encrypted" badge + the amber glyph, with the mismatch as tooltip.
      expect(inRow('t-release', find.byKey(const ValueKey('lock-badge-plaintext'))), findsOneWidget);
      final glyph = inRow('t-release', find.byKey(const ValueKey('thread-signer-mismatch-t-release')));
      expect(glyph, findsOneWidget);
      const label = 'signed by release-bot@builds.example — but sent by erik@posteo.de';
      expect(find.descendant(of: glyph, matching: find.byTooltip(label)), findsOneWidget);
      final icon = tester.widget<Icon>(find.descendant(of: glyph, matching: find.byType(Icon)));
      expect(icon.color, LockPalette.light.plaintext);

      // Bob's own key: no glyph.
      const noGlyph = ValueKey('thread-signer-mismatch-t-budget');
      expect(inRow('t-budget', find.byKey(noGlyph)), findsNothing);

      // The encrypted sample under "All mail": the lock stays, the glyph sits beside it.
      final chip = find.byKey(const Key('folder-chip-all'));
      await tester.ensureVisible(chip);
      await tester.pumpAndSettle();
      await tester.tap(chip);
      await tester.pumpAndSettle();
      const sample = 't-signer-mismatch';
      expect(inRow(sample, find.byKey(const ValueKey('lock-badge-encrypted'))), findsOneWidget);
      expect(inRow(sample, find.byKey(const ValueKey('thread-signer-mismatch-$sample'))), findsOneWidget);
    });
  });
}
