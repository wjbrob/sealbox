import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/features/recovery/recovery_copy.dart';

import 'helpers.dart';

// G15 recovery UI (docs/RECOVERY.md "App flow") against FakeCore: the
// onboarding entry, phrase validation as you type, the documented error
// strings, the credential step, and device transfer.

Future<void> _openRestore(WidgetTester tester, FakeCore core) async {
  setSurface(tester, phone);
  await tester.pumpWidget(buildApp(core: core, initialLocation: '/onboarding'));
  await tester.pumpAndSettle();
  await tester.ensureVisible(find.text(RecoveryCopy.restoreAction));
  await tester.tap(find.text(RecoveryCopy.restoreAction));
  await tester.pumpAndSettle();
  expect(find.text(RecoveryCopy.restoreTitle), findsOneWidget);
}

Future<void> _fill(WidgetTester tester, String email, String phrase) async {
  await tester.enterText(find.byKey(const Key('restore-email')), email);
  await tester.enterText(find.byKey(const Key('restore-phrase')), phrase);
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('restore: server prefilled, phrase validated while typing', (tester) async {
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await _openRestore(tester, core);
    final server = tester.widget<TextField>(find.byKey(const Key('restore-server')));
    expect(server.controller!.text, 'https://sealbox.example');

    await _fill(tester, 'me@sealbox.test', 'abandon ' * 11 + 'notaword');
    expect(find.text('Word 12 is not in the word list.'), findsOneWidget);
    await _fill(tester, 'me@sealbox.test', '${'abandon ' * 11}abandon');
    expect(find.text(RecoveryCopy.wrongOrSwapped), findsOneWidget);
    expect(
      tester.widget<FilledButton>(find.byKey(const Key('restore-submit'))).onPressed,
      isNull,
    );
  });

  testWidgets('restore: wrong phrase (401) and missing backup use the documented strings',
      (tester) async {
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await _openRestore(tester, core);
    await _fill(tester, 'me@sealbox.test', FakeCore.createdPhrase.join(' '));
    await tester.tap(find.byKey(const Key('restore-submit')));
    await tester.pumpAndSettle();
    expect(find.text(RecoveryCopy.wrongPhrase), findsOneWidget);

    await _fill(tester, 'nobackup@sealbox.test', FakeCore.samplePhrase.join(' '));
    await tester.tap(find.byKey(const Key('restore-submit')));
    await tester.pumpAndSettle();
    expect(find.text(RecoveryCopy.noBackup), findsOneWidget);
    // Offers to look the key up in the mailbox.
    expect(find.byKey(const Key('restore-lookup-password')), findsOneWidget);
  });

  testWidgets('restore → credential step → inbox', (tester) async {
    final core = FakeCore(latency: Duration.zero, seeded: false);
    await _openRestore(tester, core);
    await _fill(tester, 'me@sealbox.test', FakeCore.samplePhrase.join(' '));
    await tester.tap(find.byKey(const Key('restore-submit')));
    await tester.pumpAndSettle();
    expect(find.text('Keys restored for me@sealbox.test'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('restore-password')), 'app-password');
    await tester.pump();
    await tester.tap(find.byKey(const Key('restore-credential-save')));
    await tester.pumpAndSettle();
    expect((await core.listAccounts()).map((a) => a.email), contains('me@sealbox.test'));
    expect(find.text('Inbox'), findsWidgets);
  });

  testWidgets('transfer: the setup code is shown in nine blocks with the instruction',
      (tester) async {
    setSurface(tester, desktop);
    final core = FakeCore(latency: Duration.zero);
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/settings/transfer'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('transfer-send')));
    await tester.pumpAndSettle();
    expect(find.text(RecoveryCopy.transferInstruction), findsOneWidget);
    expect(find.text('1742'), findsOneWidget);
    expect(find.text('4473'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('transfer-source')), 'setup.7f3a@sealbox.example');
    await tester.enterText(find.byKey(const Key('transfer-code')), '1234-5678');
    await tester.pump();
    expect(
      tester.widget<FilledButton>(find.byKey(const Key('transfer-import'))).onPressed,
      isNull,
    );
    await tester.enterText(
      find.byKey(const Key('transfer-code')),
      '1742-0398-5521-8806-3317-9045-6620-1189-4473',
    );
    await tester.pump();
    await tester.tap(find.byKey(const Key('transfer-import')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('transfer-imported')), findsOneWidget);
  });

  test('engine errors map to the documented strings', () {
    expect(
      friendlyRecoveryError(
        'AnyhowException(connection error: the backup server refused the recovery token (401))',
      ),
      RecoveryCopy.wrongPhrase,
    );
    expect(
      friendlyRecoveryError('invalid input: no backup for a@b.c on https://x (tried AB)'),
      RecoveryCopy.noBackup,
    );
    expect(
      friendlyRecoveryError('invalid input: no backup slot found for a@b.c: the key is not …'),
      RecoveryCopy.noBackup,
    );
    expect(
      friendlyRecoveryError('the recovery phrase checksum does not match'),
      RecoveryCopy.wrongOrSwapped,
    );
  });
}
