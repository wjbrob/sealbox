import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/errors.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/lock/app_lock.dart';
import 'package:sealbox_app/src/lock/biometrics.dart';
import 'package:sealbox_app/src/lock/lock_providers.dart';
import 'package:sealbox_app/src/lock/lock_screen.dart';
import 'package:sealbox_app/src/lock/secret_store.dart';
import 'package:sealbox_app/src/router.dart';

import 'helpers.dart';

AppLockController newLock(
  SecretStore store, {
  Biometrics biometrics = const NoBiometrics(),
  String dir = '/profiles/a',
  DateTime Function()? clock,
}) => AppLockController(
  store: store,
  profileDir: dir,
  biometrics: biometrics,
  pinIterations: 200,
  useIsolate: false,
  clock: clock,
);

/// The unlock path awaits the store a few times; give it frames, not just microtasks.
Future<void> pumpAsync(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump(const Duration(milliseconds: 50));
  }
  await tester.pumpAndSettle();
}

void main() {
  group('AppLockController', () {
    test('PBKDF2-HMAC-SHA256 matches the RFC 7914 §11 test vector', () {
      final out = AppLockController.pbkdf2(utf8.encode('passwd'), utf8.encode('salt'), 1);
      expect(
        out.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc',
      );
    });

    test('first launch: one 32-byte key in the keystore, PIN verifier (never the PIN)', () async {
      final store = MemorySecretStore();
      final lock = newLock(store);
      await lock.init();
      expect(lock.phase, LockPhase.setup);
      expect(lock.hasProfileKey, isTrue);
      await lock.setPin('135790');
      expect(lock.phase, LockPhase.unlocked);
      expect(store.values.values.any((v) => v.contains('135790')), isFalse);
      final key = lock.takeProfileKey()!;
      expect(key, hasLength(32));
      expect(lock.takeProfileKey(), isNull, reason: 'handed out once, Dart copy wiped');

      // Next launch: same key, locked until the PIN is entered.
      final again = newLock(store);
      await again.init();
      expect(again.phase, LockPhase.locked);
      expect(() => again.takeProfileKey(), throwsStateError);
      expect(await again.unlockWithPin('000000'), isFalse);
      expect(await again.unlockWithPin('135790'), isTrue);
      expect(again.takeProfileKey(), key);
    });

    test('profiles are namespaced; no keystore ⇒ no raw key is ever written', () async {
      final store = MemorySecretStore();
      final a = newLock(store, dir: '/p/a');
      await a.init();
      await a.setPin('111111');
      final b = newLock(store, dir: '/p/b');
      await b.init();
      expect(b.phase, LockPhase.setup);

      final file = MemorySecretStore(hardwareBacked: false);
      final c = newLock(file);
      await c.init();
      expect(c.hasProfileKey, isFalse);
      await c.setPin('222222');
      expect(c.takeProfileKey(), isNull);
      expect(file.values.keys.any((k) => k.endsWith('profile_key')), isFalse);
    });

    test('wrong PINs: escalating lockout after 5 attempts, persisted', () async {
      var now = DateTime(2026, 10, 27, 12);
      final store = MemorySecretStore();
      final lock = newLock(store, clock: () => now);
      await lock.init();
      await lock.setPin('135790');
      lock.lock();
      for (var i = 0; i < 5; i++) {
        expect(await lock.unlockWithPin('999999'), isFalse);
      }
      expect(lock.lockoutRemaining, isNotNull);
      expect(await lock.unlockWithPin('135790'), isFalse, reason: 'locked out even with the right PIN');
      final restarted = newLock(store, clock: () => now);
      await restarted.init();
      expect(restarted.lockoutRemaining, isNotNull, reason: 'a restart does not reset the lockout');
      now = now.add(const Duration(seconds: 31));
      expect(await restarted.unlockWithPin('135790'), isTrue);
      expect(restarted.failedAttempts, 0);
    });

    test('auto-lock after N minutes idle or in the background', () async {
      var now = DateTime(2026, 10, 27, 12);
      final lock = newLock(MemorySecretStore(), clock: () => now);
      await lock.init();
      await lock.setPin('135790');
      await lock.setAutoLockMinutes(5);
      now = now.add(const Duration(minutes: 4));
      lock.checkIdle();
      expect(lock.isLocked, isFalse);
      lock.touch();
      now = now.add(const Duration(minutes: 4));
      lock.checkIdle();
      expect(lock.isLocked, isFalse, reason: 'activity resets the timer');
      lock.onBackground();
      now = now.add(const Duration(minutes: 6));
      lock.onForeground();
      expect(lock.isLocked, isTrue);
    });

    test('biometrics unlock only when available and enabled', () async {
      final bio = FakeBiometrics();
      final lock = newLock(MemorySecretStore(), biometrics: bio);
      await lock.init();
      await lock.setPin('135790');
      lock.lock();
      expect(await lock.unlockWithBiometrics(), isTrue);
      lock.lock();
      await lock.setBiometricsEnabled(false);
      expect(await lock.unlockWithBiometrics(), isFalse);
      expect(bio.prompts, 1);
    });
  });

  test('ProfileLocked from the engine is recognised across the bridge', () {
    expect(ProfileLockedException.matches(Exception('AnyhowException(profile locked: wrong key)')), isTrue);
    expect(ProfileLockedException.matches(Exception('IMAP: connection refused')), isFalse);
  });

  group('lock screen', () {
    testWidgets('setup: digits only, both PINs must match, then unlocked', (tester) async {
      setSurface(tester, phone);
      final lock = newLock(MemorySecretStore());
      await lock.init();
      await tester.pumpWidget(MaterialApp(home: LockScreen(lock: lock)));
      expect(find.text('Protect Sealbox with a PIN'), findsOneWidget);
      expect(find.byKey(const Key('lock-key-storage')), findsOneWidget);
      FilledButton submit() => tester.widget<FilledButton>(find.byKey(const Key('lock-submit')));
      await tester.enterText(find.byKey(const Key('lock-pin')), '12ab34');
      await tester.pump();
      expect(submit().onPressed, isNull, reason: 'letters are filtered out → 4 digits');
      await tester.enterText(find.byKey(const Key('lock-pin')), '135790');
      await tester.enterText(find.byKey(const Key('lock-pin-confirm')), '135799');
      await tester.pump();
      await tester.tap(find.byKey(const Key('lock-submit')));
      await tester.pump();
      expect(find.text('The two PINs do not match'), findsOneWidget);
      await tester.enterText(find.byKey(const Key('lock-pin-confirm')), '135790');
      await tester.pump();
      await tester.tap(find.byKey(const Key('lock-submit')));
      await tester.pumpAndSettle();
      expect(lock.phase, LockPhase.unlocked);
    });

    testWidgets('"Lock now" in Settings covers the app; the PIN brings it back', (tester) async {
      setSurface(tester, phone);
      final lock = newLock(MemorySecretStore());
      await lock.init();
      await lock.setPin('135790');
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            coreApiProvider.overrideWithValue(FakeCore(latency: Duration.zero)),
            initialLocationProvider.overrideWithValue('/settings'),
            appLockProvider.overrideWithValue(lock),
          ],
          child: const SealboxApp(),
        ),
      );
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.byKey(const Key('settings-lock-now')),
        200,
        scrollable: find.descendant(of: find.byKey(const Key('settings-list')), matching: find.byType(Scrollable)).first,
      );
      expect(find.byKey(const Key('settings-auto-lock')), findsOneWidget);
      await Scrollable.ensureVisible(tester.element(find.byKey(const Key('settings-lock-now'))), alignment: 0.5);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('settings-lock-now')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('lock-screen')), findsOneWidget);
      expect(find.text('Sealbox is locked'), findsOneWidget);
      expect(find.text('Settings'), findsNothing, reason: 'the app is not painted while locked');

      await tester.enterText(find.byKey(const Key('lock-pin')), '000000');
      await tester.pump();
      await tester.tap(find.byKey(const Key('lock-submit')));
      await pumpAsync(tester);
      expect(lock.failedAttempts, 1);
      expect(find.byKey(const Key('lock-error')), findsOneWidget);
      await tester.enterText(find.byKey(const Key('lock-pin')), '135790');
      await tester.pump();
      await tester.tap(find.byKey(const Key('lock-submit')));
      await pumpAsync(tester);
      expect(find.byKey(const Key('lock-screen')), findsNothing);
      expect(find.text('Settings'), findsWidgets);
    });

    testWidgets('biometrics button only where available', (tester) async {
      setSurface(tester, phone);
      final lock = newLock(MemorySecretStore(), biometrics: FakeBiometrics(result: false));
      await lock.init();
      await lock.setPin('135790');
      lock.lock();
      await tester.pumpWidget(MaterialApp(home: LockScreen(lock: lock)));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('lock-biometric')), findsOneWidget);

      final noBio = newLock(MemorySecretStore(), dir: '/x');
      await noBio.init();
      await noBio.setPin('135790');
      noBio.lock();
      await tester.pumpWidget(MaterialApp(home: LockScreen(lock: noBio, key: UniqueKey())));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('lock-biometric')), findsNothing);
    });
  });
}
