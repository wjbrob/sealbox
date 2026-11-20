import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/lock/app_lock.dart';
import 'package:sealbox_app/src/lock/lock_providers.dart';
import 'package:sealbox_app/src/lock/lock_screen.dart';
import 'package:sealbox_app/src/lock/secret_store.dart';

import 'helpers.dart';

// Review P6: the theme chosen in Settings is kept in the app lock's store (next to the
// live-updates choice) and the lock screen shown before the engine opens uses it, read before
// its first frame — a light app no longer opens behind a dark (system-theme) lock screen.

/// A store holding [mode] under the theme key (nothing for null).
MemorySecretStore storeWith(String? mode) {
  final s = MemorySecretStore();
  if (mode != null) s.values[themeModeStoreKey] = mode;
  return s;
}

/// The same entries in a new store object: what the next launch reads.
MemorySecretStore nextLaunch(MemorySecretStore s) => MemorySecretStore()..values.addAll(s.values);

ProviderContainer containerWith(SecretStore? store) =>
    ProviderContainer(overrides: [liveUpdatesStoreProvider.overrideWithValue(store)]);

Future<AppLockController> lockOn(SecretStore store) async {
  final lock = AppLockController(
    store: store,
    profileDir: '/profiles/theme',
    pinIterations: 200,
    useIsolate: false,
  );
  await lock.init();
  return lock;
}

Widget gate(AppLockController lock) => LockGateApp(
  lock: lock,
  theme: buildTheme(Brightness.light),
  darkTheme: buildTheme(Brightness.dark),
);

Brightness lockBrightness(WidgetTester tester) =>
    Theme.of(tester.element(find.byKey(const Key('lock-screen')))).brightness;

void systemBrightness(WidgetTester tester, Brightness b) {
  tester.platformDispatcher.platformBrightnessTestValue = b;
  addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
}

void main() {
  group('the stored theme', () {
    test('survives a new ProviderContainer (the next launch)', () async {
      final store = MemorySecretStore();
      final first = containerWith(store);
      expect(first.read(themeModeProvider), ThemeMode.system);
      await first.read(themeModeProvider.notifier).loaded;
      expect(first.read(themeModeProvider), ThemeMode.system, reason: 'nothing stored yet');
      await first.read(themeModeProvider.notifier).set(ThemeMode.dark);
      expect(first.read(themeModeProvider), ThemeMode.dark);
      first.dispose();
      expect(store.values[themeModeStoreKey], 'dark');

      // The next launch: a new store object over the same entries, read once.
      final relaunched = nextLaunch(store);
      final second = containerWith(relaunched);
      await second.read(themeModeProvider.notifier).loaded;
      expect(second.read(themeModeProvider), ThemeMode.dark);
      await second.read(themeModeProvider.notifier).set(ThemeMode.light);
      second.dispose();
      expect(relaunched.values[themeModeStoreKey], 'light');

      // Same process, same store (the lock screen read it): known before any await.
      final third = containerWith(relaunched);
      expect(third.read(themeModeProvider), ThemeMode.light);
      third.dispose();
    });

    test('the last of quick successive choices is the one stored', () async {
      final store = _GatedWriteStore();
      final c = containerWith(store);
      final ctl = c.read(themeModeProvider.notifier);
      final first = ctl.set(ThemeMode.dark);
      final second = ctl.set(ThemeMode.light);
      await Future<void>.delayed(Duration.zero);
      store.releaseFirstWrite();
      await Future.wait([first, second]);
      expect(store.values[themeModeStoreKey], 'light');
      expect(c.read(themeModeProvider), ThemeMode.light);
      c.dispose();
    });

    test('a choice made while the stored one is being read wins', () async {
      final store = _GatedReadStore('dark');
      final c = containerWith(store);
      final ctl = c.read(themeModeProvider.notifier);
      await ctl.set(ThemeMode.light);
      store.release();
      await ctl.loaded;
      expect(c.read(themeModeProvider), ThemeMode.light);
      c.dispose();
    });

    test('without a store (no app lock) it lasts for the session', () async {
      final c = containerWith(null);
      await c.read(themeModeProvider.notifier).set(ThemeMode.dark);
      expect(c.read(themeModeProvider), ThemeMode.dark);
      c.dispose();
    });

    test('an unreadable or unwritable store leaves System / the session choice', () async {
      final c = containerWith(_BrokenStore());
      await c.read(themeModeProvider.notifier).loaded;
      expect(c.read(themeModeProvider), ThemeMode.system);
      await c.read(themeModeProvider.notifier).set(ThemeMode.dark);
      expect(c.read(themeModeProvider), ThemeMode.dark);
      c.dispose();
    });

    test('garbage in the store is ignored', () async {
      final c = containerWith(storeWith('sepia'));
      await c.read(themeModeProvider.notifier).loaded;
      expect(c.read(themeModeProvider), ThemeMode.system);
      c.dispose();
    });
  });

  group('the lock screen before the engine opens', () {
    testWidgets('is light when Light is chosen, though the system is dark', (tester) async {
      systemBrightness(tester, Brightness.dark);
      final lock = await lockOn(storeWith('light'));
      await tester.pumpWidget(gate(lock));
      await tester.pumpAndSettle();
      expect(lockBrightness(tester), Brightness.light);
      expect(find.text('Protect Sealbox with a PIN'), findsOneWidget);
    });

    testWidgets('is dark when Dark is chosen, though the system is light', (tester) async {
      systemBrightness(tester, Brightness.light);
      final lock = await lockOn(storeWith('dark'));
      await tester.pumpWidget(gate(lock));
      await tester.pumpAndSettle();
      expect(lockBrightness(tester), Brightness.dark);
    });

    testWidgets('follows the system while nothing is chosen, and a choice at once', (tester) async {
      systemBrightness(tester, Brightness.dark);
      final store = storeWith(null);
      final lock = await lockOn(store);
      await tester.pumpWidget(gate(lock));
      await tester.pumpAndSettle();
      expect(lockBrightness(tester), Brightness.dark);
      // The review tour chooses Light while the gate is on screen.
      await ThemePreference.of(store).set(ThemeMode.light);
      await tester.pumpAndSettle();
      expect(lockBrightness(tester), Brightness.light);
      expect(store.values[themeModeStoreKey], 'light');
    });

    testWidgets('holds its first frame until the stored theme is read', (tester) async {
      systemBrightness(tester, Brightness.dark);
      final store = _GatedReadStore('light', gateOnlyTheme: true);
      final lock = await lockOn(store);
      await tester.pumpWidget(gate(lock));
      await tester.pump();
      expect(tester.binding.sendFramesToEngine, isFalse, reason: 'no frame in the wrong theme');
      store.release();
      await tester.pumpAndSettle();
      expect(tester.binding.sendFramesToEngine, isTrue);
      expect(lockBrightness(tester), Brightness.light);
    });

    testWidgets('a store that does not answer holds the first frame for themeWait at most', (
      tester,
    ) async {
      systemBrightness(tester, Brightness.dark);
      final store = _GatedReadStore('light', gateOnlyTheme: true);
      final lock = await lockOn(store);
      await tester.pumpWidget(gate(lock));
      await tester.pump(LockGateApp.themeWait - const Duration(milliseconds: 10));
      expect(tester.binding.sendFramesToEngine, isFalse);
      await tester.pump(const Duration(milliseconds: 20));
      await tester.pumpAndSettle();
      expect(tester.binding.sendFramesToEngine, isTrue, reason: 'never a blank window for long');
      expect(lockBrightness(tester), Brightness.dark, reason: 'the system theme meanwhile');
      store.release();
      await tester.pumpAndSettle();
      expect(lockBrightness(tester), Brightness.light, reason: 'applied as soon as read');
    });

    testWidgets('the app opened after the unlock starts in the same theme (no flash)', (
      tester,
    ) async {
      systemBrightness(tester, Brightness.dark);
      final store = storeWith('light');
      final lock = await lockOn(store);
      await tester.pumpWidget(gate(lock));
      await tester.pumpAndSettle();
      await lock.setPin('135790');
      final c = ProviderContainer(
        overrides: [
          coreApiProvider.overrideWithValue(FakeCore(latency: Duration.zero)),
          appLockProvider.overrideWithValue(lock),
        ],
      );
      addTearDown(c.dispose);
      expect(c.read(themeModeProvider), ThemeMode.light, reason: 'before any await');
    });
  });

  testWidgets('Settings: choosing Dark applies and stores it', (tester) async {
    systemBrightness(tester, Brightness.light);
    setSurface(tester, desktop);
    final store = storeWith('light');
    await tester.pumpWidget(
      buildApp(
        core: FakeCore(latency: Duration.zero),
        initialLocation: '/settings',
        overrides: [liveUpdatesStoreProvider.overrideWithValue(store)],
      ),
    );
    await tester.pumpAndSettle();
    final row = find.byKey(const Key('settings-theme'));
    await tester.scrollUntilVisible(row, 200, scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    expect(tester.widget<SegmentedButton<ThemeMode>>(row).selected, {ThemeMode.light});
    await tester.tap(find.descendant(of: row, matching: find.text('Dark')));
    await tester.pumpAndSettle();
    expect(store.values[themeModeStoreKey], 'dark');
    expect(Theme.of(tester.element(row)).brightness, Brightness.dark);
  });
}

/// Holds reads until [release] (a slow OS keystore); with [gateOnlyTheme] only the theme
/// key waits (the lock's own entries answer at once, so the lock can initialise).
class _GatedReadStore extends MemorySecretStore {
  _GatedReadStore(String value, {this.gateOnlyTheme = false}) {
    values[themeModeStoreKey] = value;
  }

  final bool gateOnlyTheme;
  final _gate = Completer<void>();

  void release() => _gate.complete();

  /// Returns what was stored when the read began, like a keystore round trip that a write
  /// issued meanwhile does not change.
  @override
  Future<String?> read(String key) async {
    if (gateOnlyTheme && key != themeModeStoreKey) return values[key];
    final value = values[key];
    await _gate.future;
    return value;
  }
}

/// Holds its first write until [releaseFirstWrite]; later writes go through at once.
class _GatedWriteStore extends MemorySecretStore {
  final _gate = Completer<void>();
  var _writes = 0;

  void releaseFirstWrite() => _gate.complete();

  @override
  Future<void> write(String key, String value) async {
    if (_writes++ == 0) await _gate.future;
    await super.write(key, value);
  }
}

class _BrokenStore extends MemorySecretStore {
  @override
  Future<String?> read(String key) => Future.error(StateError('keyring locked'));

  @override
  Future<void> write(String key, String value) => Future.error(StateError('keyring locked'));
}
