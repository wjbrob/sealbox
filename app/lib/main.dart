import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';

import 'src/app.dart';
import 'src/core/core_providers.dart';
import 'src/core/errors.dart';
import 'src/core/frb_core.dart';
import 'src/core/review_tour.dart';
import 'src/lock/app_lock.dart';
import 'src/lock/biometrics.dart';
import 'src/lock/lock_providers.dart';
import 'src/lock/lock_screen.dart';
import 'src/lock/secret_store.dart';
import 'src/router.dart';
import 'src/rust/api/sealbox.dart' as frb_smoke;
import 'src/rust/frb_generated.dart';

/// `--dart-define=SEALBOX_PROFILE=<dir>` pins the profile directory (tests, the
/// review loop). The `SEALBOX_PROFILE` environment variable does the same at
/// run time without a rebuild; otherwise the platform's application-support
/// directory is used (`~/.local/share/sealbox_app/profile` on Linux).
const String _profileDefine = String.fromEnvironment('SEALBOX_PROFILE');

/// `--dart-define=SEALBOX_REVIEW=fresh|seeded` (or the environment variable)
/// starts the scripted screen tour used by `scripts/review_desktop.sh`.
const String _reviewDefine = String.fromEnvironment('SEALBOX_REVIEW');

String _setting(String define, String envName) {
  if (define.isNotEmpty) return define;
  return Platform.environment[envName] ?? '';
}

Future<String> resolveProfileDir() async {
  final pinned = _setting(_profileDefine, 'SEALBOX_PROFILE');
  if (pinned.isNotEmpty) return pinned;
  final support = await getApplicationSupportDirectory();
  return '${support.path}${Platform.pathSeparator}profile';
}

/// `--dart-define=SEALBOX_APP_LOCK=off` (or the environment variable) starts
/// without the app lock. Only for scripted runs on hosts where nobody can type
/// a PIN; it is never the default.
const String _lockDefine = String.fromEnvironment('SEALBOX_APP_LOCK');

bool get appLockDisabled {
  final v = _setting(_lockDefine, 'SEALBOX_APP_LOCK').toLowerCase();
  return v == 'off' || v == '0' || v == 'false';
}

/// Rust-bridge start-up self-check: a real Ed25519/X25519 key generated in
/// Rust and its fingerprint handed back (`scripts/gate_flutter.sh` greps the
/// line). Runs before the lock screen, so it needs no engine.
Future<void> bridgeSelfCheck(String profileDir) async {
  final version = frb_smoke.sealboxVersion();
  final probe = await frb_smoke.generateIdentityPreview(
    name: 'Sealbox self-test',
    email: 'selftest@sealbox.test',
  );
  debugPrint(
    '[sealbox] bridge OK: core $version, profile $profileDir, '
    'test key fingerprint ${probe.fingerprint} '
    '(${probe.fingerprint.length} hex chars, created '
    '${DateTime.fromMillisecondsSinceEpoch(probe.createdAt.toInt() * 1000, isUtc: true).toIso8601String()})',
  );
}

/// Initialises the Rust bridge, opens the engine on the profile directory and
/// prints the start-up self-check line. [profileKey] is the app lock's raw
/// profile key (`ProfileKeySource::Raw`), handed over after an unlock.
Future<FrbCore> bootstrapCore({String? profileDir, Uint8List? profileKey}) async {
  await RustLib.init();
  final dir = profileDir ?? await resolveProfileDir();
  await bridgeSelfCheck(dir);
  return FrbCore.open(dir, profileKey: profileKey);
}

/// The app lock for [profileDir]: OS keystore through flutter_secure_storage
/// when reachable, otherwise a profile-local file for the PIN verifier only.
///
/// Review runs (`SEALBOX_REVIEW`) use throw-away profiles: their lock state
/// goes to the profile file, so scripted runs never write into the user's
/// login keyring.
Future<AppLockController> createAppLock(String profileDir, {bool throwAway = false}) async {
  final secure = SecureSecretStore();
  final SecretStore store;
  if (throwAway) {
    store = FileSecretStore(profileDir, reviewProfile: true);
  } else if (await secure.probe()) {
    store = secure;
  } else {
    debugPrint('[sealbox] app lock: no OS keystore reachable; PIN verifier kept in the profile, '
        'no raw profile key');
    store = FileSecretStore(profileDir);
  }
  final lock = AppLockController(
    store: store,
    profileDir: profileDir,
    biometrics: LocalAuthBiometrics(),
  );
  await lock.init();
  return lock;
}

/// Builds the provider container and runs the app. Returns the container so
/// integration tests and the review tour can drive the app programmatically.
/// With [lock] the app is covered by the lock screen whenever it is locked.
Future<ProviderContainer> runSealbox(
  CoreApi core, {
  String? initialLocation,
  AppLockController? lock,
}) async {
  final accounts = await core.listAccounts();
  final container = ProviderContainer(
    overrides: [
      coreApiProvider.overrideWithValue(core),
      initialLocationProvider.overrideWithValue(
        initialLocation ?? (accounts.isEmpty ? '/onboarding' : '/inbox'),
      ),
      if (lock != null) appLockProvider.overrideWithValue(lock),
    ],
  );
  runApp(
    UncontrolledProviderScope(
      container: container,
      child: const SealboxApp(),
    ),
  );
  return container;
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final dir = await resolveProfileDir();
  await bridgeSelfCheck(dir);
  final review = _setting(_reviewDefine, 'SEALBOX_REVIEW');
  final reviewing = review.isNotEmpty && review != '0' && review != 'false';

  // `SEALBOX_REVIEW=fake`: the review tour's states the real loop cannot provoke (a
  // correspondent's key changing, a key-transparency alert) on FakeCore's sample data.
  // Review tooling only; screenshots are named `fake-*`.
  if (review == 'fake') {
    final container = await runSealbox(ReviewTour.fakeCore());
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ReviewTour(container, mode: review).run();
    });
    return;
  }

  AppLockController? lock;
  Uint8List? profileKey;
  var shots = 0;
  if (!appLockDisabled) {
    lock = await createAppLock(dir, throwAway: reviewing);
    runApp(LockGateApp(lock: lock, theme: buildTheme(Brightness.light), darkTheme: buildTheme(Brightness.dark)));
    if (reviewing) shots = await ReviewTour.driveLock(lock);
    await lock.unlocked;
    profileKey = lock.takeProfileKey();
  }
  final FrbCore core;
  try {
    core = await FrbCore.open(dir, profileKey: profileKey);
  } on ProfileLockedException catch (e) {
    debugPrint('[sealbox] profile locked: ${friendlyError(e.detail)}');
    runApp(ProfileLockedApp(
      detail: friendlyError(e.detail),
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
    ));
    return;
  } finally {
    profileKey?.fillRange(0, profileKey.length, 0);
  }
  final container = await runSealbox(core, lock: lock);
  if (reviewing) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ReviewTour(container, mode: review, shotsBefore: shots).run();
    });
  }
}
