import 'dart:async';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import 'biometrics.dart';
import 'secret_store.dart';

/// Where the app lock is in its life cycle.
enum LockPhase { initializing, setup, locked, unlocked }

/// App lock + the profile key (`ProfileKeySource::Raw`, gate G27).
///
/// * On first launch a random 32-byte profile key is generated once and kept in
///   the OS keystore through [SecretStore] (Android Keystore / iOS Keychain /
///   libsecret / Credential Manager). It is never written anywhere else: when
///   no keystore is reachable there is no raw key and the engine falls back to
///   its own default (the contract's `Keyring` / passphrase / `None`).
/// * The user sets a PIN (6–12 digits); a PBKDF2-HMAC-SHA256 verifier is
///   stored, never the PIN. Biometrics may unlock instead of the PIN.
/// * Only after an unlock does [takeProfileKey] hand the key to the engine's
///   `open`; the Dart copy is wiped right after.
///
/// The PIN gates the UI; it does not wrap the profile key (a 6-digit PIN would
/// be brute-forced offline in seconds). The key's protection is the keystore.
class AppLockController extends ChangeNotifier {
  AppLockController({
    required this.store,
    required String profileDir,
    this.biometrics = const NoBiometrics(),
    this.pinIterations = 60000,
    this.useIsolate = true,
    DateTime Function()? clock,
    Random? random,
  }) : _ns = 'sealbox.v1.${sha256.convert(utf8.encode(profileDir)).toString().substring(0, 16)}',
       _clock = clock ?? DateTime.now,
       _random = random ?? Random.secure();

  final SecretStore store;
  final Biometrics biometrics;
  final int pinIterations;

  /// PBKDF2 runs off the UI isolate in the app; tests run it inline.
  final bool useIsolate;
  final String _ns;
  final DateTime Function() _clock;
  final Random _random;

  static const minPinLength = 6;
  static const maxPinLength = 12;
  static const freeAttempts = 5;
  static const autoLockChoices = [1, 5, 15, 30, 60];

  LockPhase _phase = LockPhase.initializing;
  LockPhase get phase => _phase;
  bool get isLocked => _phase != LockPhase.unlocked;

  Uint8List? _profileKey;

  /// Whether a raw profile key exists in the keystore (false ⇒ engine default).
  bool get hasProfileKey => _hasKey;
  bool _hasKey = false;

  /// Where the key / verifier live, for Settings.
  String get keyStorage => store.hardwareBacked
      ? store.backend
      : 'not available — ${store.backend}';

  bool _biometricsAvailable = false;
  bool get biometricsAvailable => _biometricsAvailable;
  bool _biometricsEnabled = true;
  bool get biometricsEnabled => _biometricsAvailable && _biometricsEnabled;

  int _autoLockMinutes = 5;
  int get autoLockMinutes => _autoLockMinutes;

  int _failed = 0;
  int get failedAttempts => _failed;
  DateTime? _lockedOutUntil;

  /// Non-null while too many wrong PINs block further attempts.
  Duration? get lockoutRemaining {
    final u = _lockedOutUntil;
    if (u == null) return null;
    final d = u.difference(_clock());
    return d.isNegative ? null : d;
  }

  final Completer<void> _firstUnlock = Completer<void>();

  /// Completes on the first successful unlock (or setup) of this process.
  Future<void> get unlocked => _firstUnlock.future;

  DateTime _lastActivity = DateTime.fromMillisecondsSinceEpoch(0);
  DateTime? _backgroundSince;

  String _k(String name) => '$_ns.$name';

  Future<void> init() async {
    _lastActivity = _clock();
    final key = await store.read(_k('profile_key'));
    if (key != null) {
      _profileKey = base64Decode(key);
      _hasKey = true;
    } else if (store.hardwareBacked) {
      final fresh = Uint8List.fromList(List.generate(32, (_) => _random.nextInt(256)));
      await store.write(_k('profile_key'), base64Encode(fresh));
      _profileKey = fresh;
      _hasKey = true;
    }
    final settings = await store.read(_k('settings'));
    if (settings != null) {
      try {
        final m = jsonDecode(settings) as Map<String, dynamic>;
        _autoLockMinutes = (m['auto_lock_minutes'] as num?)?.toInt() ?? _autoLockMinutes;
        _biometricsEnabled = m['biometrics'] as bool? ?? true;
        _failed = (m['failed'] as num?)?.toInt() ?? 0;
        final until = (m['locked_out_until'] as num?)?.toInt();
        _lockedOutUntil = until == null ? null : DateTime.fromMillisecondsSinceEpoch(until);
      } catch (_) {}
    }
    _biometricsAvailable = await biometrics.available();
    final verifier = await store.read(_k('pin'));
    _phase = verifier == null ? LockPhase.setup : LockPhase.locked;
    notifyListeners();
  }

  Future<void> _saveSettings() => store.write(
    _k('settings'),
    jsonEncode({
      'auto_lock_minutes': _autoLockMinutes,
      'biometrics': _biometricsEnabled,
      'failed': _failed,
      'locked_out_until': _lockedOutUntil?.millisecondsSinceEpoch,
    }),
  );

  static bool isPlausiblePin(String pin) =>
      RegExp('^[0-9]{$minPinLength,$maxPinLength}\$').hasMatch(pin);

  /// First launch (or PIN change while unlocked): stores a verifier for [pin].
  Future<void> setPin(String pin) async {
    if (!isPlausiblePin(pin)) {
      throw ArgumentError('the PIN must be $minPinLength–$maxPinLength digits');
    }
    if (_phase != LockPhase.setup && _phase != LockPhase.unlocked) {
      throw StateError('unlock before changing the PIN');
    }
    final salt = Uint8List.fromList(List.generate(16, (_) => _random.nextInt(256)));
    final hash = await _derive(pin, salt, pinIterations);
    await store.write(
      _k('pin'),
      jsonEncode({
        'alg': 'pbkdf2-hmac-sha256',
        'iter': pinIterations,
        'salt': base64Encode(salt),
        'hash': base64Encode(hash),
      }),
    );
    _unlock();
  }

  /// `true` when [pin] matches. Wrong PINs count towards an escalating lockout.
  Future<bool> unlockWithPin(String pin) async {
    if (lockoutRemaining != null) return false;
    final raw = await store.read(_k('pin'));
    if (raw == null) return false;
    final v = jsonDecode(raw) as Map<String, dynamic>;
    final salt = base64Decode(v['salt'] as String);
    final expected = base64Decode(v['hash'] as String);
    final got = await _derive(pin, salt, (v['iter'] as num).toInt());
    if (_constantTimeEquals(got, expected)) {
      _failed = 0;
      _lockedOutUntil = null;
      await _saveSettings();
      _unlock();
      return true;
    }
    _failed++;
    if (_failed >= freeAttempts) {
      final secs = 30 * (1 << min(_failed - freeAttempts, 8));
      _lockedOutUntil = _clock().add(Duration(seconds: secs));
    }
    await _saveSettings();
    notifyListeners();
    return false;
  }

  Future<bool> unlockWithBiometrics() async {
    if (!biometricsEnabled || _phase != LockPhase.locked) return false;
    final ok = await biometrics.authenticate('Unlock Sealbox');
    if (ok) _unlock();
    return ok;
  }

  void _unlock() {
    _phase = LockPhase.unlocked;
    _lastActivity = _clock();
    _backgroundSince = null;
    if (!_firstUnlock.isCompleted) _firstUnlock.complete();
    notifyListeners();
  }

  /// "Lock now" and auto-lock. The UI is covered until the next unlock.
  void lock() {
    if (_phase != LockPhase.unlocked) return;
    _phase = LockPhase.locked;
    notifyListeners();
  }

  /// The raw profile key for the engine's `open` — only while unlocked, and
  /// only once: the Dart copy is zeroed after it was handed out.
  Uint8List? takeProfileKey() {
    if (_phase != LockPhase.unlocked) {
      throw StateError('the profile key is only released after an unlock');
    }
    final k = _profileKey;
    if (k == null) return null;
    final copy = Uint8List.fromList(k);
    k.fillRange(0, k.length, 0);
    _profileKey = null;
    return copy;
  }

  Future<void> setAutoLockMinutes(int minutes) async {
    _autoLockMinutes = minutes;
    await _saveSettings();
    notifyListeners();
  }

  Future<void> setBiometricsEnabled(bool on) async {
    _biometricsEnabled = on;
    await _saveSettings();
    notifyListeners();
  }

  // -- auto-lock ---------------------------------------------------------------

  void touch() => _lastActivity = _clock();

  /// Periodic check while in the foreground.
  void checkIdle() {
    if (_phase == LockPhase.unlocked &&
        _clock().difference(_lastActivity) >= Duration(minutes: _autoLockMinutes)) {
      lock();
    }
  }

  void onBackground() => _backgroundSince ??= _clock();

  void onForeground() {
    final since = _backgroundSince;
    _backgroundSince = null;
    if (since != null &&
        _phase == LockPhase.unlocked &&
        _clock().difference(since) >= Duration(minutes: _autoLockMinutes)) {
      lock();
      return;
    }
    checkIdle();
  }

  // -- PBKDF2 ------------------------------------------------------------------

  Future<Uint8List> _derive(String pin, Uint8List salt, int iterations) {
    final p = Uint8List.fromList(utf8.encode(pin));
    if (!useIsolate) return Future.value(pbkdf2(p, salt, iterations));
    return Isolate.run(() => pbkdf2(p, salt, iterations));
  }

  /// PBKDF2-HMAC-SHA256 (RFC 8018), one 32-byte block.
  static Uint8List pbkdf2(List<int> password, List<int> salt, int iterations) {
    final hmac = Hmac(sha256, password);
    var u = hmac.convert([...salt, 0, 0, 0, 1]).bytes;
    final out = Uint8List.fromList(u);
    for (var i = 1; i < iterations; i++) {
      u = hmac.convert(u).bytes;
      for (var j = 0; j < out.length; j++) {
        out[j] ^= u[j];
      }
    }
    return out;
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) {
      d |= a[i] ^ b[i];
    }
    return d == 0;
  }
}
