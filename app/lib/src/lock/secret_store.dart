import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Small key/value store for the app lock: the profile key, the PIN verifier
/// and lock settings.
abstract class SecretStore {
  /// Human-readable backend name ("Android Keystore", "file in the profile", …).
  String get backend;

  /// True when values are protected by the OS keystore (Android Keystore,
  /// iOS/macOS Keychain, Secret Service / libsecret, Windows Credential
  /// Manager). Only such a store may hold the profile key.
  bool get hardwareBacked;

  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// `flutter_secure_storage`: Android Keystore (AES-GCM, RSA-OAEP wrapped key),
/// iOS/macOS Keychain (this device only, after first unlock), libsecret on
/// Linux, Credential Manager / DPAPI on Windows.
class SecureSecretStore implements SecretStore {
  SecureSecretStore() : _s = const FlutterSecureStorage(
         iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
         mOptions: MacOsOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
       );

  final FlutterSecureStorage _s;

  @override
  String get backend {
    if (Platform.isAndroid) return 'Android Keystore';
    if (Platform.isIOS) return 'iOS Keychain';
    if (Platform.isMacOS) return 'macOS Keychain';
    if (Platform.isLinux) return 'Secret Service (libsecret)';
    if (Platform.isWindows) return 'Windows Credential Manager';
    return 'secure storage';
  }

  @override
  bool get hardwareBacked => true;

  @override
  Future<String?> read(String key) => _s.read(key: key);

  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _s.delete(key: key);

  /// One write + read round trip. Linux without a running Secret Service
  /// (headless sessions, Xvfb) fails here; the caller falls back.
  Future<bool> probe() async {
    const k = 'sealbox.probe';
    try {
      await _s.write(key: k, value: '1');
      final ok = await _s.read(key: k) == '1';
      await _s.delete(key: k);
      return ok;
    } catch (_) {
      return false;
    }
  }
}

/// Fallback when no OS keystore is reachable: a 0600 JSON file in the profile
/// directory. It holds the PIN verifier and settings only — never the
/// profile key ([hardwareBacked] is false, so the controller refuses).
class FileSecretStore implements SecretStore {
  FileSecretStore(String dir, {this.reviewProfile = false})
    : _file = File('$dir${Platform.pathSeparator}applock.json');

  /// Review runs only (`SEALBOX_REVIEW`, throw-away profiles): the raw key is
  /// kept next to the profile so the scripted loop can open a keyed profile
  /// without touching the user's keyring. Never used otherwise.
  final bool reviewProfile;

  final File _file;

  @override
  String get backend => reviewProfile
      ? 'review profile file (test only)'
      : 'file in the profile (no OS keystore reachable)';

  @override
  bool get hardwareBacked => reviewProfile;

  Future<Map<String, dynamic>> _load() async {
    try {
      if (!await _file.exists()) return {};
      final v = jsonDecode(await _file.readAsString());
      return v is Map<String, dynamic> ? v : {};
    } catch (_) {
      return {};
    }
  }

  Future<void> _save(Map<String, dynamic> m) async {
    await _file.parent.create(recursive: true);
    await _file.writeAsString(jsonEncode(m), flush: true);
    if (!Platform.isWindows) {
      await Process.run('chmod', ['600', _file.path]);
    }
  }

  @override
  Future<String?> read(String key) async => (await _load())[key] as String?;

  @override
  Future<void> write(String key, String value) async {
    final m = await _load();
    m[key] = value;
    await _save(m);
  }

  @override
  Future<void> delete(String key) async {
    final m = await _load();
    if (m.remove(key) != null) await _save(m);
  }
}

/// In-memory store for tests (behaves like a keystore-backed one by default).
class MemorySecretStore implements SecretStore {
  MemorySecretStore({this.hardwareBacked = true});

  final Map<String, String> values = {};

  @override
  final bool hardwareBacked;

  @override
  String get backend => 'memory (test)';

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);
}
