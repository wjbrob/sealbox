import 'dart:io';

import 'package:local_auth/local_auth.dart';

/// Fingerprint / face unlock where the platform has it (`local_auth`:
/// Android, iOS, macOS, Windows). Linux has no backend: PIN only.
abstract class Biometrics {
  Future<bool> available();
  Future<bool> authenticate(String reason);
}

class LocalAuthBiometrics implements Biometrics {
  final LocalAuthentication _auth = LocalAuthentication();

  @override
  Future<bool> available() async {
    if (!(Platform.isAndroid || Platform.isIOS || Platform.isMacOS || Platform.isWindows)) {
      return false;
    }
    try {
      if (!await _auth.isDeviceSupported()) return false;
      return (await _auth.getAvailableBiometrics()).isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(localizedReason: reason, biometricOnly: true);
    } catch (_) {
      return false;
    }
  }
}

class NoBiometrics implements Biometrics {
  const NoBiometrics();

  @override
  Future<bool> available() async => false;

  @override
  Future<bool> authenticate(String reason) async => false;
}

/// Test double: [result] decides every prompt.
class FakeBiometrics implements Biometrics {
  FakeBiometrics({this.isAvailable = true, this.result = true});

  bool isAvailable;
  bool result;
  int prompts = 0;

  @override
  Future<bool> available() async => isAvailable;

  @override
  Future<bool> authenticate(String reason) async {
    prompts++;
    return result;
  }
}
