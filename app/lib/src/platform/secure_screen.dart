import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const String _reviewDefine = String.fromEnvironment('SEALBOX_REVIEW');

/// Blocks screenshots / screen recording / the recents thumbnail while a
/// secret is on screen, where the platform allows it: Android `FLAG_SECURE`
/// (MainActivity.kt). iOS and desktops have no such switch; nothing happens
/// there. Review runs (`SEALBOX_REVIEW`) skip it so the capture loop can
/// photograph the screen with throw-away words.
class SecureScreen {
  static const _channel = MethodChannel('sealbox/secure_screen');

  static bool get _reviewing {
    final v = _reviewDefine.isNotEmpty
        ? _reviewDefine
        : (kIsWeb ? '' : (Platform.environment['SEALBOX_REVIEW'] ?? ''));
    return v.isNotEmpty && v != '0' && v != 'false';
  }

  static Future<void> set(bool on) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android || _reviewing) return;
    try {
      await _channel.invokeMethod<void>('setSecure', on);
    } on MissingPluginException {
      // Widget tests: no platform side.
    } on PlatformException catch (e) {
      debugPrint('[sealbox] secure screen: $e');
    }
  }
}
