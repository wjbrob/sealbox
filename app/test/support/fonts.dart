import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

bool _loaded = false;

/// Registers real fonts with the test engine so goldens and contrast checks
/// render actual glyphs instead of the harness's "Ahem" boxes.
///
/// This is the equivalent of golden_toolkit's `loadAppFonts()` (that package
/// is discontinued upstream, so the ~40 lines live here):
///
///  1. every family listed in the asset bundle's `FontManifest.json`
///     (MaterialIcons and CupertinoIcons for this app), loaded from the
///     bundle exactly as the running app would;
///  2. Roboto — Material's default family — in regular/medium/bold, plus a
///     monospace face registered under the family name `monospace` (the app
///     uses `fontFamily: 'monospace'` for fingerprints and server rows), both
///     from `test/support/fonts/` (licences in `NOTICE.txt` there).
///
/// Called once per test isolate from `test/flutter_test_config.dart`.
Future<void> loadSealboxTestFonts() async {
  if (_loaded) return;
  TestWidgetsFlutterBinding.ensureInitialized();

  final manifest =
      json.decode(await rootBundle.loadString('FontManifest.json')) as List<dynamic>;
  for (final entry in manifest.cast<Map<String, dynamic>>()) {
    final loader = FontLoader(entry['family'] as String);
    for (final font in (entry['fonts'] as List<dynamic>).cast<Map<String, dynamic>>()) {
      loader.addFont(rootBundle.load(font['asset'] as String));
    }
    await loader.load();
  }

  final dir = _fontsDir();
  await _loadFamily(dir, 'Roboto', [
    'Roboto-Regular.ttf',
    'Roboto-Medium.ttf',
    'Roboto-Bold.ttf',
  ]);
  await _loadFamily(dir, 'monospace', ['DejaVuSansMono.ttf']);
  _loaded = true;
}

Future<void> _loadFamily(Directory dir, String family, List<String> files) async {
  final loader = FontLoader(family);
  for (final name in files) {
    final bytes = File('${dir.path}/$name').readAsBytesSync();
    loader.addFont(Future.value(ByteData.sublistView(bytes)));
  }
  await loader.load();
}

/// `flutter test` runs with the package root as the working directory; walk up
/// a few levels anyway so the helper also works when invoked from `test/`.
Directory _fontsDir() {
  var dir = Directory.current;
  for (var i = 0; i < 4; i++) {
    final candidate = Directory('${dir.path}/test/support/fonts');
    if (candidate.existsSync()) return candidate;
    dir = dir.parent;
  }
  throw StateError(
    'test/support/fonts not found from ${Directory.current.path}; '
    'run `flutter test` from app/',
  );
}
