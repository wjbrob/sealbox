import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fonts.dart';
import 'support/golden_comparator.dart';

/// Runs once per test isolate before any test in `app/test/`.
///
/// * real fonts (Roboto, MaterialIcons, a monospace face) so text and icons
///   render in goldens and the contrast guideline measures real glyphs;
/// * a deterministic text cursor (always painted while focused, no blink
///   timer) so a focused field never produces a flaky golden;
/// * the project golden comparator (pixel-exact; see golden_comparator.dart).
///
/// Everything here is harmless for the plain widget tests: it only changes
/// how pixels look, not what the widgets do.
Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  TestWidgetsFlutterBinding.ensureInitialized();
  await loadSealboxTestFonts();
  EditableText.debugDeterministicCursor = true;
  installSealboxGoldenComparator();
  await testMain();
}
