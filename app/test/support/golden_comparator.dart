import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

/// The project's golden comparator: pixel-exact by default.
///
/// Goldens are generated on Linux x64 with the pinned Flutter SDK and the
/// fonts in `test/support/fonts/`, which makes them deterministic on this
/// host. If another machine's rasteriser differs by a few anti-aliased pixels,
/// `SEALBOX_GOLDEN_MAX_DIFF_PERCENT=0.1 flutter test …` tolerates that much of
/// the image (0.1 = one pixel in a thousand) instead of failing; the default
/// is 0 so a real regression never hides behind a tolerance.
///
/// On failure the standard `test/failures/` triplet (expected / actual /
/// masked diff) is written, exactly as with Flutter's default comparator.
class SealboxGoldenComparator extends LocalFileComparator {
  SealboxGoldenComparator(super.testFile, {this.maxDiffPercent = 0});

  /// Allowed share of differing pixels, in percent (0–100).
  final double maxDiffPercent;

  @override
  Future<bool> compare(Uint8List imageBytes, Uri golden) async {
    final result = await GoldenFileComparator.compareLists(
      imageBytes,
      await getGoldenBytes(golden),
    );
    if (result.passed) return true;
    final diffPercent = result.diffPercent * 100;
    if (diffPercent <= maxDiffPercent) {
      debugPrint(
        'GOLDEN_TOLERATED ${golden.path}: ${diffPercent.toStringAsFixed(3)}% '
        '<= $maxDiffPercent% (SEALBOX_GOLDEN_MAX_DIFF_PERCENT)',
      );
      return true;
    }
    await generateFailureOutput(result, golden, basedir);
    throw FlutterError(
      'Golden "${golden.path}" does not match: ${result.error}\n'
      'Review the images under test/failures/; if the change is intended run '
      '`flutter test --update-goldens <file>` and commit the new PNG.',
    );
  }
}

/// Replaces the default [LocalFileComparator] (same base directory) with
/// [SealboxGoldenComparator]. No-op when a different comparator is installed,
/// e.g. by a CI golden service.
void installSealboxGoldenComparator() {
  final current = goldenFileComparator;
  if (current is! LocalFileComparator || current is SealboxGoldenComparator) return;
  final tolerance =
      double.tryParse(Platform.environment['SEALBOX_GOLDEN_MAX_DIFF_PERCENT'] ?? '') ?? 0;
  goldenFileComparator = SealboxGoldenComparator(
    current.basedir.resolve('placeholder_test.dart'),
    maxDiffPercent: tolerance < 0 ? 0 : tolerance,
  );
}
