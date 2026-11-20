// Host side of the Android smoke loop (gate G19). Receives the screenshots and
// the report data that integration_test/android_smoke_test.dart produces on the
// device and writes them to $SEALBOX_SHOTS_DIR (host environment; default
// build/review_shots). Run by scripts/review_android.sh:
//
//   SEALBOX_SHOTS_DIR=review/android/<date> flutter drive \
//     --driver=test_driver/integration_test.dart \
//     --target=integration_test/android_smoke_test.dart -d <serial>
import 'dart:convert';
import 'dart:io';

import 'package:integration_test/integration_test_driver_extended.dart';

Future<void> main() async {
  final out = Directory(
    Platform.environment['SEALBOX_SHOTS_DIR'] ?? 'build/review_shots',
  );
  await out.create(recursive: true);
  await integrationDriver(
    writeResponseOnFailure: true,
    onScreenshot:
        (String name, List<int> bytes, [Map<String, Object?>? args]) async {
          final file = File('${out.path}/$name.png');
          await file.writeAsBytes(bytes, flush: true);
          stdout.writeln('[driver] screenshot ${file.path} (${bytes.length} bytes)');
          return true;
        },
    responseDataCallback: (Map<String, dynamic>? data) async {
      final file = File('${out.path}/smoke_report.json');
      final json = const JsonEncoder.withIndent('  ').convert(data ?? {});
      await file.writeAsString('$json\n', flush: true);
      stdout.writeln('[driver] report ${file.path}');
    },
  );
}
