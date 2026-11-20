import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/router.dart';

/// The real app (router, theme, shell) wired to a [CoreApi] of the test's choice;
/// [overrides] adds provider overrides (e.g. a preference store).
Widget buildApp({
  required CoreApi core,
  String initialLocation = '/inbox',
  List<Override> overrides = const [],
}) {
  return ProviderScope(
    overrides: [
      coreApiProvider.overrideWithValue(core),
      initialLocationProvider.overrideWithValue(initialLocation),
      ...overrides,
    ],
    child: const SealboxApp(),
  );
}

/// Phone (narrow) or desktop (wide) window, reset after the test.
void setSurface(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

const phone = Size(420, 900);
const desktop = Size(1400, 900);
