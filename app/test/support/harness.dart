import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/router.dart';

/// The two window classes every screen is captured in.
///
/// * phone — 390×844 logical at 3× (an iPhone-14-class portrait window),
///   `TargetPlatform.android`: bottom navigation, stacked list/detail,
///   48 dp tap targets (what the accessibility guidelines measure);
/// * desktop — 1280×800 at 1×, `TargetPlatform.linux`: navigation rail,
///   list + detail side by side, desktop tap-target sizing, scrollbars.
enum GoldenDevice {
  phone(Size(390, 844), 3.0, TargetPlatform.android),
  desktop(Size(1280, 800), 1.0, TargetPlatform.linux);

  const GoldenDevice(this.logicalSize, this.devicePixelRatio, this.platform);

  final Size logicalSize;
  final double devicePixelRatio;
  final TargetPlatform platform;
}

enum GoldenTheme {
  light(Brightness.light),
  dark(Brightness.dark);

  const GoldenTheme(this.brightness);

  final Brightness brightness;
}

/// One cell of the device × theme matrix; [suffix] is the golden file suffix.
class Variant {
  const Variant(this.device, this.theme);

  final GoldenDevice device;
  final GoldenTheme theme;

  String get suffix => '${device.name}_${theme.name}';

  @override
  String toString() => suffix;
}

/// The full matrix: a screen's primary state is captured in all four cells.
const fullMatrix = [
  Variant(GoldenDevice.phone, GoldenTheme.light),
  Variant(GoldenDevice.phone, GoldenTheme.dark),
  Variant(GoldenDevice.desktop, GoldenTheme.light),
  Variant(GoldenDevice.desktop, GoldenTheme.dark),
];

/// Secondary states get one cell per device with the themes crossed, so both
/// themes and both devices stay covered while the golden count stays small.
/// Alternate [reducedA] and [reducedB] between neighbouring states.
const reducedA = [
  Variant(GoldenDevice.phone, GoldenTheme.light),
  Variant(GoldenDevice.desktop, GoldenTheme.dark),
];
const reducedB = [
  Variant(GoldenDevice.phone, GoldenTheme.dark),
  Variant(GoldenDevice.desktop, GoldenTheme.light),
];

/// The repaint boundary every golden is captured from.
const goldenRootKey = Key('golden-root');

/// The real app (router, theme, shell) on a [CoreApi] of the test's choice,
/// wrapped in the capture boundary. Same wiring as `main.dart` and
/// `test/helpers.dart`.
Widget buildSealbox({
  required CoreApi core,
  String initialLocation = '/inbox',
  List<Override> overrides = const [],
}) {
  return RepaintBoundary(
    key: goldenRootKey,
    child: ProviderScope(
      overrides: [
        coreApiProvider.overrideWithValue(core),
        initialLocationProvider.overrideWithValue(initialLocation),
        ...overrides,
      ],
      child: const SealboxApp(),
    ),
  );
}

/// Window size, pixel ratio, platform brightness and target platform for
/// [variant]. View and brightness overrides are undone at tear-down; the
/// platform override is cleared by [testVariant] right after the test body.
void configureVariant(WidgetTester tester, Variant variant) {
  final d = variant.device;
  tester.view.physicalSize = d.logicalSize * d.devicePixelRatio;
  tester.view.devicePixelRatio = d.devicePixelRatio;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  tester.platformDispatcher.platformBrightnessTestValue = variant.theme.brightness;
  addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
  debugDefaultTargetPlatformOverride = d.platform;
}

/// `testWidgets` for one matrix cell.
///
/// Configures window, pixel ratio, brightness and target platform for
/// [variant] before [body] runs and clears the platform override right after
/// it: the test binding asserts that foundation debug variables are back to
/// their defaults *before* tear-down callbacks run, so a plain `addTearDown`
/// would be too late.
void testVariant(
  String description,
  Variant variant,
  Future<void> Function(WidgetTester tester) body,
) {
  testWidgets(description, (tester) async {
    configureVariant(tester, variant);
    try {
      await body(tester);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });
}

/// Pumps the app at [initialLocation] (inside a [testVariant] body).
///
/// [settle] waits for every animation (route transitions, the FAB, ripple
/// ink) to finish; pass `false` for states that animate forever (spinners)
/// and pump a fixed duration yourself.
Future<void> pumpSealbox(
  WidgetTester tester, {
  required CoreApi core,
  String initialLocation = '/inbox',
  bool settle = true,
  List<Override> overrides = const [],
}) async {
  await tester.pumpWidget(
    buildSealbox(core: core, initialLocation: initialLocation, overrides: overrides),
  );
  if (settle) {
    await tester.pumpAndSettle();
  } else {
    await tester.pump();
  }
}

/// Compares the whole window with `test/goldens/<screen>_<state>_<suffix>.png`.
///
/// The image is rasterised at the device's pixel ratio (so phone goldens are
/// true 3× renders, 1170×2532), which is why this captures the boundary's
/// image itself rather than handing `matchesGoldenFile` the finder.
Future<void> expectGolden(
  WidgetTester tester,
  String screen,
  String state,
  Variant variant,
) async {
  final name = '${screen}_${state}_${variant.suffix}';
  final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(goldenRootKey));
  final Future<ui.Image> image = boundary.toImage(
    pixelRatio: variant.device.devicePixelRatio,
  );
  await expectLater(image, matchesGoldenFile('goldens/$name.png'));
  debugPrint('GOLDEN_COMPARED $name');
}
