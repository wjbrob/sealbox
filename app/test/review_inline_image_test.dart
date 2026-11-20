import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/app.dart';
import 'package:sealbox_app/src/core/core_providers.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/review_tour.dart';
import 'package:sealbox_app/src/router.dart';

import 'support/harness.dart';

// The fake review session's last shot, `fake-thread-html-inline-image` (docs/HTML_MAIL.md,
// "Inline images"): ReviewFakeCore's switch gives the HTML sample's logo part the Content-ID
// its cid: image names, so the thread shows the logo; off (every earlier shot), the sample is
// FakeCore's own, with the placeholder.

Finder _inlineImage() => find.byWidgetPredicate((w) => w is Image && w.image is MemoryImage);

void main() {
  testWidgets('switched on, the HTML sample shows its inline logo from the store', (tester) async {
    final core = ReviewTour.fakeCore();
    expect(core, isA<ReviewFakeCore>());
    (core as ReviewFakeCore).inlineImage = true;
    await pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-html-statement');
    expect(find.byKey(const Key('html-inline-image')), findsOneWidget, reason: 'what the tour waits for');
    final image = tester.widget<Image>(_inlineImage());
    expect((image.image as MemoryImage).bytes, ReviewFakeCore.inlineLogoPng);
    expect(find.text('2 remote images blocked'), findsOneWidget);
    final m = await core.getMessage(FakeCore.htmlSampleId);
    expect(m?.attachments.single.contentId, ReviewFakeCore.inlineCid);
    // shown inline, so not listed again as an attachment chip (review N4)
    expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsNothing);
  });

  testWidgets('off by default: the placeholder, as in every earlier shot', (tester) async {
    final core = ReviewTour.fakeCore();
    await pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-html-statement');
    expect(find.byKey(ValueKey('message-html-${FakeCore.htmlSampleId}')), findsOneWidget);
    expect(_inlineImage(), findsNothing);
    expect(find.byKey(const Key('html-inline-image')), findsNothing);
    expect(find.widgetWithText(Container, 'Example Bank'), findsOneWidget);
    final m = await core.getMessage(FakeCore.htmlSampleId);
    expect(m?.attachments.single.contentId, isNull);
    expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsOneWidget);
  });

  // integration_test/android_smoke_test.dart's last step, on the test binding: after the
  // key-changed tree, a tree of its own (keyed) with the switch on opens on the newsletter, and
  // at phone size the logo is on screen when it shoots `NN-fake-thread-html-inline-image`.
  testVariant(
    'the Android smoke step: its own tree opens on the newsletter, logo on screen',
    const Variant(GoldenDevice.phone, GoldenTheme.light),
    (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            coreApiProvider.overrideWithValue(ReviewTour.fakeCore()),
            initialLocationProvider.overrideWithValue('/inbox/t/t-budget'),
          ],
          child: const SealboxApp(),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('key-changed-banner-bob@sealbox.test')), findsOneWidget);

      final core = ReviewTour.fakeCore() as ReviewFakeCore;
      core.inlineImage = true;
      await tester.pumpWidget(
        ProviderScope(
          key: const ValueKey('smoke-fake-inline-image'),
          overrides: [
            coreApiProvider.overrideWithValue(core),
            initialLocationProvider.overrideWithValue('/inbox/t/t-html-statement'),
          ],
          child: const SealboxApp(),
        ),
      );
      await tester.pumpAndSettle();
      final logo = find.byKey(const Key('html-inline-image'));
      expect(logo, findsOneWidget, reason: 'what the smoke step waits for');
      expect(find.byKey(const ValueKey('key-changed-banner-bob@sealbox.test')), findsNothing);
      expect(find.text('2 remote images blocked'), findsOneWidget);
      expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsNothing);
      final screen = tester.view.physicalSize / tester.view.devicePixelRatio;
      expect(tester.getRect(logo).bottom, lessThanOrEqualTo(screen.height), reason: 'in the shot');
    },
  );

  for (final v in reducedA) {
    testVariant('the tour step reopens the thread and shoots once the logo is there $v', v, (
      tester,
    ) async {
      final core = ReviewTour.fakeCore();
      await pumpSealbox(tester, core: core);
      final container = ProviderScope.containerOf(tester.element(find.byType(SealboxApp)));
      final tour = ReviewTour(container, mode: 'fake', settle: const Duration(milliseconds: 50));
      final markers = <String>[];
      final original = debugPrint;
      debugPrint = (String? message, {int? wrapWidth}) {
        if (message != null && message.startsWith('[review] ')) markers.add(message);
      };
      Object? failure;
      var finished = false;
      try {
        tour.fakeInlineImageStep().then((_) => finished = true, onError: (Object e) {
          failure = e;
          finished = true;
        });
        for (var i = 0; i < 600 && !finished; i++) {
          await tester.pump(const Duration(milliseconds: 50));
        }
      } finally {
        debugPrint = original;
      }
      expect(failure, isNull);
      expect(finished, isTrue);
      expect(markers, hasLength(1));
      expect(markers.single, endsWith('-fake-thread-html-inline-image'));
      expect(find.byKey(const Key('html-inline-image')), findsOneWidget);
      expect(find.text('2 remote images blocked'), findsOneWidget);
      expect(find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')), findsNothing);
    });
  }
}
