import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/inbox/message_body.dart';

import 'support/golden_core.dart';
import 'support/harness.dart';
import 'support/inline_image_core.dart';

// MessageBody (docs/HTML_MAIL.md): the thread view renders the engine's sanitized HTML,
// keeps remote images blocked until the reader asks, confirms every link before opening it
// and offers the plain-text view. The fixture is FakeCore's HTML statement sample
// (two remote images, an inline cid: logo, a table, an http and a mailto link).

/// Opens the HTML sample's conversation ("Review samples", listed under "All mail").
Future<void> _openHtmlThread(WidgetTester tester) async {
  await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-html-statement');
  expect(
    find.byKey(ValueKey('message-card-${FakeCore.htmlSampleId}')),
    findsOneWidget,
    reason: 'the HTML sample conversation opened',
  );
}

Finder _html() => find.byKey(ValueKey('message-html-${FakeCore.htmlSampleId}'));
Finder _text() => find.byKey(ValueKey('message-body-${FakeCore.htmlSampleId}'));

void main() {
  testWidgets('sanitized HTML renders as widgets, not as markup', (tester) async {
    await _openHtmlThread(tester);
    expect(_html(), findsOneWidget);
    expect(_text(), findsNothing, reason: 'the HTML view replaces the text view');
    // the structure survived as text runs …
    expect(find.textContaining('Your October statement'), findsWidgets);
    // the HTML renders into RichText spans, so these finders must look inside them
    expect(find.textContaining('Hello Alice', findRichText: true), findsOneWidget);
    expect(find.textContaining('View it online', findRichText: true), findsOneWidget);
    expect(find.textContaining('Subscription', findRichText: true), findsOneWidget);
    expect(find.textContaining('12.00 EUR', findRichText: true), findsOneWidget);
    expect(find.textContaining('help@statements.example', findRichText: true), findsOneWidget);
    // … and no tag or attribute is shown anywhere
    for (final markup in ['<p>', '<h1>', '<table', 'href=', 'data-src', 'span class']) {
      expect(
        find.textContaining(markup, findRichText: true),
        findsNothing,
        reason: 'markup $markup must not be rendered as text',
      );
    }
  });

  testWidgets('the banner counts blocked remote images and nothing is fetched', (tester) async {
    await _openHtmlThread(tester);
    expect(find.byKey(const Key('html-remote-banner')), findsOneWidget);
    expect(find.text('2 remote images blocked'), findsOneWidget);
    expect(find.byKey(const Key('html-load-images')), findsOneWidget);
    // both remote images are placeholders; the inline cid: logo is one too (this sample's
    // part carries no Content-ID, so nothing matches it), so three in total and no Image
    expect(find.byKey(const Key('html-blocked-image')), findsNWidgets(3));
    expect(find.byType(Image), findsNothing);
    expect(find.textContaining('Image from cdn.example'), findsOneWidget);
    expect(
      find.widgetWithText(Container, 'Example Bank'),
      findsOneWidget,
      reason: "the inline logo's placeholder carries its alt text",
    );
  });

  testWidgets('Load images reveals them and the banner goes', (tester) async {
    await _openHtmlThread(tester);
    await tester.tap(find.byKey(const Key('html-load-images')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('html-remote-banner')), findsNothing);
    expect(find.text('2 remote images blocked'), findsNothing);
    // the two remote images are real images now; the cid: one is still a placeholder
    expect(find.byType(Image), findsNWidgets(2));
    expect(find.byKey(const Key('html-blocked-image')), findsOneWidget);
  });

  testWidgets('a link opens a sheet that shows the real target first', (tester) async {
    await _openHtmlThread(tester);
    await tester.tapOnText(find.textRange.ofSubstring('View it online'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('html-link-sheet')), findsOneWidget);
    expect(
      find.byKey(const Key('html-link-url')),
      findsOneWidget,
      reason: 'the sheet shows where the link really goes',
    );
    expect(
      tester.widget<SelectableText>(find.byKey(const Key('html-link-url'))).data,
      'https://statements.example/october',
    );
    expect(find.byKey(const Key('html-link-open')), findsOneWidget);
    // cancelling leaves the thread as it was and opens nothing
    await tester.tap(find.byKey(const Key('html-link-cancel')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('html-link-sheet')), findsNothing);
    expect(_html(), findsOneWidget);
  });

  testWidgets('Show as text switches to the plain-text view and back', (tester) async {
    await _openHtmlThread(tester);
    await tester.tap(find.byKey(const Key('message-show-text')));
    await tester.pumpAndSettle();
    expect(_html(), findsNothing);
    expect(_text(), findsOneWidget);
    expect(find.byKey(const Key('html-remote-banner')), findsNothing);
    final shown = tester.widget<SelectableText>(_text()).data ?? '';
    expect(shown, contains('Your October statement'));
    expect(shown, contains('<https://statements.example/october>'));
    expect(shown, isNot(contains('<p>')));
    expect(find.text('Show formatting'), findsOneWidget);
    await tester.tap(find.byKey(const Key('message-show-text')));
    await tester.pumpAndSettle();
    expect(_html(), findsOneWidget);
  });

  testWidgets('a message without an HTML part is the plain-text view, unchanged', (tester) async {
    await pumpSealbox(tester, core: GoldenCore(), initialLocation: '/inbox/t/t-lunch');
    expect(find.byKey(const Key('message-show-text')), findsNothing);
    expect(find.byKey(const Key('html-remote-banner')), findsNothing);
    expect(find.byKey(const ValueKey('message-body-m-3')), findsOneWidget);
    expect(find.byType(Image), findsNothing);
  });

  testWidgets('the HTML body inherits the theme in dark mode (no white boxes)', (tester) async {
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await pumpSealbox(
      tester,
      core: GoldenCore(),
      initialLocation: '/inbox/t/t-html-statement',
    );
    // Dark theme is the app's; take the colours the widget was given.
    final context = tester.element(_html());
    final theme = Theme.of(context);
    if (theme.brightness == Brightness.dark) {
      final texts = tester.widgetList<RichText>(find.byType(RichText));
      for (final t in texts) {
        final style = t.text.style;
        final colour = style?.color;
        if (colour == null) continue;
        expect(
          colour.computeLuminance() > 0.3,
          isTrue,
          reason: 'HTML text must be light on a dark surface, got $colour',
        );
      }
    }
    // no opaque light container was introduced by the HTML view
    for (final c in tester.widgetList<Container>(find.byType(Container))) {
      final d = c.decoration;
      if (d is BoxDecoration && d.color == Colors.white) {
        fail('a white box was painted inside the message body');
      }
    }
  });

  group('accessibility', () {
    for (final v in [
      const Variant(GoldenDevice.phone, GoldenTheme.light),
      const Variant(GoldenDevice.desktop, GoldenTheme.dark),
    ]) {
      testVariant('message body guidelines $v', v, (tester) async {
        await _openHtmlThread(tester);
        await expectLater(tester, meetsGuideline(textContrastGuideline));
        await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
        if (v.device == GoldenDevice.phone) {
          await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
          await expectLater(tester, meetsGuideline(iOSTapTargetGuideline));
        }
        debugPrint('A11Y_ASSERT message_body/$v PASS');
      });
    }

    testWidgets('a blocked image is announced with its alt text', (tester) async {
      final handle = tester.ensureSemantics();
      await _openHtmlThread(tester);
      expect(
        find.bySemanticsLabel(RegExp(r'Example Bank \(not loaded\)')),
        findsOneWidget,
        reason: 'a screen reader hears what the image was',
      );
      expect(find.bySemanticsLabel(RegExp('remote images blocked')), findsOneWidget);
      handle.dispose();
    });
  });

  test('HtmlBody.hasBlockedImages is about this rendering, not the count alone', () {
    const blocked = HtmlBody(
      html: '<span class="sealbox-blocked-image" data-src="https://x.example/a.png"></span>',
      remoteImages: 1,
    );
    const loaded = HtmlBody(html: '<img src="https://x.example/a.png">', remoteImages: 1);
    const none = HtmlBody(html: '<p>t</p>');
    expect(blocked.hasBlockedImages, isTrue);
    expect(loaded.hasBlockedImages, isFalse, reason: 'already loaded: no banner');
    expect(none.hasBlockedImages, isFalse);
  });

  group('inline cid: images', () {
    Finder inlineImage() =>
        find.byWidgetPredicate((w) => w is Image && w.image is MemoryImage);
    Finder logoPlaceholder() => find.widgetWithText(Container, 'Example Bank');

    Future<void> open(WidgetTester tester, InlineImageCore core) =>
        pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-html-statement');

    testWidgets('a cid: image shows the part with that Content-ID, read once', (tester) async {
      final core = InlineImageCore();
      await open(tester, core);
      expect(_html(), findsOneWidget);
      expect(inlineImage(), findsOneWidget);
      final image = tester.widget<Image>(inlineImage());
      expect((image.image as MemoryImage).bytes, inlineLogoPng);
      expect(image.semanticLabel, 'Example Bank', reason: "the image's alt text");
      expect(logoPlaceholder(), findsNothing);
      // the remote images stay blocked, and the banner counts only them
      expect(find.byKey(const Key('html-blocked-image')), findsNWidgets(2));
      expect(find.text('2 remote images blocked'), findsOneWidget);
      expect(core.reads, ['${FakeCore.htmlSampleId}/0']);

      // Re-rendering the HTML reads nothing again: text view and back, then Load images.
      await tester.tap(find.byKey(const Key('message-show-text')));
      await tester.pumpAndSettle();
      expect(inlineImage(), findsNothing, reason: '"Show as text" is unchanged');
      expect(_text(), findsOneWidget);
      await tester.tap(find.byKey(const Key('message-show-text')));
      await tester.pumpAndSettle();
      expect(inlineImage(), findsOneWidget);
      await tester.tap(find.byKey(const Key('html-load-images')));
      await tester.pumpAndSettle();
      expect(find.byType(Image), findsNWidgets(3), reason: 'the two remote images and the logo');
      expect(core.reads, hasLength(1), reason: 'one read per Content-ID while the widget lives');
    });

    testWidgets('a shown inline image is announced with its alt text', (tester) async {
      final handle = tester.ensureSemantics();
      await open(tester, InlineImageCore());
      expect(
        tester.getSemantics(inlineImage()),
        isSemantics(label: 'Example Bank', isImage: true),
        reason: 'a screen reader hears what the image is',
      );
      expect(find.bySemanticsLabel(RegExp(r'Example Bank \(not loaded\)')), findsNothing);
      await expectLater(tester, meetsGuideline(textContrastGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      handle.dispose();
    });

    testWidgets('a cid: that no part carries stays a placeholder and reads nothing', (
      tester,
    ) async {
      // another Content-ID, and the right one in another case (Content-IDs are compared exactly)
      for (final cid in ['other@statements.example', 'LOGO@statements.example']) {
        final core = InlineImageCore(contentId: cid);
        await open(tester, core);
        expect(inlineImage(), findsNothing, reason: cid);
        expect(logoPlaceholder(), findsOneWidget, reason: cid);
        expect(core.reads, isEmpty, reason: cid);
      }
    });

    testWidgets('a failing read stays a placeholder, never an exception', (tester) async {
      final core = InlineImageCore(failRead: true);
      await open(tester, core);
      expect(tester.takeException(), isNull);
      expect(core.reads, hasLength(1));
      expect(inlineImage(), findsNothing);
      expect(logoPlaceholder(), findsOneWidget);
      expect(_html(), findsOneWidget, reason: 'the rest of the body renders');
      expect(
        find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')),
        findsOneWidget,
        reason: 'not shown inline after all, so the part keeps its chip (N4)',
      );
    });

    testWidgets('a part larger than 5 MiB is not read', (tester) async {
      final core = InlineImageCore(declaredSize: kInlineImageMaxBytes + 1);
      await open(tester, core);
      expect(core.reads, isEmpty);
      expect(inlineImage(), findsNothing);
      expect(logoPlaceholder(), findsOneWidget);
    });

    testWidgets('a huge image is decoded at most 2048 px on its longer side', (tester) async {
      // single-colour PNGs of 4096×4 and 4×4096 (142 and 192 bytes), and the 180×48 logo
      final wide = base64Decode(
        'iVBORw0KGgoAAAANSUhEUgAAEAAAAAAECAIAAACBjm2YAAAAVUlEQVR42u3bQQ0AAAjEsFOCECSiGhskNKmC/ZfqAQAAAAAAAAAAAAAAjosEAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAADwwwKnsINJ9VmjtgAAAABJRU5ErkJggg==',
      );
      final tall = base64Decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAQAABAACAIAAADa3NfxAAAAh0lEQVR42u3HMQ0AAAgDsClBCBJRzYcDviZ9muo5EREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREfnJAi6ig0nI4FnaAAAAAElFTkSuQmCC',
      );
      for (final (png, size) in [
        (wide, const Size(kInlineImageMaxSide + 0.0, 2)),
        (tall, const Size(2, kInlineImageMaxSide + 0.0)),
        (inlineLogoPng, const Size(180, 48)),
      ]) {
        await open(tester, InlineImageCore(bytes: png));
        final provider = tester.widget<Image>(inlineImage()).image;
        // the decode the Image widget started, awaited outside the fake clock
        final decoded = await tester.runAsync(() {
          final done = Completer<ui.Image>();
          final stream = provider.resolve(ImageConfiguration.empty);
          late final ImageStreamListener listener;
          listener = ImageStreamListener(
            (info, _) {
              done.complete(info.image.clone());
              info.dispose();
              stream.removeListener(listener);
            },
            onError: (error, stackTrace) => done.completeError(error, stackTrace),
          );
          stream.addListener(listener);
          return done.future;
        });
        expect(Size(decoded!.width.toDouble(), decoded.height.toDouble()), size);
        decoded.dispose();
      }
    });

    testWidgets('bytes that do not decode fall back to the placeholder', (tester) async {
      final core = InlineImageCore(bytes: Uint8List.fromList(List.filled(64, 7)));
      await open(tester, core);
      expect(inlineImage(), findsOneWidget);
      // image codecs run outside the fake clock
      await tester.runAsync(
        () => precacheImage(
          tester.widget<Image>(inlineImage()).image,
          tester.element(inlineImage()),
          onError: (error, stackTrace) {},
        ),
      );
      await tester.pumpAndSettle();
      expect(logoPlaceholder(), findsOneWidget);
      expect(tester.takeException(), isNull);
      expect(
        find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0')),
        findsOneWidget,
        reason: 'not shown inline after all, so the part keeps its chip (N4)',
      );
    });
  });

  group('attachment chips (review N4)', () {
    Finder chip() => find.byKey(ValueKey('attachment-${FakeCore.htmlSampleId}-0'));

    Future<void> open(WidgetTester tester, GoldenCore core) =>
        pumpSealbox(tester, core: core, initialLocation: '/inbox/t/t-html-statement');

    testWidgets('an image shown inline is not listed again; as text it is', (tester) async {
      await open(tester, InlineImageCore());
      expect(find.byKey(const Key('html-inline-image')), findsOneWidget);
      expect(chip(), findsNothing, reason: 'the logo is on screen already');
      expect(find.textContaining('logo.png'), findsNothing);

      // "Show as text": the image is its [alt], so its chip is the way to the part
      await tester.tap(find.byKey(const Key('message-show-text')));
      await tester.pumpAndSettle();
      expect(chip(), findsOneWidget);
      expect(find.text('logo.png · 421 B'), findsOneWidget);
      expect(tester.widget<ActionChip>(chip()).tooltip, 'Save logo.png (image/png)');

      await tester.tap(find.byKey(const Key('message-show-text')));
      await tester.pumpAndSettle();
      expect(chip(), findsNothing);
      // loading the remote images leaves the inline one as it was
      await tester.tap(find.byKey(const Key('html-load-images')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('html-inline-image')), findsOneWidget);
      expect(chip(), findsNothing);
    });

    testWidgets('a part the body does not show inline keeps its chip', (tester) async {
      for (final (why, core) in [
        ('no Content-ID (the cid: names nothing)', GoldenCore()),
        ('the body never names this part', InlineImageCore(contentId: 'other@statements.example')),
        ('over the inline cap', InlineImageCore(declaredSize: kInlineImageMaxBytes + 1)),
        ('not an image', InlineImageCore(contentType: 'application/pdf')),
      ]) {
        await open(tester, core);
        expect(find.byKey(const Key('html-inline-image')), findsNothing, reason: why);
        expect(chip(), findsOneWidget, reason: why);
      }
    });

    testWidgets('"Resend link" stays above the chips, with or without one', (tester) async {
      Finder resend() => find.byKey(ValueKey('message-resend-${FakeCore.htmlSampleId}'));
      await open(tester, InlineImageCore(guestLink: true, contentId: 'other@statements.example'));
      expect(resend(), findsOneWidget);
      expect(chip(), findsOneWidget);
      expect(tester.getTopLeft(resend()).dy, lessThan(tester.getTopLeft(chip()).dy));
      await open(tester, InlineImageCore(guestLink: true));
      expect(resend(), findsOneWidget, reason: 'nothing to list, the link is still offered');
      expect(chip(), findsNothing);
    });
  });

  group('imageSources / listedAttachments', () {
    test('imageSources reads the src of every <img>, and of nothing else', () {
      expect(
        imageSources('<p><img src="cid:logo@x" alt="Bank"></p><img alt=\'a\' src=\'cid:b@x\'/>'),
        ['cid:logo@x', 'cid:b@x'],
      );
      expect(imageSources('<IMG SRC=cid:u@x>'), ['cid:u@x']);
      expect(imageSources('<img alt="a > b" src="cid:f@x">'), ['cid:f@x']);
      // character references are decoded, as the HTML parser does
      expect(imageSources('<img src="cid:a&amp;b@x">'), ['cid:a&b@x']);
      expect(imageSources('<img src="cid:&#x6c;og&#111;@x">'), ['cid:logo@x']);
      expect(imageSources('<img src="cid:a&unknown;b@x">'), ['cid:a&unknown;b@x']);
      // markup in another tag's attribute, a comment, a lookalike tag, a blocked image
      expect(
        imageSources(
          '<p title="<img src=cid:a@x>">t</p><!-- <img src="cid:c@x"> -->'
          '<imgx src="cid:d@x"><span class="sealbox-blocked-image" data-src="cid:e@x"></span>',
        ),
        isEmpty,
      );
      expect(imageSources('<img src="cid:g@x"'), ['cid:g@x'], reason: 'never closed');
      expect(imageSources('<img alt="x">'), isEmpty);
      expect(imageSources(''), isEmpty);
    });

    test('listedAttachments leaves out exactly the images shown inline', () {
      AttachmentMeta part(int i, String? cid, {String type = 'image/png', int size = 3}) =>
          AttachmentMeta(index: i, filename: 'p$i', contentType: type, size: size, contentId: cid);
      final logo = part(0, 'logo@x');
      final pdf = part(1, 'doc@x', type: 'application/pdf');
      final big = part(2, 'big@x', size: kInlineImageMaxBytes + 1);
      final unnamed = part(3, 'unused@x');
      final plain = part(4, null);
      final parts = [logo, pdf, big, unnamed, plain];
      const html =
          '<img src="cid:logo@x"><img src="cid:doc@x"><img src="cid:big@x"><img src="cid:no@x">';
      expect(listedAttachments(parts, html), [pdf, big, unnamed, plain]);
      expect(listedAttachments(parts, null), parts, reason: 'shown as text: every part');
      expect(listedAttachments(parts, '<p>no image</p>'), parts);
      expect(
        listedAttachments(parts, '<img src="cid:LOGO@x"><img src="https://x.example/logo@x">'),
        parts,
        reason: 'Content-IDs compare exactly; a remote image names no part',
      );
      expect(listedAttachments([part(0, 'logo@x', size: kInlineImageMaxBytes)], html), isEmpty);
      // two parts with one Content-ID: the first is the image shown, the other keeps its chip
      final twin = part(5, 'logo@x');
      expect(listedAttachments([logo, twin], html), [twin]);
      // an image that could not be shown after all (read or decode failed) keeps its chip
      expect(listedAttachments(parts, html, unshown: {'logo@x'}), [logo, pdf, big, unnamed, plain]);
      expect(
        listedAttachments([part(0, '<logo@x>')], html, unshown: {'logo@x'}),
        hasLength(1),
        reason: 'compared without angle brackets, as inlinePartFor does',
      );
    });
  });

  group('cidContentId / inlinePartFor', () {
    test('a cid: URL names its Content-ID (RFC 2392)', () {
      expect(cidContentId('cid:logo@x'), 'logo@x');
      expect(cidContentId('CID:logo@x'), 'logo@x');
      expect(cidContentId(' cid:<logo@x> '), 'logo@x');
      expect(cidContentId('cid:foo4%2Afoo1@bar.net'), 'foo4*foo1@bar.net');
      expect(cidContentId('cid:%E6%97%A5@x'), '\u65e5@x');
      // an escape that does not decode leaves the text as it is (as the engine does)
      expect(cidContentId('cid:a%zz@x'), 'a%zz@x');
      expect(cidContentId('cid:a%ff@x'), 'a%ff@x');
      expect(cidContentId('cid:a%4'), 'a%4');
      for (final other in ['cid:', 'cid:<>', 'https://x/logo@x', 'logo@x', 'data:image/png;base64,AA', '']) {
        expect(cidContentId(other), isNull, reason: other);
      }
    });

    test('inlinePartFor matches the Content-ID exactly', () {
      AttachmentMeta part(int index, String? cid) => AttachmentMeta(
        index: index,
        filename: 'p$index.png',
        contentType: 'image/png',
        size: 3,
        contentId: cid,
      );
      final parts = [part(0, null), part(1, 'logo@x'), part(2, '<Pic@x>')];
      expect(inlinePartFor(parts, 'cid:logo@x')?.index, 1);
      expect(inlinePartFor(parts, 'cid:logo%40x')?.index, 1);
      expect(inlinePartFor(parts, 'cid:Pic@x')?.index, 2);
      for (final none in ['cid:LOGO@x', 'cid:pic@x', 'cid:missing@x', 'https://x.example/logo@x']) {
        expect(inlinePartFor(parts, none), isNull, reason: none);
      }
    });
  });
}
