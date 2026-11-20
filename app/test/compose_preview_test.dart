import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/features/compose/compose_preview.dart';

import 'helpers.dart';

// Compose → Preview (`composePreview`): the text the engine will send, the
// signature where the settings put it, the quote of a reply and the forwarded
// message; replies and forwards hand quoting to the engine (ComposeOptions).

/// Records what `send` was given; [withAttachment] gives m-4 two attachments.
class _Core extends FakeCore {
  _Core({this.previewError}) : super(latency: Duration.zero);

  final Object? previewError;
  final sent = <DraftMessage>[];
  int previews = 0;

  @override
  Future<ComposePreview> composePreview(DraftMessage draft) async {
    previews++;
    if (previewError != null) throw previewError!;
    return super.composePreview(draft);
  }

  @override
  Future<SendReceipt> send(DraftMessage draft) {
    sent.add(draft);
    return super.send(draft);
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    final m = await super.getMessage(messageId);
    if (m == null || messageId != 'm-4') return m;
    return m.copyWith(
      attachments: const [
        AttachmentMeta(index: 0, filename: 'notes.md', contentType: 'text/markdown', size: 812),
        AttachmentMeta(
          index: 1,
          filename: 'sig.asc',
          contentType: 'application/pgp-signature',
          size: 228,
        ),
      ],
    );
  }
}

String previewText(WidgetTester tester) =>
    tester.widget<SelectableText>(find.byKey(const Key('compose-preview-text'))).data!;

/// The compose list builds lazily: scroll the Preview card into view.
Future<void> showPreview(WidgetTester tester) async {
  await tester.scrollUntilVisible(
    find.byKey(const Key('compose-preview-toggle')),
    200,
    scrollable: find.byType(Scrollable).first,
  );
  await tester.pumpAndSettle();
}

Future<void> openPreview(WidgetTester tester) async {
  await showPreview(tester);
  await tester.tap(find.byKey(const Key('compose-preview-toggle')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('a new message: collapsed until opened, then body + signature', (tester) async {
    setSurface(tester, desktop);
    final core = _Core();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compose-preview-text')), findsNothing);
    expect(core.previews, 0, reason: 'no engine call while collapsed');
    await tester.enterText(find.byKey(const Key('compose-body')), 'See you at noon.');
    await openPreview(tester);
    expect(
      previewText(tester),
      'See you at noon.\n\n-- \nAlice Rivera\nSent with Sealbox — end-to-end encrypted',
    );
    expect(find.text('Signature added'), findsOneWidget);
    expect(find.text('New message'), findsWidgets);
  });

  testWidgets('typing refreshes the preview after a short pause, not on every key', (tester) async {
    setSurface(tester, desktop);
    final core = _Core();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await openPreview(tester);
    final calls = core.previews;
    await tester.enterText(find.byKey(const Key('compose-body')), 'A');
    await tester.pump(const Duration(milliseconds: 100));
    await tester.enterText(find.byKey(const Key('compose-body')), 'AB');
    await tester.pump(const Duration(milliseconds: 100));
    expect(core.previews, calls, reason: 'still inside the debounce');
    await tester.pump(ComposePreviewPanel.debounce);
    await tester.pumpAndSettle();
    expect(core.previews, calls + 1);
    expect(previewText(tester), startsWith('AB\n\n-- \n'));
  });

  testWidgets('changing the sending account uses that account\'s signature', (tester) async {
    setSurface(tester, desktop);
    final core = _Core();
    await core.setSignature(
      'acct-2',
      const SignatureSettings(enabled: true, text: 'Alice @ Fastmail'),
    );
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('compose-body')), 'Hi');
    await openPreview(tester);
    expect(previewText(tester), contains('Sent with Sealbox'));
    await tester.tap(find.byKey(const Key('compose-account')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('alice@fastmail.com').last);
    await tester.pump(ComposePreviewPanel.debounce);
    await tester.pumpAndSettle();
    expect(previewText(tester), 'Hi\n\n-- \nAlice @ Fastmail');
  });

  testWidgets('reply: no quote in the editor; the preview (open) shows the engine\'s quote; '
      'send passes ComposeOptions.reply', (tester) async {
    setSurface(tester, desktop);
    final core = _Core();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose?reply=t-lunch'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<TextField>(find.byKey(const Key('compose-body'))).controller!.text,
      isEmpty,
    );
    await showPreview(tester);
    expect(find.text('Reply with quote'), findsOneWidget);
    expect(
      previewText(tester),
      contains('Dana Whitfield <dana@example.org> wrote:\n> The Lebanese place'),
    );
    await tester.enterText(find.byKey(const Key('compose-body')), 'Thursday works.');
    await tester.pump(ComposePreviewPanel.debounce);
    await tester.pumpAndSettle();
    expect(
      previewText(tester),
      startsWith('Thursday works.\n\n-- \n'),
      reason: 'typed text, then signature',
    );
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    if (find.byKey(const Key('guest-sent-done')).evaluate().isNotEmpty) {
      await tester.tap(find.byKey(const Key('guest-sent-done')));
      await tester.pumpAndSettle();
    }
    final d = core.sent.single;
    expect(
      (d.compose.kind, d.compose.quote, d.inReplyTo, d.body),
      (ComposeKind.reply, true, 'm-3', 'Thursday works.'),
    );
  });

  testWidgets('forward: Fwd: subject, the forwarded message and its attachments in the preview', (
    tester,
  ) async {
    setSurface(tester, desktop);
    final core = _Core();
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose?forward=m-4'));
    await tester.pumpAndSettle();
    expect(find.text('Forward'), findsWidgets);
    expect(
      tester.widget<TextField>(find.byKey(const Key('compose-subject'))).controller!.text,
      'Fwd: sealbox-crypto 0.3 release notes (signed)',
    );
    await tester.enterText(find.byKey(const Key('compose-to')), 'bob@sealbox.test');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    await showPreview(tester);
    expect(
      previewText(tester),
      contains('-------- Forwarded Message --------\nSubject: sealbox-crypto 0.3'),
    );
    expect(find.text('Attachments that go along: notes.md, sig.asc'), findsOneWidget);
    await tester.tap(find.byKey(const Key('compose-send')));
    await tester.pumpAndSettle();
    final d = core.sent.single;
    expect((d.compose.kind, d.compose.forwardOf), (ComposeKind.forward, 'm-4'));
  });

  testWidgets('an engine refusal shows in the preview (friendlyError)', (tester) async {
    setSurface(tester, desktop);
    final core = _Core(
      previewError: ArgumentError(
        'invalid input: cannot quote: the replied-to message is not stored locally',
      ),
    );
    await tester.pumpWidget(buildApp(core: core, initialLocation: '/compose?reply=t-lunch'));
    await tester.pumpAndSettle();
    await showPreview(tester);
    expect(find.byKey(const Key('compose-preview-error')), findsOneWidget);
    expect(
      find.text('invalid input: cannot quote: the replied-to message is not stored locally'),
      findsOneWidget,
    );
  });
}
