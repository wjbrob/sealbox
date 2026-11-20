import 'dart:convert';
import 'dart:typed_data';

import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'golden_core.dart';

/// A 180×48 PNG "bank logo" (421 bytes): the inline image of the HTML sample.
final Uint8List inlineLogoPng = base64Decode(
  'iVBORw0KGgoAAAANSUhEUgAAALQAAAAwCAYAAAC47FD8AAABbElEQVR42u3dMU7DMBSAYdvqGRhBXAPORefOcC56DURHLgFLI4SaVlUSBz/3+9YyUOfPw46A5nTB/dPrd4LGHPbbfO61LGR6CruImajGWi1ipqeoi5jpKeoiZnqKulgKelLWns6f7y9WnWpTOq8V9FjID89vrgKLqh70NRNZ2Cy25Whhe2EbQtMTek6gpjXNBL3kpBU2/xZ0zS1DjbBtcdqz1HWeFfSaYSzxhoXcf9glShxipMqEbiGsKXexG+I2pvQmYhDD9+LgyOSgxUNXQV87rcfCr/31MPtQCIIOetAgznUyobGHjn73e4TX70/QjcXDHhoEDYIGe+hLPnZfrvrR4+7OhBaz9RC0i2ddBA2CRtAgaCd669KkfGv/edThsO+bPOSfYA2m/E6GSW3LAYIGQYOg4VdOyWes0IfDfptNaPrbclz6qFmIMp3/7KFFTfSYTw6FoiZyzCdBi5rIMad0fMpxjqcfRAl58AP0vpWRG3NAbwAAAABJRU5ErkJggg==',
);

/// The Content-ID the HTML sample's `<img src="cid:…">` names (FakeCore's statement sample).
const inlineLogoCid = 'logo@statements.example';

/// [GoldenCore] whose HTML sample (`FakeCore.htmlSampleId`) has its logo part carry the
/// Content-ID the body's `cid:` image names, with [inlineLogoPng] behind it — what the engine
/// returns for an inline image since it keeps Content-IDs. FakeCore's own sample keeps no
/// Content-ID, so the other HTML tests and goldens still show the placeholder.
///
/// [contentId] is the part's Content-ID (another one leaves the `cid:` unresolved);
/// [failRead] makes the attachment read throw; [declaredSize] overrides the part's stored size
/// (the 5 MiB cap is decided on it, before any read); [bytes] replaces the PNG; [contentType]
/// replaces `image/png`; [guestLink] marks the sample as our own guest-link mail (the card
/// then offers "Resend link" above the attachment chips).
class InlineImageCore extends GoldenCore {
  InlineImageCore({
    this.contentId = inlineLogoCid,
    this.failRead = false,
    this.declaredSize,
    this.contentType = 'image/png',
    this.guestLink = false,
    Uint8List? bytes,
  }) : bytes = bytes ?? inlineLogoPng;

  final String contentId;
  final bool failRead;
  final int? declaredSize;
  final String contentType;
  final bool guestLink;
  final Uint8List bytes;

  /// Every `getAttachment` call as `messageId/index`.
  final List<String> reads = [];

  AttachmentMeta get logo => AttachmentMeta(
    index: 0,
    filename: 'logo.png',
    contentType: contentType,
    size: declaredSize ?? bytes.length,
    contentId: contentId,
  );

  Message _withLogo(Message m) => m.id == FakeCore.htmlSampleId
      ? m.copyWith(attachments: [logo], guestLink: guestLink ? true : null)
      : m;

  @override
  Future<MailThread?> getThread(String threadId) async {
    final t = await super.getThread(threadId);
    if (t == null) return null;
    return MailThread(
      id: t.id,
      subject: t.subject,
      accountId: t.accountId,
      messages: [for (final m in t.messages) _withLogo(m)],
    );
  }

  @override
  Future<Message?> getMessage(String messageId) async {
    final m = await super.getMessage(messageId);
    return m == null ? null : _withLogo(m);
  }

  @override
  Future<AttachmentBytes> getAttachment(String messageId, int index) async {
    reads.add('$messageId/$index');
    if (failRead) throw StateError('the store could not open attachment $index');
    if (messageId == FakeCore.htmlSampleId && index == 0) {
      return AttachmentBytes(meta: logo, data: bytes);
    }
    return super.getAttachment(messageId, index);
  }
}
