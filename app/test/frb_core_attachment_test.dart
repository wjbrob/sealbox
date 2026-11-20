import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/rust/api/engine.dart' as frb;

import 'support/fake_frb_engine.dart';

// FrbCore maps the bridge's attachment metadata, Content-ID included: an inline `cid:` image in
// the thread view finds its part by it (docs/HTML_MAIL.md, "Inline images").

class _Engine extends FakeFrbEngine {
  final List<String> reads = [];

  @override
  Future<frb.AttachmentBytes> getAttachment({required int id, required int index}) async {
    reads.add('$id/$index');
    return frb.AttachmentBytes(info: _logo, data: Uint8List.fromList([1, 2, 3]));
  }
}

const _logo = frb.AttachmentInfo(
  index: 1,
  filename: 'logo.png',
  contentType: 'image/png',
  size: 3,
  contentId: 'logo@x',
);

void main() {
  test('message attachments and attachment reads carry the Content-ID', () async {
    final s = FakeFrbEngine.summary(5);
    final engine = _Engine()
      ..summaries.add(s)
      ..details[5] = frb.MessageDetail(
        summary: s,
        html: '<p><img src="cid:logo@x"></p>',
        attachments: const [
          frb.AttachmentInfo(index: 0, filename: 'a.pdf', contentType: 'application/pdf', size: 9),
          _logo,
        ],
        inReplyTo: const [],
        references: const [],
      );
    final core = FrbCore(engine);
    final m = await core.getMessage('5');
    expect(m, isNotNull);
    expect([for (final a in m!.attachments) a.contentId], [null, 'logo@x']);
    expect(m.attachments[1].filename, 'logo.png');

    final bytes = await core.getAttachment('5', 1);
    expect(engine.reads, ['5/1']);
    expect(bytes.meta.contentId, 'logo@x');
    expect(bytes.meta.index, 1);
    expect(bytes.data, [1, 2, 3]);
  });
}
