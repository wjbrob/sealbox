/// The body of one message in the thread view: sanitized HTML when the mail has an HTML
/// part, plain text otherwise (and whenever the reader asks for text).
///
/// The HTML has already been through the engine's sanitizer (`docs/HTML_MAIL.md`): no script,
/// no CSS, allow-listed tags only, links `http(s)`/`mailto`, images `cid:` / `data:image/*`
/// and — only after the reader taps "Load images" — `http(s)`. This widget adds the two
/// decisions the engine leaves to the screen:
///
/// * **Remote images stay blocked** until the reader asks for them, per message. Loading one
///   tells the sender's server that the mail was opened, so the banner says how many are
///   waiting and nothing is fetched before the tap. The image factory below refuses any URL
///   the sanitizer did not allow, so a bug upstream cannot turn into a silent fetch.
/// * **A link is never followed on a single tap.** Tapping one opens a sheet that shows the
///   real target (which can differ from the link text) and asks before leaving the app.
/// * **Inline images** (`<img src="cid:…">`) show the attachment whose Content-ID they name
///   ([AttachmentMeta.contentId]; see [inlinePartFor]). The bytes come from the local store,
///   never the network, are read once per Content-ID while the widget lives, and are decoded
///   at most [kInlineImageMaxSide] pixels on the longer side. A `cid:` that no part carries, a
///   part that is not an image or is larger than [kInlineImageMaxBytes], and a read or decode
///   that fails all stay the labelled placeholder.
/// * **An image shown inline is not listed again** among the attachment chips under the body
///   (review N4, [listedAttachments]): the card passes its chips in as [MessageBody.footer] and
///   gets back the parts to list. A part the HTML never names, one that is not an image or is
///   over the cap, one whose read or decode failed (a placeholder stands in its place), and
///   every part while the body is shown as text keep their chip. Saving an inline image goes
///   through "Show as text", which lists every part again (the thread has no per-message
///   menu).
library;

import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_widget_from_html_core/flutter_widget_from_html_core.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';

/// Largest inline image (stored bytes) the thread view reads and decodes; a larger part stays a
/// placeholder with the image's alt text.
const int kInlineImageMaxBytes = 5 * 1024 * 1024;

/// Longest side, in pixels, an inline image is decoded at. A few kilobytes of PNG can describe
/// a bitmap of gigabytes, so the decode is bounded whatever the file says.
const int kInlineImageMaxSide = 2048;

/// The Content-ID a `cid:` URL names (RFC 2392): the rest of the URL percent-decoded, angle
/// brackets dropped. `null` for any other URL and for an empty one. An escape that does not
/// decode leaves the text as it was, as the engine's `cid_content_id` does.
String? cidContentId(String src) {
  final s = src.trim();
  if (s.length < 4 || s.substring(0, 4).toLowerCase() != 'cid:') return null;
  final rest = s.substring(4);
  String decoded;
  try {
    decoded = Uri.decodeComponent(rest);
  } catch (_) {
    decoded = rest;
  }
  final id = _withoutAngles(decoded);
  return id.isEmpty ? null : id;
}

/// The attachment an `<img src="cid:…">` names: the part whose Content-ID equals the URL's
/// ([cidContentId]; compared exactly, case-sensitive). `null` for any other URL and for a
/// `cid:` that no part carries.
AttachmentMeta? inlinePartFor(List<AttachmentMeta> parts, String src) {
  final cid = cidContentId(src);
  if (cid == null) return null;
  for (final p in parts) {
    final own = p.contentId;
    if (own != null && _withoutAngles(own) == cid) return p;
  }
  return null;
}

/// Does the thread view show [part] in place of an `<img src="cid:…">` that names it? Only an
/// `image/*` part of at most [kInlineImageMaxBytes] (stored size, decided before any read); any
/// other part a `cid:` names stays a placeholder and is reached through its chip.
bool showsInline(AttachmentMeta part) =>
    part.size <= kInlineImageMaxBytes && part.contentType.toLowerCase().startsWith('image/');

/// The `src` of every `<img>` in [html], in document order, character references decoded.
///
/// [html] is the engine's sanitized markup (html5ever's serialization: lower-case names, values
/// in double quotes, no comments); single-quoted and unquoted values are read as well. Quoted
/// values are skipped as a whole, so markup written inside another tag's attribute (a `title`
/// may hold `<img src=…>` verbatim) is not taken for an image.
List<String> imageSources(String html) {
  final sources = <String>[];
  var i = 0;
  while (true) {
    final lt = html.indexOf('<', i);
    if (lt < 0) break;
    if (html.startsWith('<!--', lt)) {
      final end = html.indexOf('-->', lt + 4);
      if (end < 0) break;
      i = end + 3;
      continue;
    }
    final name = _tagName.matchAsPrefix(html, lt);
    if (name == null) {
      i = lt + 1;
      continue;
    }
    final isImg = name[1]!.toLowerCase() == 'img';
    var j = name.end;
    while (j < html.length && html[j] != '>') {
      final a = _attribute.matchAsPrefix(html, j);
      if (a == null) {
        j++; // whitespace, the `/` of `/>`, or a stray quote or `=`
        continue;
      }
      if (isImg && a[1]!.toLowerCase() == 'src') {
        final value = a[2] ?? a[3] ?? a[4];
        if (value != null) sources.add(_decodeReferences(value));
      }
      j = a.end;
    }
    if (j >= html.length) break; // a tag the markup never closes
    i = j + 1;
  }
  return sources;
}

final _tagName = RegExp(r'<([A-Za-z][^\s/>]*)');
final _attribute = RegExp(r'''([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?''');
final _reference = RegExp(r'&(#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z]+);');
const _named = {'amp': '&', 'quot': '"', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': '\u00a0'};

/// [s] with its character references decoded (numeric ones and the few a serializer writes);
/// anything else stays as written.
String _decodeReferences(String s) => s.contains('&')
    ? s.replaceAllMapped(_reference, (m) {
        final ref = m[1]!;
        if (!ref.startsWith('#')) return _named[ref] ?? m[0]!;
        final hex = ref.length > 1 && (ref[1] == 'x' || ref[1] == 'X');
        final code = int.tryParse(hex ? ref.substring(2) : ref.substring(1), radix: hex ? 16 : 10);
        return code == null || code > 0x10FFFF ? m[0]! : String.fromCharCode(code);
      })
    : s;

/// The attachments the thread lists as chips under a message's body (review N4): every one of
/// [parts] but an image the HTML on screen shows inline — the part an `<img src="cid:…">` in
/// [html] names ([inlinePartFor]) when it [showsInline]. [html] is `null` while the body is
/// shown as text (no HTML part, still loading, or "Show as text"); then every part is listed,
/// as it is the only way to reach one. [unshown] holds the Content-IDs whose image could not
/// be shown after all (the read failed, the bytes did not decode): a placeholder stands there,
/// so those parts keep their chip too.
List<AttachmentMeta> listedAttachments(
  List<AttachmentMeta> parts,
  String? html, {
  Set<String> unshown = const {},
}) {
  if (html == null || parts.isEmpty) return parts;
  final inline = <AttachmentMeta>{
    for (final src in imageSources(html))
      if (inlinePartFor(parts, src) case final part?
          when showsInline(part) && !unshown.contains(_withoutAngles(part.contentId ?? '')))
        part,
  };
  if (inline.isEmpty) return parts;
  return [
    for (final p in parts)
      if (!inline.contains(p)) p,
  ];
}

String _withoutAngles(String s) {
  var t = s.trim();
  while (t.startsWith('<')) {
    t = t.substring(1);
  }
  while (t.endsWith('>')) {
    t = t.substring(0, t.length - 1);
  }
  return t;
}

/// The sanitized HTML body of a message, blocked or loaded.
final messageHtmlProvider = FutureProvider.family<HtmlBody?, MessageHtmlRequest>((ref, r) {
  return ref.watch(coreApiProvider).messageHtml(r.messageId, allowRemote: r.allowRemote);
});

/// Key of [messageHtmlProvider]: one entry per message and remote-content choice.
@immutable
class MessageHtmlRequest {
  const MessageHtmlRequest(this.messageId, {this.allowRemote = false});

  final String messageId;
  final bool allowRemote;

  @override
  bool operator ==(Object other) =>
      other is MessageHtmlRequest &&
      other.messageId == messageId &&
      other.allowRemote == allowRemote;

  @override
  int get hashCode => Object.hash(messageId, allowRemote);
}

class MessageBody extends ConsumerStatefulWidget {
  const MessageBody({
    super.key,
    required this.messageId,
    required this.text,
    this.attachments = const [],
    this.footer,
  });

  /// Local message id (the engine's).
  final String messageId;

  /// The plain-text view: shown while the HTML loads, when there is none, and when the
  /// reader chose "Show as text".
  final String text;

  /// The message's attachments: where an inline `cid:` image finds its part.
  final List<AttachmentMeta> attachments;

  /// What follows the body in its card, given the attachments to list there as chips:
  /// [attachments] without an image the HTML shows inline ([listedAttachments], review N4).
  /// Built again when the reader switches between the HTML and "Show as text".
  final List<Widget> Function(BuildContext context, List<AttachmentMeta> listed)? footer;

  @override
  ConsumerState<MessageBody> createState() => _MessageBodyState();
}

class _MessageBodyState extends ConsumerState<MessageBody> {
  bool _allowRemote = false;
  bool _asText = false;

  /// Inline-image reads by Content-ID: at most one per Content-ID while this widget lives,
  /// whatever re-renders the HTML ("Show as text" and back, "Load images").
  final Map<String, _InlineFetch> _inline = {};

  /// Content-IDs whose image could not be shown (the read failed, the bytes did not decode):
  /// their placeholder stays, and their part keeps its chip ([listedAttachments]).
  final Set<String> _unshown = {};

  @override
  void didUpdateWidget(MessageBody oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.messageId != widget.messageId) {
      _inline.clear();
      _unshown.clear();
    }
  }

  void _markUnshown(String cid) {
    if (!mounted || _unshown.contains(cid)) return;
    setState(() => _unshown.add(cid));
  }

  /// What an `<img src="cid:…">` becomes: the image of the part it names, or the placeholder.
  Widget _inlineImage(String src, String? alt) {
    final placeholder = _BlockedImage(src: src, alt: alt);
    final part = inlinePartFor(widget.attachments, src);
    if (part == null || !showsInline(part)) return placeholder;
    final cid = _withoutAngles(part.contentId ?? '');
    final fetch = _inline.putIfAbsent(cid, () {
      final read = _InlineFetch(_readInline(part));
      read.future.then((bytes) {
        if (bytes == null) _markUnshown(cid);
      });
      return read;
    });
    return _InlineImage(
      fetch: fetch,
      alt: alt,
      placeholder: placeholder,
      // Called while the image builds: the chip comes back after this frame.
      onDecodeError: () => WidgetsBinding.instance.addPostFrameCallback((_) => _markUnshown(cid)),
    );
  }

  /// The part's bytes from the store; `null` (a placeholder, never an exception in the thread)
  /// when the read fails or returns nothing usable.
  Future<Uint8List?> _readInline(AttachmentMeta part) async {
    try {
      final bytes = await ref.read(coreApiProvider).getAttachment(widget.messageId, part.index);
      final data = bytes.data;
      return data.isEmpty || data.length > kInlineImageMaxBytes ? null : data;
    } catch (_) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final request = MessageHtmlRequest(widget.messageId, allowRemote: _allowRemote);
    final body = ref.watch(messageHtmlProvider(request)).value;
    final theme = Theme.of(context);
    final footer = widget.footer;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Above the body, so it is reachable without scrolling a long newsletter to its end.
        if (body != null) ...[
          // Wrap, not a Row: on a phone the banner and the toggle do not fit on one line,
          // and squeezing them would wrap "2 remote images blocked" into five.
          Wrap(
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 8,
            children: [
              if (!_asText && body.hasBlockedImages)
                _BlockedImagesBanner(
                  count: body.remoteImages,
                  onLoad: () => setState(() => _allowRemote = true),
                ),
              _toggle(toText: !_asText),
            ],
          ),
          const SizedBox(height: 4),
        ],
        if (body == null || _asText)
          // No HTML part, still loading, or the reader asked for text.
          _text()
        else
          HtmlWidget(
            body.html,
            key: ValueKey('message-html-${widget.messageId}'),
            // Inherit the thread's text colour: no white boxes in dark mode (the sanitizer
            // removed every colour the sender chose, so nothing fights this).
            textStyle: theme.textTheme.bodyMedium ?? const TextStyle(),
            renderMode: RenderMode.column,
            // Nothing async: widget tests and goldens settle in one pump.
            buildAsync: false,
            enableCaching: false,
            factoryBuilder: () =>
                _SafeImageFactory(allowRemote: _allowRemote, inlineImage: _inlineImage),
            customWidgetBuilder: (element) {
              if (element.localName == 'span' &&
                  element.classes.contains(HtmlBody.blockedImageClass)) {
                return _BlockedImage(src: element.attributes['data-src'] ?? '');
              }
              return null;
            },
            onTapUrl: (url) => _confirmLink(context, url),
          ),
        if (footer != null)
          ...footer(
            context,
            listedAttachments(
              widget.attachments,
              body == null || _asText ? null : body.html,
              unshown: _unshown,
            ),
          ),
      ],
    );
  }

  Widget _text() => SelectableText(
    widget.text,
    key: ValueKey('message-body-${widget.messageId}'),
    style: Theme.of(context).textTheme.bodyMedium,
  );

  Widget _toggle({required bool toText}) => Align(
    alignment: Alignment.centerLeft,
    child: TextButton.icon(
      key: const Key('message-show-text'),
      onPressed: () => setState(() => _asText = toText),
      icon: Icon(toText ? Icons.subject : Icons.article_outlined, size: 18),
      label: Text(toText ? 'Show as text' : 'Show formatting'),
    ),
  );

  /// The link sheet: the real target, then a deliberate "Open link".
  Future<bool> _confirmLink(BuildContext context, String url) async {
    final messenger = ScaffoldMessenger.of(context);
    final go = await showModalBottomSheet<bool>(
      context: context,
      showDragHandle: true,
      builder: (context) {
        final theme = Theme.of(context);
        return SafeArea(
          child: Padding(
            key: const Key('html-link-sheet'),
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Open this link?', style: theme.textTheme.titleMedium),
                const SizedBox(height: 8),
                // The whole point of the sheet: what the link really points at.
                SelectableText(
                  url,
                  key: const Key('html-link-url'),
                  style: theme.textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
                ),
                const SizedBox(height: 4),
                Text(
                  'A link in a message can say one thing and point somewhere else. '
                  'Check the address above before you open it.',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    TextButton(
                      key: const Key('html-link-cancel'),
                      onPressed: () => Navigator.of(context).pop(false),
                      child: const Text('Cancel'),
                    ),
                    const SizedBox(width: 8),
                    FilledButton.icon(
                      key: const Key('html-link-open'),
                      onPressed: () => Navigator.of(context).pop(true),
                      icon: const Icon(Icons.open_in_new),
                      label: const Text('Open link'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
    if (go != true) return true; // handled: the sheet decided not to open it
    final uri = Uri.tryParse(url);
    if (uri == null) return true;
    try {
      final ok = await launchUrl(uri, mode: LaunchMode.externalApplication);
      if (!ok) messenger.showSnackBar(SnackBar(content: Text('Could not open $url')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not open $url: $e')));
    }
    return true;
  }
}

/// "N images blocked · Load images".
class _BlockedImagesBanner extends StatelessWidget {
  const _BlockedImagesBanner({required this.count, required this.onLoad});

  final int count;
  final VoidCallback onLoad;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final label = count == 1 ? '1 remote image blocked' : '$count remote images blocked';
    return Container(
      key: const Key('html-remote-banner'),
      padding: const EdgeInsets.fromLTRB(12, 4, 8, 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.image_not_supported_outlined,
            size: 18,
            color: theme.colorScheme.onSurfaceVariant,
          ),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
          TextButton(
            key: const Key('html-load-images'),
            onPressed: onLoad,
            child: const Text('Load images'),
          ),
        ],
      ),
    );
  }
}

/// Stands in for a remote image that was not loaded, and for an inline `cid:` image that
/// cannot be shown: no part has its Content-ID, the part is not an image or is too large, or
/// reading or decoding it failed (and, briefly, while it is being read).
class _BlockedImage extends StatelessWidget {
  const _BlockedImage({required this.src, this.alt});

  final String src;
  final String? alt;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final host = Uri.tryParse(src)?.host;
    final label = alt?.trim().isNotEmpty == true
        ? alt!.trim()
        : host?.isNotEmpty == true
        ? 'Image from $host'
        : 'Image';
    return Semantics(
      label: '$label (not loaded)',
      image: true,
      child: ExcludeSemantics(
        // Only as wide as its label: a placeholder for a 600 px banner must not stretch
        // across the whole card as if it were the image itself.
        child: Align(
          alignment: Alignment.centerLeft,
          child: Container(
            key: const Key('html-blocked-image'),
            margin: const EdgeInsets.symmetric(vertical: 4),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
            decoration: BoxDecoration(
              border: Border.all(color: theme.colorScheme.outlineVariant),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.image_outlined,
                  size: 18,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 8),
                Flexible(
                  child: Text(
                    label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// One inline image's read: started once, its result kept so a re-render shows it at once.
class _InlineFetch {
  _InlineFetch(Future<Uint8List?> read) {
    future = read.then((b) => bytes = b);
  }

  late final Future<Uint8List?> future;

  /// The bytes once [future] completed with some (`null` before, and after a failure).
  Uint8List? bytes;
}

/// An inline `cid:` image: the placeholder until its bytes are read, then the image; the
/// placeholder again when they do not decode.
class _InlineImage extends StatelessWidget {
  const _InlineImage({
    required this.fetch,
    required this.placeholder,
    this.alt,
    this.onDecodeError,
  });

  /// The bytes did not decode (the placeholder is shown instead).
  final VoidCallback? onDecodeError;

  final _InlineFetch fetch;
  final Widget placeholder;
  final String? alt;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Uint8List?>(
      future: fetch.future,
      // Already read (the HTML re-rendered): the image in the first frame, no placeholder.
      initialData: fetch.bytes,
      builder: (context, snapshot) {
        final bytes = snapshot.data;
        if (bytes == null) return placeholder;
        final label = alt?.trim() ?? '';
        // At its own size (scaled down to fit) at the start of the line, as a browser shows
        // an inline image — not stretched or centred in a full-width block.
        return Align(
          key: const Key('html-inline-image'),
          alignment: AlignmentDirectional.centerStart,
          widthFactor: 1,
          heightFactor: 1,
          child: Image(
            image: _InlineMemoryImage(bytes),
            semanticLabel: label.isEmpty ? null : label,
            excludeFromSemantics: label.isEmpty,
            fit: BoxFit.scaleDown,
            gaplessPlayback: true,
            errorBuilder: (context, error, stackTrace) {
              onDecodeError?.call();
              return placeholder;
            },
          ),
        );
      },
    );
  }
}

/// A [MemoryImage] decoded at most [kInlineImageMaxSide] pixels on its longer side (aspect
/// ratio kept); smaller images decode at their own size. Same cache key as a [MemoryImage].
class _InlineMemoryImage extends MemoryImage {
  const _InlineMemoryImage(super.bytes);

  @override
  ImageStreamCompleter loadImage(MemoryImage key, ImageDecoderCallback decode) =>
      super.loadImage(key, (buffer, {getTargetSize}) => decode(buffer, getTargetSize: _bounded));

  static ui.TargetImageSize _bounded(int width, int height) {
    if (width <= kInlineImageMaxSide && height <= kInlineImageMaxSide) {
      return const ui.TargetImageSize();
    }
    return width >= height
        ? const ui.TargetImageSize(width: kInlineImageMaxSide)
        : const ui.TargetImageSize(height: kInlineImageMaxSide);
  }
}

/// Decides what every `<img>` in a message may become. The sanitizer already limited the
/// sources; this refuses anything else anyway, so no bug upstream can produce a fetch the
/// reader did not ask for.
class _SafeImageFactory extends WidgetFactory {
  _SafeImageFactory({required this.allowRemote, required this.inlineImage});

  final bool allowRemote;

  /// Builds a `cid:` image: the attachment it names, from the local store.
  final Widget Function(String src, String? alt) inlineImage;

  @override
  Widget? buildImageWidget(BuildTree tree, ImageSource src) {
    final url = src.url;
    final alt = src.image?.alt ?? src.image?.title;
    if (url.startsWith('data:image/')) {
      final provider = imageProviderFromDataUri(url);
      if (provider == null) return _BlockedImage(src: url, alt: alt);
      return Image(image: provider, semanticLabel: alt, fit: BoxFit.scaleDown);
    }
    if (url.toLowerCase().startsWith('cid:')) return inlineImage(url, alt);
    final remote = url.startsWith('https://') || url.startsWith('http://');
    if (remote && allowRemote) {
      return super.buildImageWidget(tree, src);
    }
    // A remote image while blocked, anything else.
    return _BlockedImage(src: url, alt: alt);
  }

  /// Nothing is ever decoded from an asset or a local file in a message.
  @override
  ImageProvider? imageProviderFromAsset(String url) => null;

  @override
  ImageProvider? imageProviderFromFileUri(String url) => null;

  @override
  ImageProvider? imageProviderFromNetwork(String url) =>
      allowRemote ? super.imageProviderFromNetwork(url) : null;

  /// `data:image/…;base64,…` only, and only the four formats the sanitizer allows.
  @override
  ImageProvider? imageProviderFromDataUri(String url) {
    final comma = url.indexOf(',');
    if (comma < 0) return null;
    final meta = url.substring(0, comma).toLowerCase();
    const allowed = [
      'data:image/png;base64',
      'data:image/jpeg;base64',
      'data:image/gif;base64',
      'data:image/webp;base64',
    ];
    if (!allowed.contains(meta)) return null;
    try {
      return MemoryImage(base64Decode(url.substring(comma + 1).replaceAll(' ', '')));
    } catch (_) {
      return null;
    }
  }
}
