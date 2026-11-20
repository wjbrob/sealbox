import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import 'compose_controller.dart';

/// The collapsible "Preview" under the message body: exactly the text the
/// engine will send (`composePreview`) — the typed text, the account signature
/// where its settings put it, and the quote of a reply or the forwarded
/// message — refreshed a moment after the body or the sending account changes.
class ComposePreviewPanel extends ConsumerStatefulWidget {
  const ComposePreviewPanel({super.key, this.initiallyOpen = false});

  /// Replies and forwards open it: the quote is no longer in the editor.
  final bool initiallyOpen;

  static const debounce = Duration(milliseconds: 400);

  @override
  ConsumerState<ComposePreviewPanel> createState() => _ComposePreviewPanelState();
}

class _ComposePreviewPanelState extends ConsumerState<ComposePreviewPanel> {
  late bool _open = widget.initiallyOpen;
  ComposePreview? _preview;
  String? _error;
  bool _loading = false;
  Timer? _timer;
  int _seq = 0;

  @override
  void initState() {
    super.initState();
    if (_open) WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void didUpdateWidget(covariant ComposePreviewPanel old) {
    super.didUpdateWidget(old);
    if (widget.initiallyOpen && !old.initiallyOpen && !_open) {
      _open = true;
      _schedule(Duration.zero);
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _schedule([Duration delay = ComposePreviewPanel.debounce]) {
    _timer?.cancel();
    _timer = Timer(delay, _load);
  }

  Future<void> _load() async {
    if (!mounted || !_open) return;
    final draft = ref.read(composeControllerProvider.notifier).draft();
    if (draft == null) {
      setState(() {
        _preview = null;
        _error = 'Choose the sending account first.';
      });
      return;
    }
    final seq = ++_seq;
    setState(() => _loading = true);
    try {
      final p = await ref.read(coreApiProvider).composePreview(draft);
      if (!mounted || seq != _seq) return;
      setState(() {
        _preview = p;
        _error = null;
        _loading = false;
      });
    } catch (e) {
      if (!mounted || seq != _seq) return;
      setState(() {
        _error = friendlyError(e);
        _loading = false;
      });
    }
  }

  void _toggle() {
    setState(() => _open = !_open);
    if (_open) _schedule(Duration.zero);
  }

  @override
  Widget build(BuildContext context) {
    // What the preview depends on: the text, the account (its signature) and the
    // reply / forward options.
    ref.listen(composeControllerProvider, (prev, next) {
      if (!_open || prev == null) return;
      if (prev.accountId != next.accountId ||
          prev.inReplyTo != next.inReplyTo ||
          !identical(prev.compose, next.compose)) {
        _schedule(Duration.zero); // a choice, not typing: refresh at once
      } else if (prev.body != next.body) {
        _schedule();
      }
    });
    final theme = Theme.of(context);
    final p = _preview;
    return Card(
      key: const Key('compose-preview'),
      margin: EdgeInsets.zero,
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ListTile(
            key: const Key('compose-preview-toggle'),
            leading: const Icon(Icons.preview_outlined),
            title: const Text('Preview'),
            subtitle: const Text('What Sealbox will send, signature and quote included'),
            trailing: Icon(_open ? Icons.expand_less : Icons.expand_more),
            onTap: _toggle,
          ),
          if (_open) ...[
            SizedBox(
              height: 2,
              child: _loading ? const LinearProgressIndicator(minHeight: 2) : null,
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
              child: _error != null
                  ? Text(
                      _error!,
                      key: const Key('compose-preview-error'),
                      style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
                    )
                  : p == null
                  ? const SizedBox(height: 24)
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Wrap(
                          spacing: 8,
                          runSpacing: 4,
                          children: [
                            Chip(
                              avatar: Icon(switch (p.kind) {
                                ComposeKind.reply => Icons.reply,
                                ComposeKind.forward => Icons.forward,
                                ComposeKind.newMessage => Icons.edit_outlined,
                              }, size: 18),
                              label: Text(switch (p.kind) {
                                ComposeKind.reply => 'Reply with quote',
                                ComposeKind.forward => 'Forward',
                                ComposeKind.newMessage => 'New message',
                              }),
                            ),
                            Chip(
                              key: const Key('compose-preview-signature'),
                              avatar: Icon(
                                p.signatureApplied ? Icons.draw_outlined : Icons.do_not_disturb_alt,
                                size: 18,
                              ),
                              label: Text(p.signatureApplied ? 'Signature added' : 'No signature'),
                            ),
                          ],
                        ),
                        if (p.forwardedAttachments.isNotEmpty) ...[
                          const SizedBox(height: 8),
                          Text(
                            'Attachments that go along: ${p.forwardedAttachments.join(', ')}',
                            key: const Key('compose-preview-attachments'),
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                        const SizedBox(height: 8),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: SelectableText(
                            p.text.trimRight().isEmpty ? '(empty message)' : p.text.trimRight(),
                            key: const Key('compose-preview-text'),
                            style: theme.textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
                          ),
                        ),
                      ],
                    ),
            ),
          ],
        ],
      ),
    );
  }
}
