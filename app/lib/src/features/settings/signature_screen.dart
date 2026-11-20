import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';

/// Per-account signature editor (engine: `Engine::set_signature`, applied by `send`).
class SignatureSettingsScreen extends ConsumerStatefulWidget {
  const SignatureSettingsScreen({super.key, required this.accountId});

  final String accountId;

  @override
  ConsumerState<SignatureSettingsScreen> createState() => _SignatureSettingsScreenState();
}

class _SignatureSettingsScreenState extends ConsumerState<SignatureSettingsScreen> {
  final _text = TextEditingController();
  final _html = TextEditingController();
  SignatureSettings? _edit;
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _text.dispose();
    _html.dispose();
    super.dispose();
  }

  void _load(SignatureSettings s) {
    if (_edit != null) return;
    _edit = s;
    _text.text = s.text;
    _html.text = s.html ?? '';
  }

  Future<void> _save() async {
    final e = _edit;
    if (e == null) return; // not loaded yet
    setState(() {
      _saving = true;
      _error = null;
    });
    final messenger = ScaffoldMessenger.of(context);
    try {
      final stored = await ref.read(coreApiProvider).setSignature(
        widget.accountId,
        e.copyWith(text: _text.text, html: _html.text.trim().isEmpty ? '' : _html.text),
      );
      ref.invalidate(signatureProvider(widget.accountId));
      if (!mounted) return;
      setState(() {
        _edit = stored;
        _text.text = stored.text;
        _html.text = stored.html ?? '';
        _saving = false;
      });
      messenger.showSnackBar(
        SnackBar(content: Text(stored.enabled ? 'Signature saved and on' : 'Signature saved (off)')),
      );
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _error = '$err';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final loaded = ref.watch(signatureProvider(widget.accountId));
    return Scaffold(
      appBar: AppBar(
        leading: BackButton(onPressed: () => context.canPop() ? context.pop() : context.go('/settings')),
        title: const Text('Signature'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: FilledButton.icon(
              key: const Key('signature-save'),
              // `_edit` is seeded during the first data build, so enable from the
              // loaded state rather than from `_edit` (else Save is off on first paint).
              onPressed: _saving || !loaded.hasValue ? null : _save,
              icon: _saving
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.save_outlined),
              label: const Text('Save'),
            ),
          ),
        ],
      ),
      body: loaded.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(child: Text('Could not load the signature: $e')),
        data: (s) {
          _load(s);
          final e = _edit!;
          return Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 820),
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  Text(widget.accountId, style: theme.textTheme.bodySmall),
                  const SizedBox(height: 8),
                  SwitchListTile(
                    key: const Key('signature-enabled'),
                    title: const Text('Add my signature to outgoing mail'),
                    subtitle: const Text('Appended after the "-- " separator; encrypted mail carries it inside the encrypted part.'),
                    value: e.enabled,
                    onChanged: (v) => setState(() => _edit = e.copyWith(enabled: v)),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('signature-text'),
                    controller: _text,
                    minLines: 3,
                    maxLines: 8,
                    decoration: InputDecoration(
                      labelText: 'Signature (plain text)',
                      alignLabelWithHint: true,
                      border: const OutlineInputBorder(),
                      errorText: _error,
                      errorMaxLines: 3,
                    ),
                    onChanged: (_) => setState(() {}),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('signature-html'),
                    controller: _html,
                    minLines: 2,
                    maxLines: 6,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: const InputDecoration(
                      labelText: 'HTML signature (optional, sanitised)',
                      helperText: 'Used only when a message has an HTML body. Scripts, styles and tracking are stripped.',
                      alignLabelWithHint: true,
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text('Placement in replies', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 6),
                  SegmentedButton<SignaturePlacement>(
                    key: const Key('signature-placement'),
                    showSelectedIcon: false,
                    segments: const [
                      ButtonSegment(value: SignaturePlacement.aboveQuote, label: Text('Above the quote')),
                      ButtonSegment(value: SignaturePlacement.belowQuote, label: Text('Below the quote')),
                    ],
                    selected: {e.placement},
                    onSelectionChanged: (v) => setState(() => _edit = e.copyWith(placement: v.first)),
                  ),
                  const SizedBox(height: 16),
                  Text('Include on', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 6),
                  SegmentedButton<SignatureIncludeOn>(
                    key: const Key('signature-include-on'),
                    showSelectedIcon: false,
                    segments: const [
                      ButtonSegment(value: SignatureIncludeOn.newOnly, label: Text('New messages')),
                      ButtonSegment(value: SignatureIncludeOn.newAndReplies, label: Text('New + replies')),
                      ButtonSegment(value: SignatureIncludeOn.all, label: Text('Everything')),
                    ],
                    selected: {e.includeOn},
                    onSelectionChanged: (v) => setState(() => _edit = e.copyWith(includeOn: v.first)),
                  ),
                  const SizedBox(height: 24),
                  Text('Preview', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 6),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Text(
                        _text.text.trim().isEmpty
                            ? '(empty — nothing will be added)'
                            : 'Your message text…\n\n-- \n${_text.text}',
                        key: const Key('signature-preview'),
                        style: theme.textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}
