import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../platform/secure_screen.dart';
import 'recovery_copy.dart';

/// Settings → Security → "Transfer to another device" (docs/RECOVERY.md,
/// Autocrypt Setup Message): send the setup message to ourselves and show
/// the 36-digit code large; or, on the receiving device, import one.
class TransferScreen extends ConsumerStatefulWidget {
  const TransferScreen({super.key, this.accountId, this.initialExport});

  final String? accountId;

  /// Review/golden captures only: show this export result immediately.
  final SetupExportResult? initialExport;

  @override
  ConsumerState<TransferScreen> createState() => _TransferScreenState();
}

class _TransferScreenState extends ConsumerState<TransferScreen> {
  SetupExportResult? _export;
  bool _busy = false;
  String? _error;
  final _source = TextEditingController();
  final _code = TextEditingController();
  String? _importResult;

  @override
  void initState() {
    super.initState();
    _export = widget.initialExport;
    SecureScreen.set(true);
  }

  @override
  void dispose() {
    SecureScreen.set(false);
    _source.dispose();
    _code.dispose();
    super.dispose();
  }

  Future<String?> _account() async {
    if (widget.accountId != null && widget.accountId!.isNotEmpty) return widget.accountId;
    final accounts = await ref.read(accountsProvider.future);
    return accounts.isEmpty ? null : accounts.first.id;
  }

  Future<void> _send() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final account = await _account();
      if (account == null) throw StateError('Add an account first.');
      final e = await ref.read(coreApiProvider).setupMessageExport(account);
      if (mounted) setState(() => _export = e);
    } catch (e) {
      if (mounted) setState(() => _error = 'Could not send the setup message: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _import() async {
    setState(() {
      _busy = true;
      _error = null;
      _importResult = null;
    });
    try {
      final a = await ref.read(coreApiProvider).setupMessageImport(_source.text.trim(), _code.text);
      ref.invalidate(identityProvider);
      ref.invalidate(accountsProvider);
      if (mounted) {
        setState(
          () => _importResult =
              'Key imported for ${a.email}. Mail encrypted to it opens after the next fetch.',
        );
      }
    } catch (e) {
      final m = '$e';
      if (mounted) {
        setState(
          () => _error = m.contains('wrong setup code')
              ? 'Wrong setup code, or the setup message is damaged. Nothing was changed.'
              : 'Could not import: $m',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final e = _export;
    return Scaffold(
      appBar: AppBar(title: const Text(RecoveryCopy.transferTitle)),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: ListView(
            key: const Key('transfer-list'),
            padding: const EdgeInsets.all(16),
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Send your key to the other device', style: theme.textTheme.titleMedium),
                      const SizedBox(height: 8),
                      Text(
                        'Sealbox mails your secret key to yourself, locked with a setup code that '
                        'is shown only here. No server is involved. Use this when you still have '
                        'this device.',
                        style: theme.textTheme.bodyMedium,
                      ),
                      const SizedBox(height: 12),
                      if (e == null)
                        FilledButton.icon(
                          key: const Key('transfer-send'),
                          onPressed: _busy ? null : _send,
                          icon: const Icon(Icons.send_to_mobile),
                          label: const Text('Send setup message'),
                        )
                      else ...[
                        Text(
                          RecoveryCopy.transferInstruction,
                          key: const Key('transfer-instruction'),
                          style: theme.textTheme.bodyLarge,
                        ),
                        const SizedBox(height: 16),
                        _SetupCode(blocks: e.blocks),
                        const SizedBox(height: 8),
                        Text(
                          'The message is in your inbox as "Autocrypt Setup Message".',
                          style: theme.textTheme.bodySmall,
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Receive a key on this device', style: theme.textTheme.titleMedium),
                      const SizedBox(height: 8),
                      Text(
                        'Add the account here first, fetch mail, then enter the setup message '
                        '(its id, Message-ID or a saved file) and the code shown on the other '
                        'device.',
                        style: theme.textTheme.bodyMedium,
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        key: const Key('transfer-source'),
                        controller: _source,
                        autocorrect: false,
                        decoration: const InputDecoration(
                          labelText: 'Setup message',
                          hintText: 'Message id, Message-ID or file path',
                          border: OutlineInputBorder(),
                        ),
                        onChanged: (_) => setState(() {}),
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        key: const Key('transfer-code'),
                        controller: _code,
                        autocorrect: false,
                        enableSuggestions: false,
                        keyboardType: TextInputType.number,
                        style: const TextStyle(fontFamily: 'monospace'),
                        decoration: const InputDecoration(
                          labelText: 'Setup code (36 digits)',
                          border: OutlineInputBorder(),
                        ),
                        onChanged: (_) => setState(() {}),
                      ),
                      const SizedBox(height: 12),
                      FilledButton(
                        key: const Key('transfer-import'),
                        onPressed:
                            _busy ||
                                _source.text.trim().isEmpty ||
                                _code.text.replaceAll(RegExp(r'[^0-9]'), '').length != 36
                            ? null
                            : _import,
                        child: const Text('Import key'),
                      ),
                      if (_importResult != null) ...[
                        const SizedBox(height: 12),
                        Text(_importResult!, key: const Key('transfer-imported')),
                      ],
                    ],
                  ),
                ),
              ),
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(
                  _error!,
                  key: const Key('transfer-error'),
                  style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// The nine 4-digit blocks, large, three per row.
class _SetupCode extends StatelessWidget {
  const _SetupCode({required this.blocks});

  final List<String> blocks;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: const Key('transfer-code-display'),
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      // 3 × 96 + 2 × 20: exactly three blocks per row.
      child: Center(
        child: SizedBox(
          width: 328,
          child: Wrap(
            alignment: WrapAlignment.center,
            spacing: 20,
            runSpacing: 12,
            children: [
              for (final b in blocks)
                SizedBox(
                  width: 96,
                  child: Text(
                    b,
                    textAlign: TextAlign.center,
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.w600,
                      letterSpacing: 2,
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
