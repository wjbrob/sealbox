import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import 'directory_publish.dart' show directoryProgressProvider;

/// Settings → Server: the Sealbox server URL (guest links, the key directory,
/// encrypted backups, the key-transparency log), editable at run time
/// (`setServerUrl`, stored in the profile, wins over `SEALBOX_SERVER_URL`).
class ServerSection extends ConsumerStatefulWidget {
  const ServerSection({super.key});

  @override
  ConsumerState<ServerSection> createState() => _ServerSectionState();
}

class _ServerSectionState extends ConsumerState<ServerSection> {
  final _url = TextEditingController();
  String? _shown;
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<void> _set(String? url) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final effective = await ref.read(coreApiProvider).setServerUrl(url);
      invalidateServer(ref);
      // A challenge mailed by the previous server means nothing for this one.
      ref.invalidate(directoryProgressProvider);
      _shown = null; // re-seed the field from the new effective URL
      messenger?.removeCurrentSnackBar();
      messenger?.showSnackBar(
        SnackBar(
          key: const Key('server-url-snackbar'),
          content: Text(
            effective == null
                ? 'Server cleared: guest links, backups and the key directory are off.'
                : url == null || url.trim().isEmpty
                ? 'Server setting cleared; using $effective from the environment.'
                : 'Sealbox server set to $effective.',
          ),
        ),
      );
    } catch (e) {
      if (mounted) setState(() => _error = friendlyError(e).replaceFirst('invalid input: ', ''));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final url = ref.watch(serverUrlProvider);
    final source = ref.watch(serverUrlSourceProvider).value;
    final caps = ref.watch(capabilitiesProvider).value;
    final current = url.value;
    if (url.hasValue && _shown != current) {
      // Seed (and re-seed after a change) without fighting the user's typing.
      _shown = current;
      _url.text = current ?? '';
    }
    // The line under the title names where the URL comes from (review N3: it used to
    // repeat the title as "No server configured").
    final (IconData icon, String sourceLabel) = switch (source) {
      ServerUrlSource.settings => (Icons.tune, 'Source: settings (wins over SEALBOX_SERVER_URL)'),
      ServerUrlSource.environment => (Icons.terminal, 'Source: environment (SEALBOX_SERVER_URL)'),
      ServerUrlSource.none || null => (Icons.cloud_off_outlined, 'Source: none — set a URL below'),
    };
    return Card(
      key: const Key('settings-server'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(current == null ? Icons.cloud_off_outlined : Icons.dns_outlined),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    current ?? 'No Sealbox server configured',
                    key: const Key('server-url-current'),
                    style: theme.textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Row(
              key: const Key('server-url-source'),
              children: [
                Icon(icon, size: 16, color: theme.colorScheme.onSurfaceVariant),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    sourceLabel,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              current == null
                  ? 'Encrypted mail to other Sealbox and Autocrypt users works without one. Guest '
                        'links, the key directory, server backups and the key-transparency log need '
                        'a Sealbox server.'
                  : 'Used for guest links${caps?.keyDirectory == true ? ', the key directory' : ''}, '
                        'encrypted backups and the key-transparency log. It never sees your mail in '
                        'plaintext.',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('server-url-field'),
              controller: _url,
              keyboardType: TextInputType.url,
              autocorrect: false,
              enabled: !_busy,
              decoration: InputDecoration(
                labelText: 'Server URL',
                hintText: 'https://sealbox.example.org',
                border: const OutlineInputBorder(),
                errorText: _error,
                errorMaxLines: 3,
              ),
              onChanged: (_) {
                if (_error != null) setState(() => _error = null);
              },
              onSubmitted: (v) => _set(v),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                FilledButton.tonal(
                  key: const Key('server-url-save'),
                  onPressed: _busy ? null : () => _set(_url.text),
                  child: const Text('Save'),
                ),
                if (source == ServerUrlSource.settings)
                  TextButton(
                    key: const Key('server-url-clear'),
                    onPressed: _busy ? null : () => _set(null),
                    child: const Text('Clear'),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
