import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import 'spam_explain_sheet.dart' show percent;

String spamSettingsRoute(String accountId) =>
    '/settings/spam?account=${Uri.encodeQueryComponent(accountId)}';

/// Settings → Mail handling → Spam: what the personal model has learned (all
/// accounts), and one account's spam settings: on/off, the two thresholds with
/// the engine's labels, DNS blocklists (with what they reveal), where spam goes,
/// and the allow / block lists.
class SpamSettingsScreen extends ConsumerStatefulWidget {
  const SpamSettingsScreen({super.key, required this.accountId});

  final String accountId;

  @override
  ConsumerState<SpamSettingsScreen> createState() => _SpamSettingsScreenState();
}

class _SpamSettingsScreenState extends ConsumerState<SpamSettingsScreen> {
  SpamSettings? _edit;
  final _folder = TextEditingController();
  final _allow = TextEditingController();
  final _block = TextEditingController();
  bool _saving = false;
  String? _error;
  String? _listError;

  @override
  void dispose() {
    _folder.dispose();
    _allow.dispose();
    _block.dispose();
    super.dispose();
  }

  void _seed(SpamSettings s) {
    if (_edit != null) return;
    _edit = s;
    _folder.text = s.moveToFolder;
  }

  static String _clean(Object e) => friendlyError(e).replaceFirst('invalid input: ', '');

  Future<void> _save() async {
    final e = _edit;
    if (e == null) return;
    final messenger = ScaffoldMessenger.maybeOf(context);
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      final stored = await ref
          .read(coreApiProvider)
          .setSpamSettings(widget.accountId, e.copyWith(moveToFolder: _folder.text.trim()));
      ref.invalidate(spamSettingsProvider(widget.accountId));
      ref.invalidate(spamStatusProvider);
      if (!mounted) return;
      setState(() {
        _edit = stored;
        _folder.text = stored.moveToFolder;
        _saving = false;
      });
      messenger?.showSnackBar(
        SnackBar(
          key: const Key('spam-saved-snackbar'),
          content: Text(
            stored.enabled ? 'Spam settings saved' : 'Spam filtering is off for this account',
          ),
        ),
      );
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _error = _clean(err);
      });
    }
  }

  Future<void> _list({required bool allow, required String entry, required bool add}) async {
    final e = entry.trim();
    if (e.isEmpty) return;
    setState(() => _listError = null);
    try {
      final core = ref.read(coreApiProvider);
      final r = allow
          ? await core.spamAllow(widget.accountId, e, add: add)
          : await core.spamBlock(widget.accountId, e, add: add);
      ref.invalidate(spamSettingsProvider(widget.accountId));
      if (!mounted) return;
      setState(() {
        // Keep unsaved threshold edits; take the lists as stored.
        _edit = (_edit ?? r).copyWith(allowlist: r.allowlist, blocklist: r.blocklist);
        if (add) (allow ? _allow : _block).clear();
      });
    } catch (err) {
      if (mounted) setState(() => _listError = _clean(err));
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final loaded = ref.watch(spamSettingsProvider(widget.accountId));
    final status = ref.watch(spamStatusProvider).value;
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final account = accounts.where((a) => a.id == widget.accountId).firstOrNull;
    final mine = status?.accounts.where((a) => a.accountId == widget.accountId).firstOrNull;
    return Scaffold(
      appBar: AppBar(
        leading: BackButton(
          onPressed: () => context.canPop() ? context.pop() : context.go('/settings'),
        ),
        title: const Text('Spam'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: FilledButton.icon(
              key: const Key('spam-save'),
              onPressed: _saving || !loaded.hasValue ? null : _save,
              icon: _saving
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.save_outlined),
              label: const Text('Save'),
            ),
          ),
        ],
      ),
      body: loaded.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) =>
            Center(child: Text('Could not load the spam settings: ${friendlyError(e)}')),
        data: (s) {
          _seed(s);
          final e = _edit!;
          return Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 820),
              child: ListView(
                key: const Key('spam-settings-list'),
                padding: const EdgeInsets.all(16),
                children: [
                  _ModelCard(status: status),
                  const SizedBox(height: 16),
                  if (accounts.length > 1) ...[
                    DropdownMenu<String>(
                      key: const Key('spam-account'),
                      initialSelection: widget.accountId,
                      label: const Text('Account'),
                      expandedInsets: EdgeInsets.zero,
                      trailingIcon: const Tooltip(
                        message: 'Choose the account',
                        child: Icon(Icons.arrow_drop_down),
                      ),
                      selectedTrailingIcon: const Tooltip(
                        message: 'Choose the account',
                        child: Icon(Icons.arrow_drop_up),
                      ),
                      onSelected: (id) {
                        if (id != null && id != widget.accountId) {
                          context.go(spamSettingsRoute(id));
                        }
                      },
                      dropdownMenuEntries: [
                        for (final a in accounts) DropdownMenuEntry(value: a.id, label: a.email),
                      ],
                    ),
                    const SizedBox(height: 12),
                  ] else
                    Padding(
                      padding: const EdgeInsets.only(left: 4, bottom: 8),
                      child: Text(
                        account?.email ?? widget.accountId,
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                  Card(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SwitchListTile(
                          key: const Key('spam-enabled'),
                          secondary: const Icon(Icons.report_outlined),
                          title: const Text('Filter spam'),
                          subtitle: Text(
                            e.enabled
                                ? 'New mail in INBOX is checked on this device; spam is moved out.'
                                : 'Off: nothing is classified or moved for this account.',
                          ),
                          value: e.enabled,
                          onChanged: (v) => setState(() => _edit = e.copyWith(enabled: v)),
                        ),
                        const Divider(height: 1),
                        _Threshold(
                          sliderKey: const Key('spam-unsure-threshold'),
                          label: SpamLabel.unsure.label,
                          value: e.unsureThreshold,
                          enabled: e.enabled,
                          onChanged: (v) => setState(
                            () => _edit = e.copyWith(
                              unsureThreshold: v,
                              spamThreshold: v > e.spamThreshold ? v : null,
                            ),
                          ),
                        ),
                        _Threshold(
                          sliderKey: const Key('spam-spam-threshold'),
                          label: SpamLabel.spam.label,
                          value: e.spamThreshold,
                          enabled: e.enabled,
                          onChanged: (v) => setState(
                            () => _edit = e.copyWith(
                              spamThreshold: v,
                              unsureThreshold: v < e.unsureThreshold ? v : null,
                            ),
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                          child: Text(
                            'Below ${percent(e.unsureThreshold)}: ${SpamLabel.ham.label.toLowerCase()}. From '
                            '${percent(e.unsureThreshold)}: marked "${SpamLabel.unsure.label.toLowerCase()}" and '
                            'left in INBOX. From ${percent(e.spamThreshold)}: '
                            '${SpamLabel.spam.label.toLowerCase()}, moved to '
                            '${mine?.spamFolder ?? e.moveToFolder}.',
                            key: const Key('spam-threshold-summary'),
                            style: theme.textTheme.bodyMedium,
                          ),
                        ),
                        const Divider(height: 1),
                        SwitchListTile(
                          key: const Key('spam-dnsbl'),
                          secondary: const Icon(Icons.dns_outlined),
                          title: const Text('Ask DNS blocklists (Spamhaus)'),
                          subtitle: const Text(
                            'Off by default: reveals sender IPs and link domains to your DNS resolver.',
                          ),
                          value: e.dnsblEnabled,
                          onChanged: e.enabled
                              ? (v) => setState(() => _edit = e.copyWith(dnsblEnabled: v))
                              : null,
                        ),
                        const Divider(height: 1),
                        Padding(
                          padding: const EdgeInsets.all(16),
                          child: TextField(
                            key: const Key('spam-folder'),
                            controller: _folder,
                            enabled: e.enabled,
                            decoration: InputDecoration(
                              labelText: 'Move spam to',
                              helperStyle: theme.textTheme.bodyMedium?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                              helperText:
                                  '"${SpamSettings.defaultFolder}" means the server\'s junk folder'
                                  '${mine == null ? '' : ' (${mine.spamFolder} here)'}.',
                              helperMaxLines: 2,
                              border: const OutlineInputBorder(),
                              errorText: _error,
                              errorMaxLines: 3,
                            ),
                            onChanged: (_) {
                              if (_error != null) setState(() => _error = null);
                            },
                          ),
                        ),
                        if (mine != null)
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                            child: Text(
                              'Stored here: ${mine.spamCount} spam · ${mine.unsureCount} possibly spam · '
                              '${mine.hamCount} not spam.',
                              key: const Key('spam-counts'),
                              style: theme.textTheme.bodyMedium,
                            ),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  _SenderList(
                    title: 'Never spam',
                    subtitle: 'Addresses or domains that always reach your inbox.',
                    entries: e.allowlist,
                    keyPrefix: 'spam-allow',
                    controller: _allow,
                    onAdd: (v) => _list(allow: true, entry: v, add: true),
                    onRemove: (v) => _list(allow: true, entry: v, add: false),
                  ),
                  const SizedBox(height: 12),
                  _SenderList(
                    title: 'Always spam',
                    subtitle: 'Addresses or domains whose mail always goes to spam.',
                    entries: e.blocklist,
                    keyPrefix: 'spam-block',
                    controller: _block,
                    onAdd: (v) => _list(allow: false, entry: v, add: true),
                    onRemove: (v) => _list(allow: false, entry: v, add: false),
                  ),
                  if (_listError != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text(
                        _listError!,
                        key: const Key('spam-list-error'),
                        style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
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

class _ModelCard extends StatelessWidget {
  const _ModelCard({required this.status});

  final SpamStatus? status;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final s = status;
    return Card(
      key: const Key('spam-model'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.psychology_outlined),
                const SizedBox(width: 12),
                Expanded(child: Text('Personal spam model', style: theme.textTheme.titleMedium)),
                if (s != null)
                  Text(
                    'trusted ${percent(s.modelConfidence)}',
                    key: const Key('spam-model-confidence'),
                    style: theme.textTheme.labelLarge,
                  ),
              ],
            ),
            const SizedBox(height: 8),
            LinearProgressIndicator(value: s?.modelConfidence ?? 0, minHeight: 6),
            const SizedBox(height: 8),
            Text(
              s == null
                  ? 'Loading…'
                  : 'Learned from ${s.modelSpamMessages} spam and ${s.modelHamMessages} not-spam '
                        'messages (${s.modelTokens} words). Every "Mark as spam" or "Not spam" teaches '
                        'it; until it is confident, the rules (sender authentication, links, wording) '
                        'decide. It stays on this device.',
              key: const Key('spam-model-learned'),
              style: theme.textTheme.bodyMedium,
            ),
          ],
        ),
      ),
    );
  }
}

class _Threshold extends StatelessWidget {
  const _Threshold({
    required this.sliderKey,
    required this.label,
    required this.value,
    required this.enabled,
    required this.onChanged,
  });

  final Key sliderKey;
  final String label;
  final double value;
  final bool enabled;
  final ValueChanged<double> onChanged;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('$label from ${percent(value)}', style: theme.textTheme.titleSmall),
          Semantics(
            label: '$label threshold',
            child: Slider(
              key: sliderKey,
              value: value.clamp(0, 1),
              divisions: 100,
              label: percent(value),
              onChanged: enabled ? (v) => onChanged((v * 100).round() / 100) : null,
            ),
          ),
        ],
      ),
    );
  }
}

class _SenderList extends StatelessWidget {
  const _SenderList({
    required this.title,
    required this.subtitle,
    required this.entries,
    required this.keyPrefix,
    required this.controller,
    required this.onAdd,
    required this.onRemove,
  });

  final String title;
  final String subtitle;
  final List<String> entries;
  final String keyPrefix;
  final TextEditingController controller;
  final ValueChanged<String> onAdd;
  final ValueChanged<String> onRemove;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      key: Key('$keyPrefix-list'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(height: 2),
            Text(subtitle, style: theme.textTheme.bodyMedium),
            const SizedBox(height: 8),
            if (entries.isEmpty)
              Text(
                'None yet.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              )
            else
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final e in entries)
                    InputChip(
                      key: ValueKey('$keyPrefix-$e'),
                      label: Text(e),
                      deleteButtonTooltipMessage: 'Remove $e',
                      onDeleted: () => onRemove(e),
                    ),
                ],
              ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    key: Key('$keyPrefix-input'),
                    controller: controller,
                    keyboardType: TextInputType.emailAddress,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'Address or domain',
                      hintText: 'friend@example.org or example.org',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    onSubmitted: onAdd,
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filledTonal(
                  key: Key('$keyPrefix-add'),
                  tooltip: 'Add to "$title"',
                  onPressed: () => onAdd(controller.text),
                  icon: const Icon(Icons.add),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
