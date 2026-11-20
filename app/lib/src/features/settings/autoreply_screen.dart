import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../inbox/inbox_list_pane.dart' show fullTime;

/// Out-of-office auto-reply editor (RFC 3834; engine: `Engine::set_autoreply`, run from sync).
class AutoReplySettingsScreen extends ConsumerStatefulWidget {
  const AutoReplySettingsScreen({super.key, required this.accountId});

  final String accountId;

  @override
  ConsumerState<AutoReplySettingsScreen> createState() => _AutoReplySettingsScreenState();
}

class _AutoReplySettingsScreenState extends ConsumerState<AutoReplySettingsScreen> {
  final _subject = TextEditingController();
  final _body = TextEditingController();
  AutoReplySettings? _edit;
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _subject.dispose();
    _body.dispose();
    super.dispose();
  }

  void _load(AutoReplySettings s) {
    if (_edit != null) return;
    _edit = s;
    _subject.text = s.subjectTemplate;
    _body.text = s.body;
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
      final stored = await ref.read(coreApiProvider).setAutoReply(
        widget.accountId,
        e.copyWith(subjectTemplate: _subject.text, body: _body.text),
      );
      ref.invalidate(autoReplyProvider(widget.accountId));
      ref.invalidate(autoReplyLogProvider(widget.accountId));
      if (!mounted) return;
      setState(() {
        _edit = stored;
        _subject.text = stored.subjectTemplate;
        _body.text = stored.body;
        _saving = false;
      });
      messenger.showSnackBar(
        SnackBar(content: Text(stored.enabled ? 'Auto-reply saved and on' : 'Auto-reply saved (off)')),
      );
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _error = '$err';
      });
    }
  }

  Future<void> _pickDate(bool start) async {
    final e = _edit!;
    final now = DateTime.now();
    final initial = (start ? e.start : e.end)?.toLocal() ?? now;
    final day = await showDatePicker(
      context: context,
      initialDate: initial,
      firstDate: DateTime(now.year - 1),
      lastDate: DateTime(now.year + 3),
    );
    if (day == null || !mounted) return;
    final time = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(initial),
    );
    final picked = DateTime(day.year, day.month, day.day, time?.hour ?? 0, time?.minute ?? 0).toUtc();
    setState(() {
      _edit = start ? e.copyWith(start: picked) : e.copyWith(end: picked);
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final loaded = ref.watch(autoReplyProvider(widget.accountId));
    final log = ref.watch(autoReplyLogProvider(widget.accountId));
    return Scaffold(
      appBar: AppBar(
        leading: BackButton(onPressed: () => context.canPop() ? context.pop() : context.go('/settings')),
        title: const Text('Out of office'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: FilledButton.icon(
              key: const Key('autoreply-save'),
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
        error: (e, _) => Center(child: Text('Could not load the auto-reply: $e')),
        data: (s) {
          _load(s);
          final e = _edit!;
          String when(DateTime? t, String none) => t == null ? none : fullTime(t);
          return Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 820),
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  Text(widget.accountId, style: theme.textTheme.bodySmall),
                  const SizedBox(height: 8),
                  SwitchListTile(
                    key: const Key('autoreply-enabled'),
                    title: const Text('Reply automatically while I am away'),
                    subtitle: Text(
                      e.isActiveNow
                          ? 'Active now. Each sender gets at most one reply per '
                                '${e.replyOncePerSenderDays == 0 ? 'absence' : '${e.replyOncePerSenderDays} days'}; '
                                'mailing lists, bounces and auto-submitted mail are never answered.'
                          : 'Replies are sent during a fetch (sync) while this is on and inside the dates below.',
                    ),
                    value: e.enabled,
                    onChanged: (v) => setState(() => _edit = e.copyWith(enabled: v)),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton.icon(
                          key: const Key('autoreply-start'),
                          onPressed: () => _pickDate(true),
                          icon: const Icon(Icons.event_available_outlined),
                          label: Text('From: ${when(e.start, 'as soon as enabled')}'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: OutlinedButton.icon(
                          key: const Key('autoreply-end'),
                          onPressed: () => _pickDate(false),
                          icon: const Icon(Icons.event_busy_outlined),
                          label: Text('Until: ${when(e.end, 'disabled by hand')}'),
                        ),
                      ),
                      if (e.start != null || e.end != null)
                        IconButton(
                          tooltip: 'Clear dates',
                          onPressed: () => setState(() => _edit = e.copyWith(clearDates: true)),
                          icon: const Icon(Icons.clear),
                        ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('autoreply-subject'),
                    controller: _subject,
                    decoration: const InputDecoration(
                      labelText: 'Subject',
                      helperText: '{subject} is replaced by the original subject',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('autoreply-body'),
                    controller: _body,
                    minLines: 4,
                    maxLines: 10,
                    decoration: InputDecoration(
                      labelText: 'Message',
                      alignLabelWithHint: true,
                      border: const OutlineInputBorder(),
                      errorText: _error,
                      errorMaxLines: 3,
                    ),
                  ),
                  const SizedBox(height: 8),
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('One reply per sender every'),
                    trailing: DropdownButton<int>(
                      key: const Key('autoreply-days'),
                      value: const [0, 1, 3, 7, 14, 30].contains(e.replyOncePerSenderDays)
                          ? e.replyOncePerSenderDays
                          : 7,
                      items: const [
                        DropdownMenuItem(value: 0, child: Text('whole absence')),
                        DropdownMenuItem(value: 1, child: Text('1 day')),
                        DropdownMenuItem(value: 3, child: Text('3 days')),
                        DropdownMenuItem(value: 7, child: Text('7 days')),
                        DropdownMenuItem(value: 14, child: Text('14 days')),
                        DropdownMenuItem(value: 30, child: Text('30 days')),
                      ],
                      onChanged: (v) => v == null ? null : setState(() => _edit = e.copyWith(replyOncePerSenderDays: v)),
                    ),
                  ),
                  SwitchListTile(
                    key: const Key('autoreply-encrypt'),
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Encrypt the reply when the sender has a key'),
                    value: e.encryptWhenPossible,
                    onChanged: (v) => setState(() => _edit = e.copyWith(encryptWhenPossible: v)),
                  ),
                  SwitchListTile(
                    key: const Key('autoreply-known-only'),
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Only answer people I have written to'),
                    subtitle: const Text('Or whose key I imported. Keeps your absence private from strangers.'),
                    value: e.onlyToKnownContacts,
                    onChanged: (v) => setState(() => _edit = e.copyWith(onlyToKnownContacts: v)),
                  ),
                  const SizedBox(height: 24),
                  Text('Replies sent', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 6),
                  Card(
                    child: log.when(
                      loading: () => const ListTile(title: LinearProgressIndicator()),
                      error: (err, _) => ListTile(title: Text('Could not load the log: $err')),
                      data: (entries) => entries.isEmpty
                          ? const ListTile(
                              key: Key('autoreply-log-empty'),
                              leading: Icon(Icons.history),
                              title: Text('No automatic replies sent yet'),
                            )
                          : Column(
                              children: [
                                for (final x in entries)
                                  ListTile(
                                    leading: Icon(x.encrypted ? Icons.lock : Icons.lock_open),
                                    title: Text(x.sender),
                                    subtitle: Text(fullTime(x.sentAt)),
                                  ),
                              ],
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
