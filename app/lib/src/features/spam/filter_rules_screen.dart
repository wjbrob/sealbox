import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import '../../widgets/message_subject.dart';
import 'spam_explain_sheet.dart' show describeFilterOutcome;

String filterRulesRoute(String accountId) =>
    '/settings/filters?account=${Uri.encodeQueryComponent(accountId)}';

/// `Subject contains "[newsletter]": move to Newsletters, then stop` — words, not the
/// engine's code form (and no arrow: the UI font may lack the glyph).
String describeFilterRule(FilterRule r) {
  final c = r.condition;
  final field = c.field == FilterField.header ? 'Header ${c.headerName ?? ''}' : c.field.label;
  final test = c.op == FilterOp.domain ? 'domain is' : c.op.label;
  final action = switch (r.action.kind) {
    FilterActionKind.moveTo => 'move to ${r.action.folder ?? ''}',
    FilterActionKind.addFlag => 'flag ${r.action.flag ?? ''}',
    FilterActionKind.markRead => 'mark read',
    FilterActionKind.star => 'star',
  };
  return '$field $test "${c.value}"${c.caseInsensitive ? '' : ' (match case)'}: $action'
      '${r.stop ? ', then stop' : ''}';
}

String _clean(Object e) => friendlyError(e).replaceFirst('invalid input: ', '');

/// Settings → Mail handling → Filters: one account's rules in evaluation order.
/// Switches enable a rule, the handle reorders (`setFilterRules`), a tap edits,
/// and "Test" dry-runs every enabled rule against a stored message.
class FilterRulesScreen extends ConsumerStatefulWidget {
  const FilterRulesScreen({super.key, required this.accountId});

  final String accountId;

  @override
  ConsumerState<FilterRulesScreen> createState() => _FilterRulesScreenState();
}

class _FilterRulesScreenState extends ConsumerState<FilterRulesScreen> {
  /// The list as last stored (null until loaded); ids change on a reorder.
  List<FilterRule>? _rules;
  FilterTestReport? _report;

  /// The message the last dry run was made against (its title heads the report).
  Message? _reportMessage;
  String? _error;
  bool _busy = false;

  Future<void> _mutate(Future<List<FilterRule>?> Function() op) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await op();
      ref.invalidate(filterRulesProvider(widget.accountId));
      ref.invalidate(spamStatusProvider);
      if (!mounted) return;
      setState(() {
        if (r != null) _rules = r;
        _report = null;
      });
    } catch (e) {
      if (mounted) setState(() => _error = _clean(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _reorder(List<FilterRule> rules, int from, int to) {
    // `onReorderItem`: [to] already accounts for the removed item.
    final next = [...rules];
    final moved = next.removeAt(from);
    next.insert(to.clamp(0, next.length), moved);
    setState(() => _rules = next); // show the new order at once
    return _mutate(() => ref.read(coreApiProvider).setFilterRules(widget.accountId, next));
  }

  Future<void> _toggle(FilterRule r, bool on) => _mutate(() async {
    final updated = await ref
        .read(coreApiProvider)
        .setFilterRuleEnabled(widget.accountId, r.id, on);
    return [
      for (final x in _rules ?? const <FilterRule>[])
        if (x.id == r.id) updated else x,
    ];
  });

  Future<void> _edit([FilterRule? rule]) async {
    final changed = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      useSafeArea: true,
      constraints: const BoxConstraints(maxWidth: 720),
      builder: (_) => FilterRuleEditor(accountId: widget.accountId, rule: rule),
    );
    if (changed == true) {
      await _mutate(() => ref.read(coreApiProvider).filterRules(widget.accountId));
    }
  }

  Future<void> _test() async {
    final picked = await showDialog<Message>(
      context: context,
      builder: (_) => _MessagePicker(accountId: widget.accountId),
    );
    if (picked == null || !mounted) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await ref.read(coreApiProvider).testFilterRules(widget.accountId, picked.id);
      if (!mounted) return;
      setState(() {
        _report = r;
        _reportMessage = picked;
      });
    } catch (e) {
      if (mounted) setState(() => _error = _clean(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final loaded = ref.watch(filterRulesProvider(widget.accountId));
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final account = accounts.where((a) => a.id == widget.accountId).firstOrNull;
    final rules = _rules ?? loaded.value;
    return Scaffold(
      appBar: AppBar(
        leading: BackButton(
          onPressed: () => context.canPop() ? context.pop() : context.go('/settings'),
        ),
        title: const Text('Filters'),
        actions: [
          TextButton.icon(
            key: const Key('filters-test'),
            onPressed: _busy || rules == null || rules.isEmpty ? null : _test,
            icon: const Icon(Icons.science_outlined),
            label: const Text('Test'),
          ),
          const SizedBox(width: 8),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        key: const Key('filters-add'),
        heroTag: 'filters-add',
        onPressed: _busy || rules == null ? null : () => _edit(),
        icon: const Icon(Icons.add),
        label: const Text('Add rule'),
      ),
      body: rules == null
          ? loaded.hasError
                ? Center(child: Text('Could not load the rules: ${friendlyError(loaded.error!)}'))
                : const Center(child: CircularProgressIndicator())
          : Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 820),
                child: CustomScrollView(
                  slivers: [
                    SliverPadding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                      sliver: SliverList.list(
                        children: [
                          if (accounts.length > 1)
                            DropdownMenu<String>(
                              key: const Key('filters-account'),
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
                                  context.go(filterRulesRoute(id));
                                }
                              },
                              dropdownMenuEntries: [
                                for (final a in accounts)
                                  DropdownMenuEntry(value: a.id, label: a.email),
                              ],
                            )
                          else
                            Text(
                              account?.email ?? widget.accountId,
                              style: theme.textTheme.bodySmall,
                            ),
                          const SizedBox(height: 8),
                          Text(
                            'Rules run on new mail in INBOX after the spam check, top to bottom. '
                            'Every enabled rule that matches adds its action (the first move '
                            'wins); "then stop" ends the run. A rule never deletes mail.',
                            style: theme.textTheme.bodyMedium,
                          ),
                          if (_busy) ...[
                            const SizedBox(height: 8),
                            const LinearProgressIndicator(key: Key('filters-busy')),
                          ],
                          if (_error != null) ...[
                            const SizedBox(height: 8),
                            Text(
                              _error!,
                              key: const Key('filters-error'),
                              style: theme.textTheme.bodyMedium?.copyWith(
                                color: theme.colorScheme.error,
                              ),
                            ),
                          ],
                          const SizedBox(height: 8),
                        ],
                      ),
                    ),
                    if (rules.isEmpty)
                      SliverToBoxAdapter(
                        child: Padding(
                          key: const Key('filters-empty'),
                          padding: const EdgeInsets.all(32),
                          child: Column(
                            children: [
                              Icon(
                                Icons.filter_alt_off_outlined,
                                size: 48,
                                color: theme.colorScheme.outline,
                              ),
                              const SizedBox(height: 12),
                              Text('No rules yet', style: theme.textTheme.titleMedium),
                              const SizedBox(height: 6),
                              Text(
                                'Sort newsletters into a folder, star mail from your team, mark '
                                'notifications read.',
                                textAlign: TextAlign.center,
                                style: theme.textTheme.bodySmall,
                              ),
                            ],
                          ),
                        ),
                      )
                    else
                      SliverPadding(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        sliver: SliverReorderableList(
                          key: const Key('filters-list'),
                          itemCount: rules.length,
                          onReorderItem: (a, b) => _busy ? null : _reorder(rules, a, b),
                          itemBuilder: (context, i) {
                            final r = rules[i];
                            return Material(
                              key: ValueKey('filter-rule-${r.id}'),
                              color: Colors.transparent,
                              child: Card(
                                margin: const EdgeInsets.only(bottom: 8),
                                child: ListTile(
                                  leading: ReorderableDragStartListener(
                                    index: i,
                                    child: Tooltip(
                                      message: 'Drag to reorder',
                                      child: Icon(
                                        Icons.drag_indicator,
                                        semanticLabel:
                                            'Reorder ${r.name.isEmpty ? 'rule ${i + 1}' : r.name}',
                                      ),
                                    ),
                                  ),
                                  title: Text(r.name.isEmpty ? 'Rule ${i + 1}' : r.name),
                                  subtitle: Text(describeFilterRule(r)),
                                  onTap: _busy ? null : () => _edit(r),
                                  trailing: MergeSemantics(
                                    child: Semantics(
                                      label:
                                          'Rule "${r.name.isEmpty ? 'Rule ${i + 1}' : r.name}" on',
                                      child: Switch(
                                        key: ValueKey('filter-enabled-${r.id}'),
                                        value: r.enabled,
                                        onChanged: _busy ? null : (v) => _toggle(r, v),
                                      ),
                                    ),
                                  ),
                                ),
                              ),
                            );
                          },
                        ),
                      ),
                    if (_report != null)
                      SliverPadding(
                        padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                        sliver: SliverToBoxAdapter(
                          child: _TestReport(
                            report: _report!,
                            message: _reportMessage,
                            rules: rules,
                          ),
                        ),
                      ),
                    const SliverToBoxAdapter(child: SizedBox(height: 96)),
                  ],
                ),
              ),
            ),
    );
  }
}

class _TestReport extends StatelessWidget {
  const _TestReport({required this.report, required this.message, required this.rules});

  final FilterTestReport report;
  final Message? message;
  final List<FilterRule> rules;

  /// `Test: "Q4 budget"`, or `Test: Encrypted message` (italic, no quotes) for mail
  /// whose subject is only the provider's placeholder (review N1).
  Widget _reportTitle(BuildContext context) {
    final style = Theme.of(context).textTheme.titleMedium;
    final m = message;
    if (m == null) return Text('Test: "${report.messageId}"', style: style);
    final title = messageSubjectTitle(m);
    if (!title.placeholder) return Text('Test: "${title.text}"', style: style);
    return Text.rich(
      TextSpan(
        children: [
          const TextSpan(text: 'Test: '),
          TextSpan(text: title.text, style: subjectTitleStyle(context, null, placeholder: true)),
        ],
      ),
      key: const Key('filters-test-title'),
      style: style,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = LockColors.ofContext(context);
    return Card(
      key: const Key('filters-test-report'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _reportTitle(context),
            const SizedBox(height: 4),
            Text(
              describeFilterOutcome(report.outcome, rules),
              key: const Key('filters-test-outcome'),
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 8),
            if (report.rules.isEmpty) const Text('No enabled rule to test.'),
            for (final r in report.rules)
              ListTile(
                key: ValueKey('filter-test-rule-${r.ruleId}'),
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  r.matched ? Icons.check_circle : Icons.radio_button_unchecked,
                  color: r.matched ? palette.encrypted : theme.colorScheme.outline,
                  semanticLabel: r.matched ? 'Matches' : 'Does not match',
                ),
                title: Text(
                  rules.where((x) => x.id == r.ruleId).map((x) => x.name).firstOrNull ??
                      'Rule #${r.ruleId}',
                ),
                subtitle: Text(r.description, style: const TextStyle(fontFamily: 'monospace')),
                trailing: Text(r.matched ? 'matches' : 'no match'),
              ),
            const SizedBox(height: 4),
            Text(
              'A dry run: nothing was moved or flagged.',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }
}

/// Picks one of the account's stored messages (newest first) for a dry run.
class _MessagePicker extends ConsumerWidget {
  const _MessagePicker({required this.accountId});

  final String accountId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final threads = ref.watch(_testMessagesProvider(accountId));
    return AlertDialog(
      key: const Key('filters-test-picker'),
      title: const Text('Test against a message'),
      content: SizedBox(
        width: 520,
        height: 420,
        child: threads.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) => Text('Could not list messages: ${friendlyError(e)}'),
          data: (list) => list.isEmpty
              ? const Center(child: Text('No stored message on this account yet.'))
              : ListView(
                  children: [
                    for (final m in list)
                      ListTile(
                        key: ValueKey('filter-test-pick-${m.id}'),
                        title: _PickTitle(message: m),
                        subtitle: Text(
                          '${m.from.display} · ${m.folder}',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        onTap: () => Navigator.of(context).pop(m),
                      ),
                  ],
                ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
      ],
    );
  }
}

/// A picker row's title: the subject, or "Encrypted message" in the secondary italic
/// style for mail whose subject is only the provider's placeholder (review N1).
class _PickTitle extends StatelessWidget {
  const _PickTitle({required this.message});

  final Message message;

  @override
  Widget build(BuildContext context) {
    final title = messageSubjectTitle(message);
    return Text(
      title.text,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: subjectTitleStyle(context, null, placeholder: title.placeholder),
    );
  }
}

/// The account's stored messages across folders, newest first (at most 40).
final _testMessagesProvider = FutureProvider.autoDispose.family<List<Message>, String>((
  ref,
  accountId,
) async {
  final core = ref.watch(coreApiProvider);
  final threads = await core.listThreadsIn(MailFolder.all);
  final out = [
    for (final t in threads)
      if (t.accountId == accountId) ...t.messages,
  ]..sort((a, b) => b.date.compareTo(a.date));
  return out.take(40).toList();
});

/// Add or edit one rule. Saves through the engine itself, so its validation
/// errors (`invalid input: …`) show inline; pops `true` after a change.
class FilterRuleEditor extends ConsumerStatefulWidget {
  const FilterRuleEditor({super.key, required this.accountId, this.rule});

  final String accountId;

  /// Null: a new rule.
  final FilterRule? rule;

  @override
  ConsumerState<FilterRuleEditor> createState() => _FilterRuleEditorState();
}

class _FilterRuleEditorState extends ConsumerState<FilterRuleEditor> {
  late final _name = TextEditingController(text: widget.rule?.name ?? '');
  late final _header = TextEditingController(text: widget.rule?.condition.headerName ?? '');
  late final _value = TextEditingController(text: widget.rule?.condition.value ?? '');
  late final _folder = TextEditingController(text: widget.rule?.action.folder ?? '');
  late final _flag = TextEditingController(text: widget.rule?.action.flag ?? '');
  late FilterField _field = widget.rule?.condition.field ?? FilterField.subject;
  late FilterOp _op = widget.rule?.condition.op ?? FilterOp.contains;
  late bool _matchCase = !(widget.rule?.condition.caseInsensitive ?? true);
  late FilterActionKind _action = widget.rule?.action.kind ?? FilterActionKind.moveTo;
  late bool _stop = widget.rule?.stop ?? false;
  bool _busy = false;
  String? _error;

  static const _addressFields = {FilterField.from, FilterField.to, FilterField.cc};

  @override
  void dispose() {
    for (final c in [_name, _header, _value, _folder, _flag]) {
      c.dispose();
    }
    super.dispose();
  }

  FilterRule get _built {
    final base = widget.rule;
    return FilterRule(
      id: base?.id ?? 0,
      order: base?.order ?? 0,
      enabled: base?.enabled ?? true,
      name: _name.text.trim(),
      stop: _stop,
      condition: FilterCondition(
        field: _field,
        headerName: _field == FilterField.header ? _header.text.trim() : null,
        op: _op,
        value: _value.text.trim(),
        caseInsensitive: !_matchCase,
      ),
      action: switch (_action) {
        FilterActionKind.moveTo => FilterAction.moveTo(_folder.text.trim()),
        FilterActionKind.addFlag => FilterAction.addFlag(_flag.text.trim()),
        FilterActionKind.markRead => const FilterAction.markRead(),
        FilterActionKind.star => const FilterAction.star(),
      },
    );
  }

  Future<void> _save() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final nav = Navigator.of(context);
    try {
      final core = ref.read(coreApiProvider);
      if (widget.rule == null) {
        await core.addFilterRule(widget.accountId, _built);
      } else {
        await core.updateFilterRule(widget.accountId, _built);
      }
      nav.pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = _clean(e);
        });
      }
    }
  }

  Future<void> _remove() async {
    final rule = widget.rule!;
    final nav = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        key: const Key('filter-remove-dialog'),
        title: Text('Remove "${rule.name.isEmpty ? describeFilterRule(rule) : rule.name}"?'),
        content: const Text('Mail it already sorted stays where it is.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(
            key: const Key('filter-remove-confirm'),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    setState(() => _busy = true);
    try {
      await ref.read(coreApiProvider).removeFilterRule(widget.accountId, rule.id);
      nav.pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = _clean(e);
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ops = [
      for (final o in FilterOp.values)
        if (o != FilterOp.domain || _addressFields.contains(_field)) o,
    ];
    if (!ops.contains(_op)) _op = FilterOp.contains;
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: SingleChildScrollView(
        key: const Key('filter-editor'),
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(widget.rule == null ? 'New rule' : 'Edit rule', style: theme.textTheme.titleLarge),
            const SizedBox(height: 16),
            TextField(
              key: const Key('filter-name'),
              controller: _name,
              decoration: const InputDecoration(
                labelText: 'Name (optional)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            Text('When', style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                DropdownMenu<FilterField>(
                  key: const Key('filter-field'),
                  initialSelection: _field,
                  label: const Text('Field'),
                  trailingIcon: const Tooltip(message: 'Field', child: Icon(Icons.arrow_drop_down)),
                  selectedTrailingIcon: const Tooltip(
                    message: 'Field',
                    child: Icon(Icons.arrow_drop_up),
                  ),
                  onSelected: (f) => setState(() => _field = f ?? _field),
                  dropdownMenuEntries: [
                    for (final f in FilterField.values) DropdownMenuEntry(value: f, label: f.label),
                  ],
                ),
                DropdownMenu<FilterOp>(
                  key: ValueKey('filter-op-${_field.name}'),
                  initialSelection: _op,
                  label: const Text('Condition'),
                  trailingIcon: const Tooltip(
                    message: 'Condition',
                    child: Icon(Icons.arrow_drop_down),
                  ),
                  selectedTrailingIcon: const Tooltip(
                    message: 'Condition',
                    child: Icon(Icons.arrow_drop_up),
                  ),
                  onSelected: (o) => setState(() => _op = o ?? _op),
                  dropdownMenuEntries: [
                    for (final o in ops) DropdownMenuEntry(value: o, label: o.label),
                  ],
                ),
              ],
            ),
            if (_field == FilterField.header) ...[
              const SizedBox(height: 12),
              TextField(
                key: const Key('filter-header'),
                controller: _header,
                decoration: const InputDecoration(
                  labelText: 'Header name',
                  hintText: 'X-Mailer',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
            const SizedBox(height: 12),
            TextField(
              key: const Key('filter-value'),
              controller: _value,
              decoration: InputDecoration(
                labelText: _op == FilterOp.regex ? 'Regular expression' : 'Value',
                hintText: _op == FilterOp.domain ? 'example.org' : '[newsletter]',
                border: const OutlineInputBorder(),
              ),
            ),
            SwitchListTile(
              key: const Key('filter-case'),
              contentPadding: EdgeInsets.zero,
              title: const Text('Match case'),
              value: _matchCase,
              onChanged: (v) => setState(() => _matchCase = v),
            ),
            const SizedBox(height: 8),
            Text('Then', style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            DropdownMenu<FilterActionKind>(
              key: const Key('filter-action'),
              initialSelection: _action,
              label: const Text('Action'),
              // As wide as the fields below it (a stretched Column child).
              expandedInsets: EdgeInsets.zero,
              trailingIcon: const Tooltip(message: 'Action', child: Icon(Icons.arrow_drop_down)),
              selectedTrailingIcon: const Tooltip(
                message: 'Action',
                child: Icon(Icons.arrow_drop_up),
              ),
              onSelected: (a) => setState(() => _action = a ?? _action),
              dropdownMenuEntries: const [
                DropdownMenuEntry(value: FilterActionKind.moveTo, label: 'Move to folder'),
                DropdownMenuEntry(value: FilterActionKind.addFlag, label: 'Add a flag'),
                DropdownMenuEntry(value: FilterActionKind.markRead, label: 'Mark read'),
                DropdownMenuEntry(value: FilterActionKind.star, label: 'Star'),
              ],
            ),
            if (_action == FilterActionKind.moveTo) ...[
              const SizedBox(height: 12),
              TextField(
                key: const Key('filter-folder'),
                controller: _folder,
                decoration: InputDecoration(
                  helperStyle: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  labelText: 'Folder',
                  helperText: 'Created on the server when it does not exist.',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
            if (_action == FilterActionKind.addFlag) ...[
              const SizedBox(height: 12),
              TextField(
                key: const Key('filter-flag'),
                controller: _flag,
                decoration: InputDecoration(
                  helperStyle: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  labelText: 'Flag',
                  hintText: r'$Newsletter',
                  helperText: 'An IMAP keyword: no spaces, parentheses or quotes.',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
            SwitchListTile(
              key: const Key('filter-stop'),
              contentPadding: EdgeInsets.zero,
              title: const Text('Then stop'),
              subtitle: const Text('Later rules do not run on a message this rule matched.'),
              value: _stop,
              onChanged: (v) => setState(() => _stop = v),
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(
                _error!,
                key: const Key('filter-error'),
                style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
              ),
            ],
            const SizedBox(height: 16),
            Row(
              children: [
                if (widget.rule != null)
                  TextButton.icon(
                    key: const Key('filter-remove'),
                    onPressed: _busy ? null : _remove,
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('Remove'),
                  ),
                const Spacer(),
                TextButton(
                  onPressed: _busy ? null : () => Navigator.of(context).pop(false),
                  child: const Text('Cancel'),
                ),
                const SizedBox(width: 8),
                FilledButton(
                  key: const Key('filter-save'),
                  onPressed: _busy ? null : _save,
                  child: const Text('Save'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
