import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../core/threading.dart' show isPlaceholderSubject;
import '../../widgets/lock_badge.dart';
import '../../widgets/message_subject.dart';

/// "Why is this spam?" for one stored message (`spamExplain`, offline): the
/// label and probability, the reasons with their weights, SPF / DKIM / DMARC,
/// what the filter rules would do, and the two feedback buttons.
Future<void> showSpamExplanation(
  BuildContext context, {
  required String messageId,
  required String accountId,
}) => showModalBottomSheet<void>(
  context: context,
  isScrollControlled: true,
  showDragHandle: true,
  useSafeArea: true,
  constraints: const BoxConstraints(maxWidth: 720),
  builder: (_) => SpamExplanationSheet(messageId: messageId, accountId: accountId),
);

/// The explanation of one message, as the engine gives it.
final spamExplanationProvider = FutureProvider.autoDispose.family<SpamExplanation, String>(
  (ref, messageId) => ref.watch(coreApiProvider).spamExplain(messageId),
);

/// The stored message behind an explanation; read only when the explanation's subject is a
/// placeholder, to tell undecryptable mail (shown as "Encrypted message") from a protected
/// subject that really is `...`.
final _explainedMessageProvider = FutureProvider.autoDispose.family<Message?, String>(
  (ref, messageId) => ref.watch(coreApiProvider).getMessage(messageId),
);

String percent(double p) {
  final v = (p * 100).clamp(0, 100);
  return v >= 10 || v == 0 ? '${v.round()} %' : '${v.toStringAsFixed(1)} %';
}

/// Colour of a spam label: spam is an error, "possibly" a warning, not spam is fine.
Color spamLabelColor(BuildContext context, SpamLabel l) {
  final palette = LockColors.ofContext(context);
  return switch (l) {
    SpamLabel.spam => palette.undecryptable,
    SpamLabel.unsure => palette.plaintext,
    SpamLabel.ham => palette.encrypted,
  };
}

class SpamExplanationSheet extends ConsumerStatefulWidget {
  const SpamExplanationSheet({super.key, required this.messageId, required this.accountId});

  final String messageId;
  final String accountId;

  @override
  ConsumerState<SpamExplanationSheet> createState() => _SpamExplanationSheetState();
}

class _SpamExplanationSheetState extends ConsumerState<SpamExplanationSheet> {
  bool _busy = false;

  Future<void> _learn(bool isSpam) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    final nav = Navigator.of(context);
    setState(() => _busy = true);
    try {
      final r = await ref.read(coreApiProvider).spamLearn(widget.messageId, isSpam: isSpam);
      ref.invalidate(threadsProvider);
      ref.invalidate(threadProvider);
      ref.invalidate(spamStatusProvider);
      ref.invalidate(spamExplanationProvider(widget.messageId));
      final what = isSpam ? 'Marked as spam' : 'Marked as not spam';
      messenger?.removeCurrentSnackBar();
      messenger?.showSnackBar(
        SnackBar(
          key: const Key('thread-action-snackbar'),
          content: Text(r.movedTo == null ? what : '$what · moved to ${r.movedTo}'),
        ),
      );
      if (mounted) nav.pop();
    } catch (e) {
      if (!mounted) return;
      setState(() => _busy = false);
      messenger?.showSnackBar(
        SnackBar(content: Text('Could not save your verdict: ${friendlyError(e)}')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final explained = ref.watch(spamExplanationProvider(widget.messageId));
    final rules = ref.watch(filterRulesProvider(widget.accountId)).value ?? const <FilterRule>[];
    return DraggableScrollableSheet(
      key: const Key('spam-explain-sheet'),
      expand: false,
      initialChildSize: 0.75,
      minChildSize: 0.4,
      maxChildSize: 0.95,
      builder: (context, scroll) => explained.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            'Could not explain this message: ${friendlyError(e)}',
            key: const Key('spam-explain-error'),
          ),
        ),
        data: (x) {
          final v = x.verdict;
          final color = spamLabelColor(context, v.label);
          final reasons = [...v.reasons]..sort((a, b) => b.weight.abs().compareTo(a.weight.abs()));
          return ListView(
            controller: scroll,
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
            children: [
              Text(
                v.label == SpamLabel.ham ? 'Spam check' : 'Why is this spam?',
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 4),
              _SenderLine(explanation: x),
              const SizedBox(height: 16),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  StatusChip(
                    key: const Key('spam-explain-label'),
                    icon: v.label == SpamLabel.ham
                        ? Icons.mark_email_read_outlined
                        : Icons.report_outlined,
                    label: '${v.label.label} · ${percent(v.spamProbability)}',
                    color: color,
                  ),
                  if (x.stored.learned != null)
                    StatusChip(
                      icon: Icons.person_outline,
                      label: 'You said: ${x.stored.learned!.label.toLowerCase()}',
                      color: theme.colorScheme.onSurfaceVariant,
                    )
                  else if (x.stored.label != null && x.stored.label != v.label)
                    StatusChip(
                      icon: Icons.history,
                      label: 'On arrival: ${x.stored.label!.label.toLowerCase()}',
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                'Personal model trusted ${percent(v.bayesConfidence)} · rules ${_signed(v.rulesScore)}. '
                'Thresholds: possibly spam from ${percent(x.settings.unsureThreshold)}, spam from '
                '${percent(x.settings.spamThreshold)}.',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 12,
                runSpacing: 8,
                children: [
                  if (v.label != SpamLabel.spam || x.stored.learned != SpamLabel.spam)
                    FilledButton.tonalIcon(
                      key: const Key('spam-explain-mark-spam'),
                      onPressed: _busy ? null : () => _learn(true),
                      icon: const Icon(Icons.report_outlined),
                      label: const Text('Mark as spam'),
                    ),
                  if (v.label != SpamLabel.ham || x.stored.learned != SpamLabel.ham)
                    OutlinedButton.icon(
                      key: const Key('spam-explain-not-spam'),
                      onPressed: _busy ? null : () => _learn(false),
                      icon: const Icon(Icons.report_off_outlined),
                      label: const Text('Not spam'),
                    ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                'Your verdict trains the personal model on this device and moves the message.',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 20),
              Text('Reasons', style: theme.textTheme.titleSmall),
              const SizedBox(height: 4),
              Card(
                key: const Key('spam-explain-reasons'),
                margin: EdgeInsets.zero,
                child: Column(
                  children: [
                    if (reasons.isEmpty)
                      const ListTile(
                        title: Text('No rule fired; the personal model decided alone.'),
                      ),
                    for (final r in reasons)
                      ListTile(
                        key: ValueKey('spam-reason-${r.code}'),
                        dense: true,
                        leading: SizedBox(
                          width: 52,
                          child: Text(
                            r.weight == 0 ? '—' : _signed(r.weight),
                            textAlign: TextAlign.end,
                            style: theme.textTheme.titleSmall?.copyWith(
                              fontFamily: 'monospace',
                              color: r.weight > 0
                                  ? spamLabelColor(context, SpamLabel.spam)
                                  : r.weight < 0
                                  ? spamLabelColor(context, SpamLabel.ham)
                                  : theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ),
                        title: Text(r.detail),
                        subtitle: Text(r.code, style: const TextStyle(fontFamily: 'monospace')),
                      ),
                  ],
                ),
              ),
              const SizedBox(height: 20),
              Text('Sender authentication', style: theme.textTheme.titleSmall),
              const SizedBox(height: 8),
              Wrap(
                key: const Key('spam-explain-auth'),
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final (name, result) in [
                    ('SPF', x.features.spf),
                    ('DKIM', x.features.dkim),
                    ('DMARC', x.features.dmarc),
                  ])
                    StatusChip(
                      key: ValueKey('spam-auth-$name'),
                      icon: switch (result) {
                        SpamAuthResult.pass => Icons.check_circle_outline,
                        SpamAuthResult.fail || SpamAuthResult.softFail => Icons.cancel_outlined,
                        _ => Icons.remove_circle_outline,
                      },
                      label: '$name ${_auth(result, x.features.authPresent)}',
                      color: switch (result) {
                        SpamAuthResult.pass => spamLabelColor(context, SpamLabel.ham),
                        SpamAuthResult.fail ||
                        SpamAuthResult.softFail => spamLabelColor(context, SpamLabel.spam),
                        _ => theme.colorScheme.onSurfaceVariant,
                      },
                    ),
                ],
              ),
              if (x.features.replyTo != null ||
                  x.features.lastExternalIp != null ||
                  x.features.urls.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  [
                    if (x.features.replyTo != null) 'Reply-To ${x.features.replyTo}',
                    if (x.features.lastExternalIp != null) 'sent from ${x.features.lastExternalIp}',
                    if (x.features.urls.isNotEmpty)
                      '${x.features.urls.length} link${x.features.urls.length == 1 ? '' : 's'}: '
                          '${x.features.urls.take(3).join(', ')}',
                  ].join(' · '),
                  style: theme.textTheme.bodyMedium,
                ),
              ],
              const SizedBox(height: 20),
              Text('Your filter rules', style: theme.textTheme.titleSmall),
              const SizedBox(height: 4),
              Text(
                describeFilterOutcome(x.filters, rules),
                key: const Key('spam-explain-filters'),
                style: theme.textTheme.bodyMedium,
              ),
            ],
          );
        },
      ),
    );
  }

  static String _signed(double w) => '${w > 0 ? '+' : ''}${w.toStringAsFixed(1)}';

  static String _auth(SpamAuthResult? r, bool present) => switch (r) {
    null => present ? 'not checked' : 'no result',
    SpamAuthResult.pass => 'pass',
    SpamAuthResult.fail => 'fail',
    SpamAuthResult.softFail => 'softfail',
    SpamAuthResult.neutral => 'neutral',
    SpamAuthResult.none => 'none',
    SpamAuthResult.other => 'other',
  };
}

/// `Sender <address> · Subject` under the sheet's title. Mail whose subject is only the
/// provider's placeholder reads "Encrypted message" in italics, as in the inbox (review N1).
class _SenderLine extends ConsumerWidget {
  const _SenderLine({required this.explanation});

  final SpamExplanation explanation;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final x = explanation;
    final style = theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant);
    final subject = x.subject;
    final message = subject != null && isPlaceholderSubject(subject)
        ? ref.watch(_explainedMessageProvider(x.messageId)).value
        : null;
    final title = subjectTitleOf(subject, message: message);
    if (subject == null || !title.placeholder) {
      return Text(
        '${x.from}${subject == null ? '' : ' · ${title.text}'}',
        key: const Key('spam-explain-from'),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: style,
      );
    }
    return Text.rich(
      TextSpan(
        children: [
          TextSpan(text: '${x.from} · '),
          TextSpan(text: title.text, style: subjectTitleStyle(context, null, placeholder: true)),
        ],
      ),
      key: const Key('spam-explain-from'),
      maxLines: 2,
      overflow: TextOverflow.ellipsis,
      style: style,
    );
  }
}

/// "Would move to Newsletters and star it (rules: Finance)" or "No rule matches".
String describeFilterOutcome(FilterOutcome o, List<FilterRule> rules) {
  if (o.matchedRuleIds.isEmpty && o.errors.isEmpty) return 'No rule matches this message.';
  final names = [
    for (final id in o.matchedRuleIds)
      rules.where((r) => r.id == id).map((r) => r.name.isEmpty ? '#$id' : r.name).firstOrNull ??
          '#$id',
  ];
  final effects = [
    if (o.moveTo != null) 'move it to ${o.moveTo}',
    if (o.star) 'star it',
    if (o.markRead) 'mark it read',
    for (final f in o.addFlags) 'flag it $f',
  ];
  final b = StringBuffer();
  b.write(effects.isEmpty ? 'Matching rules change nothing' : 'Would ${effects.join(', ')}');
  if (names.isNotEmpty) b.write(' (${names.length == 1 ? 'rule' : 'rules'}: ${names.join(', ')})');
  b.write('.');
  for (final e in o.errors) {
    b.write(' Rule #${e.ruleId} could not run: ${e.error}.');
  }
  return b.toString();
}
