import 'package:flutter/material.dart';

import '../../core/core_providers.dart' show BackfillStatus;
import '../../core/models.dart';

// What the inbox says while mail is being fetched (docs/PERFORMANCE.md, "What the app does
// with it"): a line under the app bar's title — `Key('sync-status')` while a sync runs,
// `Key('backfill-status')` while older mail loads in the background — and, during a sync, a
// thin bar in the app bar's bottom edge (`Key('sync-progress')`) that fills as batches are
// stored. The numbers are the engine's, per folder: what the step set out to fetch, or what
// is stored of what the server holds while older mail loads.

/// `3,410`: a count as the sync status writes it.
String groupedCount(int n) {
  final digits = n.abs().toString();
  final out = StringBuffer(n < 0 ? '-' : '');
  for (var i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 == 0) out.write(',');
    out.write(digits[i]);
  }
  return out.toString();
}

/// ` in Sent Mail` for a folder other than INBOX (the last part of the server's name, so
/// `[Gmail]/Sent Mail` reads `Sent Mail`), else nothing.
String _inFolder(String folder) {
  if (folder.toUpperCase() == 'INBOX') return '';
  final name = folder.split(RegExp(r'[/.]')).lastWhere((p) => p.isNotEmpty, orElse: () => folder);
  return ' in $name';
}

String _account(String? account) => account == null ? '' : ' · $account';

/// The sync's line: "Fetching mail…" until the first batch is stored, then "Fetching newest
/// mail… 200 of 500" (a folder's first sync), "Fetching mail… 3,410 of 10,000" (new mail) or
/// "Loading older mail… 4,200 of 10,000" (a sync also fetches some older mail). With
/// [account] (several accounts) the address follows.
String syncProgressLabel(SyncProgress? p, {String? account}) {
  if (p == null) return 'Fetching mail…';
  final where = _inFolder(p.folder);
  final text = switch (p.phase) {
    SyncPhase.initial =>
      'Fetching newest mail$where… ${groupedCount(p.fetched)} of ${groupedCount(p.planned)}',
    SyncPhase.incremental =>
      'Fetching mail$where… ${groupedCount(p.fetched)} of ${groupedCount(p.planned)}',
    SyncPhase.backfill => _olderMail(p),
  };
  return '$text${_account(account)}';
}

String _olderMail(SyncProgress p) =>
    'Loading older mail${_inFolder(p.folder)}… '
    '${groupedCount(p.local)} of ${groupedCount(p.totalKnown)}';

/// How far the step is, for the bar: fetched of planned (stored of what the server holds
/// while older mail loads), 0–1; null — an indeterminate bar — while nothing is known.
double? syncProgressFraction(SyncProgress? p) {
  if (p == null) return null;
  final (done, of) = p.phase == SyncPhase.backfill
      ? (p.local, p.totalKnown)
      : (p.fetched, p.planned);
  if (of <= 0) return null;
  return (done / of).clamp(0.0, 1.0);
}

/// The background backfill's line: "Loading older mail in the background…" until its first
/// batch, then "Loading older mail… 4,200 of 10,000"; after a failure, when it tries again.
String backfillLabel(BackfillStatus s, {String? account}) {
  final retry = s.retryIn;
  final p = s.progress;
  final text = retry != null
      ? 'Loading older mail paused · trying again in ${retry.inSeconds} s'
      : p == null
      ? 'Loading older mail in the background…'
      : _olderMail(p);
  return '$text${_account(account)}';
}

/// The inbox app bar's title with a status line under it (when [status] is set).
class InboxTitle extends StatelessWidget {
  const InboxTitle({super.key, required this.title, this.status, this.statusKey});

  final String title;
  final String? status;
  final Key? statusKey;

  @override
  Widget build(BuildContext context) {
    final line = status;
    if (line == null) return Text(title);
    final theme = Theme.of(context);
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title),
        Text(
          line,
          key: statusKey,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
      ],
    );
  }
}

/// The sync's thin bar (`Key('sync-progress')`): filling as batches are stored when the step's
/// size is known ([syncProgressFraction]), indeterminate before.
class SyncProgressBar extends StatelessWidget {
  const SyncProgressBar({super.key, required this.progress});

  final SyncProgress? progress;

  /// Screen readers get the bar's percentage (a progress bar's semantics value must be a
  /// number); the counts are in the status line above it.
  @override
  Widget build(BuildContext context) => LinearProgressIndicator(
    key: const Key('sync-progress'),
    minHeight: 3,
    value: syncProgressFraction(progress),
    semanticsLabel: 'Sync progress',
  );
}
