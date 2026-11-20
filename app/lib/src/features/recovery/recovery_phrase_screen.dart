import 'dart:ui' show ImageFilter;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../platform/secure_screen.dart';
import '../../widgets/lock_badge.dart';
import 'recovery_copy.dart';

enum _Step { intro, words, confirm, saving, done }

/// Settings → Security → "Recovery phrase" (docs/RECOVERY.md, "Show-once
/// screen"): create the 12 words, show them blurred until tapped (no copy
/// button, not selectable), confirm words 3, 7 and 11, then
/// `backup_to_server`. The words live only in this widget's state and are
/// cleared when it goes away.
class RecoveryPhraseScreen extends ConsumerStatefulWidget {
  const RecoveryPhraseScreen({super.key, this.accountId, this.initialRevealed = false});

  final String? accountId;

  /// Review/golden captures only: start on the words step, revealed.
  final bool initialRevealed;

  @override
  ConsumerState<RecoveryPhraseScreen> createState() => _RecoveryPhraseScreenState();
}

class _RecoveryPhraseScreenState extends ConsumerState<RecoveryPhraseScreen> {
  static const confirmPositions = [3, 7, 11];

  _Step _step = _Step.intro;
  List<String> _words = const [];
  bool _revealed = false;
  String? _account;
  String? _error;
  final _confirm = [for (var i = 0; i < 3; i++) TextEditingController()];
  final _server = TextEditingController();

  @override
  void initState() {
    super.initState();
    SecureScreen.set(true);
  }

  @override
  void dispose() {
    SecureScreen.set(false);
    for (final c in _confirm) {
      c.dispose();
    }
    _server.dispose();
    _words = const [];
    super.dispose();
  }

  Future<String?> _resolveAccount() async {
    if (_account != null) return _account;
    final id = widget.accountId;
    if (id != null && id.isNotEmpty) return _account = id;
    final accounts = await ref.read(accountsProvider.future);
    return _account = accounts.isEmpty ? null : accounts.first.id;
  }

  Future<void> _create() async {
    setState(() => _error = null);
    final account = await _resolveAccount();
    if (account == null) {
      setState(() => _error = 'Add an account first: the phrase protects that account\'s key.');
      return;
    }
    try {
      final words = await ref.read(coreApiProvider).recoveryPhraseCreate(account);
      if (!mounted) return;
      setState(() {
        _words = words;
        _revealed = widget.initialRevealed;
        _step = _Step.words;
      });
    } catch (e) {
      if (mounted) setState(() => _error = 'Could not create a phrase: $e');
    }
  }

  bool get _confirmed {
    for (var i = 0; i < confirmPositions.length; i++) {
      if (_confirm[i].text.trim().toLowerCase() != _words[confirmPositions[i] - 1]) return false;
    }
    return true;
  }

  Future<void> _backup(String? configured) async {
    final server = (configured ?? _server.text).trim();
    if (server.isEmpty) {
      setState(() => _error = 'Enter the address of your Sealbox server to store the backup.');
      return;
    }
    final account = (await _resolveAccount())!;
    setState(() {
      _step = _Step.saving;
      _error = null;
    });
    try {
      await ref.read(coreApiProvider).backupToServer(account, server, _words.join(' '));
      ref.invalidate(backupStatusProvider);
      ref.invalidate(recoveryStatusProvider);
      if (!mounted) return;
      setState(() {
        _words = const [];
        _step = _Step.done;
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _Step.confirm;
          _error = 'The backup did not go through: ${friendlyRecoveryError(e)}';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final server = ref.watch(serverUrlProvider).value;
    final body = switch (_step) {
      _Step.intro => _intro(theme),
      _Step.words => _wordsStep(theme),
      _Step.confirm || _Step.saving => _confirmStep(theme, server),
      _Step.done => _done(theme),
    };
    return Scaffold(
      appBar: AppBar(title: const Text('Your recovery phrase')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: ListView(
            key: const Key('recovery-phrase'),
            padding: const EdgeInsets.all(16),
            children: [
              ...body,
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(
                  _error!,
                  key: const Key('recovery-error'),
                  style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  List<Widget> _intro(ThemeData theme) => [
    Text(RecoveryCopy.showOnceBody, style: theme.textTheme.bodyLarge),
    const SizedBox(height: 16),
    for (final tip in RecoveryCopy.advice)
      Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Padding(padding: EdgeInsets.only(top: 2), child: Icon(Icons.check, size: 18)),
            const SizedBox(width: 8),
            Expanded(child: Text(tip, style: theme.textTheme.bodyMedium)),
          ],
        ),
      ),
    const SizedBox(height: 16),
    FilledButton.icon(
      key: const Key('recovery-create'),
      onPressed: _create,
      icon: const Icon(Icons.key),
      label: const Text('Show my recovery phrase'),
    ),
  ];

  List<Widget> _wordsStep(ThemeData theme) => [
    Text(RecoveryCopy.showOnceBody, style: theme.textTheme.bodyLarge),
    const SizedBox(height: 16),
    _WordGrid(
      words: _words,
      revealed: _revealed,
      onReveal: () => setState(() => _revealed = true),
    ),
    const SizedBox(height: 16),
    FilledButton(
      key: const Key('recovery-wrote-down'),
      onPressed: _revealed ? () => setState(() => _step = _Step.confirm) : null,
      child: const Text('I wrote them down'),
    ),
  ];

  List<Widget> _confirmStep(ThemeData theme, String? configured) => [
    Text(RecoveryCopy.confirmPrompt, style: theme.textTheme.bodyLarge),
    const SizedBox(height: 16),
    for (var i = 0; i < confirmPositions.length; i++)
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          key: Key('recovery-confirm-${confirmPositions[i]}'),
          controller: _confirm[i],
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: 'Word ${confirmPositions[i]}',
            border: const OutlineInputBorder(),
          ),
          onChanged: (_) => setState(() {}),
        ),
      ),
    if (configured == null)
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          key: const Key('recovery-server'),
          controller: _server,
          keyboardType: TextInputType.url,
          autocorrect: false,
          decoration: const InputDecoration(
            labelText: 'Sealbox server',
            hintText: 'https://sealbox.example',
            helperText: 'No server is configured in this build; enter the one you use.',
            border: OutlineInputBorder(),
          ),
        ),
      )
    else
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Text('Backup goes to $configured.', style: theme.textTheme.bodySmall),
      ),
    Row(
      children: [
        TextButton(
          onPressed: _step == _Step.saving
              ? null
              : () => setState(() {
                  _revealed = true;
                  _step = _Step.words;
                }),
          child: const Text('Show the words again'),
        ),
        const Spacer(),
        FilledButton(
          key: const Key('recovery-confirm'),
          onPressed: _step == _Step.saving || !_confirmed ? null : () => _backup(configured),
          child: _step == _Step.saving
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Confirm and back up'),
        ),
      ],
    ),
  ];

  List<Widget> _done(ThemeData theme) => [
    Icon(Icons.cloud_done, size: 48, color: LockColors.ofContext(context).encrypted),
    const SizedBox(height: 12),
    Text(
      RecoveryCopy.backupSaved,
      key: const Key('recovery-done'),
      style: theme.textTheme.bodyLarge,
      textAlign: TextAlign.center,
    ),
    const SizedBox(height: 16),
    FilledButton(
      onPressed: () => context.canPop() ? context.pop() : context.go('/settings'),
      child: const Text('Done'),
    ),
  ];
}

/// The numbered 3×4 grid, blurred until tapped. Plain `Text` (not
/// selectable) and no copy action: the words go on paper.
class _WordGrid extends StatelessWidget {
  const _WordGrid({required this.words, required this.revealed, required this.onReveal});

  final List<String> words;
  final bool revealed;
  final VoidCallback onReveal;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final grid = LayoutBuilder(
      builder: (context, box) {
        // The documented 3×4 grid; two columns only on very narrow windows.
        final cols = box.maxWidth < 300 ? 2 : 3;
        final w = (box.maxWidth - (cols - 1) * 8) / cols;
        return Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (var i = 0; i < words.length; i++)
              Container(
                key: Key('recovery-word-${i + 1}'),
                width: w,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    SizedBox(
                      width: 24,
                      child: Text(
                        '${i + 1}.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                    Expanded(
                      child: FittedBox(
                        fit: BoxFit.scaleDown,
                        alignment: Alignment.centerLeft,
                        child: Text(
                          words[i],
                          style: theme.textTheme.titleMedium?.copyWith(fontFamily: 'monospace'),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        );
      },
    );
    if (revealed) return grid;
    return GestureDetector(
      key: const Key('recovery-reveal'),
      onTap: onReveal,
      child: Semantics(
        button: true,
        label: 'Tap to show the 12 words',
        child: Stack(
          alignment: Alignment.center,
          children: [
            ExcludeSemantics(
              child: ImageFiltered(
                imageFilter: ImageFilter.blur(sigmaX: 9, sigmaY: 9),
                child: grid,
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(999),
                border: Border.all(color: theme.colorScheme.outline),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.visibility_outlined, size: 18),
                  const SizedBox(width: 8),
                  Text('Tap to show — make sure nobody is watching', style: theme.textTheme.labelLarge),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Widget-test / golden entry: the words step with given words.
@visibleForTesting
class RecoveryWordGridForTest extends StatelessWidget {
  const RecoveryWordGridForTest({super.key, required this.words, this.revealed = true});

  final List<String> words;
  final bool revealed;

  @override
  Widget build(BuildContext context) => _WordGrid(words: words, revealed: revealed, onReveal: () {});
}

/// Phrase-entry dialog behind Settings → Backup → "Back up now" when a phrase
/// exists already (it is never stored, so it has to be typed again).
Future<bool> showBackupNowDialog(BuildContext context, {required String accountId}) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (_) => _BackupNowDialog(accountId: accountId),
  );
  return ok ?? false;
}

class _BackupNowDialog extends ConsumerStatefulWidget {
  const _BackupNowDialog({required this.accountId});

  final String accountId;

  @override
  ConsumerState<_BackupNowDialog> createState() => _BackupNowDialogState();
}

class _BackupNowDialogState extends ConsumerState<_BackupNowDialog> {
  final _phrase = TextEditingController();
  final _server = TextEditingController();
  String? _error;
  String? _phraseError;
  bool _busy = false;

  @override
  void dispose() {
    _phrase.dispose();
    _server.dispose();
    super.dispose();
  }

  Future<void> _check(String v) async {
    final e = await phraseFieldError(ref.read(coreApiProvider), v);
    if (mounted) setState(() => _phraseError = e);
  }

  Future<void> _go(String? configured) async {
    final server = (configured ?? _server.text).trim();
    if (server.isEmpty) {
      setState(() => _error = 'Enter the address of your Sealbox server.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(coreApiProvider).backupToServer(widget.accountId, server, _phrase.text);
      ref.invalidate(backupStatusProvider);
      ref.invalidate(recoveryStatusProvider);
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = friendlyRecoveryError(e);
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final configured = ref.watch(serverUrlProvider).value;
    return AlertDialog(
      key: const Key('backup-now-dialog'),
      title: const Text('Back up now'),
      content: SizedBox(
        width: 480,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Type your 12-word recovery phrase. Sealbox does not keep a copy, so it needs it '
              'for every backup.',
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('backup-now-phrase'),
              controller: _phrase,
              minLines: 2,
              maxLines: 3,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: 'Recovery phrase (12 words)',
                border: const OutlineInputBorder(),
                errorText: _phraseError,
              ),
              onChanged: _check,
            ),
            if (configured == null) ...[
              const SizedBox(height: 12),
              TextField(
                key: const Key('backup-now-server'),
                controller: _server,
                keyboardType: TextInputType.url,
                decoration: const InputDecoration(
                  labelText: 'Sealbox server',
                  hintText: 'https://sealbox.example',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ],
            const SizedBox(height: 8),
            TextButton(
              key: const Key('backup-now-new-phrase'),
              onPressed: () {
                Navigator.of(context).pop(false);
                context.push(recoveryPhraseRoute(widget.accountId));
              },
              child: const Text('Lost it? Create a new phrase'),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('backup-now-confirm'),
          onPressed: _busy || _phraseError != null || _phrase.text.trim().isEmpty
              ? null
              : () => _go(configured),
          child: const Text('Back up'),
        ),
      ],
    );
  }
}

/// Settings and the inbox: "Back up your keys …" with "Back up now", while
/// `backup_status.reminder` is set.
class BackupReminderBanner extends ConsumerWidget {
  const BackupReminderBanner({super.key, required this.status});

  final BackupStatus status;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final amber = LockColors.ofContext(context).plaintext;
    return Container(
      key: const Key('backup-reminder'),
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(12, 8, 8, 8),
      decoration: BoxDecoration(
        color: amber.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(Icons.cloud_upload_outlined, color: amber),
          const SizedBox(width: 12),
          Expanded(child: Text(RecoveryCopy.reminder, style: theme.textTheme.bodyMedium)),
          const SizedBox(width: 8),
          TextButton(
            key: const Key('backup-reminder-action'),
            onPressed: () => startBackup(context, ref, status),
            child: const Text('Back up now'),
          ),
        ],
      ),
    );
  }
}

String recoveryPhraseRoute(String? accountId) => accountId == null
    ? '/settings/recovery-phrase'
    : '/settings/recovery-phrase?account=${Uri.encodeQueryComponent(accountId)}';

/// "Back up now": no phrase yet on this device → the show-once screen;
/// otherwise the phrase dialog.
Future<void> startBackup(BuildContext context, WidgetRef ref, BackupStatus status) async {
  var account = status.accountId;
  if (account == null) {
    final accounts = await ref.read(accountsProvider.future);
    if (accounts.isEmpty || !context.mounted) return;
    account = accounts.first.id;
  }
  if (!context.mounted) return;
  if (status.phraseCreatedAt == null) {
    context.push(recoveryPhraseRoute(account));
    return;
  }
  final messenger = ScaffoldMessenger.of(context);
  if (await showBackupNowDialog(context, accountId: account)) {
    messenger.showSnackBar(const SnackBar(content: Text(RecoveryCopy.backupSaved)));
  }
}
