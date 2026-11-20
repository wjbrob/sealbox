import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';

/// What this session's actions learned that `directoryStatus` cannot say: the
/// engine reports only what the directory serves (published / other key / nothing),
/// so "a challenge was mailed, waiting for it" (after Publish) and "the link was
/// refused" (after Complete verification) are kept here, per account, until the
/// directory itself reports the key.
final directoryProgressProvider = NotifierProvider<DirectoryProgress, Map<String, DirectoryState>>(
  DirectoryProgress.new,
);

class DirectoryProgress extends Notifier<Map<String, DirectoryState>> {
  @override
  Map<String, DirectoryState> build() => const {};

  void set(String accountId, DirectoryState? s) => state = {
    for (final e in state.entries)
      if (e.key != accountId) e.key: e.value,
    accountId: ?s,
  };
}

/// The state to show: the directory's own answer when it is decisive, else what the
/// last action here found out (pending challenge, refused link).
DirectoryState effectiveDirectoryState(DirectoryState fromStatus, DirectoryState? progress) =>
    switch (fromStatus) {
      DirectoryState.unpublished || DirectoryState.unknown => progress ?? fromStatus,
      _ => fromStatus,
    };

/// Settings → My key → key directory: what the Sealbox server's directory holds
/// for the account (`directoryStatus`), with the one action that moves it on —
/// Publish, Complete verification, Retry — or a pointer to the Server section
/// when no server is configured.
class DirectoryPublishPanel extends ConsumerStatefulWidget {
  const DirectoryPublishPanel({super.key, required this.account, this.onSetServer});

  final Account account;

  /// Brings the Server section into view ("Set a server URL first").
  final VoidCallback? onSetServer;

  @override
  ConsumerState<DirectoryPublishPanel> createState() => _DirectoryPublishPanelState();
}

class _DirectoryPublishPanelState extends ConsumerState<DirectoryPublishPanel> {
  bool _busy = false;
  String? _error;

  String get _id => widget.account.id;

  Future<void> _run(Future<String> Function() action) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final done = await action();
      messenger?.removeCurrentSnackBar();
      messenger?.showSnackBar(SnackBar(key: const Key('directory-snackbar'), content: Text(done)));
    } catch (e) {
      if (mounted) setState(() => _error = friendlyError(e));
    } finally {
      ref.invalidate(directoryStatusProvider(_id));
      ref.invalidate(ktAuditProvider(_id));
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _publish() => _run(() async {
    final r = await ref.read(coreApiProvider).publishKey(_id);
    ref.read(directoryProgressProvider.notifier).set(_id, r.tokenIssued ? r.state : null);
    return r.tokenIssued
        ? 'Key uploaded. The directory mailed a verification link to ${widget.account.email}.'
        : 'Your key already is in the directory on ${_host(r.serverUrl)}.';
  });

  Future<void> _complete() => _run(() async {
    final s = await ref.read(coreApiProvider).completeDirectoryVerification(_id);
    ref
        .read(directoryProgressProvider.notifier)
        .set(_id, s.state == DirectoryState.published ? null : s.state);
    return switch (s.state) {
      DirectoryState.published => 'Verified: your key is published.',
      DirectoryState.awaitingVerification =>
        'The directory\'s mail has not arrived yet. Fetch mail and try again in a moment.',
      DirectoryState.verificationFailed =>
        'The verification link was refused. Publish again for a fresh one.',
      _ => 'Directory: ${s.state.name}',
    };
  });

  static String _host(String? url) {
    if (url == null || url.isEmpty) return 'the server';
    final u = Uri.tryParse(url);
    return u == null || u.host.isEmpty ? url : (u.hasPort ? '${u.host}:${u.port}' : u.host);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = LockColors.ofContext(context);
    final status = ref.watch(directoryStatusProvider(_id));
    final progress = ref.watch(directoryProgressProvider)[_id];
    final muted = theme.colorScheme.onSurfaceVariant;

    Widget chip(DirectoryState s, IconData icon, String label, Color color) => StatusChip(
      key: ValueKey('directory-state-${s.name}'),
      icon: icon,
      label: label,
      color: color,
    );

    Widget publishButton(String label) => FilledButton.tonalIcon(
      key: const Key('directory-publish'),
      onPressed: _busy ? null : _publish,
      icon: const Icon(Icons.upload),
      label: Text(label),
    );

    Widget retry() => TextButton.icon(
      key: const Key('directory-retry'),
      onPressed: _busy ? null : () => ref.invalidate(directoryStatusProvider(_id)),
      icon: const Icon(Icons.refresh),
      label: const Text('Retry'),
    );

    final (Widget head, String? note, List<Widget> actions) = status.when(
      loading: () => (
        chip(DirectoryState.unknown, Icons.manage_search, 'Checking the key directory…', muted),
        null,
        const <Widget>[],
      ),
      error: (e, _) => (
        chip(DirectoryState.unknown, Icons.help_outline, 'Directory status unknown', muted),
        friendlyError(e),
        [retry()],
      ),
      data: (d) => switch (effectiveDirectoryState(d.state, progress)) {
        // `chip(st, …)`: the key names the state shown, which may come from [progress].
        DirectoryState.noServer => (
          chip(
            DirectoryState.noServer,
            Icons.cloud_off_outlined,
            'Not published: no server',
            muted,
          ),
          'Publishing lets other apps find your key by your address. It needs a Sealbox server.',
          [
            FilledButton.tonalIcon(
              key: const Key('directory-publish'),
              onPressed: null,
              icon: const Icon(Icons.upload),
              label: const Text('Publish'),
            ),
            TextButton(
              key: const Key('directory-set-server'),
              onPressed: widget.onSetServer,
              child: const Text('Set a server URL first'),
            ),
          ],
        ),
        DirectoryState.unpublished => (
          chip(
            DirectoryState.unpublished,
            Icons.public_off_outlined,
            'Not in the key directory',
            muted,
          ),
          'Publish your key to ${_host(d.serverUrl)} so others can find it by your address. The '
              'directory mails you a link to confirm the address is yours.',
          [
            publishButton('Publish'),
            TextButton(
              key: const Key('directory-complete-earlier'),
              onPressed: _busy ? null : _complete,
              child: const Text('I already have the mail'),
            ),
          ],
        ),
        DirectoryState.awaitingVerification => (
          chip(
            DirectoryState.awaitingVerification,
            Icons.mark_email_unread_outlined,
            'Waiting for verification',
            palette.plaintext,
          ),
          'Check your inbox for the directory\'s mail. Sealbox follows its link for you: fetch '
              'mail, then complete the verification here.',
          [
            FilledButton.icon(
              key: const Key('directory-complete'),
              onPressed: _busy ? null : _complete,
              icon: const Icon(Icons.verified_outlined),
              label: const Text('Complete verification'),
            ),
            TextButton(
              key: const Key('directory-republish'),
              onPressed: _busy ? null : _publish,
              child: const Text('Send the mail again'),
            ),
          ],
        ),
        DirectoryState.published => (
          chip(
            DirectoryState.published,
            Icons.check_circle_outline,
            'Published on ${_host(d.serverUrl)}',
            palette.encrypted,
          ),
          'Anyone can find this key for ${widget.account.email} in the directory.',
          const <Widget>[],
        ),
        DirectoryState.otherKey => (
          chip(
            DirectoryState.otherKey,
            Icons.warning_amber_rounded,
            'Another key is published',
            palette.plaintext,
          ),
          'The directory on ${_host(d.serverUrl)} holds another key for this address (an old '
              'device?). Publish to replace it with this one.',
          [publishButton('Publish this key')],
        ),
        DirectoryState.verificationFailed => (
          chip(
            DirectoryState.verificationFailed,
            Icons.gpp_bad_outlined,
            'Verification failed',
            palette.undecryptable,
          ),
          'The verification link was refused (expired or already used).',
          [publishButton('Publish again')],
        ),
        DirectoryState.unreachable => (
          chip(
            DirectoryState.unreachable,
            Icons.wifi_off,
            'Directory unreachable',
            palette.undecryptable,
          ),
          d.error ?? 'The key directory did not answer.',
          [retry()],
        ),
        DirectoryState.unknown => (
          chip(DirectoryState.unknown, Icons.help_outline, 'Directory status unknown', muted),
          null,
          [retry()],
        ),
      },
    );

    return Column(
      key: const Key('directory-status'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text('Key directory', style: theme.textTheme.titleSmall),
            const SizedBox(width: 8),
            if (_busy)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
          ],
        ),
        const SizedBox(height: 6),
        head,
        if (note != null) ...[
          const SizedBox(height: 6),
          Text(note, key: const Key('directory-note'), style: theme.textTheme.bodySmall),
        ],
        if (_error != null) ...[
          const SizedBox(height: 6),
          Text(
            _error!,
            key: const Key('directory-error'),
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
          ),
        ],
        if (actions.isNotEmpty) ...[
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 4,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: actions,
          ),
        ],
      ],
    );
  }
}
