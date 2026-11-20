import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart' show CustomSemanticsAction;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../inbox/inbox_list_pane.dart' show avatarColorFor, relativeTime;
import 'draft_attachment_sweep.dart' show draftCopiesSweepProvider;

/// Bumped whenever a draft is saved or deleted, so every list of drafts reloads. A
/// keep-alive notifier: compose bumps it even after its own screen has gone (the draft
/// saved on leaving lands a moment later).
final draftsRevisionProvider = NotifierProvider<DraftsRevision, int>(DraftsRevision.new);

class DraftsRevision extends Notifier<int> {
  @override
  int build() => 0;

  /// A draft was saved or deleted.
  void bump() {
    if (ref.mounted) state++;
  }
}

/// The saved drafts of every account, newest first (`CoreDraftOps.listDrafts`).
final draftsProvider = FutureProvider<List<SavedDraft>>((ref) {
  ref.watch(draftsRevisionProvider);
  return ref.watch(coreApiProvider).listDrafts();
});

/// The message list shows the Drafts chip's list (local drafts, not an IMAP folder)
/// instead of the selected folder's conversations.
final draftsChipProvider = NotifierProvider<DraftsChipController, bool>(DraftsChipController.new);

class DraftsChipController extends Notifier<bool> {
  @override
  bool build() {
    // Every inbox builds the chip row, so this is the drafts feature's start-up hook: the
    // sweep of attachment copies no draft refers to runs from here, once per run.
    ref.listen(draftCopiesSweepProvider, (_, _) {});
    return false;
  }

  void set(bool showDrafts) => state = showDrafts;
}

/// Route of the compose screen editing saved draft [id].
String draftRoute(int id) => '/compose?draft=$id';

/// "Discard this draft?" — true when the user confirmed. [editing]: asked from compose
/// (the cancel button keeps editing) rather than from the list.
Future<bool> confirmDiscardDraft(BuildContext context, {bool editing = true}) async =>
    await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        key: const Key('discard-draft-dialog'),
        icon: const Icon(Icons.delete_outline),
        title: const Text('Discard this draft?'),
        content: const Text(
          'The message is deleted from this device and from your Drafts folder on the server, '
          'with the copies of its attached files. This cannot be undone.',
        ),
        actions: [
          TextButton(
            key: const Key('discard-draft-cancel'),
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(editing ? 'Keep editing' : 'Keep'),
          ),
          FilledButton(
            key: const Key('discard-draft-confirm'),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Discard'),
          ),
        ],
      ),
    ) ??
    false;

/// The Drafts chip's list: every saved draft, newest first, with its recipients, subject,
/// the start of its text and when it was last saved. A row opens the draft in compose;
/// swiping it away (or the screen reader's action) discards it after a confirmation.
class DraftsList extends ConsumerStatefulWidget {
  const DraftsList({super.key});

  @override
  ConsumerState<DraftsList> createState() => _DraftsListState();
}

class _DraftsListState extends ConsumerState<DraftsList> {
  /// Rows swiped away: hidden at once (a dismissed row must leave the tree) until the
  /// reloaded list no longer has them.
  final _hidden = <int>{};

  /// Why the last drafts sync could not reach a server (null: it could, or none ran yet).
  String? _syncProblem;

  @override
  void initState() {
    super.initState();
    // Opening the Drafts list syncs the drafts with the server (other devices' drafts
    // come in); the list shows what is stored here meanwhile.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _sync();
    });
  }

  /// `syncDrafts`, then the list reloads when it changed anything here.
  Future<void> _sync() async {
    final core = ref.read(coreApiProvider);
    try {
      final r = await core.syncDrafts();
      if (!mounted) return;
      setState(
        () => _syncProblem = r.failures.isEmpty
            ? null
            : 'Could not sync with the server, so drafts from your other devices may be '
                  'missing (${r.failures.join('; ')}).',
      );
      if (r.changedHere) ref.read(draftsRevisionProvider.notifier).bump();
    } catch (e) {
      if (mounted) {
        setState(() => _syncProblem = 'Could not sync with the server: ${friendlyError(e)}');
      }
    }
  }

  Future<void> _discard(SavedDraft d) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    try {
      await ref.read(coreApiProvider).deleteDraft(d.id);
      messenger?.showSnackBar(
        const SnackBar(key: Key('draft-discarded-snackbar'), content: Text('Draft discarded')),
      );
    } catch (e) {
      messenger?.showSnackBar(
        SnackBar(content: Text('Could not discard the draft: ${friendlyError(e)}')),
      );
    }
    ref.read(draftsRevisionProvider.notifier).bump();
  }

  @override
  Widget build(BuildContext context) {
    final drafts = ref.watch(draftsProvider);
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final byId = {for (final a in accounts) a.id: a};
    final all = drafts.value;
    final list = all == null
        ? null
        : [
            for (final d in all)
              if (!_hidden.contains(d.id)) d,
          ];
    if (list == null) {
      if (drafts.hasError) {
        return _DraftsMessage(
          key: const Key('drafts-error'),
          icon: Icons.error_outline,
          title: 'Could not load the drafts',
          body: friendlyError(drafts.error!),
          error: true,
        );
      }
      return const Center(child: CircularProgressIndicator());
    }
    final problem = _syncProblem;
    if (list.isEmpty) {
      return RefreshIndicator(
        onRefresh: _sync,
        child: CustomScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          slivers: [
            if (problem != null) SliverToBoxAdapter(child: _SyncProblem(text: problem)),
            const SliverFillRemaining(
              // The message lays itself out (LayoutBuilder): no intrinsic sizing.
              hasScrollBody: true,
              child: _DraftsMessage(
                key: Key('drafts-empty'),
                icon: Icons.drafts_outlined,
                title: 'No drafts',
                body:
                    'A message you start is saved here as you type, and when you leave it. '
                    'Drafts are also kept in your Drafts folder on the server, encrypted so '
                    'that only your devices with your key can read them.',
              ),
            ),
          ],
        ),
      );
    }
    final rows = problem == null ? 0 : 1;
    return RefreshIndicator(
      onRefresh: _sync,
      child: ListView.separated(
        key: const Key('drafts-list'),
        physics: const AlwaysScrollableScrollPhysics(),
        padding: EdgeInsets.only(bottom: 88 + MediaQuery.paddingOf(context).bottom),
        itemCount: list.length + rows,
        separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
        itemBuilder: (context, index) {
          if (index < rows) return _SyncProblem(text: problem!);
          final i = index - rows;
          final d = list[i];
          return Dismissible(
            key: ValueKey('draft-dismiss-${d.id}'),
            direction: DismissDirection.endToStart,
            background: const SizedBox.shrink(),
            secondaryBackground: const _DiscardBackground(),
            confirmDismiss: (_) => confirmDiscardDraft(context, editing: false),
            onDismissed: (_) {
              setState(() => _hidden.add(d.id));
              _discard(d);
            },
            child: DraftTile(
              draft: d,
              account: byId[d.accountId],
              showAccount: accounts.length > 1,
              onTap: () => context.go(draftRoute(d.id)),
              onDiscard: () async {
                if (await confirmDiscardDraft(context, editing: false) && mounted) {
                  setState(() => _hidden.add(d.id));
                  await _discard(d);
                }
              },
            ),
          );
        },
      ),
    );
  }
}

/// The line above the drafts when the last sync could not reach a server.
class _SyncProblem extends StatelessWidget {
  const _SyncProblem({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      key: const Key('drafts-sync-problem'),
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
      child: Row(
        children: [
          Icon(Icons.cloud_off_outlined, size: 18, color: scheme.onSurfaceVariant),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context).textTheme.bodySmall
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }
}

/// One saved draft: recipients, last-saved time, subject, the start of the text, and tags
/// for a reply / forward, attached files and (with several accounts) the account.
class DraftTile extends StatelessWidget {
  const DraftTile({
    super.key,
    required this.draft,
    required this.onTap,
    this.onDiscard,
    this.account,
    this.showAccount = false,
  });

  final SavedDraft draft;
  final VoidCallback onTap;
  final VoidCallback? onDiscard;
  final Account? account;
  final bool showAccount;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final d = draft;
    final recipients = d.recipients;
    final to = recipients.isEmpty ? 'No recipients yet' : 'To ${recipients.join(', ')}';
    final subject = d.subject.trim().isEmpty ? '(no subject)' : d.subject.trim();
    final text = d.body.replaceAll(RegExp(r'\s+'), ' ').trim();
    final secondary = theme.textTheme.bodySmall?.copyWith(color: scheme.onSurfaceVariant);
    final tags = <Widget>[
      if (d.kind == ComposeKind.reply) const _DraftTag(icon: Icons.reply, label: 'Reply'),
      if (d.kind == ComposeKind.forward) const _DraftTag(icon: Icons.forward, label: 'Forward'),
      if (d.attachments.isNotEmpty)
        _DraftTag(
          icon: Icons.attach_file,
          label: '${d.attachments.length} file${d.attachments.length == 1 ? '' : 's'}',
        ),
      if (showAccount && account != null) _DraftTag(label: account!.providerName),
      if (d.origin == DraftOrigin.server)
        const _DraftTag(
          key: Key('draft-origin-server'),
          icon: Icons.cloud_download_outlined,
          label: 'From another device',
        ),
      if (d.remoteFiles > 0)
        _DraftTag(
          key: const Key('draft-remote-files'),
          icon: Icons.link_off,
          label: '${d.remoteFiles} file${d.remoteFiles == 1 ? '' : 's'} on the other device',
        ),
    ];
    return Semantics(
      customSemanticsActions: onDiscard == null
          ? null
          : {const CustomSemanticsAction(label: 'Discard draft'): onDiscard!},
      child: MergeSemantics(
        child: ListTile(
          key: ValueKey('draft-tile-${d.id}'),
          onTap: onTap,
          leading: ExcludeSemantics(
            child: CircleAvatar(
              backgroundColor: recipients.isEmpty
                  ? scheme.surfaceContainerHighest
                  : avatarColorFor(recipients.first, scheme),
              foregroundColor: recipients.isEmpty ? scheme.onSurfaceVariant : Colors.white,
              child: recipients.isEmpty
                  ? const Icon(Icons.edit_outlined, size: 20)
                  : Text(recipients.first[0].toUpperCase()),
            ),
          ),
          title: Row(
            children: [
              Expanded(
                child: Text(
                  to,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontStyle: recipients.isEmpty ? FontStyle.italic : null,
                    color: recipients.isEmpty ? scheme.onSurfaceVariant : null,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Text(
                relativeTime(d.updatedAt),
                style: theme.textTheme.labelSmall?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                subject,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontStyle: d.subject.trim().isEmpty ? FontStyle.italic : null,
                ),
              ),
              if (text.isNotEmpty) ...[
                const SizedBox(height: 2),
                Text(text, maxLines: 1, overflow: TextOverflow.ellipsis, style: secondary),
              ],
              if (tags.isNotEmpty) ...[
                const SizedBox(height: 4),
                Wrap(spacing: 6, runSpacing: 4, children: tags),
              ],
            ],
          ),
          isThreeLine: true,
        ),
      ),
    );
  }
}

class _DraftTag extends StatelessWidget {
  const _DraftTag({super.key, this.icon, required this.label});

  final IconData? icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        border: Border.all(color: scheme.outlineVariant),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 12, color: scheme.onSurfaceVariant),
            const SizedBox(width: 3),
          ],
          Text(label, style: Theme.of(context).textTheme.labelSmall),
        ],
      ),
    );
  }
}

/// What a draft row reveals while it is swiped away: "Discard".
class _DiscardBackground extends StatelessWidget {
  const _DiscardBackground();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ColoredBox(
      key: const Key('draft-swipe-discard'),
      color: scheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            Icon(Icons.delete_outline, color: scheme.onErrorContainer),
            const SizedBox(width: 8),
            Text(
              'Discard',
              style: TextStyle(color: scheme.onErrorContainer, fontWeight: FontWeight.w600),
            ),
          ],
        ),
      ),
    );
  }
}

class _DraftsMessage extends StatelessWidget {
  const _DraftsMessage({
    super.key,
    required this.icon,
    required this.title,
    required this.body,
    this.error = false,
  });

  final IconData icon;
  final String title;
  final String body;
  final bool error;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return LayoutBuilder(
      builder: (context, box) => SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: box.maxHeight, minWidth: box.maxWidth),
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(icon, size: 48, color: error ? scheme.error : scheme.outline),
                  const SizedBox(height: 12),
                  Text(title, style: theme.textTheme.titleMedium, textAlign: TextAlign.center),
                  const SizedBox(height: 6),
                  Text(
                    body,
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: error ? scheme.error : scheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
