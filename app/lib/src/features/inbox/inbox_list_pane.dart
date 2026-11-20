import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart' show CustomSemanticsAction;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../core/signer_mismatch.dart';
import '../../core/threading.dart' show conversationTitle, normalizeSubject;
import '../../widgets/lock_badge.dart';
import '../../widgets/sealbox_logo.dart';
import '../compose/drafts.dart';
import '../recovery/recovery_phrase_screen.dart' show BackupReminderBanner;
import 'sync_progress.dart';
import 'thread_actions.dart';

/// The unified message list: every account's conversations in the folder of
/// the selected chip (by special-use role), newest first, with lock badges.
/// The refresh action (and pull-to-refresh) syncs the chip's folder; the first
/// time the inbox is shown with at least one account it syncs by itself, and
/// Spam / Trash / Archive sync themselves the first time they are opened in a
/// session. Rows swipe right to archive (or restore) and left to delete. The Drafts
/// chip lists the drafts saved on this device instead (`DraftsList`). While a sync runs
/// a line under the title says how far it got and a bar fills under the chips; while
/// older mail loads in the background the line says that (`sync_progress.dart`).
class InboxListPane extends ConsumerStatefulWidget {
  const InboxListPane({super.key, this.selectedThreadId});

  final String? selectedThreadId;

  @override
  ConsumerState<InboxListPane> createState() => _InboxListPaneState();
}

class _InboxListPaneState extends ConsumerState<InboxListPane> {
  /// Rows swiped away whose action is still running (the list keeps showing
  /// its previous data until the refreshed one arrives).
  final _hidden = <String>{};

  /// Fetches the selected folder: INBOX + Sent for Inbox / Sent / All mail,
  /// the role's own folder for Spam / Trash / Archive.
  Future<void> _sync() async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    final role = ref.read(folderProvider).role;
    final SyncOutcome? outcome;
    if (roleNeedsOwnSync(role)) {
      final accounts = ref.read(accountsProvider).value ?? const <Account>[];
      outcome = await ref.read(folderSyncProvider.notifier).syncNow(role!, accounts);
    } else {
      outcome = await ref.read(syncControllerProvider.notifier).syncNow();
    }
    if (!mounted || outcome == null) return;
    ref.invalidate(accountsProvider);
    // A watcher waiting to reconnect (or stopped after a failed login) tries again now.
    ref.read(liveWatchProvider.notifier).retryNow();
    messenger?.showSnackBar(
      SnackBar(
        key: const Key('inbox-sync-snackbar'),
        content: Text(outcome.summary),
        duration: const Duration(seconds: 3),
      ),
    );
  }

  void _select(MailFolder f, List<Account> accounts) {
    ref.read(draftsChipProvider.notifier).set(false);
    ref.read(folderProvider.notifier).set(f);
    if (roleNeedsOwnSync(f.role)) {
      ref.read(folderSyncProvider.notifier).ensureSynced(f.role!, accounts);
    }
  }

  /// Spam / Trash / Archive opened without a chip tap (restored state): the
  /// first-open sync still runs, once per account per session.
  void _maybeRoleSync(MailFolder folder, List<Account> accounts) {
    final role = folder.role;
    if (!roleNeedsOwnSync(role) || accounts.isEmpty) return;
    final s = ref.read(folderSyncProvider)[role] ?? const RoleSyncState();
    if (s.running || accounts.every((a) => s.attempted.contains(a.id))) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || ref.read(folderProvider).role != role) return;
      ref.read(folderSyncProvider.notifier).ensureSynced(role!, accounts);
    });
  }

  /// The swipe actions of a row in [folder]: (right, left).
  static (ThreadAction?, ThreadAction) swipeActionsFor(MailFolder folder) => switch (folder) {
    MailFolder.inbox => (ThreadAction.archive, ThreadAction.delete),
    MailFolder.archive => (ThreadAction.moveToInbox, ThreadAction.delete),
    MailFolder.trash => (ThreadAction.moveToInbox, ThreadAction.deleteForever),
    MailFolder.spam => (ThreadAction.notSpam, ThreadAction.delete),
    MailFolder.sent || MailFolder.all => (null, ThreadAction.delete),
  };

  /// Swipe or row action prepared: the plan, and the delete confirmation.
  final _pending = <String, (ThreadAction, ThreadActionPlan)>{};

  Future<ThreadActionPlan?> _prepare(MailThread t, ThreadAction action) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    final plan = await planFor(ref, t.accountId, t.messages);
    if (!mounted) return null;
    final n = plan.targets(action).length;
    if (n == 0) {
      messenger?.showSnackBar(
        SnackBar(content: Text('Nothing to ${action.label.toLowerCase()} in this conversation')),
      );
      return null;
    }
    if (action.confirms &&
        !await confirmThreadDelete(context, count: n, forever: action == ThreadAction.deleteForever)) {
      return null;
    }
    return mounted ? plan : null;
  }

  /// `confirmDismiss`: the row slides away only for an action that will run.
  Future<bool> _confirmSwipe(MailThread t, ThreadAction action) async {
    final plan = await _prepare(t, action);
    if (plan == null) return false;
    _pending[t.id] = (action, plan);
    return true;
  }

  void _dismissed(MailThread t) {
    final p = _pending.remove(t.id);
    setState(() => _hidden.add(t.id));
    if (p != null) _run(t, p.$1, p.$2);
  }

  /// The same actions from the row's menu (long press) or a screen reader.
  Future<void> _rowAction(MailThread t, ThreadAction action) async {
    final plan = await _prepare(t, action);
    if (plan == null || !mounted) return;
    if (action.leavesList) setState(() => _hidden.add(t.id));
    await _run(t, action, plan);
  }

  Future<void> _run(MailThread t, ThreadAction action, ThreadActionPlan plan) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    final router = GoRouter.of(context);
    final wasOpen = t.id == widget.selectedThreadId;
    await runThreadAction(ref, messenger, t.accountId, plan, action);
    if (wasOpen && action.leavesList) router.go('/inbox');
    // Keep the row hidden until the refreshed list is in (it reappears only if
    // something of it is still in this folder).
    try {
      await ref.read(threadsProvider.future);
    } catch (_) {}
    if (mounted) setState(() => _hidden.remove(t.id));
  }

  void _maybeAutoSync(List<Account> accounts) {
    if (accounts.isEmpty) return;
    if (ref.read(syncControllerProvider).ranOnce) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || ref.read(syncControllerProvider).ranOnce) return;
      ref.read(syncControllerProvider.notifier).syncNow();
    });
  }

  @override
  Widget build(BuildContext context) {
    final accounts = ref.watch(accountsProvider);
    final threads = ref.watch(threadsProvider);
    final sync = ref.watch(syncControllerProvider);
    // R4: the keys the user verified (one signing for another address is a warning).
    final contacts = ref.watch(contactsProvider).value ?? const <ContactKey>[];
    accounts.whenData(_maybeAutoSync);

    final folder = ref.watch(folderProvider);
    final roleSync = ref.watch(folderSyncProvider)[folder.role] ?? const RoleSyncState();
    final accts = accounts.value ?? const <Account>[];
    _maybeRoleSync(folder, accts);
    final busy = sync.running || roleSync.running;
    final showDrafts = ref.watch(draftsChipProvider);
    final backfill = ref.watch(backfillProvider);
    // With several accounts the status line names the one it is about.
    String? whose(SyncProgress? p) => accts.length > 1 ? p?.account : null;
    // The empty inbox says how far the sync got itself; the line would repeat it.
    final emptyInbox =
        !showDrafts &&
        !roleNeedsOwnSync(folder.role) &&
        accts.isNotEmpty &&
        (threads.value?.every((t) => _hidden.contains(t.id)) ?? false);
    final (String? status, Key? statusKey) = sync.running
        ? (
            emptyInbox ? null : syncProgressLabel(sync.progress, account: whose(sync.progress)),
            const Key('sync-status'),
          )
        : backfill.active
        ? (backfillLabel(backfill, account: whose(backfill.progress)), const Key('backfill-status'))
        : (null, null);
    return Scaffold(
      appBar: AppBar(
        title: InboxTitle(
          title: showDrafts
              ? 'Drafts'
              : folder == MailFolder.inbox
              ? 'Inbox'
              : folder.label,
          status: status,
          statusKey: statusKey,
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(51),
          child: Column(
            children: [
              // A Row (not a lazy ListView): every chip stays in the tree, so
              // scrolling one into view never unmounts another.
              SizedBox(
                height: 48,
                child: FadingChipRow(
                  children: [
                    for (final f in MailFolder.values) ...[
                      Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: ChoiceChip(
                          key: Key('folder-chip-${f.name}'),
                          label: Text(f.label),
                          selected: f == folder && !showDrafts,
                          onSelected: (_) => _select(f, accts),
                        ),
                      ),
                      // Local drafts (not an IMAP folder), next to Sent.
                      if (f == MailFolder.sent)
                        Padding(
                          padding: const EdgeInsets.only(right: 8),
                          child: ChoiceChip(
                            key: const Key('folder-chip-drafts'),
                            // No count: chip widths stay put, so no other chip ends up
                            // half under the row's arrow (and the label never jumps).
                            label: const Text('Drafts'),
                            tooltip: 'Drafts saved on this device',
                            selected: showDrafts,
                            onSelected: (_) => ref.read(draftsChipProvider.notifier).set(true),
                          ),
                        ),
                    ],
                  ],
                ),
              ),
              SizedBox(
                height: 3,
                child: sync.running
                    ? SyncProgressBar(progress: sync.progress)
                    : roleSync.running
                    ? const LinearProgressIndicator(key: Key('inbox-sync-progress'), minHeight: 3)
                    : null,
              ),
            ],
          ),
        ),
        actions: [
          IconButton(
            key: const Key('inbox-search'),
            tooltip: 'Search mail',
            icon: const Icon(Icons.search),
            onPressed: () => context.go('/search'),
          ),
          const LiveStatusIndicator(),
          if (showDrafts)
            IconButton(
              key: const Key('drafts-reload'),
              tooltip: 'Reload drafts',
              icon: const Icon(Icons.refresh),
              onPressed: () => ref.read(draftsRevisionProvider.notifier).bump(),
            )
          else
            IconButton(
              key: const Key('inbox-sync'),
              tooltip: busy
                  ? 'Fetching mail…'
                  : roleNeedsOwnSync(folder.role)
                  ? 'Fetch ${folder.label}'
                  : 'Fetch new mail',
              icon: const Icon(Icons.refresh),
              onPressed: busy ? null : _sync,
            ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        heroTag: 'compose-fab',
        onPressed: () => context.go('/compose'),
        icon: const Icon(Icons.edit),
        label: const Text('Compose'),
      ),
      body: accounts.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => _ErrorView(error: e),
        data: (accts) {
          if (accts.isEmpty) return const _NoAccounts();
          final reminder = ref.watch(backupStatusProvider).value;
          final content = threads.when(
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, _) => _ErrorView(error: e),
            data: (all) {
              final list = [
                for (final t in all)
                  if (!_hidden.contains(t.id)) t,
              ];
              if (list.isEmpty) {
                final empty = roleNeedsOwnSync(folder.role)
                    ? _EmptyFolder(folder: folder, state: roleSync, accounts: accts, onSync: _sync)
                    : _EmptyInbox(
                        folder: folder,
                        syncing: sync.running,
                        progress: sync.progress,
                        account: whose(sync.progress),
                        live: ref.watch(liveUpdatesProvider),
                        lastError: sync.last?.errors.firstOrNull?.error,
                      );
                return _Refreshable(onRefresh: _sync, child: empty);
              }
              final byId = {for (final a in accts) a.id: a};
              final own = ownAddressesOf(accts);
              final (right, left) = swipeActionsFor(folder);
              return RefreshIndicator(
                key: const Key('inbox-refresh'),
                onRefresh: _sync,
                child: ListView.separated(
                  key: const Key('inbox-list'),
                  physics: const AlwaysScrollableScrollPhysics(),
                  // Clear the Compose FAB and the system inset (L12).
                  padding: EdgeInsets.only(bottom: 88 + MediaQuery.paddingOf(context).bottom),
                  itemCount: list.length,
                  separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
                  itemBuilder: (context, i) {
                    final t = list[i];
                    final tile = ThreadTile(
                      thread: t,
                      account: byId[t.accountId],
                      own: own,
                      contacts: contacts,
                      showAccount: accts.length > 1,
                      selected: t.id == widget.selectedThreadId,
                      onTap: () => context.go('/inbox/t/${t.id}'),
                      actions: [?right, left, if (!t.unread) ThreadAction.markUnread],
                      onAction: (a) => _rowAction(t, a),
                    );
                    return Dismissible(
                      key: ValueKey('thread-dismiss-${t.id}'),
                      direction: right == null
                          ? DismissDirection.endToStart
                          : DismissDirection.horizontal,
                      background: right == null
                          ? const SizedBox.shrink()
                          : SwipeBackground(action: right, start: true),
                      secondaryBackground: SwipeBackground(action: left, start: false),
                      confirmDismiss: (d) => _confirmSwipe(
                        t,
                        d == DismissDirection.startToEnd && right != null ? right : left,
                      ),
                      onDismissed: (_) => _dismissed(t),
                      child: tile,
                    );
                  },
                ),
              );
            },
          );
          final shown = showDrafts ? const DraftsList() : content;
          if (reminder?.reminder == null || reminder?.available != true) return shown;
          return Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
                child: BackupReminderBanner(status: reminder!),
              ),
              Expanded(child: shown),
            ],
          );
        },
      ),
    );
  }
}

/// What the inbox app bar says about live updates: the overall [LiveStatus], a short
/// [label] for screen readers and the [details] its tooltip shows. [emailOf] names the
/// accounts (id → address).
({LiveStatus status, String label, String details}) describeLiveStatus(
  LiveUpdatesState live,
  Map<String, String> emailOf,
) {
  final status = live.status;
  String name(String id) => emailOf[id] ?? id;
  List<String> where(LiveWatchPhase p) => [
    for (final e in live.accounts.entries)
      if (e.value.phase == p) e.key,
  ];
  String why(String id) {
    final error = live.accounts[id]!.error ?? 'unknown error';
    return isIdleUnsupportedError(error) ? 'the server does not support IMAP IDLE' : error;
  }

  final stopped = where(LiveWatchPhase.stopped);
  final stoppedNote = stopped.isEmpty
      ? ''
      : ' Stopped for ${[for (final id in stopped) '${name(id)} (${why(id)})'].join(', ')}; '
            'Fetch new mail tries again.';
  final details = switch (status) {
    LiveStatus.off when !live.enabled =>
      'Live updates are off: new mail shows up when you fetch. Turn them on in Settings '
          '(Appearance & sync).',
    LiveStatus.off =>
      'Live updates stopped for ${[for (final id in stopped) '${name(id)} (${why(id)})'].join(', ')}. '
          'Fetch new mail to try again.',
    LiveStatus.connecting =>
      'Live updates: connecting to ${where(LiveWatchPhase.connecting).map(name).join(', ')}…',
    LiveStatus.reconnecting =>
      'Live updates reconnecting: ${[
        for (final id in where(LiveWatchPhase.waiting))
          '${name(id)} in ${live.accounts[id]!.retryIn?.inSeconds ?? 0} s (${why(id)})',
      ].join('; ')}. Fetch new mail to retry now.',
    LiveStatus.on => live.accounts.isEmpty
        ? 'Live updates are on; they start with your first account.'
        : 'Live updates on: new mail appears without fetching (IMAP IDLE).$stoppedNote',
  };
  final label = switch (status) {
    LiveStatus.on => 'Live updates on',
    LiveStatus.connecting => 'Live updates connecting',
    LiveStatus.reconnecting => 'Live updates reconnecting',
    LiveStatus.off => 'Live updates off',
  };
  return (status: status, label: label, details: details);
}

/// Live updates in the inbox app bar (`Key('live-status')`): on, connecting, reconnecting
/// or off as an icon, the details in its tooltip (tap, long-press or hover) and a label
/// for screen readers. Not a button: Settings (Appearance & sync) turns live updates on
/// and off, and "Fetch new mail" retries a watcher that waits to reconnect.
class LiveStatusIndicator extends ConsumerWidget {
  const LiveStatusIndicator({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final live = ref.watch(liveWatchProvider);
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final view = describeLiveStatus(live, {for (final a in accounts) a.id: a.email});
    final scheme = Theme.of(context).colorScheme;
    final (IconData icon, Color color) = switch (view.status) {
      LiveStatus.on => (Icons.flash_on, scheme.primary),
      LiveStatus.connecting => (Icons.sync, scheme.onSurfaceVariant),
      LiveStatus.reconnecting => (Icons.sync_problem, LockColors.ofContext(context).plaintext),
      LiveStatus.off => (Icons.flash_off, scheme.onSurfaceVariant),
    };
    return Semantics(
      key: const Key('live-status'),
      container: true,
      label: view.label,
      child: Tooltip(
        message: view.details,
        triggerMode: TooltipTriggerMode.tap,
        showDuration: const Duration(seconds: 6),
        child: SizedBox(
          width: 40,
          height: 48,
          child: Icon(icon, key: ValueKey('live-status-${view.status.name}'), color: color),
        ),
      ),
    );
  }
}

/// A horizontally scrolling row (the folder chips) with an arrow on each edge
/// that has more to scroll, so a clipped "Arch…" reads as "more folders" and
/// is one tap away (lead review L11, Android S3-10). Every child stays mounted.
class FadingChipRow extends StatefulWidget {
  const FadingChipRow({super.key, required this.children});

  final List<Widget> children;

  @override
  State<FadingChipRow> createState() => _FadingChipRowState();
}

class _FadingChipRowState extends State<FadingChipRow> {
  final _ctl = ScrollController();
  bool _moreLeft = false;
  bool _moreRight = false;

  @override
  void initState() {
    super.initState();
    _ctl.addListener(_update);
    WidgetsBinding.instance.addPostFrameCallback((_) => _update());
  }

  @override
  void dispose() {
    _ctl.dispose();
    super.dispose();
  }

  void _update() {
    if (!mounted || !_ctl.hasClients) return;
    final p = _ctl.position;
    final left = p.pixels > p.minScrollExtent + 1;
    final right = p.pixels < p.maxScrollExtent - 1;
    if (left != _moreLeft || right != _moreRight) {
      setState(() {
        _moreLeft = left;
        _moreRight = right;
      });
    }
  }

  void _page(double by) {
    if (!_ctl.hasClients) return;
    final p = _ctl.position;
    _ctl.animateTo(
      (p.pixels + by).clamp(p.minScrollExtent, p.maxScrollExtent),
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    // The AppBar's own surface, so the arrow sits on an opaque edge (a fade
    // would lower the contrast of the clipped chip's text).
    final bg = Theme.of(context).appBarTheme.backgroundColor ?? Theme.of(context).colorScheme.surface;
    Widget arrow(bool right) => DecoratedBox(
      decoration: BoxDecoration(
        color: bg,
        boxShadow: [
          BoxShadow(
            color: Theme.of(context).colorScheme.shadow.withValues(alpha: 0.18),
            blurRadius: 6,
            offset: Offset(right ? -2 : 2, 0),
          ),
        ],
      ),
      child: IconButton(
        key: Key(right ? 'folder-chips-more-right' : 'folder-chips-more-left'),
        tooltip: right ? 'More folders' : 'Previous folders',
        icon: Icon(right ? Icons.chevron_right : Icons.chevron_left),
        onPressed: () => _page(right ? 160 : -160),
      ),
    );
    return NotificationListener<ScrollMetricsNotification>(
      onNotification: (_) {
        _update();
        return false;
      },
      // The arrows sit beside the viewport, never over a chip, so a chip that
      // was scrolled into view is always tappable.
      // Keyed: the left arrow appearing must not shift the scroll view to a new
      // element (that would recreate it and jump the row back to the start).
      child: Row(
        children: [
          if (_moreLeft) KeyedSubtree(key: const ValueKey('chips-left'), child: arrow(false)),
          Expanded(
            key: const ValueKey('chips-viewport'),
            child: SingleChildScrollView(
              key: const Key('folder-chips'),
              controller: _ctl,
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 12),
              // A Row (not a lazy ListView): every chip stays in the tree, so
              // scrolling one into view never unmounts another.
              child: Row(children: widget.children),
            ),
          ),
          if (_moreRight) KeyedSubtree(key: const ValueKey('chips-right'), child: arrow(true)),
        ],
      ),
    );
  }
}

/// Tile key of a conversation by its normalised subject (`Re:`/`Fwd:` stripped,
/// lower case): stable across reference-threading ids, for tests and tours.
ValueKey<String> threadSubjectKey(String subject) =>
    ValueKey('thread-subject-${normalizeSubject(subject)}');

class ThreadTile extends StatelessWidget {
  const ThreadTile({
    super.key,
    required this.thread,
    required this.onTap,
    this.account,
    this.own = const {},
    this.contacts = const [],
    this.showAccount = false,
    this.selected = false,
    this.actions = const [],
    this.onAction,
  });

  final MailThread thread;
  final Account? account;

  /// Our own addresses: a newest message from one of them is an outgoing row.
  final Set<String> own;

  /// Known contacts: a key the user verified for another address signing this mail (R4).
  final List<ContactKey> contacts;
  final bool showAccount;
  final bool selected;
  final VoidCallback onTap;

  /// Row actions (the swipe actions, Mark unread), offered on long press and
  /// to screen readers as custom actions.
  final List<ThreadAction> actions;
  final void Function(ThreadAction)? onAction;

  Future<void> _menu(BuildContext context) async {
    final box = context.findRenderObject() as RenderBox?;
    final overlay = Overlay.of(context).context.findRenderObject() as RenderBox?;
    if (box == null || overlay == null || onAction == null || actions.isEmpty) return;
    final at = box.localToGlobal(box.size.center(Offset.zero), ancestor: overlay);
    final picked = await showMenu<ThreadAction>(
      context: context,
      position: RelativeRect.fromRect(at & const Size(1, 1), Offset.zero & overlay.size),
      items: [
        for (final a in actions)
          PopupMenuItem(
            key: ValueKey('thread-row-action-${a.name}'),
            value: a,
            child: ListTile(leading: Icon(a.icon), title: Text(a.label)),
          ),
      ],
    );
    if (picked != null) onAction?.call(picked);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final latest = thread.latest;
    final weight = thread.unread ? FontWeight.w700 : FontWeight.w400;
    final from = latest.from;
    final outgoing = (isOwnMessage(latest, own) || (own.isEmpty && latest.isSent)) &&
        latest.to.isNotEmpty;
    final sender = outgoing ? 'To ${latest.to.map((c) => c.display).join(', ')}' : from.display;
    // Outgoing rows show the recipient, not our own initial.
    final avatarOf = outgoing ? latest.to.first : from;
    // N1: the provider's "..." of mail nobody here could decrypt reads "Encrypted message",
    // secondary and italic (the lock badge says why); the row key keeps the raw subject.
    final title = conversationTitle(thread);
    // R4: signed with a key that is not the sender's. The badge keeps its encryption
    // meaning (a signed-only message is "Not encrypted" once its signature does not vouch
    // for the sender) and the amber glyph beside it stands for the signature, as the
    // thread view's chip does.
    final mismatch = signerMismatch(latest, contacts: contacts, own: own);
    final badgeState = mismatch != null && thread.state == EncryptionState.signed
        ? EncryptionState.plaintext
        : thread.state;

    final tile = ListTile(
      key: ValueKey('thread-tile-${thread.id}'),
      onLongPress: actions.isEmpty || onAction == null ? null : () => _menu(context),
      selected: selected,
      selectedTileColor: theme.colorScheme.secondaryContainer.withValues(
        alpha: 0.5,
      ),
      onTap: onTap,
      leading: CircleAvatar(
        backgroundColor: avatarColorFor(avatarOf.email, theme.colorScheme),
        foregroundColor: Colors.white,
        child: outgoing
            ? Stack(
                alignment: Alignment.center,
                children: [
                  Text(avatarOf.initial),
                  const Positioned(
                    right: 0,
                    bottom: 0,
                    child: Icon(Icons.north_east, size: 12, color: Colors.white),
                  ),
                ],
              )
            : Text(avatarOf.initial),
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(
              sender,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleSmall?.copyWith(fontWeight: weight),
            ),
          ),
          const SizedBox(width: 8),
          // Unread: bold row and a primary-coloured time; the key and the label
          // let tests and screen readers tell without reading styles.
          Semantics(
            key: thread.unread ? const ValueKey('thread-unread') : null,
            label: thread.unread ? 'Unread' : null,
            child: Text(
              relativeTime(latest.date),
              style: theme.textTheme.labelSmall?.copyWith(
                color: thread.unread
                    ? theme.colorScheme.primary
                    : theme.colorScheme.onSurfaceVariant,
                fontWeight: weight,
              ),
            ),
          ),
        ],
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title.text,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: weight,
              fontStyle: title.placeholder ? FontStyle.italic : null,
              color: title.placeholder ? theme.colorScheme.onSurfaceVariant : null,
            ),
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              LockBadge(state: badgeState),
              if (mismatch != null) ...[
                const SizedBox(width: 4),
                SignerMismatchGlyph(
                  key: ValueKey('thread-signer-mismatch-${thread.id}'),
                  mismatch: mismatch,
                ),
              ],
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  latest.snippet,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              if (showAccount && account != null) ...[
                const SizedBox(width: 6),
                _AccountDot(account: account!),
              ],
            ],
          ),
        ],
      ),
      isThreeLine: true,
    );
    return KeyedSubtree(
      key: threadSubjectKey(thread.subject),
      child: Semantics(
        customSemanticsActions: onAction == null
            ? null
            : {
                for (final a in actions)
                  CustomSemanticsAction(label: a.label): () => onAction!(a),
              },
        child: tile,
      ),
    );
  }
}

/// What a row reveals while it is swiped: the action's icon and label on the
/// side the swipe started from.
class SwipeBackground extends StatelessWidget {
  const SwipeBackground({super.key, required this.action, required this.start});

  final ThreadAction action;

  /// Swiping from the start edge (right swipe in LTR).
  final bool start;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final destructive = action.confirms;
    final bg = destructive ? scheme.errorContainer : scheme.secondaryContainer;
    final fg = destructive ? scheme.onErrorContainer : scheme.onSecondaryContainer;
    return ColoredBox(
      key: ValueKey('swipe-${action.name}'),
      color: bg,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: Row(
          mainAxisAlignment: start ? MainAxisAlignment.start : MainAxisAlignment.end,
          children: [
            Icon(action.icon, color: fg),
            const SizedBox(width: 8),
            Text(action.label, style: TextStyle(color: fg, fontWeight: FontWeight.w600)),
          ],
        ),
      ),
    );
  }
}

/// Pull-to-refresh around a non-scrolling child (the empty states): the child
/// keeps its centred layout and the gesture still works.
class _Refreshable extends StatelessWidget {
  const _Refreshable({required this.onRefresh, required this.child});

  final Future<void> Function() onRefresh;
  final Widget child;

  @override
  Widget build(BuildContext context) => RefreshIndicator(
    onRefresh: onRefresh,
    child: LayoutBuilder(
      builder: (context, box) => SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: box.maxHeight, minWidth: box.maxWidth),
          child: child,
        ),
      ),
    ),
  );
}

/// Spam / Trash / Archive with no conversation: says whether that is what the
/// server holds or whether the folder was never fetched (or failed to be).
class _EmptyFolder extends ConsumerWidget {
  const _EmptyFolder({
    required this.folder,
    required this.state,
    required this.accounts,
    required this.onSync,
  });

  final MailFolder folder;
  final RoleSyncState state;
  final List<Account> accounts;
  final Future<void> Function() onSync;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final role = folder.role!;
    final synced = state.syncedAll(accounts);
    final names = <String>{
      for (final a in accounts)
        for (final r in ref.watch(folderRolesProvider(a.id)).value ?? const <FolderRoleInfo>[])
          if (r.role == role) r.folder,
    };
    final (Key key, IconData icon, String title, String body) = state.running
        ? (
            const Key('folder-empty-syncing'),
            Icons.sync,
            'Checking ${folder.label} on the server…',
            'Sealbox fetches this folder the first time you open it.',
          )
        : synced
        ? (
            const Key('folder-empty-synced'),
            Icons.inbox_outlined,
            'Nothing in ${folder.label} on the server.',
            'Checked ${names.isEmpty ? 'just now' : '${names.join(', ')} '
                    '${state.lastAt == null ? 'just now' : 'at ${_hm(state.lastAt!)}'}'}.',
          )
        : (
            const Key('folder-empty-not-synced'),
            Icons.cloud_off_outlined,
            '${folder.label} is not synced yet.',
            state.lastError != null
                ? 'The last attempt failed: ${state.lastError}'
                : 'Its messages appear here once Sealbox has fetched the folder from the server.',
          );
    return Center(
      key: const Key('inbox-empty'),
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          key: key,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (state.running)
              const SizedBox(width: 40, height: 40, child: CircularProgressIndicator())
            else
              Icon(icon, size: 48, color: theme.colorScheme.outline),
            const SizedBox(height: 12),
            Text(title, style: theme.textTheme.titleMedium, textAlign: TextAlign.center),
            const SizedBox(height: 6),
            Text(
              body,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall?.copyWith(
                color: state.lastError != null && !synced && !state.running
                    ? theme.colorScheme.error
                    : theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (!state.running) ...[
              const SizedBox(height: 16),
              OutlinedButton.icon(
                key: const Key('folder-sync-now'),
                onPressed: onSync,
                icon: const Icon(Icons.refresh),
                label: Text(synced ? 'Check again' : 'Sync now'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  static String _hm(DateTime d) {
    final l = d.toLocal();
    return '${l.hour.toString().padLeft(2, '0')}:${l.minute.toString().padLeft(2, '0')}';
  }
}

class _AccountDot extends StatelessWidget {
  const _AccountDot({required this.account});

  final Account account;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: account.email,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
        decoration: BoxDecoration(
          border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Text(
          account.providerName,
          style: Theme.of(context).textTheme.labelSmall,
        ),
      ),
    );
  }
}

/// The empty inbox's second line: short enough for one line at the narrowest pane (review P8).
const _emptyInboxSecond = 'Mail you send is encrypted; replies can be too.';

class _EmptyInbox extends StatelessWidget {
  const _EmptyInbox({
    required this.folder,
    required this.syncing,
    required this.live,
    this.progress,
    this.account,
    this.lastError,
  });

  final MailFolder folder;
  final bool syncing;

  /// While [syncing]: the batch stored last (the title counts it, `syncProgressLabel`).
  final SyncProgress? progress;

  /// The account [progress] is about, when there are several.
  final String? account;

  /// Live updates on: new mail arrives by itself, so the copy must not say "after a fetch".
  final bool live;
  final String? lastError;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      key: const Key('inbox-empty'),
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.inbox_outlined, size: 48, color: theme.colorScheme.outline),
            const SizedBox(height: 12),
            Text(
              syncing
                  ? syncProgressLabel(progress, account: account)
                  : folder == MailFolder.inbox
                  ? 'Nothing here yet.'
                  : 'Nothing in ${folder.label} yet.',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            Text(
              lastError != null
                  ? 'Last fetch failed: $lastError'
                  : switch (folder) {
                      // One line per sentence (review P8): each fits on its own from a
                      // 360 dp phone (296 px here) up, so no word is ever left alone on the
                      // last line, whatever width the pane or phone has.
                      MailFolder.inbox || MailFolder.all =>
                        live
                            ? 'New messages appear here as they arrive.\n$_emptyInboxSecond'
                            : 'New messages show up here after a fetch.\n$_emptyInboxSecond',
                      MailFolder.sent => 'Copies of what you send from Sealbox appear here.',
                      _ => 'Pull down or press fetch to check ${folder.label} on the server.',
                    },
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall?.copyWith(
                color: lastError != null ? theme.colorScheme.error : theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _NoAccounts extends StatelessWidget {
  const _NoAccounts();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const SealboxLogo(size: 56),
            const SizedBox(height: 16),
            Text(
              'Welcome to Sealbox',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            const Text(
              'Private email, without changing your email address. Add the '
              'mailbox you already have; every message you send from here is '
              'encrypted, and the status is always shown.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              key: const Key('inbox-add-account'),
              onPressed: () => context.push('/onboarding'),
              icon: const Icon(Icons.add),
              label: const Text('Add an account'),
            ),
          ],
        ),
      ),
    );
  }
}

class _ErrorView extends StatelessWidget {
  const _ErrorView({required this.error});

  final Object error;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(24),
      child: Text('Could not load: $error'),
    ),
  );
}

/// Stable per-address avatar colour (inbox rows and thread cards agree).
Color avatarColorFor(String seed, ColorScheme scheme) {
  const palette = [
    Color(0xFF0E7C6B),
    Color(0xFF3F51B5),
    Color(0xFF8E24AA),
    Color(0xFFD84315),
    Color(0xFF00838F),
    Color(0xFF6D4C41),
  ];
  final h = seed.toLowerCase().codeUnits.fold<int>(7, (a, c) => (a * 31 + c) & 0x7fffffff);
  return palette[h % palette.length];
}

const _weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const _months = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

String _two(int n) => n.toString().padLeft(2, '0');

/// `14:05` today, `Tue` within the week, `27 Oct` otherwise.
String relativeTime(DateTime date, {DateTime? now}) {
  final n = now ?? DateTime.now();
  final d = date.toLocal();
  final sameDay = d.year == n.year && d.month == n.month && d.day == n.day;
  if (sameDay) return '${_two(d.hour)}:${_two(d.minute)}';
  if (n.difference(d).inDays < 7) return _weekdays[d.weekday - 1];
  return '${d.day} ${_months[d.month - 1]}';
}

/// `27 Oct 2026, 14:05`.
String fullTime(DateTime date) {
  final d = date.toLocal();
  return '${d.day} ${_months[d.month - 1]} ${d.year}, ${_two(d.hour)}:${_two(d.minute)}';
}
