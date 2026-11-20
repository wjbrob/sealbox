import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';

/// The role a server folder plays on an account: by the engine's role table
/// (`folderRoles`, learned from `LIST`), else by the usual names.
FolderRole? roleOfFolder(String folder, List<FolderRoleInfo> roles) {
  final f = folder.trim().toLowerCase();
  if (f == 'inbox') return FolderRole.inbox;
  for (final r in roles) {
    if (r.folder.trim().toLowerCase() == f) return r.role;
  }
  for (final chip in const [
    MailFolder.sent,
    MailFolder.spam,
    MailFolder.trash,
    MailFolder.archive,
  ]) {
    if (chip.matches(folder)) return chip.role;
  }
  return null;
}

/// Lower-cased addresses of the profile's own accounts.
Set<String> ownAddressesOf(Iterable<Account> accounts) => {
  for (final a in accounts) a.email.trim().toLowerCase(),
};

/// Written by one of our own accounts (a Sent copy, a note to self).
bool isOwnMessage(Message m, Set<String> own) => own.contains(m.from.email.trim().toLowerCase());

/// What the thread menu and the list's swipe actions can do.
enum ThreadAction {
  archive,
  moveToInbox,
  markSpam,
  notSpam,
  delete,
  deleteForever,
  markUnread;

  String get label => switch (this) {
    ThreadAction.archive => 'Archive',
    ThreadAction.moveToInbox => 'Move to Inbox',
    ThreadAction.markSpam => 'Mark as spam',
    ThreadAction.notSpam => 'Not spam',
    ThreadAction.delete => 'Delete',
    ThreadAction.deleteForever => 'Delete forever',
    ThreadAction.markUnread => 'Mark unread',
  };

  IconData get icon => switch (this) {
    ThreadAction.archive => Icons.archive_outlined,
    ThreadAction.moveToInbox => Icons.move_to_inbox_outlined,
    ThreadAction.markSpam => Icons.report_outlined,
    ThreadAction.notSpam => Icons.report_off_outlined,
    ThreadAction.delete => Icons.delete_outline,
    ThreadAction.deleteForever => Icons.delete_forever_outlined,
    ThreadAction.markUnread => Icons.mark_email_unread_outlined,
  };

  /// The widget key of the action in the thread menu (`thread-archive`, …).
  Key get menuKey => Key(switch (this) {
    ThreadAction.archive => 'thread-archive',
    ThreadAction.moveToInbox => 'thread-move-inbox',
    ThreadAction.markSpam => 'thread-spam',
    ThreadAction.notSpam => 'thread-not-spam',
    ThreadAction.delete => 'thread-delete-menu',
    ThreadAction.deleteForever => 'thread-delete-forever',
    ThreadAction.markUnread => 'thread-mark-unread',
  });

  /// Delete has no undo here, so it asks first; everything else just runs.
  bool get confirms => this == ThreadAction.delete || this == ThreadAction.deleteForever;

  /// Leaves the current list (the conversation's rows there go away).
  bool get leavesList => this != ThreadAction.markUnread;
}

/// Which messages of a conversation each action applies to.
///
/// [messages] are the ones the user sees: a list row's members (its folder's,
/// plus the Sent replies on Inbox rows) or the whole conversation in the thread
/// view.
class ThreadActionPlan {
  ThreadActionPlan({required this.messages, required this.roles, required this.own});

  final List<Message> messages;
  final List<FolderRoleInfo> roles;
  final Set<String> own;

  FolderRole? roleOf(Message m) => roleOfFolder(m.folder, roles);

  bool _own(Message m) => isOwnMessage(m, own);

  List<Message> get _received => [
    for (final m in messages)
      if (!_own(m)) m,
  ];

  /// Out of Spam, Trash or Archive (own messages go back to Sent).
  static const _restorable = {
    FolderRole.junk,
    FolderRole.trash,
    FolderRole.archive,
    FolderRole.all,
  };

  List<Message> targets(ThreadAction a) => switch (a) {
    ThreadAction.archive => [
      for (final m in messages)
        if (roleOf(m) == FolderRole.inbox) m,
    ],
    ThreadAction.moveToInbox => [
      for (final m in messages)
        if (_restorable.contains(roleOf(m))) m,
    ],
    ThreadAction.markSpam => [
      for (final m in _received)
        if (roleOf(m) != FolderRole.junk && roleOf(m) != FolderRole.trash) m,
    ],
    ThreadAction.notSpam => [
      for (final m in messages)
        if (roleOf(m) == FolderRole.junk) m,
    ],
    ThreadAction.delete => [
      for (final m in messages)
        if (roleOf(m) != FolderRole.trash) m,
    ],
    ThreadAction.deleteForever => [
      for (final m in messages)
        if (roleOf(m) == FolderRole.trash) m,
    ],
    ThreadAction.markUnread => [
      if (_received.isNotEmpty) _received.last else if (messages.isNotEmpty) messages.last,
    ],
  };

  bool can(ThreadAction a) => targets(a).isNotEmpty;

  /// The menu entries, in menu order. Delete and Delete forever never show
  /// together: a conversation partly in Trash offers Delete (the rest goes to
  /// Trash); one entirely in Trash offers Delete forever.
  List<ThreadAction> get available => [
    for (final a in const [
      ThreadAction.archive,
      ThreadAction.moveToInbox,
      ThreadAction.markSpam,
      ThreadAction.notSpam,
      ThreadAction.markUnread,
    ])
      if (can(a)) a,
    if (can(ThreadAction.delete))
      ThreadAction.delete
    else if (can(ThreadAction.deleteForever))
      ThreadAction.deleteForever,
  ];

  /// The conversation sits in the junk folder (Why is this spam? / Not spam).
  bool get inSpam => messages.any((m) => roleOf(m) == FolderRole.junk);

  /// The message a spam explanation is about: the newest received one.
  Message? get spamSubject => _received.isEmpty ? null : _received.last;
}

/// The plan for [messages] of [accountId] (loads the account's role table).
Future<ThreadActionPlan> planFor(WidgetRef ref, String accountId, List<Message> messages) async {
  List<FolderRoleInfo> roles;
  try {
    roles = await ref.read(folderRolesProvider(accountId).future);
  } catch (_) {
    roles = const [];
  }
  final List<Account> accounts =
      ref.read(accountsProvider).value ?? await ref.read(accountsProvider.future);
  return ThreadActionPlan(messages: messages, roles: roles, own: ownAddressesOf(accounts));
}

/// "Delete these 2 messages?" — `true` when confirmed.
Future<bool> confirmThreadDelete(
  BuildContext context, {
  required int count,
  required bool forever,
}) async {
  final what = count == 1 ? 'this message' : 'these $count messages';
  final ok = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      key: const Key('thread-delete-dialog'),
      title: Text(forever ? 'Delete $what forever?' : 'Delete $what?'),
      content: Text(
        forever
            ? 'They are removed from the server (expunged) and from this device. '
                  'This cannot be undone.'
            : 'They are moved to the Trash folder on the server. Empty the Trash '
                  'there, or delete them again from Trash, to remove them for good.',
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(
          key: const Key('thread-delete-confirm'),
          onPressed: () => Navigator.pop(context, true),
          child: Text(forever ? 'Delete forever' : 'Delete'),
        ),
      ],
    ),
  );
  return ok == true;
}

/// Runs [action] on the messages [plan] selects and reports what happened in a
/// snackbar that names the destination folder. Returns true when every message
/// was handled. Never throws.
Future<bool> runThreadAction(
  WidgetRef ref,
  ScaffoldMessengerState? messenger,
  String accountId,
  ThreadActionPlan plan,
  ThreadAction action,
) async {
  final core = ref.read(coreApiProvider);
  final targets = plan.targets(action);
  if (targets.isEmpty) return true;
  final folders = <String>{};
  final restoredTo = <FolderRole>{};
  var failed = 0;
  String? error;
  var spamMoved = false;
  for (final m in targets) {
    try {
      switch (action) {
        case ThreadAction.archive:
        case ThreadAction.delete:
        case ThreadAction.moveToInbox:
          final dest = switch (action) {
            ThreadAction.archive => FolderRole.archive,
            ThreadAction.delete => FolderRole.trash,
            _ => isOwnMessage(m, plan.own) ? FolderRole.sent : FolderRole.inbox,
          };
          final r = await core.moveMessage(m.id, dest);
          folders.add(r.toFolder);
          if (r.moved) {
            restoredTo.add(dest);
            ref.read(folderSyncProvider.notifier).markStale(dest, m.accountId);
          }
        case ThreadAction.markSpam:
        case ThreadAction.notSpam:
          final r = await core.spamLearn(m.id, isSpam: action == ThreadAction.markSpam);
          if (r.movedTo != null) {
            folders.add(r.movedTo!);
            spamMoved = true;
          }
        case ThreadAction.deleteForever:
          await core.deleteMessage(m.id);
        case ThreadAction.markUnread:
          await core.markSeen(m.id, seen: false);
      }
    } catch (e) {
      failed++;
      error ??= friendlyError(e);
    }
  }
  ref.invalidate(threadsProvider);
  ref.invalidate(threadProvider);
  ref.invalidate(spamStatusProvider);
  // The engine drops a moved message locally until its new folder is fetched;
  // INBOX and Sent come back with the next fetch, so run it now.
  if (restoredTo.contains(FolderRole.inbox) || restoredTo.contains(FolderRole.sent)) {
    ref.read(syncControllerProvider.notifier).syncNow();
  }
  final n = targets.length;
  final ok = n - failed;
  final count = n == 1 ? '' : (failed == 0 ? '$n messages ' : '$ok of $n messages ');
  final where = folders.isEmpty ? '' : folders.join(', ');
  final String text;
  if (ok == 0) {
    text = 'Could not ${action.label.toLowerCase()}: $error';
  } else {
    final done = switch (action) {
      ThreadAction.archive => 'Archived ${count}to $where',
      ThreadAction.delete => 'Moved ${count}to $where',
      ThreadAction.moveToInbox => 'Moved ${count}to $where',
      ThreadAction.markSpam =>
        spamMoved ? 'Marked ${count}as spam · moved to $where' : 'Marked ${count}as spam',
      ThreadAction.notSpam =>
        spamMoved ? 'Marked ${count}as not spam · moved to $where' : 'Marked ${count}as not spam',
      ThreadAction.deleteForever => 'Deleted ${count}forever',
      ThreadAction.markUnread => 'Marked as unread',
    };
    text = failed == 0 ? done : '$done · $failed failed: $error';
  }
  // The newest action's outcome replaces the last one (no queue of stale news).
  messenger?.removeCurrentSnackBar();
  messenger?.showSnackBar(
    SnackBar(
      key: const Key('thread-action-snackbar'),
      content: Text(text),
      duration: const Duration(seconds: 4),
    ),
  );
  return failed == 0;
}
