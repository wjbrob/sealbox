import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:path_provider/path_provider.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../core/signer_mismatch.dart';
import '../../core/threading.dart' show conversationTitle;
import '../../widgets/lock_badge.dart';
import '../identity/identity_widgets.dart';
import '../spam/spam_explain_sheet.dart';
import 'home_shell.dart';
import 'inbox_list_pane.dart' show avatarColorFor, fullTime;
import 'message_body.dart';
import 'thread_actions.dart';

class ThreadScreen extends ConsumerStatefulWidget {
  const ThreadScreen({super.key, required this.threadId});

  final String threadId;

  @override
  ConsumerState<ThreadScreen> createState() => _ThreadScreenState();
}

class _ThreadScreenState extends ConsumerState<ThreadScreen> {
  /// Every message this view has shown: each is marked seen at most once, when
  /// it first appears unread. One the user marks unread here is left alone.
  final _shown = <String>{};

  /// Opening a conversation marks its unread messages `\Seen` on the server
  /// (best effort, never blocks the view).
  void _markSeen(MailThread t) {
    final unread = [
      for (final m in t.messages)
        if (m.unread && !_shown.contains(m.id)) m.id,
    ];
    _shown.addAll(t.messages.map((m) => m.id));
    if (unread.isEmpty) return;
    final core = ref.read(coreApiProvider);
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      for (final id in unread) {
        try {
          await core.markSeen(id);
        } catch (e) {
          debugPrint('[sealbox] mark seen $id failed: $e');
        }
      }
      if (mounted) {
        ref.invalidate(threadsProvider);
        ref.invalidate(threadProvider(widget.threadId));
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final thread = ref.watch(threadProvider(widget.threadId));
    return thread.when(
      loading: () => const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      ),
      error: (e, _) => Scaffold(
        appBar: AppBar(),
        body: Center(child: Text('Could not load thread: $e')),
      ),
      data: (t) {
        if (t == null) {
          return Scaffold(
            appBar: AppBar(),
            body: const Center(child: Text('This conversation no longer exists.')),
          );
        }
        _markSeen(t);
        return _ThreadView(thread: t);
      },
    );
  }
}

class _ThreadView extends ConsumerWidget {
  const _ThreadView({required this.thread});

  final MailThread thread;

  ThreadActionPlan _plan(WidgetRef ref) => ThreadActionPlan(
    messages: thread.messages,
    roles: ref.watch(folderRolesProvider(thread.accountId)).value ?? const [],
    own: ownAddressesOf(ref.watch(accountsProvider).value ?? const <Account>[]),
  );

  /// Runs [action] on the conversation; every action but "Mark unread" empties
  /// this view's folder of it, so the list comes back (Mark unread does too:
  /// staying would mark it read again).
  Future<void> _act(BuildContext context, WidgetRef ref, ThreadAction action) async {
    final plan = await planFor(ref, thread.accountId, thread.messages);
    if (!context.mounted) return;
    final n = plan.targets(action).length;
    if (n == 0) return;
    if (action.confirms &&
        !await confirmThreadDelete(context, count: n, forever: action == ThreadAction.deleteForever)) {
      return;
    }
    if (!context.mounted) return;
    final messenger = ScaffoldMessenger.of(context);
    final router = GoRouter.of(context);
    await runThreadAction(ref, messenger, thread.accountId, plan, action);
    router.go('/inbox');
  }

  void _explain(BuildContext context, ThreadActionPlan plan) {
    final m = plan.spamSubject;
    if (m == null) return;
    showSpamExplanation(context, messageId: m.id, accountId: thread.accountId);
  }

  /// Short title: the folder the conversation is in (the subject heads the
  /// first card, two lines, review D6/B1).
  String _title(ThreadActionPlan plan) {
    final newest = thread.messages.lastWhere(
      (m) => !isOwnMessage(m, plan.own),
      orElse: () => thread.latest,
    );
    final role = plan.roleOf(newest);
    return role?.label ?? newest.folder;
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final narrow = !HomeShell.isWide(context);
    final plan = _plan(ref);
    final forever = !plan.can(ThreadAction.delete) && plan.can(ThreadAction.deleteForever);
    final menu = [
      for (final a in plan.available)
        if (a != ThreadAction.delete && a != ThreadAction.deleteForever) a,
    ];
    final title = conversationTitle(thread);
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
        leading: narrow
            ? BackButton(
                key: const Key('thread-back'),
                onPressed: () =>
                    context.canPop() ? context.pop() : context.go('/inbox'),
              )
            : null,
        title: Text(_title(plan), key: const Key('thread-title'), maxLines: 1, overflow: TextOverflow.ellipsis),
        actions: [
          IconButton(
            key: const Key('thread-reply'),
            tooltip: 'Reply',
            icon: const Icon(Icons.reply),
            onPressed: () => context.go('/compose?reply=${thread.id}'),
          ),
          IconButton(
            key: const Key('thread-delete'),
            tooltip: forever ? 'Delete forever' : 'Delete conversation',
            icon: Icon(forever ? Icons.delete_forever_outlined : Icons.delete_outline),
            onPressed: () => _act(context, ref, forever ? ThreadAction.deleteForever : ThreadAction.delete),
          ),
          PopupMenuButton<String>(
            key: const Key('thread-more'),
            tooltip: 'More actions',
            onSelected: (v) {
              if (v == 'forward') {
                context.go('/compose?forward=${Uri.encodeQueryComponent(thread.latest.id)}');
              } else if (v == 'explain') {
                _explain(context, plan);
              } else {
                _act(context, ref, ThreadAction.values.byName(v));
              }
            },
            itemBuilder: (_) => [
              const PopupMenuItem(
                key: Key('thread-forward'),
                value: 'forward',
                child: ListTile(leading: Icon(Icons.forward), title: Text('Forward')),
              ),
              for (final a in menu)
                PopupMenuItem(
                  key: a.menuKey,
                  value: a.name,
                  child: ListTile(leading: Icon(a.icon), title: Text(a.label)),
                ),
              if (plan.spamSubject != null)
                PopupMenuItem(
                  key: const Key('thread-spam-explain'),
                  value: 'explain',
                  child: ListTile(
                    leading: const Icon(Icons.help_outline),
                    title: Text(plan.inSpam ? 'Why is this spam?' : 'Spam check'),
                  ),
                ),
            ],
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        heroTag: 'reply-fab',
        onPressed: () => context.go('/compose?reply=${thread.id}'),
        icon: const Icon(Icons.reply),
        label: const Text('Reply'),
      ),
      body: ListView.builder(
        key: const Key('thread-messages'),
        // The Reply FAB must never cover the last message (L12): FAB height +
        // margins + the system bottom inset (gesture bar / nav bar on phones).
        padding: EdgeInsets.fromLTRB(16, 12, 16, 104 + MediaQuery.paddingOf(context).bottom),
        itemCount: thread.messages.length,
        itemBuilder: (context, i) => _MessageCard(
          message: thread.messages[i],
          own: plan.own,
          subject: i == 0 ? title.text : null,
          subjectPlaceholder: title.placeholder,
        ),
      ),
    );
  }
}

/// Below this window width a message card shows the sender's address and "to …" on lines
/// of their own (review P9).
const double _recipientsOwnLineBelow = 600;

class _MessageCard extends ConsumerWidget {
  const _MessageCard({
    required this.message,
    this.own = const {},
    this.subject,
    this.subjectPlaceholder = false,
  });

  final Message message;

  /// Our own addresses ("(you)", no key-change banner on our own mail).
  final Set<String> own;

  /// The conversation's subject, shown on top of the first card only.
  final String? subject;

  /// [subject] stands in for a subject nobody here could decrypt ("Encrypted message",
  /// review N1): secondary and italic.
  final bool subjectPlaceholder;

  Future<void> _save(BuildContext context, WidgetRef ref, AttachmentMeta a) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      final bytes = await ref.read(coreApiProvider).getAttachment(message.id, a.index);
      final dir = await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory();
      final safe = a.filename.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
      final file = File('${dir.path}${Platform.pathSeparator}$safe');
      await file.writeAsBytes(bytes.data);
      messenger.showSnackBar(SnackBar(content: Text('Saved ${file.path}')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not save: $e')));
    }
  }

  Future<void> _resend(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    final id = message.messageId;
    if (id == null) return;
    try {
      await ref.read(coreApiProvider).resendGuestLink(id);
      messenger.showSnackBar(
        const SnackBar(content: Text('Guest link sent again. The passphrase is unchanged.')),
      );
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not resend the link: $e')));
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final m = message;
    final signer = m.signer;
    // Ours: a Sent copy, or our own mail in any folder (no "(you)" for a scam in
    // Spam just because it is not in INBOX). Doubles without accounts: by folder.
    final mine = own.isEmpty ? m.isSent : own.contains(m.from.email.trim().toLowerCase());
    // Identity state of the sender (G30): banner while the change is
    // undecided, "accepted" chip afterwards; "✓ Verified" for a signature by
    // exactly the verified key.
    final sender = m.keyChanged && !mine ? ref.watch(contactProvider(m.from.email)) : null;
    final senderContact = sender?.value;
    final changePending = m.keyChanged && !mine && (senderContact?.keyChangePending ?? false);
    final changeAccepted =
        m.keyChanged && !mine && sender != null && !sender.isLoading && !changePending;
    final palette = LockColors.ofContext(context);
    final fp = signer == null
        ? null
        : '…${signer.substring(signer.length - 8 < 0 ? 0 : signer.length - 8)}';
    final signedBy = m.signerAddress;
    // R4: a good signature by a key that belongs to another address than From.
    final mismatch = signerMismatch(
      m,
      contacts: ref.watch(contactsProvider).value ?? const <ContactKey>[],
      own: own,
    );
    final Widget? sigChip = switch (m.signature) {
      // R4: never the green chip for a key that is not the sender's: amber, and the
      // tooltip says what the signature does (and does not) show.
      SignatureState.good when mismatch != null => KeyedSubtree(
        key: ValueKey('message-signer-mismatch-${m.id}'),
        child: StatusChip(
          key: ValueKey('message-signature-${m.id}'),
          icon: Icons.gpp_maybe_outlined,
          label: mismatch.label,
          color: palette.plaintext,
          // The end ("— but sent by …") is the point: wrap rather than ellipsise.
          maxLines: 3,
          tooltip: signer == null
              ? mismatch.explanation
              : '${mismatch.explanation}\nKey $fp (${groupFingerprint(signer)})',
        ),
      ),
      // "signed by <address>" when the engine knows whose key it is (review D7);
      // the key id goes to the tooltip.
      SignatureState.good => StatusChip(
        key: ValueKey('message-signature-${m.id}'),
        icon: Icons.verified_outlined,
        label: signedBy == null ? 'signature verified' : 'signed by $signedBy',
        mono: signedBy == null ? fp : null,
        color: palette.encrypted,
        tooltip: signer == null
            ? null
            : signedBy == null
            ? 'Signed by $signer'
            : 'Signature verified: key $fp (${groupFingerprint(signer)})',
      ),
      SignatureState.bad => StatusChip(
        key: ValueKey('message-signature-${m.id}'),
        icon: Icons.gpp_bad_outlined,
        label: 'signature INVALID',
        color: theme.colorScheme.error,
      ),
      SignatureState.unknownKey => StatusChip(
        key: ValueKey('message-signature-${m.id}'),
        icon: Icons.help_outline,
        label: 'signed by an unknown key',
        color: palette.plaintext,
      ),
      SignatureState.none => null,
    };
    final recipients = m.to.map((c) => c.display).join(', ');
    final secondary = theme.textTheme.bodySmall?.copyWith(
      color: theme.colorScheme.onSurfaceVariant,
    );
    // No address line repeating the name line (Android S3-5b).
    final address = m.from.display.toLowerCase() == m.from.email.toLowerCase()
        ? null
        : m.from.email;
    // Review P9: on a phone "address · to Bob Nakamura" wrapped inside the name ("to Bob /
    // Nakamura"). There the address and "to …" get lines of their own, "to …" exactly one
    // (ellipsised): a name is never split across lines. Wider windows keep the combined line.
    final ownLines = MediaQuery.sizeOf(context).width < _recipientsOwnLineBelow;
    // Under the body: "Resend link" on our own guest-link mail, then a chip per attachment in
    // [listed]. Around an HTML body MessageBody builds this, and leaves out an image it already
    // shows inline (review N4); "Show as text" lists every part again.
    List<Widget> footer(BuildContext context, List<AttachmentMeta> listed) => [
      if (m.isSent && m.guestLink && m.messageId != null) ...[
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            key: ValueKey('message-resend-${m.id}'),
            onPressed: () => _resend(context, ref),
            icon: const Icon(Icons.forward_to_inbox),
            label: const Text('Resend link'),
          ),
        ),
      ],
      if (listed.isNotEmpty) ...[
        const SizedBox(height: 12),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (final a in listed)
              ActionChip(
                key: ValueKey('attachment-${m.id}-${a.index}'),
                avatar: const Icon(Icons.attach_file, size: 18),
                label: Text('${a.filename} · ${a.sizeLabel}'),
                tooltip: 'Save ${a.filename} (${a.contentType})',
                onPressed: () => _save(context, ref, a),
              ),
          ],
        ),
      ],
    ];
    return Card(
      key: ValueKey('message-card-${m.id}'),
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (subject != null) ...[
              Text(
                subject!,
                key: const Key('thread-subject'),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: subjectPlaceholder
                    ? theme.textTheme.titleLarge?.copyWith(
                        fontStyle: FontStyle.italic,
                        color: theme.colorScheme.onSurfaceVariant,
                      )
                    : theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 12),
            ],
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                CircleAvatar(
                  backgroundColor: avatarColorFor(m.from.email, theme.colorScheme),
                  foregroundColor: Colors.white,
                  child: Text(m.from.initial),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        mine ? '${m.from.display} (you)' : m.from.display,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (!ownLines)
                        Text(
                          address == null ? 'to $recipients' : '$address · to $recipients',
                          key: ValueKey('message-recipients-${m.id}'),
                          style: secondary,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        )
                      else ...[
                        // The whole address matters more than a tidy line (a lookalike
                        // domain differs at its end): it may take a second line.
                        if (address != null)
                          Text(
                            address,
                            key: ValueKey('message-from-address-${m.id}'),
                            style: secondary,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                        Text(
                          'to $recipients',
                          key: ValueKey('message-recipients-${m.id}'),
                          style: secondary,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Text(fullTime(m.date), style: theme.textTheme.labelSmall),
              ],
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                // A signed-only message whose signature is not the sender's is just
                // "Not encrypted"; the amber chip next to it is about the signature (R4).
                LockBadge(
                  state: mismatch != null && m.state == EncryptionState.signed
                      ? EncryptionState.plaintext
                      : m.state,
                  showLabel: true,
                ),
                ?sigChip,
                if (m.signerVerified) VerifiedChip(key: ValueKey('message-verified-${m.id}')),
                if (changeAccepted)
                  KeyChangedAcceptedChip(key: ValueKey('message-key-accepted-${m.id}')),
                if (m.isSent)
                  StatusChip(
                    key: ValueKey('message-folder-${m.id}'),
                    icon: Icons.folder_outlined,
                    label: 'in ${m.folder}',
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
              ],
            ),
            if (changePending) ...[
              const SizedBox(height: 12),
              KeyChangedBanner(address: m.from.email, name: m.from.name, contact: senderContact),
            ],
            const SizedBox(height: 12),
            if (m.state == EncryptionState.undecryptable) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: LockColors.ofContext(context).undecryptable.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  m.body.isEmpty
                      ? 'This message is encrypted, but not to a key on this device.'
                      : m.body,
                  style: theme.textTheme.bodyMedium,
                ),
              ),
              ...footer(context, m.attachments),
            ] else
              // HTML mail renders as sanitized HTML with remote images blocked, and keeps
              // the plain-text view one tap away (docs/HTML_MAIL.md); a message without an
              // HTML part is the same SelectableText as before, same key.
              MessageBody(
                key: ValueKey('message-body-widget-${m.id}'),
                messageId: m.id,
                text: m.body,
                // inline cid: images show the part whose Content-ID they name
                attachments: m.attachments,
                footer: footer,
              ),
          ],
        ),
      ),
    );
  }
}
