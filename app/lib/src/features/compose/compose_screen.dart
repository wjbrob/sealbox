import 'package:flutter/material.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../policy/encryption_policy.dart';
import '../../widgets/lock_badge.dart';
import '../identity/identity_widgets.dart' show verifyRoute;
import '../inbox/home_shell.dart';
import '../inbox/inbox_list_pane.dart' show fullTime;
import 'compose_controller.dart';
import 'compose_preview.dart';
import 'drafts.dart' show confirmDiscardDraft;
import 'guest_link_panel.dart';
import 'recipient_pill.dart';
import 'recipient_suggestions.dart';

/// Compose: recipients (To, and Cc / Bcc behind their links) with their per-recipient protection,
/// subject, text, files, and a preview of what the engine sends. The message is saved as a
/// draft 2 s after the last edit and when the screen is left (`ComposeController`); sending
/// deletes the draft, "Discard draft" deletes it after a confirmation.
class ComposeScreen extends ConsumerStatefulWidget {
  const ComposeScreen({super.key, this.replyToThreadId, this.forwardMessageId, this.draftId});

  final String? replyToThreadId;

  /// Local id of a stored message to forward (`/compose?forward=<id>`).
  final String? forwardMessageId;

  /// A saved draft to continue (`/compose?draft=<id>`).
  final int? draftId;

  @override
  ConsumerState<ComposeScreen> createState() => _ComposeScreenState();
}

class _ComposeScreenState extends ConsumerState<ComposeScreen> {
  final _to = TextEditingController();
  final _cc = TextEditingController();
  final _bcc = TextEditingController();
  final _subject = TextEditingController();
  final _body = TextEditingController();
  final _subjectFocus = FocusNode();
  final _bodyFocus = FocusNode();
  bool _prefilled = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _prefill());
    _lifecycle = AppLifecycleListener(onInactive: _saveNow, onHide: _saveNow, onPause: _saveNow);
  }

  /// The app goes to the background (a phone may end it there) or loses focus: what is
  /// unsaved is saved now rather than 2 s later.
  late final AppLifecycleListener _lifecycle;

  void _saveNow() => ref.read(composeControllerProvider.notifier).saveDraftNow();

  /// The app's messenger: it outlives this screen, so a save that fails after compose was
  /// left is still reported ([_leaveFailed]).
  ScaffoldMessengerState? _messenger;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _messenger = ScaffoldMessenger.maybeOf(context);
  }

  /// The save made on leaving failed: say so where the user is now, with Retry. The text is
  /// not lost either way: the next new compose brings it back.
  void _leaveFailed(DraftLeaveFailure failure) {
    final messenger = _messenger;
    if (messenger == null || !messenger.mounted) return;
    messenger.showSnackBar(
      SnackBar(
        key: const Key('draft-save-failed-snackbar'),
        content: Text('Draft could not be saved: ${failure.error}'),
        duration: const Duration(seconds: 10),
        action: SnackBarAction(
          key: const Key('draft-save-retry'),
          label: 'Retry',
          onPressed: () async {
            if (await failure.retry() && messenger.mounted) {
              messenger.showSnackBar(
                const SnackBar(key: Key('draft-saved-snackbar'), content: Text('Draft saved')),
              );
            }
          },
        ),
      ),
    );
  }

  /// `/compose` → `/compose?reply=<id>` keeps this widget alive: start the reply
  /// from a clean draft instead of merging it into whatever was typed before.
  @override
  void didUpdateWidget(covariant ComposeScreen old) {
    super.didUpdateWidget(old);
    if (old.replyToThreadId != widget.replyToThreadId ||
        old.forwardMessageId != widget.forwardMessageId ||
        old.draftId != widget.draftId) {
      _prefilled = false;
      _to.clear();
      _cc.clear();
      _bcc.clear();
      _subject.clear();
      _body.clear();
      // Not during build: invalidating here marks the provider scope dirty while the
      // framework is building ("setState() called during build"), and the reply was
      // never prefilled (caught by the review tour's compose → reply step).
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        ref.invalidate(composeControllerProvider);
        _prefill();
      });
    }
  }

  Future<void> _prefill() async {
    final core = ref.read(coreApiProvider);
    final ctl = ref.read(composeControllerProvider.notifier);
    final accounts = await core.listAccounts();
    if (!mounted) return;
    if (ref.read(composeControllerProvider).accountId == null &&
        accounts.isNotEmpty) {
      ctl.setAccount(accounts.first.id);
    }
    final replyId = widget.replyToThreadId;
    final forwardId = widget.forwardMessageId;
    final draftId = widget.draftId;
    if (draftId != null && !_prefilled) {
      final SavedDraft saved;
      try {
        saved = await core.getDraft(draftId);
      } catch (e) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            key: const Key('compose-draft-missing'),
            content: Text('This draft cannot be opened: ${friendlyError(e)}'),
          ),
        );
        return;
      }
      if (!mounted) return;
      await ctl.resume(saved);
      if (!mounted) return;
      final s = ref.read(composeControllerProvider);
      _subject.text = s.subject;
      _body.text = s.body;
      _prefilled = true;
    } else if (replyId != null && !_prefilled) {
      final thread = await core.getThread(replyId);
      if (!mounted || thread == null) return;
      await ctl.prefillReply(thread, accounts);
      if (!mounted) return;
      final s = ref.read(composeControllerProvider);
      _subject.text = s.subject;
      _body.text = s.body;
      _prefilled = true;
    } else if (forwardId != null && !_prefilled) {
      final message = await core.getMessage(forwardId);
      if (!mounted || message == null) return;
      ctl.prefillForward(message, accounts);
      final s = ref.read(composeControllerProvider);
      _subject.text = s.subject;
      _body.text = s.body;
      _prefilled = true;
    } else if (draftId == null && replyId == null && forwardId == null && !_prefilled) {
      // A message that could not be saved when compose was last left comes back here.
      _prefilled = true;
      if (!await ctl.restoreUnsaved() || !mounted) return;
      final s = ref.read(composeControllerProvider);
      _subject.text = s.subject;
      _body.text = s.body;
    }
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    _to.dispose();
    _cc.dispose();
    _bcc.dispose();
    _subject.dispose();
    _body.dispose();
    _subjectFocus.dispose();
    _bodyFocus.dispose();
    super.dispose();
  }

  Future<void> _addFromField([String? value]) async {
    final raw = value ?? _to.text;
    if (raw.trim().isEmpty) return;
    final ok = await ref
        .read(composeControllerProvider.notifier)
        .addRecipient(raw);
    if (ok && mounted) _to.clear();
  }

  /// A suggested address was chosen: the field empties at once, the key lookup follows.
  Future<void> _pick(String address) async {
    _to.clear();
    await ref.read(composeControllerProvider.notifier).addRecipient(address);
  }

  Future<void> _addCcFromField([String? value]) async {
    final raw = value ?? _cc.text;
    if (raw.trim().isEmpty) return;
    final ok = await ref.read(composeControllerProvider.notifier).addRecipient(raw, cc: true);
    if (ok && mounted) _cc.clear();
  }

  Future<void> _pickCc(String address) async {
    _cc.clear();
    await ref.read(composeControllerProvider.notifier).addRecipient(address, cc: true);
  }

  Future<void> _addBccFromField([String? value]) async {
    final raw = value ?? _bcc.text;
    if (raw.trim().isEmpty) return;
    final ok = await ref.read(composeControllerProvider.notifier).addRecipient(raw, bcc: true);
    if (ok && mounted) _bcc.clear();
  }

  Future<void> _pickBcc(String address) async {
    _bcc.clear();
    await ref.read(composeControllerProvider.notifier).addRecipient(address, bcc: true);
  }

  /// "Discard draft": after a confirmation the saved draft and its file copies are
  /// deleted and compose closes.
  Future<void> _discard() async {
    final messenger = ScaffoldMessenger.of(context);
    final router = GoRouter.maybeOf(context);
    if (!await confirmDiscardDraft(context) || !mounted) return;
    try {
      await ref.read(composeControllerProvider.notifier).discard();
      messenger.showSnackBar(
        const SnackBar(key: Key('draft-discarded-snackbar'), content: Text('Draft discarded')),
      );
      router?.go('/inbox');
    } catch (e) {
      messenger.showSnackBar(
        SnackBar(content: Text('Could not discard the draft: ${friendlyError(e)}')),
      );
    }
  }

  Future<void> _attach() async {
    final messenger = ScaffoldMessenger.of(context);
    final ctl = ref.read(composeControllerProvider.notifier);
    final List<XFile> files;
    try {
      files = await openFiles();
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not open the file picker: $e')));
      return;
    }
    if (files.isEmpty) return;
    final picked = <DraftAttachment>[];
    for (final f in files) {
      picked.add(
        DraftAttachment(
          name: f.name,
          contentType: f.mimeType ?? 'application/octet-stream',
          data: await f.readAsBytes(),
        ),
      );
    }
    ctl.addAttachments(picked);
  }

  Future<void> _requestPlaintext(String email) async {
    final confirmed = await showPlaintextConfirmDialog(context, email);
    if (confirmed == true && mounted) {
      ref.read(composeControllerProvider.notifier).confirmPlaintext(email);
    }
  }

  Future<void> _send() async {
    final messenger = ScaffoldMessenger.of(context);
    final router = GoRouter.maybeOf(context);
    try {
      final ctl = ref.read(composeControllerProvider.notifier);
      final receipt = await ctl.send();
      final note = ctl.lastSendNote;
      ref.invalidate(threadsProvider);
      ref.invalidate(threadProvider);
      if (receipt.guestLinks.isNotEmpty && mounted) {
        await showGuestLinkSentDialog(context, receipt.guestLinks);
      }
      messenger.showSnackBar(
        SnackBar(
          key: const Key('compose-sent-snackbar'),
          content: Text(note == null ? receipt.summary : '${receipt.summary} · $note'),
        ),
      );
      router?.go('/inbox');
    } on PartialSendException catch (e) {
      // Part went out (one of the message's sends — encrypted, a guest link, plaintext — or
      // a Bcc copy failed after the rest): who got it is named and what was sent is shown (a
      // guest link's passphrase only once); who did not get it stays on the message.
      ref.invalidate(threadsProvider);
      ref.invalidate(threadProvider);
      if (e.sent.guestLinks.isNotEmpty && mounted) {
        await showGuestLinkSentDialog(context, e.sent.guestLinks);
      }
      final got = [...e.sent.encryptedTo, ...e.sent.guestLinkTo, ...e.sent.plaintextTo];
      messenger.showSnackBar(
        SnackBar(
          key: const Key('compose-partial-snackbar'),
          content: Text(
            '${e.sent.summary} (${got.join(', ')}), but not to ${e.notSentTo.join(', ')}: '
            '${e.reason}. Still on the message: Send again to send it to them.',
          ),
          duration: const Duration(seconds: 10),
        ),
      );
    } catch (e) {
      messenger.showSnackBar(
        SnackBar(
          key: const Key('compose-error-snackbar'),
          content: Text('Could not send: ${friendlyError(e)}'),
          duration: const Duration(seconds: 6),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(composeControllerProvider);
    final ctl = ref.read(composeControllerProvider.notifier);
    // Every compose session (a reply switched to replaces it) reports a failed save on leaving.
    ctl.onLeaveFailure = _leaveFailed;
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final plan = s.plan;
    final caps = ref.watch(capabilitiesProvider).value;
    // State set programmatically (reply prefill, the review tour) reaches the
    // editors; while a field is being typed in it is the source of truth.
    if (!_subjectFocus.hasFocus && _subject.text != s.subject) _subject.text = s.subject;
    if (!_bodyFocus.hasFocus && _body.text != s.body) _body.text = s.body;
    final narrow = !HomeShell.isWide(context);
    final compact = MediaQuery.sizeOf(context).width < 480;
    final canDiscard = s.hasContent || s.draftId != null;
    final kind = widget.replyToThreadId != null
        ? ComposeKind.reply
        : widget.forwardMessageId != null
        ? ComposeKind.forward
        : s.compose.kind;
    // Suggestions never offer ourselves or anyone already on the message.
    final alreadyOn = {
      for (final a in accounts) a.email.toLowerCase(),
      for (final r in s.allRecipients) r.email.toLowerCase(),
    };

    return Scaffold(
      appBar: AppBar(
        title: _ComposeTitle(
          // P4: "New message" truncated to "New messa…" beside the actions on a phone.
          title: switch (kind) {
            ComposeKind.reply => 'Reply',
            ComposeKind.forward => 'Forward',
            ComposeKind.newMessage => narrow ? 'Compose' : 'New message',
          },
          state: s,
        ),
        actions: [
          // A phone-width bar holds the title, one icon and the Send button: Attach and
          // Discard share an overflow menu there.
          if (compact)
            PopupMenuButton<_ComposeAction>(
              key: const Key('compose-more'),
              tooltip: 'More options',
              enabled: !s.sending,
              onSelected: (a) {
                switch (a) {
                  case _ComposeAction.attach:
                    _attach();
                  case _ComposeAction.discard:
                    _discard();
                }
              },
              itemBuilder: (_) => [
                const PopupMenuItem(
                  key: Key('compose-attach'),
                  value: _ComposeAction.attach,
                  child: ListTile(leading: Icon(Icons.attach_file), title: Text('Attach files')),
                ),
                PopupMenuItem(
                  key: const Key('compose-discard'),
                  value: _ComposeAction.discard,
                  enabled: canDiscard,
                  child: const ListTile(
                    leading: Icon(Icons.delete_outline),
                    title: Text('Discard draft'),
                  ),
                ),
              ],
            )
          else ...[
            IconButton(
              key: const Key('compose-discard'),
              tooltip: 'Discard draft',
              icon: const Icon(Icons.delete_outline),
              onPressed: s.sending || !canDiscard ? null : _discard,
            ),
            IconButton(
              key: const Key('compose-attach'),
              tooltip: 'Attach files',
              icon: const Icon(Icons.attach_file),
              onPressed: s.sending ? null : _attach,
            ),
          ],
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: FilledButton.icon(
              key: const Key('compose-send'),
              // The risky action must not look like the safe one.
              style: plan.mode == SendMode.plaintext
                  ? FilledButton.styleFrom(
                      backgroundColor: LockColors.ofContext(context).plaintext,
                      foregroundColor: Theme.of(context).brightness == Brightness.dark
                          ? const Color(0xFF2B1D00)
                          : Colors.white,
                    )
                  : null,
              onPressed: s.canSendWith(caps?.guestModes ?? GuestMode.values.toSet())
                  ? _send
                  : null,
              icon: s.sending
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Icon(switch (plan.mode) {
                      SendMode.plaintext => Icons.warning_amber_rounded,
                      SendMode.guestLink => Icons.link,
                      _ => Icons.lock,
                    }),
              label: Text(switch (plan.mode) {
                SendMode.plaintext => 'Send (plaintext)',
                _ => 'Send encrypted',
              }),
            ),
          ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 820),
          child: ListView(
            key: const Key('compose-list'),
            padding: const EdgeInsets.all(16),
            children: [
              if (accounts.length > 1)
                DropdownMenu<String>(
                  key: const Key('compose-account'),
                  initialSelection: s.accountId,
                  label: const Text('From'),
                  expandedInsets: EdgeInsets.zero,
                  trailingIcon: const Tooltip(
                    message: 'Choose the sending account',
                    child: Icon(Icons.arrow_drop_down),
                  ),
                  selectedTrailingIcon: const Tooltip(
                    message: 'Choose the sending account',
                    child: Icon(Icons.arrow_drop_up),
                  ),
                  onSelected: (id) => id == null ? null : ctl.chooseAccount(id),
                  dropdownMenuEntries: [
                    for (final a in accounts)
                      DropdownMenuEntry(value: a.id, label: a.email),
                  ],
                )
              else if (accounts.length == 1)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Text(
                    'From ${accounts.first.email}',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ),
              if (s.notice != null) ...[const SizedBox(height: 8), _Notice(text: s.notice!)],
              const SizedBox(height: 12),
              if (s.recipients.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      for (final r in s.recipients)
                        RecipientPill(
                          email: r.email,
                          status: s.statusOf(r.email),
                          keySource: r.info?.source,
                          onRemove: () => ctl.removeRecipient(r.email),
                          onRequestPlaintext: () => _requestPlaintext(r.email),
                          onUseGuestLink: () => ctl.revokePlaintext(r.email),
                        ),
                    ],
                  ),
                ),
              RecipientField(
                // Keyed: the pill row appearing above must not recreate the field (it
                // would lose the focus and the caret while typing the next address).
                key: const Key('compose-recipient-field'),
                controller: _to,
                errorText: s.error,
                // Never suggest ourselves or someone already on the message (in any line:
                // an address is on one line only, so picking it here would do nothing).
                exclude: alreadyOn,
                onSubmitted: _addFromField,
                onPicked: _pick,
                onChanged: (v) {
                  if (v.endsWith(',') || v.endsWith(';') || v.endsWith(' ')) {
                    _addFromField(v);
                  }
                },
                suffix: s.showCc && s.showBcc
                    ? null
                    : Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (!s.showCc)
                            TextButton(
                              key: const Key('compose-cc-toggle'),
                              style: TextButton.styleFrom(minimumSize: const Size(48, 48)),
                              onPressed: () => ctl.setShowCc(true),
                              child: const Text('Cc', semanticsLabel: 'Add Cc recipients'),
                            ),
                          if (!s.showBcc)
                            TextButton(
                              key: const Key('compose-bcc-toggle'),
                              style: TextButton.styleFrom(minimumSize: const Size(48, 48)),
                              onPressed: () => ctl.setShowBcc(true),
                              child: const Text('Bcc', semanticsLabel: 'Add Bcc recipients'),
                            ),
                        ],
                      ),
              ),
              if (s.showCc) ...[
                const SizedBox(height: 12),
                if (s.ccRecipients.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Wrap(
                      key: const Key('compose-cc-pills'),
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        for (final r in s.ccRecipients)
                          RecipientPill(
                            email: r.email,
                            status: s.statusOf(r.email),
                            keySource: r.info?.source,
                            onRemove: () => ctl.removeRecipient(r.email),
                            onRequestPlaintext: () => _requestPlaintext(r.email),
                            onUseGuestLink: () => ctl.revokePlaintext(r.email),
                          ),
                      ],
                    ),
                  ),
                RecipientField(
                  key: const Key('compose-cc-field'),
                  controller: _cc,
                  fieldKey: const Key('compose-cc'),
                  label: 'Cc',
                  errorText: s.ccError,
                  exclude: alreadyOn,
                  onSubmitted: _addCcFromField,
                  onPicked: _pickCc,
                  onChanged: (v) {
                    if (v.endsWith(',') || v.endsWith(';') || v.endsWith(' ')) {
                      _addCcFromField(v);
                    }
                  },
                  suffix: s.ccRecipients.isEmpty
                      ? IconButton(
                          key: const Key('compose-cc-hide'),
                          tooltip: 'Remove Cc',
                          icon: const Icon(Icons.close),
                          onPressed: () {
                            _cc.clear();
                            ctl.setShowCc(false);
                          },
                        )
                      : null,
                ),
              ],
              if (s.showBcc) ...[
                const SizedBox(height: 12),
                if (s.bccRecipients.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Wrap(
                      key: const Key('compose-bcc-pills'),
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        for (final r in s.bccRecipients)
                          RecipientPill(
                            email: r.email,
                            status: s.statusOf(r.email),
                            keySource: r.info?.source,
                            onRemove: () => ctl.removeRecipient(r.email),
                            onRequestPlaintext: () => _requestPlaintext(r.email),
                            onUseGuestLink: () => ctl.revokePlaintext(r.email),
                          ),
                      ],
                    ),
                  ),
                RecipientField(
                  key: const Key('compose-bcc-field'),
                  controller: _bcc,
                  fieldKey: const Key('compose-bcc'),
                  label: 'Bcc',
                  errorText: s.bccError,
                  helperText:
                      'Each Bcc recipient gets a copy of their own, addressed to them alone.',
                  exclude: alreadyOn,
                  onSubmitted: _addBccFromField,
                  onPicked: _pickBcc,
                  onChanged: (v) {
                    if (v.endsWith(',') || v.endsWith(';') || v.endsWith(' ')) {
                      _addBccFromField(v);
                    }
                  },
                  suffix: s.bccRecipients.isEmpty
                      ? IconButton(
                          key: const Key('compose-bcc-hide'),
                          tooltip: 'Remove Bcc',
                          icon: const Icon(Icons.close),
                          onPressed: () {
                            _bcc.clear();
                            ctl.setShowBcc(false);
                          },
                        )
                      : null,
                ),
              ],
              const SizedBox(height: 12),
              _PolicyBanner(plan: plan, resolving: s.anyResolving),
              _KeyChangeWarning(recipients: [for (final r in s.allRecipients) r.email]),
              if (plan.needsPassphrase) ...[
                const SizedBox(height: 12),
                GuestLinkPanel(
                  mode: s.guestMode,
                  supported: caps?.guestModes ?? GuestMode.values.toSet(),
                  guests: plan.guestRecipients,
                  onChanged: ctl.setGuestMode,
                  serverConfigured: caps?.guestLinks ?? true,
                ),
              ],
              const SizedBox(height: 16),
              TextField(
                key: const Key('compose-subject'),
                controller: _subject,
                focusNode: _subjectFocus,
                decoration: const InputDecoration(
                  labelText: 'Subject',
                  border: OutlineInputBorder(),
                ),
                onChanged: ctl.setSubject,
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('compose-body'),
                controller: _body,
                focusNode: _bodyFocus,
                minLines: 10,
                maxLines: 30,
                decoration: const InputDecoration(
                  labelText: 'Message',
                  alignLabelWithHint: true,
                  border: OutlineInputBorder(),
                ),
                onChanged: ctl.setBody,
              ),
              if (s.attachments.isNotEmpty) ...[
                const SizedBox(height: 12),
                Wrap(
                  key: const Key('compose-attachments'),
                  spacing: 8,
                  runSpacing: 8,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    for (final a in s.attachments)
                      InputChip(
                        key: ValueKey('attachment-chip-${a.name}'),
                        avatar: const Icon(Icons.attach_file, size: 18),
                        label: Text('${a.name} · ${a.sizeLabel}'),
                        tooltip: a.contentType,
                        deleteButtonTooltipMessage: 'Remove ${a.name}',
                        onDeleted: () => ctl.removeAttachment(a.name),
                      ),
                    Text(
                      '${s.attachments.length} attachment${s.attachments.length == 1 ? '' : 's'}, '
                      '${DraftAttachment.sizeLabelOf(s.attachmentBytes)} total'
                      '${plan.allEncrypted ? ' · encrypted with the message' : ''}',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ],
              const SizedBox(height: 12),
              // Replies and forwards (a resumed one too) open it: the quote is not in the editor.
              ComposePreviewPanel(initiallyOpen: kind != ComposeKind.newMessage),
              const SizedBox(height: 8),
              Text(
                plan.allEncrypted
                    // The engine's outer Subject (sealbox-mail PROTECTED_SUBJECT_PLACEHOLDER).
                    ? 'The subject is protected too: the provider only sees "...".'
                    : 'Sealbox always adds your Autocrypt header so replies can be encrypted.',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

enum _ComposeAction { attach, discard }

/// The compose title and, under it, where the saved draft stands: "Saving draft…",
/// "Draft saved 14:05", or "Draft not saved: …" (announced to screen readers).
class _ComposeTitle extends StatelessWidget {
  const _ComposeTitle({required this.title, required this.state});

  final String title;
  final ComposeState state;

  static String _hm(DateTime d) {
    final l = d.toLocal();
    return '${l.hour.toString().padLeft(2, '0')}:${l.minute.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final s = state;
    final (String? status, bool failed) = switch (s.draftStatus) {
      DraftSaveStatus.none => (null, false),
      DraftSaveStatus.saving => ('Saving draft…', false),
      DraftSaveStatus.saved => (
        s.draftSavedAt == null ? 'Draft saved' : 'Draft saved ${_hm(s.draftSavedAt!)}',
        false,
      ),
      DraftSaveStatus.failed => ('Draft not saved: ${s.draftError ?? 'unknown error'}', true),
    };
    if (status == null) return Text(title);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(title),
        Semantics(
          liveRegion: true,
          child: Tooltip(
            message: status,
            child: Text(
              status,
              key: const Key('compose-draft-status'),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.labelSmall?.copyWith(
                color: failed ? theme.colorScheme.error : theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// A note about a resumed draft (files gone) or a message kept after a failed save.
class _Notice extends StatelessWidget {
  const _Notice({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final amber = LockColors.ofContext(context).plaintext;
    return Container(
      key: const Key('compose-notice'),
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
      decoration: BoxDecoration(
        color: amber.withValues(alpha: 0.12),
        border: Border.all(color: amber.withValues(alpha: 0.6)),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline, color: amber, size: 20),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: theme.textTheme.bodyMedium)),
        ],
      ),
    );
  }
}

/// The "send unencrypted?" warning. `true` = the user accepted plaintext for [email].
Future<bool?> showPlaintextConfirmDialog(BuildContext context, String email) {
  return showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      key: const Key('plaintext-confirm-dialog'),
      icon: Icon(Icons.warning_amber_rounded, color: LockColors.ofContext(context).plaintext),
      title: Text('Send unencrypted to $email?'),
      content: const Text(
        'This recipient has no OpenPGP key. Sealbox would normally send them a '
        'passphrase-protected guest link instead.\n\n'
        'If you continue, their copy leaves in the clear: your provider, theirs '
        'and anyone on the path can read it.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Keep the guest link'),
        ),
        FilledButton.tonal(
          key: const Key('confirm-plaintext'),
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Send in plaintext'),
        ),
      ],
    ),
  );
}

class _PolicyBanner extends StatelessWidget {
  const _PolicyBanner({required this.plan, required this.resolving});

  final MessagePlan plan;
  final bool resolving;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = LockColors.ofContext(context);
    final (icon, color) = switch (plan.mode) {
      SendMode.empty => (Icons.info_outline, theme.colorScheme.outline),
      SendMode.encrypted => (Icons.lock, palette.encrypted),
      SendMode.guestLink => (Icons.link, palette.guestLink),
      SendMode.plaintext => (Icons.warning_amber_rounded, palette.plaintext),
    };
    return Container(
      key: ValueKey('compose-policy-${plan.mode.name}'),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              resolving && plan.isEmpty ? 'Looking up keys…' : plan.summary,
              style: theme.textTheme.bodyMedium,
            ),
          ),
        ],
      ),
    );
  }
}



/// G30: recipients whose key changed recently and who have not been
/// verified or accepted since. Sending still works (to the new key); the
/// warning says so and offers to verify first.
class _KeyChangeWarning extends ConsumerWidget {
  const _KeyChangeWarning({required this.recipients});

  final List<String> recipients;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (recipients.isEmpty) return const SizedBox.shrink();
    final contacts = ref.watch(contactsProvider).value ?? const <ContactKey>[];
    final wanted = {for (final r in recipients) r.toLowerCase()};
    final changed = [
      for (final c in contacts)
        if (c.keyChangePending && wanted.contains(c.address.toLowerCase())) c,
    ];
    if (changed.isEmpty) return const SizedBox.shrink();
    final theme = Theme.of(context);
    final amber = LockColors.ofContext(context).plaintext;
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Container(
        key: const Key('compose-key-changed'),
        padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
        decoration: BoxDecoration(
          color: amber.withValues(alpha: 0.12),
          border: Border.all(color: amber.withValues(alpha: 0.6)),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final c in changed)
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Icon(Icons.warning_amber_rounded, color: amber, size: 20),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'The key for ${c.address} changed recently'
                      '${c.keyChangedAt == null ? '' : ' (${fullTime(c.keyChangedAt!)})'}. This '
                      'message will be encrypted to the new key. Compare fingerprints before '
                      'sending anything sensitive.',
                      style: theme.textTheme.bodyMedium,
                    ),
                  ),
                  TextButton(
                    key: ValueKey('compose-key-changed-verify-${c.address}'),
                    onPressed: () => context.push(verifyRoute(c.address)),
                    child: const Text('Verify'),
                  ),
                ],
              ),
          ],
        ),
      ),
    );
  }
}
