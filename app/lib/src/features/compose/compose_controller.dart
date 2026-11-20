import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../policy/encryption_policy.dart';
import '../../providers/provider_table.dart';
import 'drafts.dart' show DraftsRevision, draftsRevisionProvider;

export '../../core/models.dart' show PartialSendException;

class RecipientEntry {
  const RecipientEntry(this.email, [this.info]);

  final String email;

  /// `null` while the key lookup is in flight.
  final RecipientKeyInfo? info;

  bool get resolving => info == null;
}

/// Where the saved copy of the message stands (autosave).
enum DraftSaveStatus {
  /// Not saved (nothing typed yet, or a message that is not a draft).
  none,
  saving,
  saved,

  /// The last save failed; [ComposeState.draftError] says why. The next edit tries again.
  failed,
}

class ComposeState {
  const ComposeState({
    this.accountId,
    this.recipients = const [],
    this.confirmedPlaintext = const {},
    this.guestMode = GuestMode.passphrase,
    this.subject = '',
    this.body = '',
    this.sending = false,
    this.error,
    this.inReplyTo,
    this.attachments = const [],
    this.compose = const ComposeOptions(),
    this.ccRecipients = const [],
    this.showCc = false,
    this.ccError,
    this.bccRecipients = const [],
    this.showBcc = false,
    this.bccError,
    this.draftId,
    this.draftStatus = DraftSaveStatus.none,
    this.draftError,
    this.draftSavedAt,
    this.notice,
  });

  final String? accountId;

  /// Reply / forward: what the engine adds on send (quote, forwarded message);
  /// the body holds only the new text.
  final ComposeOptions compose;
  final List<DraftAttachment> attachments;

  int get attachmentBytes => attachments.fold(0, (n, a) => n + a.data.length);

  /// Local id (or, for a resumed draft, Message-ID) of the message being replied to.
  final String? inReplyTo;
  final List<RecipientEntry> recipients;

  /// Cc: visible copies, decided per recipient like [recipients].
  final List<RecipientEntry> ccRecipients;

  /// The Cc field is open (the "Cc" link was used, or the message has Cc recipients).
  final bool showCc;

  /// Why the text typed in Cc was not added.
  final String? ccError;

  /// Bcc: hidden copies, decided per recipient like [recipients]. Each is sent a copy of
  /// their own, addressed to them alone ([ComposeController.send]).
  final List<RecipientEntry> bccRecipients;

  /// The Bcc field is open (the "Bcc" link was used, or the message has Bcc recipients).
  final bool showBcc;

  /// Why the text typed in Bcc was not added.
  final String? bccError;

  /// Lower-cased addresses for which the user explicitly accepted plaintext.
  final Set<String> confirmedPlaintext;

  /// How guest links of this message are protected (per message, G29).
  final GuestMode guestMode;
  final String subject;
  final String body;
  final bool sending;
  final String? error;

  /// The saved draft this message is stored as; null until the first save.
  final int? draftId;
  final DraftSaveStatus draftStatus;

  /// Why the last save failed.
  final String? draftError;

  /// When the draft was last saved (the engine's clock).
  final DateTime? draftSavedAt;

  /// Something the user should know about a resumed draft (missing files, a message kept
  /// after a failed save).
  final String? notice;

  /// To, Cc and Bcc.
  List<RecipientEntry> get allRecipients => [...recipients, ...ccRecipients, ...bccRecipients];

  /// Anything worth keeping as a draft: a recipient, a subject, text or a file.
  bool get hasContent =>
      recipients.isNotEmpty ||
      ccRecipients.isNotEmpty ||
      bccRecipients.isNotEmpty ||
      subject.trim().isNotEmpty ||
      body.trim().isNotEmpty ||
      attachments.isNotEmpty;

  MessagePlan get plan => EncryptionPolicy.plan([
    for (final r in allRecipients)
      if (r.info != null) r.info!,
  ], confirmedPlaintext: confirmedPlaintext);

  /// `null` while the recipient is still being looked up.
  RecipientStatus? statusOf(String email) {
    final lower = email.toLowerCase();
    for (final d in plan.recipients) {
      if (d.email.toLowerCase() == lower) return d.status;
    }
    return null;
  }

  bool get anyResolving => allRecipients.any((r) => r.resolving);

  bool get canSend => accountId != null && plan.canSend && !anyResolving && !sending;

  /// [canSend] given the guest-link modes the engine implements: a guest
  /// recipient is never sent a weaker link than the one selected.
  bool canSendWith(Set<GuestMode> supported) =>
      canSend && (!plan.needsPassphrase || supported.contains(guestMode));

  ComposeState copyWith({
    String? accountId,
    List<RecipientEntry>? recipients,
    Set<String>? confirmedPlaintext,
    GuestMode? guestMode,
    String? subject,
    String? body,
    bool? sending,
    String? error,
    bool clearError = false,
    String? inReplyTo,
    List<DraftAttachment>? attachments,
    ComposeOptions? compose,
    List<RecipientEntry>? ccRecipients,
    bool? showCc,
    String? ccError,
    bool clearCcError = false,
    List<RecipientEntry>? bccRecipients,
    bool? showBcc,
    String? bccError,
    bool clearBccError = false,
    int? draftId,
    bool clearDraftId = false,
    DraftSaveStatus? draftStatus,
    String? draftError,
    DateTime? draftSavedAt,
    String? notice,
  }) => ComposeState(
    compose: compose ?? this.compose,
    accountId: accountId ?? this.accountId,
    inReplyTo: inReplyTo ?? this.inReplyTo,
    attachments: attachments ?? this.attachments,
    recipients: recipients ?? this.recipients,
    confirmedPlaintext: confirmedPlaintext ?? this.confirmedPlaintext,
    guestMode: guestMode ?? this.guestMode,
    subject: subject ?? this.subject,
    body: body ?? this.body,
    sending: sending ?? this.sending,
    error: clearError ? null : (error ?? this.error),
    ccRecipients: ccRecipients ?? this.ccRecipients,
    showCc: showCc ?? this.showCc,
    ccError: clearCcError ? null : (ccError ?? this.ccError),
    bccRecipients: bccRecipients ?? this.bccRecipients,
    showBcc: showBcc ?? this.showBcc,
    bccError: clearBccError ? null : (bccError ?? this.bccError),
    draftId: clearDraftId ? null : (draftId ?? this.draftId),
    draftStatus: draftStatus ?? this.draftStatus,
    draftError: draftStatus != null && draftStatus != DraftSaveStatus.failed
        ? null
        : (draftError ?? this.draftError),
    draftSavedAt: draftSavedAt ?? this.draftSavedAt,
    notice: notice ?? this.notice,
  );
}

/// The saved-draft bookkeeping of one compose session (one `build` of the controller).
/// Kept apart from the notifier: the controller is rebuilt in place when compose switches
/// to another message, and a save started for the old message must neither read the new
/// message's state nor write into it.
class _DraftSession {
  _DraftSession(this.core, this.revision, this.unsaved);

  final CoreApi core;

  /// Keep-alive: still usable after this session's provider went away.
  final DraftsRevision revision;

  /// Keep-alive: where this message is kept when its save on leaving fails.
  final UnsavedCompose unsaved;

  /// Told when the save made on leaving fails (the screen's messenger outlives the screen).
  void Function(DraftLeaveFailure failure)? onLeaveFailure;

  /// The session's build is over: never touch the notifier's state again.
  bool disposed = false;

  /// Sent, discarded, or taken over by a later compose ([ComposeController.restoreUnsaved]):
  /// never saved from here again.
  bool closed = false;

  ComposeState latest = const ComposeState();
  Timer? autosave;

  /// Saves run one after another (an id handed back by one is used by the next).
  Future<void> queue = Future<void>.value();

  /// User edits so far, and the number the last save (or the resumed draft) covered.
  int edits = 0;
  int savedEdits = 0;
  int? draftId;

  /// Attachment paths the stored draft refers to (and copies kept for a save in flight):
  /// those a later save drops are released.
  Set<String> referenced = {};
}

class ComposeController extends Notifier<ComposeState> {
  /// How long editing must pause before the draft is saved.
  static const autosaveDelay = Duration(seconds: 2);

  late _DraftSession _s;

  /// Set by [send] when the message went out but its saved draft could not be removed.
  String? lastSendNote;

  @override
  ComposeState build() {
    final session = _s = _DraftSession(
      ref.read(coreApiProvider),
      ref.read(draftsRevisionProvider.notifier),
      ref.read(unsavedComposeProvider.notifier),
    );
    lastSendNote = null;
    ref.onDispose(() => _leave(session));
    return session.latest = const ComposeState();
  }

  /// Set by the compose screen: what to do when the save made on leaving it fails (a
  /// snackbar with Retry on its messenger, which outlives the screen). The message is kept
  /// either way ([unsavedComposeProvider]) and comes back in the next new compose.
  set onLeaveFailure(void Function(DraftLeaveFailure failure)? report) =>
      _s.onLeaveFailure = report;

  /// Every state change is the session's latest state, for the save on leaving (the
  /// notifier's state cannot be read once it is being disposed).
  @override
  set state(ComposeState value) {
    super.state = value;
    _s.latest = value;
  }

  CoreApi get _core => _s.core;

  // -- edits ------------------------------------------------------------------------

  /// The sending account, chosen by the app (first account, reply prefill).
  void setAccount(String accountId) => state = state.copyWith(accountId: accountId);

  /// The sending account, chosen by the user.
  void chooseAccount(String accountId) {
    setAccount(accountId);
    _touch();
  }

  void setSubject(String v) {
    state = state.copyWith(subject: v);
    _touch();
  }

  void setBody(String v) {
    state = state.copyWith(body: v);
    _touch();
  }

  /// Opens or closes the Cc field (closing keeps Cc recipients: the field stays open while
  /// there are any).
  void setShowCc(bool show) =>
      state = state.copyWith(showCc: show || state.ccRecipients.isNotEmpty, clearCcError: true);

  /// Opens or closes the Bcc field (it stays open while there are Bcc recipients).
  void setShowBcc(bool show) =>
      state = state.copyWith(showBcc: show || state.bccRecipients.isNotEmpty, clearBccError: true);

  /// Adds files (names made unique by a counter suffix when they collide).
  void addAttachments(List<DraftAttachment> files) {
    final names = {for (final a in state.attachments) a.name};
    final added = <DraftAttachment>[];
    for (final f in files) {
      var name = f.name;
      var n = 2;
      while (names.contains(name)) {
        final dot = f.name.lastIndexOf('.');
        name = dot > 0
            ? '${f.name.substring(0, dot)} ($n)${f.name.substring(dot)}'
            : '${f.name} ($n)';
        n++;
      }
      names.add(name);
      added.add(
        name == f.name
            ? f
            : DraftAttachment(
                name: name,
                contentType: f.contentType,
                data: f.data,
                storedPath: f.storedPath,
              ),
      );
    }
    state = state.copyWith(attachments: [...state.attachments, ...added]);
    _touch();
  }

  void removeAttachment(String name) {
    state = state.copyWith(
      attachments: [
        for (final a in state.attachments)
          if (a.name != name) a,
      ],
    );
    _touch();
  }

  /// Adds one address to To (with [cc] to Cc, with [bcc] to Bcc; trailing separators
  /// tolerated) and resolves its key. An address already on the message is not added twice.
  /// Returns `false` if the input is not an address.
  Future<bool> addRecipient(String raw, {bool cc = false, bool bcc = false}) =>
      _addRecipient(raw, line: bcc ? _Line.bcc : (cc ? _Line.cc : _Line.to), edit: true);

  Future<bool> _addRecipient(String raw, {required _Line line, required bool edit}) async {
    if (!ref.mounted) return false;
    final email = raw.trim().replaceAll(RegExp(r'[,;\s]+$'), '').trim();
    if (!isValidEmail(email)) {
      if (email.isNotEmpty) {
        final why = '"$email" is not an email address';
        state = switch (line) {
          _Line.to => state.copyWith(error: why),
          _Line.cc => state.copyWith(ccError: why),
          _Line.bcc => state.copyWith(bccError: why),
        };
      }
      return false;
    }
    final lower = email.toLowerCase();
    if (state.allRecipients.any((r) => r.email.toLowerCase() == lower)) {
      return true;
    }
    final entry = RecipientEntry(email);
    state = switch (line) {
      _Line.to => state.copyWith(recipients: [...state.recipients, entry], clearError: true),
      _Line.cc => state.copyWith(
        ccRecipients: [...state.ccRecipients, entry],
        showCc: true,
        clearCcError: true,
      ),
      _Line.bcc => state.copyWith(
        bccRecipients: [...state.bccRecipients, entry],
        showBcc: true,
        clearBccError: true,
      ),
    };
    if (edit) _touch();
    final session = _s;
    final info = await _core.lookupRecipientKey(email);
    if (!ref.mounted || session.disposed) return true;
    List<RecipientEntry> resolved(List<RecipientEntry> list) => [
      for (final r in list)
        if (r.email.toLowerCase() == lower) RecipientEntry(email, info) else r,
    ];
    state = state.copyWith(
      recipients: resolved(state.recipients),
      ccRecipients: resolved(state.ccRecipients),
      bccRecipients: resolved(state.bccRecipients),
    );
    return true;
  }

  void removeRecipient(String email) {
    final lower = email.toLowerCase();
    List<RecipientEntry> without(List<RecipientEntry> list) => [
      for (final r in list)
        if (r.email.toLowerCase() != lower) r,
    ];
    state = state.copyWith(
      recipients: without(state.recipients),
      ccRecipients: without(state.ccRecipients),
      bccRecipients: without(state.bccRecipients),
      confirmedPlaintext: {...state.confirmedPlaintext}..remove(lower),
    );
    _touch();
  }

  /// Only ever called after the user confirmed the warning dialog.
  void confirmPlaintext(String email) {
    state = state.copyWith(confirmedPlaintext: {...state.confirmedPlaintext, email.toLowerCase()});
  }

  void revokePlaintext(String email) {
    state = state.copyWith(
      confirmedPlaintext: {...state.confirmedPlaintext}..remove(email.toLowerCase()),
    );
  }

  void setGuestMode(GuestMode mode) {
    state = state.copyWith(guestMode: mode);
    _touch();
  }

  // -- prefill ----------------------------------------------------------------------

  /// Pre-fills a reply: recipient = the last sender that is not one of our
  /// accounts, subject `Re:`, and `ComposeOptions.reply()`: the engine quotes
  /// the original itself (on send and in the preview), so the body starts empty.
  Future<void> prefillReply(MailThread thread, List<Account> accounts) async {
    final mine = {for (final a in accounts) a.email.toLowerCase()};
    final last = thread.messages.lastWhere(
      (m) => !mine.contains(m.from.email.toLowerCase()),
      orElse: () => thread.latest,
    );
    final subject = thread.subject.startsWith(RegExp(r'^re:', caseSensitive: false))
        ? thread.subject
        : 'Re: ${thread.subject}';
    state = state.copyWith(
      accountId: thread.accountId,
      subject: subject,
      body: '',
      inReplyTo: last.id,
      compose: const ComposeOptions.reply(),
    );
    await _addRecipient(last.from.email, line: _Line.to, edit: false);
  }

  /// Pre-fills a forward of [message]: subject `Fwd:`, no recipient yet, and
  /// `ComposeOptions.forward`: the engine adds the original's headers, text and
  /// attachments below the typed text.
  void prefillForward(Message message, List<Account> accounts) {
    final subject = message.subject.startsWith(RegExp(r'^(fwd?|fw):', caseSensitive: false))
        ? message.subject
        : 'Fwd: ${message.subject}';
    final own = accounts.any((a) => a.id == message.accountId);
    state = state.copyWith(
      accountId: own ? message.accountId : state.accountId,
      subject: subject,
      body: '',
      compose: ComposeOptions.forward(message.id),
    );
  }

  /// Opens saved draft [d] for editing: account, recipients (To, Cc and Bcc; keys looked up
  /// again), subject, text, reply / forward context, guest-link mode and files. A file that
  /// is gone is left out and named in [ComposeState.notice]; plaintext consent is never
  /// stored, so a recipient without a key is a guest-link recipient again.
  Future<void> resume(SavedDraft d) async {
    final session = _s;
    final files = <DraftAttachment>[];
    final missing = <String>[];
    for (final a in d.attachments) {
      try {
        files.add(
          DraftAttachment(
            name: a.displayName,
            contentType: a.contentType.isEmpty ? 'application/octet-stream' : a.contentType,
            data: await _core.readDraftAttachment(a.path),
            storedPath: a.path,
          ),
        );
      } catch (_) {
        missing.add(a.displayName);
      }
    }
    if (!ref.mounted || session.disposed || !identical(session, _s)) return;
    session.draftId = d.id;
    session.referenced = {for (final a in d.attachments) a.path};
    session.savedEdits = session.edits;
    final notes = [
      if (missing.isNotEmpty)
        'Not found any more, so not attached: ${missing.join(', ')} '
            '(the file was moved or deleted).',
      if (d.remoteFiles > 0)
        '${d.remoteFiles == 1 ? 'A file' : '${d.remoteFiles} files'} attached on the device '
            'that saved this draft ${d.remoteFiles == 1 ? 'is' : 'are'} not here: a file picked '
            'there stays on that device. Attach ${d.remoteFiles == 1 ? 'it' : 'them'} again to '
            'send ${d.remoteFiles == 1 ? 'it' : 'them'}.',
    ];
    state = ComposeState(
      accountId: d.accountId,
      subject: d.subject,
      body: d.body,
      inReplyTo: d.inReplyTo,
      compose: ComposeOptions(
        kind: d.kind,
        quote: d.quote,
        forwardOf: d.forwardOf,
        skipSignature: d.noSignature,
      ),
      guestMode: d.guestMode,
      attachments: files,
      showCc: d.cc.isNotEmpty,
      showBcc: d.bcc.isNotEmpty,
      draftId: d.id,
      draftStatus: DraftSaveStatus.saved,
      draftSavedAt: d.updatedAt,
      notice: notes.isEmpty ? null : notes.join('\n'),
    );
    // Compose may be left (or switched to another message) while the keys are looked up.
    bool gone() => !ref.mounted || session.disposed || !identical(session, _s);
    for (final (line, list) in [(_Line.to, d.to), (_Line.cc, d.cc), (_Line.bcc, d.bcc)]) {
      for (final a in list) {
        if (gone()) return;
        await _addRecipient(a, line: line, edit: false);
      }
    }
  }

  // -- the message --------------------------------------------------------------------

  /// The draft as it stands (what [send] and the preview hand to the engine);
  /// null without a sending account.
  DraftMessage? draft() {
    final s = state;
    final accountId = s.accountId;
    if (accountId == null) return null;
    return DraftMessage(
      accountId: accountId,
      to: [for (final r in s.recipients) r.email],
      cc: [for (final r in s.ccRecipients) r.email],
      subject: s.subject,
      body: s.body,
      guestMode: s.guestMode,
      plaintextConfirmedFor: s.plan.plaintextRecipients.toSet(),
      inReplyTo: s.inReplyTo,
      attachments: s.attachments,
      compose: s.compose,
    );
  }

  /// Sends through the per-recipient send path (`CoreApi.send`): To and Cc as one message,
  /// then every Bcc recipient a copy of their own, addressed to them alone and protected for
  /// them like any recipient (key → encrypted, none → guest link, confirmed → plaintext).
  /// So nobody learns of a Bcc recipient: one OpenPGP message encrypted to a Bcc key would
  /// show that key's id to everyone it went to. Then the saved draft and its file copies
  /// are deleted. A save still in flight finishes first, so the draft it writes is the one
  /// deleted. A failed send keeps the draft; when only part went out
  /// ([PartialSendException]: a Bcc copy, or a group of one core send, failed after the
  /// rest) those who got it leave the message (and its draft), so sending again cannot
  /// send anyone a second copy.
  Future<SendReceipt> send() async {
    final s = state;
    final draft = this.draft();
    if (draft == null || !s.canSend) {
      throw StateError('message is not ready to send');
    }
    final session = _s;
    session.autosave?.cancel();
    lastSendNote = null;
    state = s.copyWith(sending: true, clearError: true);
    try {
      await session.queue;
      final receipts = <SendReceipt>[];
      final delivered = <String>[];
      try {
        if (draft.to.isNotEmpty || draft.cc.isNotEmpty) {
          receipts.add(await session.core.send(draft));
          delivered.addAll([...draft.to, ...draft.cc]);
        }
        for (final r in s.bccRecipients) {
          receipts.add(await session.core.send(_bccCopy(draft, r.email)));
          delivered.add(r.email);
        }
      } catch (e) {
        if (e is PartialSendException) {
          // The core sends one message as up to three groups (encrypted, guest link,
          // plaintext): those before the failing one went out.
          receipts.add(e.sent);
          delivered.addAll([...e.sent.encryptedTo, ...e.sent.guestLinkTo, ...e.sent.plaintextTo]);
        }
        if (delivered.isEmpty) rethrow;
        final sentTo = {for (final a in delivered) a.toLowerCase()};
        _dropRecipients(session, sentTo);
        throw PartialSendException(
          sent: _merged(receipts),
          notSentTo: [
            for (final r in s.allRecipients)
              if (!sentTo.contains(r.email.toLowerCase())) r.email,
          ],
          reason: e is PartialSendException ? e.reason : friendlyError(e),
        );
      }
      final receipt = _merged(receipts);
      session.closed = true;
      session.autosave?.cancel();
      try {
        await _dropStoredDraft(session);
      } catch (e) {
        lastSendNote = 'the saved draft could not be removed: ${friendlyError(e)}';
      }
      return receipt;
    } finally {
      if (ref.mounted && !session.disposed) state = state.copyWith(sending: false);
    }
  }

  /// Bcc recipient [to]'s own copy of [d]: addressed to them alone, their plaintext consent
  /// only.
  static DraftMessage _bccCopy(DraftMessage d, String to) => DraftMessage(
    accountId: d.accountId,
    to: [to],
    subject: d.subject,
    body: d.body,
    guestMode: d.guestMode,
    plaintextConfirmedFor: {
      for (final a in d.plaintextConfirmedFor)
        if (a.toLowerCase() == to.toLowerCase()) a,
    },
    inReplyTo: d.inReplyTo,
    attachments: d.attachments,
    compose: d.compose,
  );

  /// One receipt for the sends of one message (To/Cc, then each Bcc copy).
  static SendReceipt _merged(List<SendReceipt> receipts) {
    if (receipts.isEmpty) throw StateError('no recipients');
    if (receipts.length == 1) return receipts.single;
    return SendReceipt(
      encryptedTo: [for (final r in receipts) ...r.encryptedTo],
      guestLinkTo: [for (final r in receipts) ...r.guestLinkTo],
      plaintextTo: [for (final r in receipts) ...r.plaintextTo],
      messageId: receipts.first.messageId,
      guestLinks: [for (final r in receipts) ...r.guestLinks],
      sentCopyAppended: receipts.every((r) => r.sentCopyAppended),
    );
  }

  /// After a partial send: the recipients in [sentTo] (lower-cased) leave the message and
  /// its saved draft, even when compose was left meanwhile.
  void _dropRecipients(_DraftSession s, Set<String> sentTo) {
    List<RecipientEntry> keep(List<RecipientEntry> list) => [
      for (final r in list)
        if (!sentTo.contains(r.email.toLowerCase())) r,
    ];
    final st = s.latest;
    final next = st.copyWith(
      recipients: keep(st.recipients),
      ccRecipients: keep(st.ccRecipients),
      bccRecipients: keep(st.bccRecipients),
      // As when a pill is removed: plaintext consent leaves with its recipient, so adding
      // them again asks again.
      confirmedPlaintext: {...st.confirmedPlaintext}..removeAll(sentTo),
    );
    if (!s.disposed && identical(s, _s) && ref.mounted) {
      state = next;
    } else {
      s.latest = next;
    }
    s.edits++;
    unawaited(_enqueueSave(s));
  }

  /// Throws the message away: the saved draft (if any) and the copies of its files are
  /// deleted, and this session never saves again.
  Future<void> discard() async {
    final session = _s;
    session.closed = true;
    session.autosave?.cancel();
    await _dropStoredDraft(session);
  }

  Future<void> _dropStoredDraft(_DraftSession s) async {
    await s.queue;
    final id = s.draftId;
    s.draftId = null;
    if (id != null) {
      await s.core.deleteDraft(id);
      s.revision.bump();
    }
    for (final p in s.referenced) {
      await s.core.releaseDraftAttachment(p);
    }
    s.referenced = {};
  }

  // -- autosave -----------------------------------------------------------------------

  /// A user edit: the draft is saved [autosaveDelay] after the last one.
  void _touch() {
    final s = _s;
    if (s.closed || s.disposed) return;
    s.edits++;
    s.autosave?.cancel();
    if (!s.core.supportsDrafts) return;
    s.autosave = Timer(autosaveDelay, () => _enqueueSave(s));
  }

  /// Saves now when anything changed since the last save (the screen calls it on leaving
  /// as well; the controller saves by itself after [autosaveDelay]).
  Future<void> saveDraftNow() => _enqueueSave(_s);

  /// Queues a save of the session's latest state; completes with null once saved (or when
  /// there was nothing to save), with the reason otherwise.
  Future<String?> _enqueueSave(_DraftSession s) {
    s.autosave?.cancel();
    final snapshot = s.latest;
    final edits = s.edits;
    final run = s.queue.then((_) => _save(s, snapshot, edits));
    s.queue = run;
    return run;
  }

  /// Leaving compose (or switching it to another message): what is unsaved is saved. A
  /// failure is not silent: the message is kept for the next compose and the screen is told
  /// ([onLeaveFailure]).
  void _leave(_DraftSession s) {
    s.disposed = true;
    s.autosave?.cancel();
    if (s.closed || s.edits <= s.savedEdits || !s.core.supportsDrafts) return;
    _enqueueSave(s).then((error) {
      if (error != null) _leaveFailed(s, error);
    });
  }

  /// The save of a left message failed: keep it ([unsavedComposeProvider]) and report it
  /// with a retry. Runs after the provider is gone: touches only the session.
  void _leaveFailed(_DraftSession s, String error) {
    if (s.closed) return;
    s.unsaved._keep(s, error);
    s.onLeaveFailure?.call(DraftLeaveFailure._(error, () => _retryLeft(s)));
  }

  /// "Retry" on a failed save after leaving: true once saved. Another failure is reported
  /// again; a message a later compose took over is not saved from here (false).
  Future<bool> _retryLeft(_DraftSession s) async {
    if (s.closed) return false;
    final error = await _enqueueSave(s);
    if (s.closed) return false;
    if (error != null) {
      _leaveFailed(s, error);
      return false;
    }
    s.unsaved._release(s);
    return true;
  }

  /// A new message: takes over the latest message whose save failed after compose was left
  /// ([unsavedComposeProvider]), with a note saying so, its saved draft (if an earlier save
  /// worked) and its file copies, and saves it again at once. False when there is none.
  Future<bool> restoreUnsaved() async {
    final session = _s;
    final kept = session.unsaved._take();
    if (kept == null) return false;
    final old = kept._session;
    old.closed = true; // its Retry no longer saves: this compose owns the message now
    await old.queue; // a retry in flight lands first, so its draft id is the one continued
    if (!ref.mounted || session.disposed || !identical(session, _s)) {
      // Left again before it was shown: keep it for the next compose.
      old.closed = false;
      session.unsaved._keep(old, kept.error);
      return false;
    }
    session.draftId = old.draftId;
    session.referenced = {...old.referenced};
    final was = old.latest;
    state = was.copyWith(
      draftId: old.draftId,
      clearDraftId: old.draftId == null,
      draftStatus: DraftSaveStatus.failed,
      draftError: kept.error,
      notice: [
        'This message could not be saved as a draft when you left it (${kept.error}), '
            'so it was kept here.',
        ?was.notice,
      ].join('\n'),
    );
    session.edits++;
    await _enqueueSave(session);
    return true;
  }

  /// Applies [change] while [s] is the live session (never after it was disposed).
  void _update(_DraftSession s, ComposeState Function(ComposeState) change) {
    if (s.disposed || !identical(s, _s) || !ref.mounted) return;
    state = change(state);
  }

  /// Saves [snap] (covering [edits] edits): files picked in compose are first copied to
  /// app-private storage so the draft can reference them by path; a message whose content
  /// was all erased deletes its draft instead. Never throws: a failure is the state's
  /// [DraftSaveStatus.failed] (the next edit tries again) and the returned reason; null when
  /// saved or when there was nothing to save.
  Future<String?> _save(_DraftSession s, ComposeState snap, int edits) async {
    if (s.closed || edits <= s.savedEdits || snap.accountId == null) return null;
    if (!snap.hasContent) {
      final id = s.draftId;
      if (id != null) {
        try {
          await s.core.deleteDraft(id);
          s.draftId = null;
          s.revision.bump();
          _update(s, (st) => st.copyWith(clearDraftId: true, draftStatus: DraftSaveStatus.none));
        } catch (_) {
          // Kept: an empty draft is harmless, the next save replaces it.
        }
      }
      s.savedEdits = edits;
      return null;
    }
    _update(s, (st) => st.copyWith(draftStatus: DraftSaveStatus.saving));
    try {
      final files = <DraftAttachment>[];
      for (final a in snap.attachments) {
        if (a.storedPath != null) {
          files.add(a);
          continue;
        }
        final kept = a.storedAt(await s.core.keepDraftAttachment(a.name, a.data));
        s.referenced.add(kept.storedPath!);
        files.add(kept);
      }
      // The copies belong to the files on screen too (the same bytes), so they are not
      // copied again by the next save.
      _update(
        s,
        (st) => st.copyWith(
          attachments: [
            for (final a in st.attachments)
              a.storedPath != null
                  ? a
                  : files.firstWhere((f) => identical(f.data, a.data), orElse: () => a),
          ],
        ),
      );
      final saved = await s.core.saveDraft(_inputOf(snap, files, s.draftId));
      s.draftId = saved.id;
      s.savedEdits = edits;
      final now = {for (final a in saved.attachments) a.path};
      for (final p in s.referenced.difference(now)) {
        await s.core.releaseDraftAttachment(p);
      }
      s.referenced = now;
      s.revision.bump();
      _update(
        s,
        (st) => st.copyWith(
          draftId: saved.id,
          draftStatus: DraftSaveStatus.saved,
          draftSavedAt: saved.updatedAt,
        ),
      );
      return null;
    } catch (e) {
      final why = friendlyError(e);
      _update(s, (st) => st.copyWith(draftStatus: DraftSaveStatus.failed, draftError: why));
      return why;
    }
  }

  /// The draft input for [st] with its files stored at [files]' paths. Plaintext consent
  /// is not stored, and the policy for the engine's own `sendDraft` is never plaintext:
  /// guest link when someone has no key, otherwise "encrypt or refuse".
  static DraftInput _inputOf(ComposeState st, List<DraftAttachment> files, int? id) => DraftInput(
    id: id,
    accountId: st.accountId!,
    kind: st.compose.kind,
    inReplyTo: st.inReplyTo,
    forwardOf: st.compose.kind == ComposeKind.forward ? st.compose.forwardOf : null,
    quote: st.compose.quote,
    to: [for (final r in st.recipients) r.email],
    cc: [for (final r in st.ccRecipients) r.email],
    bcc: [for (final r in st.bccRecipients) r.email],
    subject: st.subject,
    body: st.body,
    attachments: [
      for (final a in files)
        SavedDraftAttachment(path: a.storedPath!, name: a.name, contentType: a.contentType),
    ],
    policy: st.plan.guestRecipients.isNotEmpty || st.plan.plaintextRecipients.isNotEmpty
        ? SendPolicy.guestLink
        : SendPolicy.auto,
    guestMode: st.guestMode,
    noSignature: st.compose.skipSignature,
  );
}

final composeControllerProvider = NotifierProvider.autoDispose<ComposeController, ComposeState>(
  ComposeController.new,
);

/// Which line of the message a recipient is on.
enum _Line { to, cc, bcc }

/// A save that failed after compose was left ([ComposeController.onLeaveFailure]).
class DraftLeaveFailure {
  DraftLeaveFailure._(this.error, this._retry);

  /// Why the save failed.
  final String error;
  final Future<bool> Function() _retry;

  /// Saves the message again: true once it is saved. Another failure is reported again; a
  /// message a later compose took over is not saved from here (false).
  Future<bool> retry() => _retry();
}

/// Messages whose save failed after compose was left, newest last. Kept in memory only (never
/// written anywhere else) until a retry saves one or a new compose takes it over
/// ([ComposeController.restoreUnsaved]), so typed text is not lost to a failing save.
/// Keep-alive: a left compose session reports here after its own provider is gone.
final unsavedComposeProvider = NotifierProvider<UnsavedCompose, List<UnsavedMessage>>(
  UnsavedCompose.new,
);

class UnsavedCompose extends Notifier<List<UnsavedMessage>> {
  @override
  List<UnsavedMessage> build() => const [];

  void _keep(_DraftSession s, String error) {
    if (!ref.mounted) return;
    state = [
      for (final m in state)
        if (!identical(m._session, s)) m,
      UnsavedMessage._(s, error),
    ];
  }

  void _release(_DraftSession s) {
    if (!ref.mounted) return;
    state = [
      for (final m in state)
        if (!identical(m._session, s)) m,
    ];
  }

  UnsavedMessage? _take() {
    if (!ref.mounted || state.isEmpty) return null;
    final last = state.last;
    state = state.sublist(0, state.length - 1);
    return last;
  }
}

/// One message kept by [unsavedComposeProvider].
class UnsavedMessage {
  UnsavedMessage._(this._session, this.error);

  final _DraftSession _session;

  /// Why its last save failed.
  final String error;

  /// What compose held when it was left.
  ComposeState get message => _session.latest;
}
