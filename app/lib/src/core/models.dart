/// Plain Dart models shared by every `CoreApi` implementation and the UI.
///
/// They mirror what `sealbox-core` exposes over the bridge (`FrbCore` converts the
/// generated bridge types into these). Keeping them hand-written means screens and
/// tests do not depend on the native library.
library;

import 'dart:typed_data';

import '../providers/provider_table.dart';

/// Lock state of a received message, as shown by the inbox badge.
enum EncryptionState {
  /// `multipart/encrypted` (PGP/MIME) that we decrypted; signature verified if signed.
  encrypted,

  /// Cleartext body with a valid OpenPGP signature (`multipart/signed`).
  signed,

  /// Ordinary unencrypted email.
  plaintext,

  /// Encrypted, but not to any key we hold (or malformed): the body is unreadable.
  undecryptable,
}

/// Signature verdict of a message.
enum SignatureState { none, good, bad, unknownKey }

/// How a recipient's public key became known to us.
enum KeySource {
  /// The peer's own `Autocrypt:` header.
  autocrypt,

  /// An `Autocrypt-Gossip:` header from a third party.
  gossip,

  /// Imported by hand (pasted or from a file).
  imported,

  /// The Sealbox key directory.
  directory,
  wkd,
  keyserver,

  /// One of our own accounts.
  own,
}

class Contact {
  const Contact({required this.email, this.name});

  final String email;
  final String? name;

  String get display => (name == null || name!.trim().isEmpty) ? email : name!;

  String get initial {
    final d = display.trim();
    return d.isEmpty ? '?' : d[0].toUpperCase();
  }

  @override
  String toString() => name == null ? email : '$name <$email>';
}

class Account {
  const Account({
    required this.id,
    required this.email,
    required this.displayName,
    required this.providerName,
    required this.authMethod,
    required this.imapHost,
    required this.smtpHost,
    this.fingerprint,
    this.createdAt,
    this.login,
    this.imapPort,
    this.smtpPort,
  });

  /// The engine addresses accounts by e-mail; `FrbCore` uses the address as id.
  final String id;
  final String email;
  final String displayName;
  final String providerName;
  final AuthMethod authMethod;
  final String imapHost;
  final String smtpHost;

  /// Fingerprint of the account's OpenPGP identity (null until the engine made one).
  final String? fingerprint;
  final DateTime? createdAt;
  final String? login;
  final int? imapPort;
  final int? smtpPort;

  String get imapLabel => imapPort == null ? imapHost : '$imapHost:$imapPort';
  String get smtpLabel => smtpPort == null ? smtpHost : '$smtpHost:$smtpPort';
}

/// Attachment metadata (bytes come from `CoreApi.getAttachment`).
class AttachmentMeta {
  const AttachmentMeta({
    required this.index,
    required this.filename,
    required this.contentType,
    required this.size,
    this.contentId,
  });

  final int index;
  final String filename;
  final String contentType;
  final int size;

  /// The part's `Content-ID` without angle brackets, when it has one: what a `cid:` image in
  /// the HTML body names (an inline image, docs/HTML_MAIL.md). `null` for a part without one
  /// and for mail stored before the engine kept it.
  final String? contentId;

  String get sizeLabel {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

class AttachmentBytes {
  const AttachmentBytes({required this.meta, required this.data});

  final AttachmentMeta meta;
  final Uint8List data;
}

/// The displayable HTML of one message (`CoreMailOps.messageHtml`, docs/HTML_MAIL.md).
///
/// [Message.body] is the plain-text view; this is the HTML a message screen may render —
/// sanitized by the engine, with every remote image blocked unless the user asked for them.
class HtmlBody {
  const HtmlBody({required this.html, this.remoteImages = 0, this.text = ''});

  /// Sanitized markup: allow-listed tags only, no script, no CSS, links `http(s)`/`mailto`,
  /// images `cid:` / `data:image/*` and — only when images were allowed — `http(s)`.
  final String html;

  /// Remote images in the message. While blocked each one is a
  /// `<span class="sealbox-blocked-image" data-src="…"></span>` in [html], so the UI can
  /// offer "N images blocked · Load images" and nothing is fetched until it does.
  final int remoteImages;

  /// The same content as plain text (snippets, quoting, accessibility).
  final String text;

  /// Is a remote image still waiting to be loaded?
  bool get hasBlockedImages => remoteImages > 0 && html.contains(blockedImageClass);

  /// The class the engine marks a blocked remote image with.
  static const String blockedImageClass = 'sealbox-blocked-image';

  @override
  bool operator ==(Object other) =>
      other is HtmlBody &&
      other.html == html &&
      other.remoteImages == remoteImages &&
      other.text == text;

  @override
  int get hashCode => Object.hash(html, remoteImages, text);

  @override
  String toString() => 'HtmlBody(${html.length} chars, $remoteImages remote)';
}

class Message {
  const Message({
    required this.id,
    required this.threadId,
    required this.accountId,
    required this.from,
    required this.to,
    required this.subject,
    required this.body,
    required this.date,
    required this.state,
    this.signer,
    this.unread = false,
    this.cc = const [],
    this.folder = 'INBOX',
    this.uid = 0,
    this.signatureState,
    this.attachments = const [],
    this.decryptError,
    this.messageId,
    this.keyChanged = false,
    this.signerVerified = false,
    this.guestLink = false,
    this.inReplyTo = const [],
    this.references = const [],
    this.engineThreadId,
    this.signerAddress,
    this.protectedSubject = false,
    this.engineSnippet,
  });

  final String id;

  /// The UI's conversation id ([MailThread.id], routes `/inbox/t/<id>`). `FrbCore` derives
  /// it from [engineThreadId] (reference threading, `threading.dart`); messages without
  /// one (sample data) group by account + normalised subject.
  final String threadId;
  final String accountId;
  final Contact from;
  final List<Contact> to;
  final List<Contact> cc;
  final String subject;
  final String body;
  final DateTime date;
  final EncryptionState state;

  /// Fingerprint of the verified signer, when the message is signed and verified.
  final String? signer;

  /// Address the signing key belongs to, when the engine knows it
  /// (`SignatureSummary.signer`); the thread view says "signed by <address>".
  final String? signerAddress;
  final bool unread;

  /// IMAP folder the message lives in (`INBOX`, `Sent`, …).
  final String folder;
  final int uid;
  /// Explicit signature verdict from the engine (null for sample data).
  final SignatureState? signatureState;
  final List<AttachmentMeta> attachments;

  /// [signatureState] when given; otherwise "good" whenever a verified
  /// [signer] is known (sample data only sets the fingerprint).
  SignatureState get signature =>
      signatureState ?? (signer != null ? SignatureState.good : SignatureState.none);

  /// Why decryption failed, for [EncryptionState.undecryptable].
  final String? decryptError;
  final String? messageId;

  /// G30: the sender's key differs from the one seen before (engine
  /// `SignatureSummary.key_changed`, kept on this message for good).
  final bool keyChanged;

  /// G30: good signature by exactly the key the user verified for the sender.
  final bool signerVerified;

  /// A sent message that went out as a guest link (offers "Resend link").
  final bool guestLink;

  /// `In-Reply-To` of the message, angle brackets stripped (engine summary).
  final List<String> inReplyTo;

  /// `References` of the message, oldest first, angle brackets stripped.
  final List<String> references;

  /// The engine's conversation key (`MessageSummary.thread_id`): the Message-ID of the
  /// earliest known ancestor in this account, following References / In-Reply-To through
  /// the stored mail (a parent that arrives later pulls its replies in). Scoped to
  /// [accountId]. Null for sample data. Not the same as [threadId].
  final String? engineThreadId;

  /// [subject] came from inside the ciphertext (protected headers, engine
  /// `MessageSummary.protected_subject`). An encrypted message without it still
  /// carries the outer placeholder (`...`) the sender's client put there.
  final bool protectedSubject;

  /// The list preview the engine stored with the message (`MessageSummary.snippet`: the
  /// first 160 characters of the text, HTML reduced to text, whitespace collapsed). With it
  /// a list row needs no body; null for sample data and for mail without a readable body
  /// (`FrbCore` then reads the message, as it did before snippets existed).
  final String? engineSnippet;

  bool get isSent => folder.toLowerCase() != 'inbox';

  /// What a list row shows of the message: [engineSnippet] when the engine has one, else the
  /// start of [body]; whitespace collapsed, at most 120 characters.
  String get snippet {
    final flat = (engineSnippet ?? body).replaceAll(RegExp(r'\s+'), ' ').trim();
    return flat.length <= 120 ? flat : '${flat.substring(0, 117)}…';
  }

  Message copyWith({
    String? body,
    bool? unread,
    List<AttachmentMeta>? attachments,
    bool? keyChanged,
    bool? signerVerified,
    bool? guestLink,
    String? signer,
    String? folder,
  }) =>
      Message(
        id: id,
        threadId: threadId,
        accountId: accountId,
        from: from,
        to: to,
        cc: cc,
        subject: subject,
        body: body ?? this.body,
        date: date,
        state: state,
        signer: signer ?? this.signer,
        unread: unread ?? this.unread,
        folder: folder ?? this.folder,
        uid: uid,
        signatureState: signatureState,
        attachments: attachments ?? this.attachments,
        decryptError: decryptError,
        messageId: messageId,
        keyChanged: keyChanged ?? this.keyChanged,
        signerVerified: signerVerified ?? this.signerVerified,
        guestLink: guestLink ?? this.guestLink,
        inReplyTo: inReplyTo,
        references: references,
        engineThreadId: engineThreadId,
        signerAddress: signerAddress,
        protectedSubject: protectedSubject,
        engineSnippet: engineSnippet,
      );
}

class MailThread {
  MailThread({
    required this.id,
    required this.subject,
    required this.accountId,
    required List<Message> messages,
  }) : messages = List.unmodifiable(
         [...messages]..sort((a, b) => a.date.compareTo(b.date)),
       );

  final String id;
  final String subject;
  final String accountId;

  /// Oldest first.
  final List<Message> messages;

  Message get latest => messages.last;
  bool get unread => messages.any((m) => m.unread);

  /// The badge shown in the list reflects the newest message.
  EncryptionState get state => latest.state;

  List<Contact> get participants {
    final seen = <String>{};
    return [
      for (final m in messages)
        if (seen.add(m.from.email.toLowerCase())) m.from,
    ];
  }
}

/// Result of a recipient key lookup (own accounts → Autocrypt → imported → directory).
class RecipientKeyInfo {
  const RecipientKeyInfo({
    required this.email,
    required this.hasKey,
    this.source,
    this.fingerprint,
  });

  const RecipientKeyInfo.unknown(this.email)
    : hasKey = false,
      source = null,
      fingerprint = null;

  final String email;
  final bool hasKey;
  final KeySource? source;
  final String? fingerprint;
}

/// Somebody we hold a key or Autocrypt state for (Settings → Contacts & keys).
class ContactKey {
  const ContactKey({
    required this.address,
    required this.hasKey,
    required this.source,
    this.fingerprint,
    this.preferEncrypt = false,
    this.lastSeen,
    this.verified = false,
    this.verifiedAt,
    this.keyChangedAt,
    this.previousFingerprint,
  });

  final String address;
  final bool hasKey;
  final KeySource source;
  final String? fingerprint;

  /// The peer announced `prefer-encrypt=mutual`.
  final bool preferEncrypt;
  final DateTime? lastSeen;

  /// G30: the user compared the current key out of band.
  final bool verified;
  final DateTime? verifiedAt;

  /// G30: a message brought a different key and the user has not decided yet
  /// (cleared by "Accept new key" or by verifying).
  final DateTime? keyChangedAt;

  /// The key trusted until the change.
  final String? previousFingerprint;

  bool get keyChangePending => keyChangedAt != null;

  ContactKey copyWith({
    String? fingerprint,
    bool? verified,
    DateTime? verifiedAt,
    DateTime? keyChangedAt,
    String? previousFingerprint,
    bool clearVerifiedAt = false,
    bool clearKeyChange = false,
  }) => ContactKey(
    address: address,
    hasKey: hasKey,
    source: source,
    fingerprint: fingerprint ?? this.fingerprint,
    preferEncrypt: preferEncrypt,
    lastSeen: lastSeen,
    verified: verified ?? this.verified,
    verifiedAt: clearVerifiedAt ? null : (verifiedAt ?? this.verifiedAt),
    keyChangedAt: clearKeyChange ? null : (keyChangedAt ?? this.keyChangedAt),
    previousFingerprint: clearKeyChange ? null : (previousFingerprint ?? this.previousFingerprint),
  );
}

/// `XXXX XXXX …` grouping of a hex fingerprint for display.
String groupFingerprint(String fingerprint) {
  final hex = fingerprint.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '').toUpperCase();
  final b = StringBuffer();
  for (var i = 0; i < hex.length; i += 4) {
    if (i > 0) b.write(' ');
    b.write(hex.substring(i, i + 4 > hex.length ? hex.length : i + 4));
  }
  return b.toString();
}

/// A freshly generated (or the stored) identity key, as the UI shows it.
class IdentityPreview {
  const IdentityPreview({
    required this.fingerprint,
    required this.createdAt,
    this.email,
  });

  /// Upper-case hex, no spaces (40 chars for a v4 key). Empty = no key yet.
  final String fingerprint;
  final DateTime createdAt;
  final String? email;

  bool get isEmpty => fingerprint.isEmpty;

  /// `XXXX XXXX XXXX …` grouping for display.
  String get grouped {
    final b = StringBuffer();
    for (var i = 0; i < fingerprint.length; i += 4) {
      if (i > 0) b.write(' ');
      b.write(
        fingerprint.substring(
          i,
          i + 4 > fingerprint.length ? fingerprint.length : i + 4,
        ),
      );
    }
    return b.toString();
  }
}

class CoreInfo {
  const CoreInfo({required this.version, required this.greeting});

  final String version;
  final String greeting;
}

/// Outcome of autodiscovery for an address.
class ProviderDetection {
  const ProviderDetection({required this.domain, this.provider});

  final String domain;

  /// `null` when neither the built-in table nor the engine's network discovery
  /// (ISPDB → autoconfig → SRV → MX → guesses) found anything; the UI then
  /// offers manual settings.
  final ProviderConfig? provider;

  bool get found => provider != null;
}

/// Everything needed to add an account. `secret` is a password, app password
/// or OAuth token: it is never logged, printed or persisted by the UI.
class AccountSetup {
  const AccountSetup({
    required this.email,
    required this.displayName,
    required this.authMethod,
    required this.imap,
    required this.smtp,
    this.providerName,
    this.username,
    this.secret,
  });

  final String email;
  final String displayName;
  final AuthMethod authMethod;
  final ServerSettings imap;
  final ServerSettings smtp;
  final String? providerName;
  final String? username;
  final String? secret;

  @override
  String toString() => 'AccountSetup($email via ${imap.host}, $authMethod)';
}

class BackupStatus {
  const BackupStatus({
    required this.backedUp,
    this.lastBackup,
    this.available = true,
    this.reminder,
    this.phraseCreatedAt,
    this.accountId,
    this.serverUrl,
    this.bytes,
  });

  final bool backedUp;
  final DateTime? lastBackup;

  /// False when this build's engine has no backup API yet.
  final bool available;

  /// Engine `BackupStatus.reminder`: no backup yet, or older than 30 days.
  final String? reminder;

  /// When a recovery phrase was last shown for the account on this device.
  final DateTime? phraseCreatedAt;
  final String? accountId;

  /// Where the last backup went, and its size.
  final String? serverUrl;
  final int? bytes;
}

/// A typed recovery phrase after `recovery_phrase_validate`.
class PhraseCheck {
  const PhraseCheck({required this.words, required this.checksumOk});

  final List<String> words;
  final bool checksumOk;
}

/// `setup_message_export`: show [setupCode] on this device only.
class SetupExportResult {
  const SetupExportResult({required this.setupCode, required this.messageId});

  final String setupCode;
  final String messageId;

  /// The nine 4-digit blocks.
  List<String> get blocks => setupCode.split(RegExp(r'[^0-9]+')).where((b) => b.isNotEmpty).toList();
}

/// The five states of Settings → Security → Key transparency.
enum KtState {
  /// No Sealbox server is configured, so there is no log to audit.
  noServer,

  /// Not audited yet in this session (or running now).
  unchecked,

  /// Tree head signature, consistency and own-key inclusion all verified.
  verified,

  /// The log answered but a check failed (substitution, fork, bad signature).
  alert,

  /// The server could not be reached or refused (audit error).
  unreachable,
}

/// Result of `Engine::kt_audit` for one account, plus the UI state.
class KtAudit {
  const KtAudit({
    required this.state,
    this.accountId,
    this.logSize = 0,
    this.sthVerified = false,
    this.ownKeyIncluded = false,
    this.consistencyOk = false,
    this.alerts = const [],
    this.error,
    this.checkedAt,
  });

  factory KtAudit.fromReport({
    required String accountId,
    required int logSize,
    required bool sthVerified,
    required bool ownKeyIncluded,
    required bool consistencyOk,
    required List<String> alerts,
    DateTime? checkedAt,
  }) => KtAudit(
    state: sthVerified && ownKeyIncluded && consistencyOk && alerts.isEmpty
        ? KtState.verified
        : KtState.alert,
    accountId: accountId,
    logSize: logSize,
    sthVerified: sthVerified,
    ownKeyIncluded: ownKeyIncluded,
    consistencyOk: consistencyOk,
    alerts: alerts,
    checkedAt: checkedAt,
  );

  final KtState state;
  final String? accountId;
  final int logSize;
  final bool sthVerified;
  final bool ownKeyIncluded;
  final bool consistencyOk;
  final List<String> alerts;
  final String? error;
  final DateTime? checkedAt;

  bool get substitution => alerts.any((a) => a.startsWith('SUBSTITUTION:'));
}

/// A file picked for an outgoing message.
class DraftAttachment {
  const DraftAttachment({
    required this.name,
    required this.contentType,
    required this.data,
    this.storedPath,
  });

  final String name;
  final String contentType;
  final Uint8List data;

  /// Where a saved draft references this file ([SavedDraftAttachment.path]): the handle of
  /// the sealed copy made when the draft was first saved (`CoreDraftOps.keepDraftAttachment`),
  /// or what a resumed draft already named (a handle, or a file path from an earlier build).
  /// Null until the draft is saved.
  final String? storedPath;

  /// The same file, now referenced by a saved draft at [path].
  DraftAttachment storedAt(String path) =>
      DraftAttachment(name: name, contentType: contentType, data: data, storedPath: path);

  String get sizeLabel => sizeLabelOf(data.length);

  static String sizeLabelOf(int size) {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

/// How a guest link is protected (engine `GuestMode`, gate G29).
enum GuestMode {
  /// Default. No secret in the link; the passphrase goes by another channel.
  passphrase,

  /// The secret is in the link's fragment: anyone holding the mail can read it.
  oneClick,

  /// The recipient confirms their address with a mailed one-time code.
  emailCode;

  String get label => switch (this) {
    GuestMode.passphrase => 'Passphrase',
    GuestMode.oneClick => 'One-click',
    GuestMode.emailCode => 'Email code',
  };

  /// The one-line honest explanation shown under the selector.
  String get explanation => switch (this) {
    GuestMode.passphrase =>
      'Share the passphrase by another channel (a call, a chat). The email alone cannot open the message.',
    GuestMode.oneClick =>
      'Anyone with the link can read it — protects against the server and the network only.',
    GuestMode.emailCode =>
      'The recipient confirms their address with a one-time code before opening.',
  };
}

/// One guest link created by a send (engine `GuestLinkInfo`).
class GuestLinkResult {
  const GuestLinkResult({
    required this.url,
    required this.mode,
    required this.recipients,
    this.passphrase,
    this.expiresAt,
    this.secretInLink = false,
    this.recipientVerification = false,
  });

  final String url;
  final GuestMode mode;
  final List<String> recipients;

  /// To be shown once, only for [GuestMode.passphrase]. Never persisted.
  final String? passphrase;
  final DateTime? expiresAt;

  /// True when the URL itself can decrypt the message.
  final bool secretInLink;
  final bool recipientVerification;
}

/// What the user typed in the compose screen.
class DraftMessage {
  const DraftMessage({
    required this.accountId,
    required this.to,
    required this.subject,
    required this.body,
    this.guestMode = GuestMode.passphrase,
    this.plaintextConfirmedFor = const {},
    this.inReplyTo,
    this.attachments = const [],
    this.compose = const ComposeOptions(),
    this.cc = const [],
  });

  final String accountId;
  final List<String> to;

  /// Visible copies (`Cc`). They get the same per-recipient protection as [to].
  final List<String> cc;
  final String subject;
  final String body;
  final GuestMode guestMode;
  final Set<String> plaintextConfirmedFor;

  /// Local id of the message being replied to (threading headers).
  final String? inReplyTo;
  final List<DraftAttachment> attachments;

  /// Reply / forward quoting and signature control, applied by the engine on send and by
  /// `composePreview`. The default is a plain send: the account signature is still added
  /// per its settings, nothing is quoted. With `ComposeOptions.reply()` the engine quotes
  /// the [inReplyTo] message itself, so [body] should hold only the new text.
  final ComposeOptions compose;
}

/// The folder chips of the message list. Each maps onto the server folder
/// names providers use (`Sent`, `Sent Items`, `[Gmail]/Sent Mail`, …).
enum MailFolder {
  inbox,
  sent,
  spam,
  trash,
  archive,
  all;

  String get label => switch (this) {
    MailFolder.inbox => 'Inbox',
    MailFolder.sent => 'Sent',
    MailFolder.spam => 'Spam',
    MailFolder.trash => 'Trash',
    MailFolder.archive => 'Archive',
    MailFolder.all => 'All mail',
  };

  /// The engine's special-use role behind this chip (`listThreadsInRole`, `syncFolder`,
  /// `moveMessage`); null for [all], which spans every folder.
  FolderRole? get role => switch (this) {
    MailFolder.inbox => FolderRole.inbox,
    MailFolder.sent => FolderRole.sent,
    MailFolder.spam => FolderRole.junk,
    MailFolder.trash => FolderRole.trash,
    MailFolder.archive => FolderRole.archive,
    MailFolder.all => null,
  };

  /// Does a server folder name belong to this chip?
  bool matches(String folderName) {
    final f = folderName.toLowerCase();
    final leaf = f.split(RegExp(r'[/.]')).last.trim();
    return switch (this) {
      MailFolder.all => true,
      MailFolder.inbox => f == 'inbox',
      MailFolder.sent => leaf.startsWith('sent') || leaf == 'outbox' || f.contains('sent'),
      MailFolder.spam => leaf == 'spam' || leaf == 'junk' || leaf.startsWith('junk ') || f.contains('spam'),
      MailFolder.trash => leaf == 'trash' || leaf.startsWith('deleted') || leaf == 'bin' || f.contains('trash'),
      MailFolder.archive => leaf == 'archive' || leaf == 'archives' || leaf == 'all mail' || f.contains('archive'),
    };
  }
}

class SendReceipt {
  const SendReceipt({
    required this.encryptedTo,
    required this.guestLinkTo,
    required this.plaintextTo,
    this.messageId,
    this.guestLinks = const [],
    this.sentCopyAppended = true,
  });

  final List<String> encryptedTo;
  final List<String> guestLinkTo;
  final List<String> plaintextTo;
  final String? messageId;
  final List<GuestLinkResult> guestLinks;

  String? get guestUrl => guestLinks.firstOrNull?.url;
  final bool sentCopyAppended;

  String get summary {
    final parts = <String>[
      if (encryptedTo.isNotEmpty) 'encrypted to ${encryptedTo.length}',
      if (guestLinkTo.isNotEmpty) 'guest link for ${guestLinkTo.length}',
      if (plaintextTo.isNotEmpty) 'plaintext to ${plaintextTo.length}',
    ];
    return 'Sent: ${parts.join(', ')}';
  }
}

/// Only part of a message went out (`ComposeController.send`): the recipients in [sent] got
/// it; [notSentTo] did not and are still on the message, so sending again sends it to them
/// alone. A core's `send` throws it too: one message goes out as up to three engine sends
/// (encrypted, guest link, confirmed plaintext; one guest link per recipient for
/// [GuestMode.emailCode]), and one failing after an earlier one went out must not lose what
/// did, or sending again would mail those recipients a second copy.
class PartialSendException implements Exception {
  const PartialSendException({required this.sent, required this.notSentTo, required this.reason});

  /// What did go out (guest links included: their passphrases are shown only once).
  final SendReceipt sent;
  final List<String> notSentTo;

  /// Why the rest failed.
  final String reason;

  @override
  String toString() => 'not sent to ${notSentTo.join(', ')}: $reason';
}

/// One account's part of a sync.
class AccountSyncOutcome {
  const AccountSyncOutcome({
    required this.account,
    this.newMessages = 0,
    this.decrypted = 0,
    this.failed = 0,
    this.error,
    this.moreToBackfill = false,
    this.olderPending,
    this.removed = 0,
    this.flagsChanged = 0,
  });

  final String account;
  final int newMessages;
  final int decrypted;
  final int failed;
  final String? error;

  /// Older mail of a folder is not stored yet: a folder's first sync stores only its newest
  /// 500 messages (engine `FolderSync.more_to_backfill`); [CoreMailOps.backfill] fetches the
  /// rest, and so do later syncs, 1,000 at a time.
  final bool moreToBackfill;

  /// How many older messages are still to fetch, summed over the folders that counted them
  /// in this run (null when none did; 0 once nothing older is left).
  final int? olderPending;

  /// Stored messages dropped because the server no longer has them — deleted in webmail or on
  /// another device (engine `FolderSync.removed`). The list shrinks when this is non-zero.
  final int removed;

  /// Stored messages whose flags were brought into line with the server: read or starred
  /// elsewhere (engine `FolderSync.flags_changed`).
  final int flagsChanged;

  bool get ok => error == null;
}

class SyncOutcome {
  const SyncOutcome(this.accounts);

  final List<AccountSyncOutcome> accounts;

  int get newMessages => accounts.fold(0, (n, a) => n + a.newMessages);
  int get decrypted => accounts.fold(0, (n, a) => n + a.decrypted);
  int get failed => accounts.fold(0, (n, a) => n + a.failed);
  List<AccountSyncOutcome> get errors => [
    for (final a in accounts)
      if (!a.ok) a,
  ];

  String get summary {
    if (accounts.isEmpty) return 'No accounts to sync';
    final b = StringBuffer();
    if (errors.length == accounts.length) {
      b.write('Sync failed: ${errors.first.error}');
      return b.toString();
    }
    b.write(newMessages == 0 ? 'Up to date' : 'Synced: $newMessages new');
    if (decrypted > 0) b.write(', $decrypted decrypted');
    if (failed > 0) b.write(', $failed could not be decrypted');
    if (errors.isNotEmpty) b.write(' · ${errors.length} account(s) failed');
    return b.toString();
  }
}

/// Which part of a folder a sync step fetches (engine `SyncPhase`).
enum SyncPhase {
  /// The folder's first sync: its newest window (500 messages), the newest batch first.
  initial,

  /// Mail that arrived since the last sync, oldest first.
  incremental,

  /// Older mail below the first sync's window, the newest batch first, down to the first
  /// message.
  backfill,
}

/// One batch a running sync or backfill stored (engine `SyncProgress`). It arrives after the
/// batch is committed, so the list can show the batch at once. Counts are per folder and
/// [phase] of the run.
class SyncProgress {
  const SyncProgress({
    required this.account,
    required this.folder,
    required this.phase,
    this.fetched = 0,
    this.stored = 0,
    this.planned = 0,
    this.totalKnown = 0,
    this.local = 0,
    this.moreToBackfill = false,
  });

  /// The account's address.
  final String account;

  /// The server's name of the folder (`INBOX`, `[Gmail]/Sent Mail`, …).
  final String folder;
  final SyncPhase phase;

  /// Messages fetched so far in this phase.
  final int fetched;

  /// Of those, stored for the first time (one already stored is skipped).
  final int stored;

  /// What the phase set out to fetch: the window, the new mail, or the backfill step.
  final int planned;

  /// Messages in the folder on the server.
  final int totalKnown;

  /// Messages of the folder stored on this device now.
  final int local;

  /// Older mail is still waiting below the window after this batch.
  final bool moreToBackfill;

  @override
  String toString() =>
      'SyncProgress($account $folder ${phase.name} $fetched/$planned, $local of $totalKnown'
      '${moreToBackfill ? ', more to backfill' : ''})';
}

/// What [CoreMailOps.syncAccount] and [CoreMailOps.backfill] stream: a [progress] event after
/// every batch the engine stored, then exactly one last event with the run's [outcome],
/// after which the stream closes. A run that fails sends no outcome: its stream ends with
/// the error instead.
class SyncEvent {
  const SyncEvent.progress(SyncProgress this.progress) : outcome = null;
  const SyncEvent.done(AccountSyncOutcome this.outcome) : progress = null;

  final SyncProgress? progress;
  final AccountSyncOutcome? outcome;

  bool get isDone => outcome != null;
}

/// Where the signature goes in a reply, relative to the quoted text.
enum SignaturePlacement { aboveQuote, belowQuote }

/// Which kinds of message get the signature.
enum SignatureIncludeOn { newOnly, newAndReplies, all }

/// Per-account signature (engine: G23).
class SignatureSettings {
  const SignatureSettings({
    this.enabled = false,
    this.text = '',
    this.html,
    this.placement = SignaturePlacement.aboveQuote,
    this.includeOn = SignatureIncludeOn.all,
  });

  final bool enabled;
  final String text;
  final String? html;
  final SignaturePlacement placement;
  final SignatureIncludeOn includeOn;

  bool get isEmpty => text.trim().isEmpty && (html ?? '').trim().isEmpty;

  SignatureSettings copyWith({
    bool? enabled,
    String? text,
    String? html,
    SignaturePlacement? placement,
    SignatureIncludeOn? includeOn,
  }) => SignatureSettings(
    enabled: enabled ?? this.enabled,
    text: text ?? this.text,
    html: html == null ? this.html : (html.isEmpty ? null : html),
    placement: placement ?? this.placement,
    includeOn: includeOn ?? this.includeOn,
  );
}

/// Out-of-office auto-reply (engine: G24, RFC 3834). Times are UTC.
class AutoReplySettings {
  const AutoReplySettings({
    this.enabled = false,
    this.start,
    this.end,
    this.subjectTemplate = 'Automatic reply: {subject}',
    this.body = '',
    this.replyOncePerSenderDays = 7,
    this.encryptWhenPossible = true,
    this.onlyToKnownContacts = false,
  });

  final bool enabled;
  final DateTime? start;
  final DateTime? end;
  final String subjectTemplate;
  final String body;
  final int replyOncePerSenderDays;
  final bool encryptWhenPossible;
  final bool onlyToKnownContacts;

  bool get isActiveNow {
    final now = DateTime.now().toUtc();
    return enabled &&
        (start == null || !now.isBefore(start!)) &&
        (end == null || now.isBefore(end!));
  }

  AutoReplySettings copyWith({
    bool? enabled,
    DateTime? start,
    DateTime? end,
    bool clearDates = false,
    String? subjectTemplate,
    String? body,
    int? replyOncePerSenderDays,
    bool? encryptWhenPossible,
    bool? onlyToKnownContacts,
  }) => AutoReplySettings(
    enabled: enabled ?? this.enabled,
    start: clearDates ? null : (start ?? this.start),
    end: clearDates ? null : (end ?? this.end),
    subjectTemplate: subjectTemplate ?? this.subjectTemplate,
    body: body ?? this.body,
    replyOncePerSenderDays: replyOncePerSenderDays ?? this.replyOncePerSenderDays,
    encryptWhenPossible: encryptWhenPossible ?? this.encryptWhenPossible,
    onlyToKnownContacts: onlyToKnownContacts ?? this.onlyToKnownContacts,
  );
}

/// One auto-reply the engine sent.
class AutoReplyEntry {
  const AutoReplyEntry({
    required this.sender,
    required this.sentAt,
    required this.encrypted,
    this.messageId,
  });

  final String sender;
  final DateTime sentAt;
  final bool encrypted;
  final String? messageId;
}

/// What this build's engine can do beyond IMAP/SMTP (from its configuration).
class EngineCapabilities {
  const EngineCapabilities({
    required this.guestLinks,
    required this.keyDirectory,
    this.guestModes = const {GuestMode.passphrase, GuestMode.oneClick, GuestMode.emailCode},
  });

  /// Guest-link modes this engine implements honestly (G29). An engine
  /// without `Draft.guest_mode` always puts the secret in the link, i.e. it
  /// only does [GuestMode.oneClick].
  final Set<GuestMode> guestModes;

  /// A Sealbox server URL is configured, so guest-link sends can work.
  final bool guestLinks;

  /// A VKS key directory URL is configured for recipient-key lookups.
  final bool keyDirectory;
}

enum MailEventKind { idle, newMail, timeout }

/// Push-style event from the engine's IMAP IDLE watcher.
class MailEvent {
  const MailEvent(this.kind, {this.account, this.newMessages = 0});

  final MailEventKind kind;
  final String? account;
  final int newMessages;
}

/// How the profile's secrets (account credentials, OAuth tokens, secret keys,
/// message bodies) are protected at rest. Mirrors the engine's
/// `ProfileKeyStatus` (docs/CONTRACTS_2026-10-27b.md, "Secrets at rest").
class ProfileKeyStatus {
  const ProfileKeyStatus({
    required this.source,
    this.wrappedRows = 0,
    this.plaintextRows = 0,
    this.kdf,
    this.fallback,
  });

  /// The engine in this build cannot report a status (no `profile_key_status`
  /// on the bridge yet). Copy must then make no encryption claim.
  const ProfileKeyStatus.unknown() : this(source: 'unknown');

  /// `keyring`, `passphrase`, `raw`, `none` — or `unknown` (see above).
  final String source;
  final int wrappedRows;
  final int plaintextRows;
  final String? kdf;

  /// Why the requested key source was not used (headless keyring fallback,
  /// plaintext profile), from the engine.
  final String? fallback;

  bool get known => source != 'unknown';

  /// True only when the engine says secrets are wrapped with a profile key and
  /// nothing is left in plaintext. The only state in which the UI may say
  /// "stored encrypted".
  bool get encryptedAtRest => known && source != 'none' && plaintextRows == 0;

  String get sourceLabel => switch (source) {
    'keyring' => 'OS keyring',
    'passphrase' => 'passphrase (Argon2id)',
    'raw' => 'app-lock key',
    'none' => 'not encrypted',
    _ => 'not reported by this engine build',
  };
}

// -- folders by special-use role -------------------------------------------------

/// Special-use folder roles (engine `FolderRole`: RFC 6154 plus Gmail's All Mail and
/// Starred). The engine resolves a role per account to the folder the server calls it —
/// learned from `LIST` on every sync, else the provider's default — so [junk] is
/// `[Gmail]/Spam` on Gmail, `Junk Email` on Outlook and `Bulk Mail` on Yahoo.
enum FolderRole {
  inbox,
  sent,
  drafts,
  trash,

  /// Spam (`\Junk`).
  junk,
  archive,

  /// Gmail "All Mail" (`\All`); elsewhere the archive folder.
  all,

  /// `\Flagged` / Gmail "Starred".
  flagged;

  String get label => switch (this) {
    FolderRole.inbox => 'Inbox',
    FolderRole.sent => 'Sent',
    FolderRole.drafts => 'Drafts',
    FolderRole.trash => 'Trash',
    FolderRole.junk => 'Spam',
    FolderRole.archive => 'Archive',
    FolderRole.all => 'All Mail',
    FolderRole.flagged => 'Starred',
  };

  /// The inbox chip that shows this role; null for roles without a chip ([drafts],
  /// [flagged]). [all] maps to the archive chip: on Gmail the archive *is* All Mail.
  MailFolder? get mailFolder => switch (this) {
    FolderRole.inbox => MailFolder.inbox,
    FolderRole.sent => MailFolder.sent,
    FolderRole.junk => MailFolder.spam,
    FolderRole.trash => MailFolder.trash,
    FolderRole.archive || FolderRole.all => MailFolder.archive,
    FolderRole.drafts || FolderRole.flagged => null,
  };
}

/// One special-use role of an account and the folder it maps to (engine `FolderRoleEntry`).
class FolderRoleInfo {
  const FolderRoleInfo({
    required this.accountId,
    required this.role,
    required this.folder,
    this.learned = false,
  });

  final String accountId;
  final FolderRole role;

  /// Folder name on the server (`[Gmail]/Spam`, `Junk Email`, `Trash`, …).
  final String folder;

  /// The server's `LIST` confirmed it on a sync; false = the provider's default name, not
  /// seen on the server yet.
  final bool learned;

  MailFolder? get mailFolder => role.mailFolder;
}

/// How the server carried out a move.
enum MoveMethod {
  /// `UID MOVE` (RFC 6851).
  move,

  /// `UID COPY` + `\Deleted` + expunge, for servers without MOVE.
  copyExpunge,
}

/// Outcome of `moveMessage` (engine `MoveReport`).
///
/// Real engine: after an actual move the local copy is dropped — the message leaves the
/// current list and comes back (under a new message id; the conversation id stays) once the
/// destination folder is synced with `syncFolder(role)`. `FakeCore` relocates it at once.
class MoveResult {
  const MoveResult({
    required this.messageId,
    required this.fromFolder,
    required this.toFolder,
    this.method,
  });

  final String messageId;
  final String fromFolder;
  final String toFolder;

  /// Null when the message already was in the destination (nothing happened).
  final MoveMethod? method;

  bool get moved => method != null;
}

// -- compose: quoting and the signature (engine G23) -------------------------------

/// How a draft came to be; drives signature inclusion ([SignatureIncludeOn]) and quoting.
enum ComposeKind {
  /// A new conversation (engine `ComposeKind::New`). A draft with `inReplyTo` set counts as
  /// a [reply] even with this kind.
  newMessage,
  reply,
  forward,
}

/// Engine `ComposeOptions`: what the engine adds to the typed text on send / preview.
class ComposeOptions {
  const ComposeOptions({
    this.kind = ComposeKind.newMessage,
    this.quote = false,
    this.forwardOf,
    this.skipSignature = false,
  });

  /// Answer `DraftMessage.inReplyTo`, quoting it unless [quote] is false.
  const ComposeOptions.reply({bool quote = true, bool skipSignature = false})
    : this(kind: ComposeKind.reply, quote: quote, skipSignature: skipSignature);

  /// Forward the stored message [messageId]: its headers and text go below a
  /// `-------- Forwarded Message --------` line and its attachments are carried along.
  const ComposeOptions.forward(String messageId, {bool skipSignature = false})
    : this(kind: ComposeKind.forward, quote: true, forwardOf: messageId, skipSignature: skipSignature);

  final ComposeKind kind;

  /// Let the engine quote the replied-to message (`On <date>, <from> wrote:` + `> ` lines).
  /// Only stored messages can be quoted. Implied for forwards.
  final bool quote;

  /// Local message id (or Message-ID) of the message to forward.
  final String? forwardOf;

  /// Never add the account signature to this message.
  final bool skipSignature;

  ComposeOptions copyWith({
    ComposeKind? kind,
    bool? quote,
    String? forwardOf,
    bool? skipSignature,
  }) => ComposeOptions(
    kind: kind ?? this.kind,
    quote: quote ?? this.quote,
    forwardOf: forwardOf ?? this.forwardOf,
    skipSignature: skipSignature ?? this.skipSignature,
  );
}

/// What the engine would send for a draft (`composePreview`); nothing is sent.
class ComposePreview {
  const ComposePreview({
    required this.kind,
    required this.text,
    this.html,
    this.signatureApplied = false,
    this.forwardedAttachments = const [],
  });

  /// The effective kind (a new message with `inReplyTo` becomes a reply).
  final ComposeKind kind;

  /// The final text body: typed text, then signature and quote in the order the account's
  /// [SignaturePlacement] says.
  final String text;

  /// The final HTML body when the draft or the signature has one.
  final String? html;

  /// The account signature was added.
  final bool signatureApplied;

  /// File names of the forwarded message's attachments that go along.
  final List<String> forwardedAttachments;
}

/// The signature block alone, as the engine appends it (`signaturePreview`).
class SignaturePreview {
  const SignaturePreview({required this.text, this.html, this.placement = SignaturePlacement.aboveQuote});

  /// Starts with the `-- ` separator line; empty when the signature is HTML-only.
  final String text;

  /// The sanitised HTML block, when an HTML signature is configured.
  final String? html;
  final SignaturePlacement placement;
}

// -- spam (engine G25) --------------------------------------------------------------

enum SpamLabel {
  ham,
  unsure,
  spam;

  String get label => switch (this) {
    SpamLabel.ham => 'Not spam',
    SpamLabel.unsure => 'Possibly spam',
    SpamLabel.spam => 'Spam',
  };
}

/// One line of a spam explanation: a rule hit, a forced label or the user's feedback.
class SpamReason {
  const SpamReason({required this.code, required this.detail, this.weight = 0});

  /// Stable code: `raw_ip_url`, `allowlist`, `blocklist`, `signed_by_contact`,
  /// `user_feedback`, …
  final String code;

  /// Log-odds contribution (0 for forced labels).
  final double weight;
  final String detail;
}

/// The classifier's answer (engine `Verdict`).
class SpamVerdict {
  const SpamVerdict({
    required this.spamProbability,
    required this.label,
    this.reasons = const [],
    this.bayesLogOdds = 0,
    this.bayesConfidence = 0,
    this.rulesScore = 0,
    this.logOdds = 0,
  });

  /// 0..1.
  final double spamProbability;
  final SpamLabel label;
  final List<SpamReason> reasons;
  final double bayesLogOdds;

  /// 0..1 — how much the Bayes model was trusted (it needs training first).
  final double bayesConfidence;
  final double rulesScore;
  final double logOdds;
}

/// Per-account spam settings (engine `SpamSettings`). The engine validates on save
/// (thresholds 0..1 with unsure ≤ spam, a folder other than INBOX) and normalises the lists
/// (lower case, no leading `@`, no duplicates).
class SpamSettings {
  const SpamSettings({
    this.enabled = true,
    this.unsureThreshold = 0.5,
    this.spamThreshold = 0.9,
    this.dnsblEnabled = false,
    this.moveToFolder = defaultFolder,
    this.allowlist = const [],
    this.blocklist = const [],
  });

  /// `moveToFolder` value meaning "the server's junk folder (created as `Spam` if none)".
  static const defaultFolder = 'Spam';

  /// Classify incoming mail at all.
  final bool enabled;

  /// Probability from which a message is shown as "possibly spam".
  final double unsureThreshold;

  /// Probability from which a message is spam and moved to the junk folder.
  final double spamThreshold;

  /// Ask Spamhaus over DNS. Reveals sender IPs and link domains to the resolver: off by
  /// default, and the UI should say so.
  final bool dnsblEnabled;
  final String moveToFolder;

  /// Senders (addresses or domains) that are never spam.
  final List<String> allowlist;

  /// Senders (addresses or domains) that are always spam.
  final List<String> blocklist;

  bool get usesServerJunkFolder => moveToFolder == defaultFolder;

  SpamSettings copyWith({
    bool? enabled,
    double? unsureThreshold,
    double? spamThreshold,
    bool? dnsblEnabled,
    String? moveToFolder,
    List<String>? allowlist,
    List<String>? blocklist,
  }) => SpamSettings(
    enabled: enabled ?? this.enabled,
    unsureThreshold: unsureThreshold ?? this.unsureThreshold,
    spamThreshold: spamThreshold ?? this.spamThreshold,
    dnsblEnabled: dnsblEnabled ?? this.dnsblEnabled,
    moveToFolder: moveToFolder ?? this.moveToFolder,
    allowlist: allowlist ?? this.allowlist,
    blocklist: blocklist ?? this.blocklist,
  );
}

/// Spam bookkeeping of one account ([SpamStatus.accounts]).
class SpamAccountStatus {
  const SpamAccountStatus({
    required this.accountId,
    required this.settings,
    required this.spamFolder,
    this.spamCount = 0,
    this.unsureCount = 0,
    this.hamCount = 0,
    this.filterRuleCount = 0,
  });

  final String accountId;
  final SpamSettings settings;

  /// Where spam goes on this account (`[Gmail]/Spam`, `Junk`, …).
  final String spamFolder;
  final int spamCount;
  final int unsureCount;
  final int hamCount;
  final int filterRuleCount;
}

/// Model statistics and every account's spam state (engine `spam_status`).
class SpamStatus {
  const SpamStatus({
    this.modelSpamMessages = 0,
    this.modelHamMessages = 0,
    this.modelTokens = 0,
    this.modelConfidence = 0,
    this.accounts = const [],
  });

  /// Nothing learned, no accounts (also the default of doubles without spam support).
  const SpamStatus.empty() : this();

  final int modelSpamMessages;
  final int modelHamMessages;
  final int modelTokens;

  /// 0..1 — how much the personal Bayes model is trusted right now.
  final double modelConfidence;
  final List<SpamAccountStatus> accounts;
}

/// Result of one `Authentication-Results` method.
enum SpamAuthResult { pass, fail, softFail, neutral, none, other }

/// What the classifier extracted from a message (engine `SpamFeatureSummary`).
class SpamFeatures {
  const SpamFeatures({
    this.fromAddress,
    this.fromName,
    this.replyTo,
    this.urls = const [],
    this.attachments = const [],
    this.receivedDepth = 0,
    this.lastExternalIp,
    this.authPresent = false,
    this.spf,
    this.dkim,
    this.dmarc,
    this.htmlOnly = false,
    this.tokens = 0,
  });

  final String? fromAddress;
  final String? fromName;
  final String? replyTo;

  /// Up to 20 links found in the body.
  final List<String> urls;

  /// `name (content/type)` per attachment.
  final List<String> attachments;
  final int receivedDepth;
  final String? lastExternalIp;

  /// The provider added an `Authentication-Results` header.
  final bool authPresent;
  final SpamAuthResult? spf;
  final SpamAuthResult? dkim;
  final SpamAuthResult? dmarc;
  final bool htmlOnly;
  final int tokens;
}

/// What the message row remembers from sync / learn time.
class StoredSpamInfo {
  const StoredSpamInfo({this.score, this.label, this.reasons = const [], this.learned});

  final double? score;
  final SpamLabel? label;
  final List<SpamReason> reasons;

  /// The user's own verdict (`spamLearn`), if any.
  final SpamLabel? learned;
}

/// Why a message got its label (engine `spam_explain`, offline).
class SpamExplanation {
  const SpamExplanation({
    required this.messageId,
    required this.accountId,
    required this.folder,
    required this.from,
    required this.stored,
    required this.verdict,
    required this.settings,
    required this.features,
    required this.filters,
    this.subject,
  });

  final String messageId;
  final String accountId;
  final String folder;

  /// `Name <address>` of the sender.
  final String from;
  final String? subject;

  /// What was stored at sync / learn time.
  final StoredSpamInfo stored;

  /// A fresh verdict under the current model and settings.
  final SpamVerdict verdict;
  final SpamSettings settings;
  final SpamFeatures features;

  /// What the account's filter rules would do with this message.
  final FilterOutcome filters;
}

/// Result of `spamLearn` (engine `SpamLearnReport`).
class SpamLearnResult {
  const SpamLearnResult({
    required this.messageId,
    required this.learned,
    required this.verdict,
    this.previouslyLearned,
    this.movedTo,
    this.modelSpamMessages = 0,
    this.modelHamMessages = 0,
  });

  /// The message keeps its id (the engine relocates the local row with the move).
  final String messageId;
  final SpamLabel learned;
  final SpamLabel? previouslyLearned;

  /// Where it was moved (the junk folder, or `INBOX` for "not spam"), if it was.
  final String? movedTo;
  final int modelSpamMessages;
  final int modelHamMessages;

  /// The fresh verdict; its label is the user's.
  final SpamVerdict verdict;
}

// -- filter rules (engine G25) -------------------------------------------------------

/// Which part of a message a rule looks at.
enum FilterField {
  from,
  to,
  cc,
  subject,
  listId,

  /// A header by name ([FilterCondition.headerName]), e.g. `X-Mailer`.
  header,
  body;

  String get label => switch (this) {
    FilterField.from => 'From',
    FilterField.to => 'To',
    FilterField.cc => 'Cc',
    FilterField.subject => 'Subject',
    FilterField.listId => 'Mailing list',
    FilterField.header => 'Header',
    FilterField.body => 'Body',
  };

  /// The engine's spelling (`from`, `list-id`, `header:NAME`, …).
  String code([String? headerName]) => switch (this) {
    FilterField.listId => 'list-id',
    FilterField.header => 'header:${headerName ?? ''}',
    _ => name,
  };
}

/// How a rule compares its value.
enum FilterOp {
  contains,
  equals,
  regex,

  /// Address fields: the domain is the value or a sub-domain of it.
  domain;

  String get label => switch (this) {
    FilterOp.contains => 'contains',
    FilterOp.equals => 'is',
    FilterOp.regex => 'matches regex',
    FilterOp.domain => 'is from domain',
  };
}

/// A rule's condition.
class FilterCondition {
  const FilterCondition({
    required this.field,
    required this.op,
    required this.value,
    this.headerName,
    this.caseInsensitive = true,
  });

  final FilterField field;

  /// Required for [FilterField.header], ignored otherwise.
  final String? headerName;
  final FilterOp op;
  final String value;
  final bool caseInsensitive;
}

enum FilterActionKind { moveTo, addFlag, markRead, star }

/// What a rule does. There is deliberately no delete: "delete" is a move to Trash, so a
/// filter can never destroy mail.
class FilterAction {
  const FilterAction({required this.kind, this.folder, this.flag});

  const FilterAction.moveTo(String this.folder) : kind = FilterActionKind.moveTo, flag = null;

  const FilterAction.addFlag(String this.flag) : kind = FilterActionKind.addFlag, folder = null;

  const FilterAction.markRead() : kind = FilterActionKind.markRead, folder = null, flag = null;

  const FilterAction.star() : kind = FilterActionKind.star, folder = null, flag = null;

  final FilterActionKind kind;

  /// Destination for [FilterActionKind.moveTo] (created when missing; the first matching
  /// move wins).
  final String? folder;

  /// IMAP flag for [FilterActionKind.addFlag], e.g. `$Newsletter` (no spaces,
  /// parentheses, quotes or wildcards).
  final String? flag;

  /// The engine's spelling (`move:Lists`, `flag:$X`, `read`, `star`).
  String get code => switch (kind) {
    FilterActionKind.moveTo => 'move:${folder ?? ''}',
    FilterActionKind.addFlag => 'flag:${flag ?? ''}',
    FilterActionKind.markRead => 'read',
    FilterActionKind.star => 'star',
  };
}

/// One filter rule of an account. Rules run in [order] after spam classification; every
/// enabled matching rule contributes its action and [stop] ends the evaluation.
class FilterRule {
  const FilterRule({
    required this.condition,
    required this.action,
    this.id = 0,
    this.order = 0,
    this.enabled = true,
    this.name = '',
    this.stop = false,
  });

  /// Engine id; 0 before the rule is saved.
  final int id;

  /// Position; 0 when adding = after the existing rules.
  final int order;
  final bool enabled;

  /// Optional label for the list.
  final String name;
  final FilterCondition condition;
  final FilterAction action;
  final bool stop;

  /// The engine's one-line form: `subject contains "[newsletter]" → move:Newsletters`.
  String get summary {
    final c = condition;
    return '${c.field.code(c.headerName)} ${c.op.name} "${c.value}"'
        '${c.caseInsensitive ? '' : ' (case-sensitive)'} → ${action.code}${stop ? ' [stop]' : ''}';
  }

  FilterRule copyWith({
    int? id,
    int? order,
    bool? enabled,
    String? name,
    FilterCondition? condition,
    FilterAction? action,
    bool? stop,
  }) => FilterRule(
    id: id ?? this.id,
    order: order ?? this.order,
    enabled: enabled ?? this.enabled,
    name: name ?? this.name,
    condition: condition ?? this.condition,
    action: action ?? this.action,
    stop: stop ?? this.stop,
  );
}

/// A rule whose regex could not be evaluated.
class FilterRuleError {
  const FilterRuleError({required this.ruleId, required this.error});

  final int ruleId;
  final String error;
}

/// The combined effect of the matching rules.
class FilterOutcome {
  const FilterOutcome({
    this.matchedRuleIds = const [],
    this.moveTo,
    this.addFlags = const [],
    this.markRead = false,
    this.star = false,
    this.errors = const [],
  });

  /// In evaluation order.
  final List<int> matchedRuleIds;
  final String? moveTo;
  final List<String> addFlags;
  final bool markRead;
  final bool star;
  final List<FilterRuleError> errors;

  bool get isNoop => moveTo == null && addFlags.isEmpty && !markRead && !star;
}

/// One enabled rule in a dry run.
class FilterRuleResult {
  const FilterRuleResult({required this.ruleId, required this.description, required this.matched});

  final int ruleId;

  /// The engine's one-line form of the rule.
  final String description;
  final bool matched;
}

/// `testFilterRules`: what the rules would do with a stored message (nothing changes).
class FilterTestReport {
  const FilterTestReport({required this.messageId, required this.outcome, this.rules = const []});

  final String messageId;
  final FilterOutcome outcome;

  /// Every enabled rule in evaluation order.
  final List<FilterRuleResult> rules;
}

// -- the Sealbox server and its key directory ---------------------------------------

/// Where the effective server URL comes from (engine `server_url_source`).
enum ServerUrlSource {
  /// Stored in the profile with `setServerUrl` (wins over the environment).
  settings,

  /// `SEALBOX_SERVER_URL` of the process.
  environment,

  /// No server: guest links, backups, the key directory and transparency are off.
  none,
}

/// What the key directory holds for one of our addresses.
enum DirectoryState {
  /// No Sealbox server / directory is configured (Settings → Server).
  noServer,

  /// The directory could not be reached (see [DirectoryStatus.error]).
  unreachable,
  unpublished,

  /// Published by us, but the verification mail has not been opened yet: run
  /// `completeDirectoryVerification` once it arrived.
  awaitingVerification,

  /// The directory serves this account's current key.
  published,

  /// Another key is published for this address (not this account's).
  otherKey,

  /// The verification link was refused (expired or used): publish again.
  verificationFailed,

  /// A state this build does not know (or a double without the API).
  unknown;

  /// The engine's spelling (`published`, `other_key`, `awaiting_verification`, …).
  static DirectoryState parse(String s) => switch (s) {
    'published' => DirectoryState.published,
    'other_key' => DirectoryState.otherKey,
    'unpublished' => DirectoryState.unpublished,
    'pending' || 'awaiting_verification' => DirectoryState.awaitingVerification,
    'verification_failed' => DirectoryState.verificationFailed,
    _ => DirectoryState.unknown,
  };
}

/// Engine `DirectoryStatus` plus the two UI states [DirectoryState.noServer] /
/// [DirectoryState.unreachable].
class DirectoryStatus {
  const DirectoryStatus({
    required this.accountId,
    required this.state,
    this.serverUrl,
    this.published = false,
    this.fingerprintMatches,
    this.error,
  });

  final String accountId;
  final DirectoryState state;
  final String? serverUrl;
  final bool published;

  /// true = our current key, false = another key, null = nothing published.
  final bool? fingerprintMatches;

  /// Why the directory could not be asked ([DirectoryState.unreachable]).
  final String? error;
}

/// Result of `publishKey` (engine `PublishReport`).
class PublishResult {
  const PublishResult({
    required this.accountId,
    required this.fingerprint,
    required this.serverUrl,
    this.addressStates = const {},
    this.tokenIssued = false,
  });

  final String accountId;
  final String fingerprint;
  final String serverUrl;

  /// address → `unpublished` | `pending` | `published`, as the directory reports it.
  final Map<String, String> addressStates;

  /// A verification mail went to the address; `false` = it already was published.
  final bool tokenIssued;

  /// The engine issues no token only when the address already is published.
  DirectoryState get state =>
      tokenIssued ? DirectoryState.awaitingVerification : DirectoryState.published;
}

// -- search (engine `Engine::search`) ------------------------------------------------

/// Opens a matched term in an engine snippet (U+E000, private use: never in real text).
const String snippetMatchStart = '\u{E000}';

/// Closes a matched term in an engine snippet (U+E001).
const String snippetMatchEnd = '\u{E001}';

/// A run of snippet text; [isMatch] = a term the query matched (shown emphasised).
class SnippetSpan {
  const SnippetSpan(this.text, {this.isMatch = false});

  final String text;
  final bool isMatch;

  @override
  bool operator ==(Object other) =>
      other is SnippetSpan && other.text == text && other.isMatch == isMatch;

  @override
  int get hashCode => Object.hash(text, isMatch);

  @override
  String toString() => isMatch ? '[$text]' : text;
}

/// Splits an engine snippet into plain and matched runs. The engine wraps every matched term
/// in [snippetMatchStart] … [snippetMatchEnd]; the markers never reach the result. Robust to
/// what a well-formed snippet never holds: a stray end marker is dropped, a start inside a
/// match is ignored, and a match left open runs to the end. Empty runs are skipped and
/// neighbouring runs of the same kind are merged.
List<SnippetSpan> parseSnippet(String raw) {
  final spans = <SnippetSpan>[];
  final buf = StringBuffer();
  var inMatch = false;
  void flush() {
    if (buf.isEmpty) return;
    final text = buf.toString();
    buf.clear();
    if (spans.isNotEmpty && spans.last.isMatch == inMatch) {
      spans[spans.length - 1] = SnippetSpan(spans.last.text + text, isMatch: inMatch);
    } else {
      spans.add(SnippetSpan(text, isMatch: inMatch));
    }
  }

  for (final rune in raw.runes) {
    final c = String.fromCharCode(rune);
    if (c == snippetMatchStart) {
      if (inMatch) continue;
      flush();
      inMatch = true;
    } else if (c == snippetMatchEnd) {
      if (!inMatch) continue;
      flush();
      inMatch = false;
    } else {
      buf.write(c);
    }
  }
  flush();
  return List.unmodifiable(spans);
}

/// One search hit (engine `SearchHit`): the message (summary only, no body), the snippet
/// around the best match, and the relevance.
class SearchResult {
  const SearchResult({required this.message, this.snippet = const [], this.rank = 0});

  /// From an engine snippet with match markers.
  SearchResult.fromRaw({required Message message, required String snippet, double rank = 0})
    : this(message: message, snippet: parseSnippet(snippet), rank: rank);

  final Message message;

  /// About 16 words of the body around the best match; empty when there is no readable body.
  final List<SnippetSpan> snippet;

  /// Higher is better; comparable only within one result list.
  final double rank;

  /// The snippet without emphasis.
  String get snippetText => snippet.map((s) => s.text).join();

  /// The terms the snippet marks as matched.
  List<String> get matchedTerms => [
    for (final s in snippet)
      if (s.isMatch) s.text,
  ];
}

/// The in-memory search index (engine `SearchIndexStats`).
class SearchIndexInfo {
  const SearchIndexInfo({this.documents = 0, this.memoryBytes = 0});

  /// Messages in the index.
  final int documents;

  /// Memory the index uses, in bytes.
  final int memoryBytes;
}

// -- saved drafts (engine `drafts.rs`) ------------------------------------------------

/// How the engine sends a saved draft by itself (`sendDraft`, the CLI's `draft send`),
/// engine `SendPolicy`. The compose screen does not use it: it decides per recipient and
/// sends through `send`.
enum SendPolicy {
  /// Encrypt when every recipient has a key; otherwise refuse.
  auto,
  requireEncryption,

  /// Encrypt when everyone has a key; otherwise a passphrase-protected guest link.
  guestLink,

  /// Plaintext to everyone. The app never stores it: a draft must not carry a downgrade.
  allowPlaintext,
}

/// A file a saved draft references **by path** (engine `DraftAttachment`); the engine reads
/// it when the draft is sent. Not the bytes-based [DraftAttachment] of the compose screen.
class SavedDraftAttachment {
  const SavedDraftAttachment({required this.path, this.name = '', this.contentType = ''});

  /// A [blobHandle] naming the sealed copy the engine keeps in its store (what
  /// `CoreDraftOps.keepDraftAttachment` returns), or the path of a file — such as a plain
  /// copy under `<profile>/draft-attachments/` kept by builds before the store sealed them.
  final String path;

  /// The name the recipient sees; empty = the file name of [path] (a stored copy: its name).
  final String name;

  /// Empty = `application/octet-stream`.
  final String contentType;

  /// The engine draft blob holding the file (engine `DraftAttachment.blob_id`), or null for
  /// a file path.
  int? get blobId => blobIdOf(path);

  /// What [path] holds for engine draft blob [id].
  static String blobHandle(int id) => '$blobHandlePrefix$id';

  static const blobHandlePrefix = 'blob:';

  /// The blob id a [blobHandle] names; null for anything else (file paths are absolute).
  static int? blobIdOf(String path) {
    if (!path.startsWith(blobHandlePrefix)) return null;
    final id = int.tryParse(path.substring(blobHandlePrefix.length));
    return id != null && id > 0 ? id : null;
  }

  String get displayName {
    if (name.trim().isNotEmpty) return name;
    if (blobId != null) return 'attachment';
    final parts = path.split(RegExp(r'[/\\]'));
    return parts.isEmpty ? path : parts.last;
  }

  @override
  bool operator ==(Object other) =>
      other is SavedDraftAttachment &&
      other.path == path &&
      other.name == name &&
      other.contentType == contentType;

  @override
  int get hashCode => Object.hash(path, name, contentType);
}

/// Where a saved draft was first saved ([SavedDraft.origin]).
enum DraftOrigin {
  /// Saved on this device.
  thisDevice,

  /// Imported from the server: saved on another device with the same key.
  server,
}

/// What a drafts sync did, summed over the accounts (`CoreDraftOps.syncDrafts`).
class DraftSyncSummary {
  const DraftSyncSummary({
    this.imported = 0,
    this.updated = 0,
    this.uploaded = 0,
    this.removedLocally = 0,
    this.removedOnServer = 0,
    this.unreadable = 0,
    this.failures = const [],
  });

  /// Drafts from the server this device did not have.
  final int imported;

  /// Local drafts replaced by a newer server copy.
  final int updated;

  /// Local drafts written to the server.
  final int uploaded;

  /// Local drafts gone because their server copy went (sent or discarded elsewhere).
  final int removedLocally;

  /// Server copies deleted (drafts deleted or sent here, duplicates).
  final int removedOnServer;

  /// Drafts on the server this device cannot read (another key).
  final int unreadable;

  /// Accounts whose sync failed, with the reason (`email: error`).
  final List<String> failures;

  /// The local list of drafts changed.
  bool get changedHere => imported + updated + removedLocally > 0;
}

/// The server state of one draft (engine `DraftServerInfo`).
class DraftServerState {
  const DraftServerState({
    required this.uuid,
    required this.onServer,
    required this.pending,
    this.origin = DraftOrigin.thisDevice,
    this.remoteFiles = 0,
  });

  final String uuid;

  /// A copy has been written to or read from the server.
  final bool onServer;

  /// Changed here since that copy (the next push or Drafts sync uploads it).
  final bool pending;
  final DraftOrigin origin;
  final int remoteFiles;
}

/// Input of `saveDraft` (engine `DraftInput`): the whole draft; saving replaces every field.
class DraftInput {
  const DraftInput({
    this.id,
    required this.accountId,
    this.kind = ComposeKind.newMessage,
    this.inReplyTo,
    this.forwardOf,
    this.quote = false,
    this.to = const [],
    this.cc = const [],
    this.bcc = const [],
    this.subject = '',
    this.body = '',
    this.attachments = const [],
    this.policy = SendPolicy.auto,
    this.guestMode = GuestMode.passphrase,
    this.guestRecipientHint,
    this.noSignature = false,
  });

  /// Null = a new draft; otherwise the draft to replace (re-created under that id if gone).
  final int? id;
  final String accountId;

  /// A new message with [inReplyTo] is stored as a reply, with [forwardOf] as a forward.
  final ComposeKind kind;

  /// Reply: local id or Message-ID of the message answered (stored as its Message-ID).
  final String? inReplyTo;

  /// Forward: local id or Message-ID of the stored message forwarded.
  final String? forwardOf;

  /// Let the engine quote the answered message when the draft is sent.
  final bool quote;
  final List<String> to;
  final List<String> cc;
  final List<String> bcc;
  final String subject;
  final String body;
  final List<SavedDraftAttachment> attachments;
  final SendPolicy policy;
  final GuestMode guestMode;
  final String? guestRecipientHint;

  /// Do not add the account signature when sending.
  final bool noSignature;

  /// Anything worth keeping: a recipient, a subject, text or a file.
  bool get hasContent =>
      to.isNotEmpty ||
      cc.isNotEmpty ||
      bcc.isNotEmpty ||
      subject.trim().isNotEmpty ||
      body.trim().isNotEmpty ||
      attachments.isNotEmpty;
}

/// A saved draft (engine `SavedDraft`). Drafts live in the local profile only: there is no
/// IMAP Drafts-folder sync, so other devices and webmail do not see them.
class SavedDraft {
  const SavedDraft({
    required this.id,
    required this.accountId,
    this.kind = ComposeKind.newMessage,
    this.inReplyTo,
    this.forwardOf,
    this.quote = false,
    this.references = const [],
    this.to = const [],
    this.cc = const [],
    this.bcc = const [],
    this.subject = '',
    this.body = '',
    this.attachments = const [],
    this.policy = SendPolicy.auto,
    this.guestMode = GuestMode.passphrase,
    this.guestRecipientHint,
    this.noSignature = false,
    required this.createdAt,
    required this.updatedAt,
    this.origin = DraftOrigin.thisDevice,
    this.remoteFiles = 0,
  });

  final int id;
  final String accountId;
  final ComposeKind kind;

  /// Message-ID (no angle brackets) of the message answered, or its local id (digits).
  final String? inReplyTo;

  /// Message-ID (or local id) of the message forwarded.
  final String? forwardOf;
  final bool quote;

  /// The answered message's `References` plus its Message-ID, oldest first (informational).
  final List<String> references;
  final List<String> to;
  final List<String> cc;
  final List<String> bcc;
  final String subject;
  final String body;
  final List<SavedDraftAttachment> attachments;
  final SendPolicy policy;
  final GuestMode guestMode;
  final String? guestRecipientHint;
  final bool noSignature;
  final DateTime createdAt;

  /// Lists are newest first by this.
  final DateTime updatedAt;

  /// Saved on this device, or brought in from the account's Drafts folder on the server
  /// (saved on another device with the same key; engine `SavedDraft.origin`).
  final DraftOrigin origin;

  /// Files the device that saved it attached by reference: they stay on that device, so
  /// they are not in this draft (engine `SavedDraft.remote_files`).
  final int remoteFiles;

  /// To, Cc and Bcc in that order.
  List<String> get recipients => [...to, ...cc, ...bcc];

  /// The same draft as the input that saves it again (under its id).
  DraftInput toInput() => DraftInput(
    id: id,
    accountId: accountId,
    kind: kind,
    inReplyTo: inReplyTo,
    forwardOf: forwardOf,
    quote: quote,
    to: to,
    cc: cc,
    bcc: bcc,
    subject: subject,
    body: body,
    attachments: attachments,
    policy: policy,
    guestMode: guestMode,
    guestRecipientHint: guestRecipientHint,
    noSignature: noSignature,
  );
}
