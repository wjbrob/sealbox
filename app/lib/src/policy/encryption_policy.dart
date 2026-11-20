/// The per-recipient encryption policy (docs/ARCHITECTURE.md, "Send pipeline").
///
/// Pure Dart, no Flutter imports: this is unit-tested directly.
///
/// * every recipient has a key            ⇒ PGP/MIME encrypt + sign to all;
/// * some recipients lack a key           ⇒ those get a **guest link** by default;
/// * plaintext for a key-less recipient   ⇒ only after the user confirmed it,
///   and the confirmation is per address (adding another key-less recipient
///   never inherits it). A recipient whose key is known is never downgraded.
library;

import '../core/models.dart';

enum RecipientStatus {
  /// Key known: the message is PGP/MIME-encrypted to this recipient.
  encrypted,

  /// No key: the recipient gets a passphrase-protected guest link.
  guestLink,

  /// No key and the user explicitly accepted sending in the clear.
  plaintext,
}

extension RecipientStatusLabel on RecipientStatus {
  String get label => switch (this) {
    RecipientStatus.encrypted => 'Encrypted',
    RecipientStatus.guestLink => 'Guest link',
    RecipientStatus.plaintext => 'Plaintext',
  };
}

/// Message-level summary of the recipient decisions.
enum SendMode {
  /// Nothing to decide yet.
  empty,

  /// All recipients have keys.
  encrypted,

  /// At least one recipient gets a guest link, nobody gets plaintext.
  guestLink,

  /// At least one recipient gets plaintext (confirmed).
  plaintext,
}

class RecipientDecision {
  const RecipientDecision({
    required this.email,
    required this.status,
    this.keySource,
  });

  final String email;
  final RecipientStatus status;
  final KeySource? keySource;

  @override
  String toString() => '$email: ${status.name}';
}

class MessagePlan {
  const MessagePlan(this.recipients);

  final List<RecipientDecision> recipients;

  List<String> _emailsWith(RecipientStatus s) => [
    for (final r in recipients)
      if (r.status == s) r.email,
  ];

  List<String> get encryptedRecipients =>
      _emailsWith(RecipientStatus.encrypted);
  List<String> get guestRecipients => _emailsWith(RecipientStatus.guestLink);
  List<String> get plaintextRecipients =>
      _emailsWith(RecipientStatus.plaintext);

  bool get isEmpty => recipients.isEmpty;
  bool get allEncrypted =>
      recipients.isNotEmpty &&
      recipients.every((r) => r.status == RecipientStatus.encrypted);

  /// A guest-link message needs a passphrase to show the sender.
  bool get needsPassphrase => guestRecipients.isNotEmpty;

  /// Sending must be blocked until the user has confirmed plaintext for every
  /// recipient that would receive it; with this policy that is already
  /// encoded in the status, so the only hard block is "no recipients".
  bool get canSend => recipients.isNotEmpty;

  SendMode get mode {
    if (recipients.isEmpty) return SendMode.empty;
    if (plaintextRecipients.isNotEmpty) return SendMode.plaintext;
    if (guestRecipients.isNotEmpty) return SendMode.guestLink;
    return SendMode.encrypted;
  }

  String get summary {
    switch (mode) {
      case SendMode.empty:
        return 'Add a recipient to see how this message will be protected.';
      case SendMode.encrypted:
        return recipients.length == 1
            ? 'End-to-end encrypted (OpenPGP) and signed.'
            : 'End-to-end encrypted (OpenPGP) to all ${recipients.length} recipients and signed.';
      case SendMode.guestLink:
        final n = guestRecipients.length;
        final e = encryptedRecipients.length;
        return '${n == 1 ? '1 recipient has' : '$n recipients have'} no key: '
            'they get a passphrase-protected guest link'
            '${e > 0 ? '; $e encrypted with OpenPGP' : ''}.';
      case SendMode.plaintext:
        final n = plaintextRecipients.length;
        return 'Warning: ${n == 1 ? '1 recipient' : '$n recipients'} will receive '
            'this message unencrypted.';
    }
  }
}

class EncryptionPolicy {
  const EncryptionPolicy._();

  static RecipientStatus statusFor({
    required bool hasKey,
    required bool plaintextConfirmed,
  }) {
    if (hasKey) return RecipientStatus.encrypted;
    return plaintextConfirmed
        ? RecipientStatus.plaintext
        : RecipientStatus.guestLink;
  }

  /// Decide for every recipient. [confirmedPlaintext] holds the addresses
  /// (any case) for which the user explicitly accepted plaintext.
  static MessagePlan plan(
    Iterable<RecipientKeyInfo> recipients, {
    Set<String> confirmedPlaintext = const {},
  }) {
    final confirmed = {for (final e in confirmedPlaintext) e.toLowerCase()};
    final seen = <String>{};
    final decisions = <RecipientDecision>[];
    for (final r in recipients) {
      final email = r.email.trim();
      if (!seen.add(email.toLowerCase())) continue;
      decisions.add(
        RecipientDecision(
          email: email,
          status: statusFor(
            hasKey: r.hasKey,
            plaintextConfirmed: confirmed.contains(email.toLowerCase()),
          ),
          keySource: r.hasKey ? r.source : null,
        ),
      );
    }
    return MessagePlan(List.unmodifiable(decisions));
  }
}
