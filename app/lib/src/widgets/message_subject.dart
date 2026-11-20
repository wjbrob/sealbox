import 'package:flutter/material.dart';

import '../core/models.dart';
import '../core/threading.dart'
    show displaySubject, encryptedMessageTitle, isPlaceholderSubject, subjectUnreadable;

/// The subject of one stored message as a list of messages shows it: the provider's
/// placeholder (`...`, `…`, nothing) of mail whose real subject is not available reads
/// [encryptedMessageTitle] with `placeholder: true` (review N1, the rule the inbox row and
/// the thread header follow); an empty subject reads "(no subject)".
({String text, bool placeholder}) messageSubjectTitle(Message m) => subjectUnreadable(m)
    ? (text: encryptedMessageTitle, placeholder: true)
    : (text: displaySubject(m.subject), placeholder: false);

/// The same for a bare [subject] (an engine report that names the message by its subject
/// only). [message] is the stored message when it is known: without it a placeholder
/// subject cannot be told apart from a protected subject that really is `...`, so it is
/// shown as it is.
({String text, bool placeholder}) subjectTitleOf(String? subject, {Message? message}) =>
    message != null && isPlaceholderSubject(subject)
    ? messageSubjectTitle(message)
    : (text: displaySubject(subject), placeholder: false);

/// [base] in the secondary, italic style of a placeholder title (inbox and thread use it
/// for "Encrypted message"); [base] unchanged otherwise.
TextStyle? subjectTitleStyle(BuildContext context, TextStyle? base, {required bool placeholder}) {
  if (!placeholder) return base;
  final style = TextStyle(
    fontStyle: FontStyle.italic,
    color: Theme.of(context).colorScheme.onSurfaceVariant,
  );
  return base?.merge(style) ?? style;
}
