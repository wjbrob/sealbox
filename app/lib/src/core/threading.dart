/// Conversation grouping for the unified inbox (pure Dart, no engine types).
///
/// `sealbox-core` stores flat messages per folder and threads them itself: every
/// `MessageSummary` carries `thread_id`, the Message-ID of the earliest known
/// ancestor in its account (References / In-Reply-To). The UI groups by that key
/// ("reference threading"), so a reply with a changed subject stays in its
/// conversation and two unrelated mails with the same subject stay apart. Only
/// messages without an engine key (sample data, doubles) fall back to grouping
/// by normalised subject (`Re:`, `Fwd:` … stripped). Thread ids are URL-safe so
/// they can live in a route.
library;

import 'dart:convert';

import 'models.dart';

final RegExp _prefixRe = RegExp(
  r'^\s*((re|fw|fwd|aw|wg|sv|vs|tr)\s*(\[\d+\])?\s*:\s*)+',
  caseSensitive: false,
);

/// Lower-cased subject without reply/forward prefixes and surrounding space.
String normalizeSubject(String? subject) {
  final s = (subject ?? '').replaceFirst(_prefixRe, '').trim().toLowerCase();
  return s.isEmpty ? '(no subject)' : s.replaceAll(RegExp(r'\s+'), ' ');
}

String threadKey(String account, String? subject) =>
    '${account.trim().toLowerCase()}|${normalizeSubject(subject)}';

/// `t-<base64url(key)>` without padding.
String threadIdFor(String key) =>
    't-${base64Url.encode(utf8.encode(key)).replaceAll('=', '')}';

String threadIdOf(String account, String? subject) =>
    threadIdFor(threadKey(account, subject));

/// Conversation id of a message the engine threaded by References / In-Reply-To:
/// [reference] is `MessageSummary.thread_id`, scoped to [account]. The key starts
/// with `ref|`, which no subject key (`<account>|…`) can, so the two never meet.
String threadIdForReference(String account, String reference) =>
    threadIdFor('ref|${account.trim().toLowerCase()}|${reference.trim()}');

/// The conversation id of one message: by its engine [reference] when it has
/// one, else by subject (the same rule [groupConversations] applies).
String conversationIdOf(String account, String? subject, String? reference) =>
    (reference ?? '').trim().isEmpty
        ? threadIdOf(account, subject)
        : threadIdForReference(account, reference!);

/// Strips a subject down to the conversation title shown in the list.
String displaySubject(String? subject) {
  final s = (subject ?? '').trim();
  return s.isEmpty ? '(no subject)' : s;
}

/// What providers hold as the Subject of encrypted mail whose real subject travels inside
/// the ciphertext (protected headers): `...` (Sealbox, Thunderbird, Delta Chat), `…`, or
/// nothing at all, which [displaySubject] turns into `(no subject)`.
bool isPlaceholderSubject(String? subject) {
  final s = (subject ?? '').trim();
  return s.isEmpty || s == '...' || s == '…' || s == '(no subject)';
}

/// The title shown instead of the placeholder when the real subject is not available
/// (review N1). Screens show it in the secondary, italic style; the lock badge says why.
const encryptedMessageTitle = 'Encrypted message';

/// [m]'s subject is only the outer placeholder and the real one is not available: the
/// message could not be decrypted, or it was decrypted but carried no protected subject.
/// A protected subject that really is `...` ([Message.protectedSubject]) stays as typed.
bool subjectUnreadable(Message m) =>
    isPlaceholderSubject(m.subject) &&
    (m.state == EncryptionState.undecryptable ||
        (m.state == EncryptionState.encrypted && !m.protectedSubject));

/// The conversation title of the list row and the thread header: [MailThread.subject], or
/// [encryptedMessageTitle] with `placeholder: true` when that subject is a placeholder and
/// every member carrying a placeholder is [subjectUnreadable] (review N1). Keys and routes
/// keep using [MailThread.subject] itself.
({String text, bool placeholder}) conversationTitle(MailThread t) {
  if (!isPlaceholderSubject(t.subject)) return (text: t.subject, placeholder: false);
  final placeholders = [
    for (final m in t.messages)
      if (isPlaceholderSubject(m.subject)) m,
  ];
  return placeholders.isNotEmpty && placeholders.every(subjectUnreadable)
      ? (text: encryptedMessageTitle, placeholder: true)
      : (text: t.subject, placeholder: false);
}

/// Very small HTML → text fallback for messages without a text part.
String htmlToText(String html) {
  var s = html
      .replaceAll(RegExp(r'<\s*(br|/p|/div|/tr|/li|/h[1-6])\s*/?>', caseSensitive: false), '\n')
      .replaceAll(RegExp(r'<[^>]+>'), '');
  s = s
      .replaceAll('&nbsp;', ' ')
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"')
      .replaceAll('&#39;', "'")
      .replaceAll('&amp;', '&');
  return s.replaceAll(RegExp(r'\n{3,}'), '\n\n').trim();
}

/// Subject fallback only (messages without an engine thread key): messages of
/// one account with the same normalised subject belong to one conversation only
/// while they are no more than [conversationGap] apart; a longer silence starts
/// a new conversation ("Re: invoice" next month is another invoice, lead review
/// L13).
const Duration conversationGap = Duration(days: 7);

/// Groups [items] into conversations. Returns thread id → members (oldest
/// first); map order follows each conversation's newest message, newest first.
///
/// An item whose [reference] (the engine's `thread_id`) is non-empty joins the
/// conversation of that key in its account, whatever its subject says; the id
/// is [threadIdForReference] and stays the same as long as the engine's key does
/// (a late parent re-links its replies under the parent's key). Items without a
/// reference are grouped by normalised subject within [gap]; such an id is
/// stable as long as the conversation's first message is.
Map<String, List<T>> groupConversations<T>(
  Iterable<T> items, {
  required String Function(T) account,
  required String? Function(T) subject,
  required DateTime Function(T) date,
  required String Function(T) id,
  String? Function(T)? reference,
  Duration gap = conversationGap,
}) {
  final byReference = <String, List<T>>{};
  final bySubject = <String, List<T>>{};
  for (final m in items) {
    final ref = reference?.call(m)?.trim() ?? '';
    if (ref.isNotEmpty) {
      byReference.putIfAbsent(threadIdForReference(account(m), ref), () => []).add(m);
    } else {
      bySubject.putIfAbsent(threadKey(account(m), subject(m)), () => []).add(m);
    }
  }
  final out = <(DateTime, String, List<T>)>[];
  for (final entry in byReference.entries) {
    final sorted = [...entry.value]
      ..sort((a, b) => compareConversationOrder(date(a), id(a), date(b), id(b)));
    out.add((date(sorted.last), entry.key, sorted));
  }
  for (final entry in bySubject.entries) {
    final sorted = [...entry.value]
      ..sort((a, b) => compareConversationOrder(date(a), id(a), date(b), id(b)));
    var current = <T>[];
    void flush() {
      if (current.isEmpty) return;
      final first = current.first;
      // The first conversation of a subject keeps the plain subject id, so
      // links to subject-only thread ids keep working for the common case.
      final tid = out.any((o) => o.$2 == threadIdFor(entry.key))
          ? threadIdFor('${entry.key}|${id(first)}')
          : threadIdFor(entry.key);
      out.add((date(current.last), tid, current));
      current = <T>[];
    }

    for (final m in sorted) {
      if (current.isNotEmpty && date(m).difference(date(current.last)) > gap) flush();
      current.add(m);
    }
    flush();
  }
  out.sort((a, b) => b.$1.compareTo(a.$1));
  return {for (final o in out) o.$2: o.$3};
}

/// Order of a conversation's members: by date, then by the engine's row id
/// (numerically when both are numbers), so two messages stamped the same second
/// — a reply sent right after its parent — keep their arrival order. `List.sort`
/// is not stable: a plain date comparison let the reply come first and name the
/// conversation after itself (G17 flake, 2026-10-29).
int compareConversationOrder(DateTime dateA, String idA, DateTime dateB, String idB) {
  final byDate = dateA.compareTo(dateB);
  if (byDate != 0) return byDate;
  final a = int.tryParse(idA);
  final b = int.tryParse(idB);
  if (a != null && b != null) return a.compareTo(b);
  return idA.compareTo(idB);
}

/// The member a conversation is named after: its root — the earliest member (in
/// [compareConversationOrder] order, which [members] must already follow) that
/// does not answer another member, i.e. whose In-Reply-To / References name no
/// other member's Message-ID. When every member answers another (the parent is
/// missing, or a cycle), the earliest member.
T conversationRoot<T>(
  List<T> members, {
  required String? Function(T) messageId,
  required Iterable<String> Function(T) answers,
}) {
  assert(members.isNotEmpty, 'a conversation has at least one member');
  String norm(String id) {
    var t = id.trim();
    if (t.startsWith('<')) t = t.substring(1);
    if (t.endsWith('>')) t = t.substring(0, t.length - 1);
    return t.toLowerCase();
  }

  final ids = <String>{
    for (final m in members)
      if (messageId(m) case final id? when id.trim().isNotEmpty) norm(id),
  };
  for (final m in members) {
    final own = messageId(m);
    final self = own == null ? null : norm(own);
    final answersMember = answers(m).map(norm).any((a) => a != self && ids.contains(a));
    if (!answersMember) return m;
  }
  return members.first;
}
