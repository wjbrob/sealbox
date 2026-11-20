import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/core/threading.dart';

typedef M = ({String id, String account, String subject, DateTime date});

Map<String, List<M>> group(List<M> ms) => groupConversations<M>(
  ms,
  account: (m) => m.account,
  subject: (m) => m.subject,
  date: (m) => m.date,
  id: (m) => m.id,
);

/// A message the engine threaded: [ref] is `MessageSummary.thread_id` ('' = none).
typedef R = ({String id, String account, String subject, DateTime date, String ref});

Map<String, List<R>> groupByRef(List<R> ms) => groupConversations<R>(
  ms,
  account: (m) => m.account,
  subject: (m) => m.subject,
  date: (m) => m.date,
  id: (m) => m.id,
  reference: (m) => m.ref,
);

final _urlSafe = RegExp(r'^t-[A-Za-z0-9_-]+$');

/// A member as `conversationRoot` sees it: row id, Message-ID, what it answers.
typedef Rm = ({String id, String? mid, List<String> refs});

void main() {
  final d0 = DateTime.utc(2026, 10, 1, 9);
  M m(String id, String subject, int days, {String account = 'u66@sealbox.test'}) =>
      (id: id, account: account, subject: subject, date: d0.add(Duration(days: days)));

  test('same subject within 7 days of the previous message ⇒ one conversation', () {
    final g = group([m('1', 'Invoice', 0), m('2', 'Re: Invoice', 3), m('3', 'RE: invoice', 9)]);
    expect(g.values.single.map((x) => x.id), ['1', '2', '3']);
    expect(g.keys.single, threadIdOf('u66@sealbox.test', 'Invoice'));
  });

  test('a silence of more than 7 days starts a new conversation (L13)', () {
    final g = group([m('1', 'Invoice', 0), m('2', 'Re: invoice', 2), m('3', 'Re: invoice', 30)]);
    expect(g, hasLength(2));
    // Newest conversation first; the oldest keeps the subject-only id.
    expect(g.values.first.map((x) => x.id), ['3']);
    expect(g.values.last.map((x) => x.id), ['1', '2']);
    expect(g.keys.last, threadIdOf('u66@sealbox.test', 'invoice'));
    expect(g.keys.first, isNot(g.keys.last));
  });

  test('ids are stable when unrelated mail arrives, and differ per account', () {
    final a = group([m('1', 'Lunch', 0), m('2', 'Lunch', 20)]);
    final b = group([m('1', 'Lunch', 0), m('2', 'Lunch', 20), m('9', 'Other', 21)]);
    expect(b.keys.toSet().containsAll(a.keys), isTrue);
    final c = group([m('1', 'Lunch', 0), m('5', 'Lunch', 1, account: 'u67@sealbox.test')]);
    expect(c, hasLength(2));
  });

  // -- reference threading (the engine's thread_id) --
  {
    R r(String id, String subject, int days, String ref, {String account = 'u66@sealbox.test'}) =>
        (id: id, account: account, subject: subject, date: d0.add(Duration(days: days)), ref: ref);

    test('a reply with In-Reply-To and a changed subject stays in the conversation', () {
      final g = groupByRef([
        r('1', 'Lunch Thursday?', 0, 'a1@x.test'),
        r('2', 'Change of plan: Friday', 1, 'a1@x.test'),
      ]);
      expect(g.values.single.map((x) => x.id), ['1', '2']);
      expect(g.keys.single, threadIdForReference('u66@sealbox.test', 'a1@x.test'));
    });

    test('two unrelated mails with the same subject do not merge (even a day apart)', () {
      final g = groupByRef([
        r('1', 'Invoice', 0, 'one@x.test'),
        r('2', 'Invoice', 1, 'two@x.test'),
      ]);
      expect(g, hasLength(2));
      expect(g.values.map((v) => v.single.id).toSet(), {'1', '2'});
    });

    test('no silence limit inside a reference thread; newest conversation first', () {
      final g = groupByRef([
        r('1', 'Q4', 0, 'q4@x.test'),
        r('2', 'Re: Q4', 60, 'q4@x.test'),
        r('3', 'Other', 30, 'o@x.test'),
      ]);
      expect(g.values.first.map((x) => x.id), ['1', '2']);
      expect(g.values.last.map((x) => x.id), ['3']);
    });

    test('scoped per account; messages without a key fall back to the subject', () {
      final g = groupByRef([
        r('1', 'Hello', 0, 'same@x.test'),
        r('2', 'Hello', 0, 'same@x.test', account: 'u67@sealbox.test'),
        r('3', 'Note', 1, ''),
        r('4', 'Re: note', 2, ''),
      ]);
      expect(g, hasLength(3));
      expect(g[threadIdOf('u66@sealbox.test', 'Note')]!.map((x) => x.id), ['3', '4']);
    });

    test('ids are URL-safe and never collide with subject ids', () {
      final ref = threadIdForReference('U66@Sealbox.test', '<CAF+/x=y_z@mail.gmail.com>');
      expect(ref, matches(_urlSafe));
      expect(ref, threadIdForReference('u66@sealbox.test', '<CAF+/x=y_z@mail.gmail.com>'));
      // A subject that spells a reference key still gets a different id: subject keys
      // start with the account address, reference keys with `ref|`.
      expect(
        threadIdOf('u66@sealbox.test', 'ref|u66@sealbox.test|x@y'),
        isNot(threadIdForReference('u66@sealbox.test', 'x@y')),
      );
      expect(
        conversationIdOf('u66@sealbox.test', 'Hi', 'k@x.test'),
        threadIdForReference('u66@sealbox.test', 'k@x.test'),
      );
      expect(
        conversationIdOf('u66@sealbox.test', 'Re: Hi', ''),
        threadIdOf('u66@sealbox.test', 'Hi'),
      );
      expect(
        conversationIdOf('u66@sealbox.test', 'Re: Hi', null),
        threadIdOf('u66@sealbox.test', 'Hi'),
      );
    });
  }

  // -- N1: the placeholder subject of mail nobody here can read --
  {
    Message msg(
      String id,
      String subject,
      EncryptionState state, {
      bool protectedSubject = false,
      int minutes = 0,
    }) => Message(
      id: id,
      threadId: 't-x',
      accountId: 'u66@sealbox.test',
      from: const Contact(email: 'u67@sealbox.test'),
      to: const [Contact(email: 'u66@sealbox.test')],
      subject: subject,
      body: '',
      date: d0.add(Duration(minutes: minutes)),
      state: state,
      protectedSubject: protectedSubject,
    );
    MailThread thread(String subject, List<Message> messages) =>
        MailThread(id: 't-x', subject: subject, accountId: 'u66@sealbox.test', messages: messages);

    test('placeholders: "...", "…", empty and what displaySubject makes of empty', () {
      for (final s in ['...', ' ... ', '…', '', '   ', displaySubject(''), displaySubject(null)]) {
        expect(isPlaceholderSubject(s), isTrue, reason: '"$s"');
      }
      for (final s in ['Re: ...', 'Q4 budget', '....', '. . .', 'Encrypted message']) {
        expect(isPlaceholderSubject(s), isFalse, reason: '"$s"');
      }
    });

    test('undecryptable, or decrypted without a protected subject ⇒ unreadable', () {
      expect(subjectUnreadable(msg('1', '...', EncryptionState.undecryptable)), isTrue);
      expect(subjectUnreadable(msg('2', '(no subject)', EncryptionState.undecryptable)), isTrue);
      expect(subjectUnreadable(msg('3', '...', EncryptionState.encrypted)), isTrue);
      // The sender's protected subject really was "...": shown as typed.
      expect(
        subjectUnreadable(msg('4', '...', EncryptionState.encrypted, protectedSubject: true)),
        isFalse,
      );
      // Plaintext / signed mail has no ciphertext to hide a subject in.
      expect(subjectUnreadable(msg('5', '...', EncryptionState.plaintext)), isFalse);
      expect(subjectUnreadable(msg('6', '', EncryptionState.signed)), isFalse);
      // A real subject is never replaced.
      expect(subjectUnreadable(msg('7', 'Q4 budget', EncryptionState.undecryptable)), isFalse);
    });

    test('conversationTitle: "Encrypted message" (placeholder) only when nothing can replace it', () {
      final hidden = thread('...', [msg('1', '...', EncryptionState.undecryptable)]);
      expect(conversationTitle(hidden), (text: encryptedMessageTitle, placeholder: true));
      expect(encryptedMessageTitle, 'Encrypted message');

      // Our reply in the same conversation ("Re: ..." is not a placeholder) does not
      // bring the subject back; the undecryptable original still hides it.
      final replied = thread('...', [
        msg('1', '...', EncryptionState.undecryptable),
        msg('2', 'Re: ...', EncryptionState.encrypted, protectedSubject: true, minutes: 5),
      ]);
      expect(conversationTitle(replied).placeholder, isTrue);

      // A placeholder some member can read (a plaintext mail without subject) stays.
      final plain = thread('(no subject)', [msg('1', '', EncryptionState.plaintext)]);
      expect(conversationTitle(plain), (text: '(no subject)', placeholder: false));

      final typed = thread('...', [msg('1', '...', EncryptionState.encrypted, protectedSubject: true)]);
      expect(conversationTitle(typed), (text: '...', placeholder: false));

      final normal = thread('Q4 budget', [msg('1', 'Q4 budget', EncryptionState.undecryptable)]);
      expect(conversationTitle(normal), (text: 'Q4 budget', placeholder: false));
    });
  }

  // --- conversation order and root (G17, 2026-10-29) ---------------------------------
  final t17 = DateTime.utc(2026, 10, 29, 7, 56, 45);

  test("members stamped the same second keep the engine's row order, not List.sort's", () {
    // The engine lists newest first (date DESC, id DESC): the reply (139) before its
    // parent (138). Equal dates must not let the reply lead the conversation.
    final g = groupByRef([
      (id: '139', account: 'u01@sealbox.test', subject: 'moved on', date: t17, ref: 'k'),
      (id: '138', account: 'u01@sealbox.test', subject: 'thread', date: t17, ref: 'k'),
    ]);
    expect(g.values.single.map((m) => m.id), ['138', '139']);
  });

  test('compareConversationOrder: date first, then numeric ids, then text ids', () {
    expect(compareConversationOrder(t17, '2', t17.add(const Duration(seconds: 1)), '1'), lessThan(0));
    expect(compareConversationOrder(t17, '10', t17, '9'), greaterThan(0));
    expect(compareConversationOrder(t17, 'b', t17, 'a'), greaterThan(0));
    expect(compareConversationOrder(t17, '7', t17, '7'), 0);
  });

  test('conversationRoot: the earliest member that answers no other member', () {
    Rm m(String id, String? mid, [List<String> refs = const []]) => (id: id, mid: mid, refs: refs);
    Rm root(List<Rm> ms) => conversationRoot<Rm>(ms, messageId: (x) => x.mid, answers: (x) => x.refs);
    // Parent then reply: the parent.
    expect(root([m('138', '<p@x>'), m('139', '<r@x>', ['<p@x>'])]).id, '138');
    // Clock skew put the reply first: still the parent (it answers nobody).
    expect(root([m('139', '<r@x>', ['<p@x>']), m('138', '<p@x>')]).id, '138');
    // Angle brackets and case do not matter.
    expect(root([m('2', 'R@X', ['<P@x>']), m('1', '<p@X>')]).id, '1');
    // A message naming itself is not a reply to anyone.
    expect(root([m('1', '<a@x>', ['<a@x>']), m('2', '<b@x>', ['<a@x>'])]).id, '1');
    // Every member answers another (the parent is missing): the earliest member.
    expect(root([m('5', '<r1@x>', ['<gone@x>']), m('6', '<r2@x>', ['<r1@x>'])]).id, '5');
    // No Message-IDs at all: the earliest member.
    expect(root([m('1', null), m('2', null, ['<x@y>'])]).id, '1');
  });
}
