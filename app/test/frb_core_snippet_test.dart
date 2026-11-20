import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/frb_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'support/fake_frb_engine.dart';

// List previews come from the snippet the engine stores with every message
// (`MessageSummary.snippet`), not from one `getMessage` per conversation: that was ~800 bridge
// calls, each unsealing a body, per inbox load at 10k messages (docs/PERFORMANCE.md). Mail
// without a stored snippet (nothing readable, e.g. not decryptable here) is still read.

void main() {
  test('an inbox load reads no body when every newest message has a snippet', () async {
    final engine = FakeFrbEngine();
    for (var i = 1; i <= 40; i++) {
      engine.summaries.add(
        FakeFrbEngine.summary(i, subject: 'Topic $i', date: 1781500000 + i, snippet: 'Body $i'),
      );
    }
    final threads = await FrbCore(engine).listThreadsIn(MailFolder.inbox);
    expect(threads, hasLength(40));
    expect(engine.getMessageCalls, isEmpty, reason: 'was one getMessage per conversation');
    expect(threads.first.latest.snippet, 'Body 40', reason: 'newest conversation first');
    expect(threads.first.latest.body, isEmpty, reason: 'bodies wait for the thread view');
  });

  test('a conversation previews its newest message, by the engine snippet', () async {
    final engine = FakeFrbEngine()
      ..summaries.addAll([
        FakeFrbEngine.summary(1, threadId: 't', date: 1781500000, snippet: 'the question'),
        FakeFrbEngine.summary(2, threadId: 't', date: 1781500600, snippet: 'the   answer\n ok'),
      ]);
    final threads = await FrbCore(engine).listThreadsIn(MailFolder.inbox);
    expect(threads.single.messages, hasLength(2));
    expect(threads.single.latest.snippet, 'the answer ok', reason: 'whitespace collapsed');
    expect(engine.getMessageCalls, isEmpty);
  });

  test('without a snippet the newest message is read, as before', () async {
    final undecryptable = FakeFrbEngine.summary(
      7,
      subject: '...',
      wasEncrypted: true,
      decryptError: 'no matching key',
    );
    final engine = FakeFrbEngine()
      ..summaries.addAll([undecryptable, FakeFrbEngine.summary(8, date: 1781400000, snippet: 'hi')])
      ..details[7] = FakeFrbEngine.detail(undecryptable);
    final threads = await FrbCore(engine).listThreadsIn(MailFolder.inbox);
    expect(engine.getMessageCalls, [7], reason: 'only the one without a snippet');
    expect(
      threads.firstWhere((t) => t.latest.id == '7').latest.snippet,
      'This message is encrypted, but not to a key on this device: no matching key',
    );
  });

  test('Message.snippet: the engine snippet wins over the body, 120 characters at most', () {
    Message m({String body = '', String? engineSnippet}) => Message(
      id: '1',
      threadId: 't',
      accountId: 'a',
      from: const Contact(email: 'b@x'),
      to: const [],
      subject: 's',
      body: body,
      date: DateTime.utc(2026),
      state: EncryptionState.plaintext,
      engineSnippet: engineSnippet,
    );
    expect(m(body: 'from the body').snippet, 'from the body');
    expect(m(body: 'from the body', engineSnippet: 'stored').snippet, 'stored');
    final long = List.filled(32, 'word').join(' '); // 159 characters, as the engine stores
    expect(m(engineSnippet: long).snippet, '${long.substring(0, 117)}…');
    expect(
      m(engineSnippet: 'x').copyWith(body: 'read later').snippet,
      'x',
      reason: 'kept',
    );
  });
}
