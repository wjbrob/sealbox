import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

// Review P9: on a phone the thread header wrapped the recipient inside the name ("to Bob /
// Nakamura"). Below 600 dp the sender's address and "to …" now get a line each — one line,
// ellipsised, so a name is never split across lines; wider windows keep "address · to …".

const _many = [
  Contact(email: 'bob@sealbox.test', name: 'Bob Nakamura'),
  Contact(email: 'carol@proton.me', name: 'Carol Okafor'),
  Contact(email: 'dana@example.org', name: 'Dana Whitfield-Montgomery'),
  Contact(email: 'erik@posteo.de', name: 'Erik Lindqvist'),
];

/// FakeCore plus a conversation addressed to four people and one from a long address.
class _Core extends FakeCore {
  _Core() : super(latency: Duration.zero);

  static final _message = Message(
    id: 'm-many',
    threadId: 't-many',
    accountId: 'acct-1',
    from: const Contact(email: 'alice.rivera@gmail.com', name: 'Alice Rivera'),
    to: _many,
    subject: 'Offsite dates',
    body: 'Which week works for everyone?',
    date: DateTime(2026, 6, 15, 9, 30),
    state: EncryptionState.encrypted,
  );

  /// A sender address too long for one line of a phone header.
  static final _longFrom = Message(
    id: 'm-long-from',
    threadId: 't-long-from',
    accountId: 'acct-1',
    from: const Contact(
      email: 'notifications@accounts.nakamura-billing.example',
      name: 'Nakamura Billing',
    ),
    to: const [Contact(email: 'alice.rivera@gmail.com', name: 'Alice Rivera')],
    subject: 'Your invoice',
    body: 'Attached.',
    date: DateTime(2026, 6, 15, 9, 45),
    state: EncryptionState.plaintext,
  );

  @override
  Future<MailThread?> getThread(String threadId) async => switch (threadId) {
    't-many' => MailThread(
      id: 't-many',
      subject: 'Offsite dates',
      accountId: 'acct-1',
      messages: [_message],
    ),
    't-long-from' => MailThread(
      id: 't-long-from',
      subject: 'Your invoice',
      accountId: 'acct-1',
      messages: [_longFrom],
    ),
    _ => await super.getThread(threadId),
  };
}

Future<void> openThread(WidgetTester tester, Size size, String threadId) async {
  setSurface(tester, size);
  await tester.pumpWidget(buildApp(core: _Core(), initialLocation: '/inbox/t/$threadId'));
  await tester.pumpAndSettle();
}

Finder recipients(String id) => find.byKey(ValueKey('message-recipients-$id'));
Finder address(String id) => find.byKey(ValueKey('message-from-address-$id'));

void main() {
  testWidgets('phone: the address and "to …" have a line each', (tester) async {
    await openThread(tester, phone, 't-budget');
    expect(tester.widget<Text>(address('m-0')).data, 'alice.rivera@gmail.com');
    expect(tester.widget<Text>(recipients('m-0')).data, 'to Bob Nakamura');
    expect(tester.widget<Text>(recipients('m-1')).data, 'to Alice Rivera');
    // One line each: "to Bob Nakamura" is exactly as tall as the one-line address above it.
    expect(tester.getSize(recipients('m-0')).height, tester.getSize(address('m-0')).height);
    expect(find.textContaining('· to'), findsNothing);
  });

  testWidgets('phone: a long recipient list stays on one line, ellipsised', (tester) async {
    await openThread(tester, phone, 't-many');
    final to = recipients('m-many');
    final text = tester.widget<Text>(to);
    expect(text.data, startsWith('to Bob Nakamura, Carol Okafor, Dana Whitfield-Montgomery'));
    expect(text.maxLines, 1);
    expect(text.overflow, TextOverflow.ellipsis);
    expect(tester.renderObject<RenderParagraph>(to).didExceedMaxLines, isTrue, reason: 'cut');
    expect(tester.getSize(to).height, tester.getSize(address('m-many')).height);
  });

  testWidgets('phone: a long sender address is shown whole, on two lines', (tester) async {
    await openThread(tester, phone, 't-long-from');
    final from = address('m-long-from');
    expect(tester.widget<Text>(from).data, 'notifications@accounts.nakamura-billing.example');
    expect(tester.renderObject<RenderParagraph>(from).didExceedMaxLines, isFalse, reason: 'whole');
    expect(tester.getSize(from).height, 2 * tester.getSize(recipients('m-long-from')).height);
  });

  testWidgets('desktop keeps "address · to …" on one line of up to two', (tester) async {
    await openThread(tester, desktop, 't-budget');
    expect(tester.widget<Text>(recipients('m-0')).data, 'alice.rivera@gmail.com · to Bob Nakamura');
    expect(tester.widget<Text>(recipients('m-0')).maxLines, 2);
    expect(address('m-0'), findsNothing);
  });
}
