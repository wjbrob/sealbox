import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/models.dart';
import 'package:sealbox_app/src/policy/encryption_policy.dart';

const bob = RecipientKeyInfo(
  email: 'bob@sealbox.test',
  hasKey: true,
  source: KeySource.autocrypt,
);
const carol = RecipientKeyInfo(
  email: 'carol@proton.me',
  hasKey: true,
  source: KeySource.directory,
);
const dana = RecipientKeyInfo.unknown('dana@example.org');
const ivan = RecipientKeyInfo.unknown('ivan@hotmail.com');

void main() {
  group('EncryptionPolicy.statusFor', () {
    test('key known ⇒ encrypted, regardless of any plaintext confirmation', () {
      expect(
        EncryptionPolicy.statusFor(hasKey: true, plaintextConfirmed: false),
        RecipientStatus.encrypted,
      );
      expect(
        EncryptionPolicy.statusFor(hasKey: true, plaintextConfirmed: true),
        RecipientStatus.encrypted,
      );
    });

    test('no key ⇒ guest link by default, plaintext only after confirmation', () {
      expect(
        EncryptionPolicy.statusFor(hasKey: false, plaintextConfirmed: false),
        RecipientStatus.guestLink,
      );
      expect(
        EncryptionPolicy.statusFor(hasKey: false, plaintextConfirmed: true),
        RecipientStatus.plaintext,
      );
    });
  });

  group('EncryptionPolicy.plan', () {
    test('all recipients have keys ⇒ fully encrypted, no passphrase', () {
      final plan = EncryptionPolicy.plan([bob, carol]);
      expect(plan.mode, SendMode.encrypted);
      expect(plan.allEncrypted, isTrue);
      expect(plan.needsPassphrase, isFalse);
      expect(plan.encryptedRecipients, ['bob@sealbox.test', 'carol@proton.me']);
      expect(plan.guestRecipients, isEmpty);
      expect(plan.plaintextRecipients, isEmpty);
      expect(plan.recipients.first.keySource, KeySource.autocrypt);
      expect(plan.canSend, isTrue);
    });

    test('a key-less recipient gets a guest link by default; others stay encrypted', () {
      final plan = EncryptionPolicy.plan([bob, dana]);
      expect(plan.mode, SendMode.guestLink);
      expect(plan.allEncrypted, isFalse);
      expect(plan.needsPassphrase, isTrue);
      expect(plan.encryptedRecipients, ['bob@sealbox.test']);
      expect(plan.guestRecipients, ['dana@example.org']);
      expect(plan.plaintextRecipients, isEmpty);
      expect(plan.summary, contains('guest link'));
    });

    test('plaintext only for the explicitly confirmed address', () {
      final plan = EncryptionPolicy.plan(
        [bob, dana, ivan],
        confirmedPlaintext: {'dana@example.org'},
      );
      expect(plan.mode, SendMode.plaintext);
      expect(plan.plaintextRecipients, ['dana@example.org']);
      // Confirmation never spreads to another key-less recipient.
      expect(plan.guestRecipients, ['ivan@hotmail.com']);
      expect(plan.encryptedRecipients, ['bob@sealbox.test']);
      expect(plan.needsPassphrase, isTrue);
      expect(plan.summary, startsWith('Warning'));
    });

    test('confirmation is matched case-insensitively', () {
      final plan = EncryptionPolicy.plan(
        [dana],
        confirmedPlaintext: {'DANA@Example.org'},
      );
      expect(plan.plaintextRecipients, ['dana@example.org']);
    });

    test('a recipient with a key is never downgraded to plaintext', () {
      final plan = EncryptionPolicy.plan(
        [bob],
        confirmedPlaintext: {'bob@sealbox.test'},
      );
      expect(plan.mode, SendMode.encrypted);
      expect(plan.plaintextRecipients, isEmpty);
    });

    test('duplicate addresses collapse to one decision', () {
      final plan = EncryptionPolicy.plan([
        dana,
        const RecipientKeyInfo.unknown('Dana@Example.org'),
      ]);
      expect(plan.recipients, hasLength(1));
    });

    test('no recipients ⇒ nothing to send yet', () {
      final plan = EncryptionPolicy.plan(const []);
      expect(plan.mode, SendMode.empty);
      expect(plan.isEmpty, isTrue);
      expect(plan.canSend, isFalse);
      expect(plan.needsPassphrase, isFalse);
    });
  });
}
