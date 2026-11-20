import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/errors.dart';

void main() {
  group('friendlyError', () {
    test('drops the bridge wrapper and Dart prefixes', () {
      expect(
        friendlyError('AnyhowException(IMAP: connect to 127.0.0.1:1 failed: Connection refused)'),
        'IMAP: connect to 127.0.0.1:1 failed: Connection refused',
      );
      expect(
        friendlyError(StateError('no Sealbox server configured')),
        'no Sealbox server configured',
      );
      expect(friendlyError(ArgumentError('invalid input: bad')), 'invalid input: bad');
    });

    test('strips the (os error N) suffix Rust appends (review D5)', () {
      expect(
        friendlyError(
          'AnyhowException(IMAP: connect to 127.0.0.1:1 failed: Connection refused (os error 111))',
        ),
        'IMAP: connect to 127.0.0.1:1 failed: Connection refused',
      );
      expect(
        friendlyError(
          Exception('connection: reset (os error 104); retry failed: timed out (os error 110)'),
        ),
        'connection: reset; retry failed: timed out',
      );
      expect(friendlyError('(os error 2)'), 'unknown error');
      expect(friendlyError('the word "os error" alone stays'), 'the word "os error" alone stays');
    });
  });
}
