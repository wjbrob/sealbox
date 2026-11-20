import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/providers/provider_table.dart';

void main() {
  group('built-in provider table', () {
    test('Gmail: OAuth first, app-password fallback, TLS on 993/465', () {
      final p = detectProviderForEmail('Someone@Gmail.com')!;
      expect(p.id, 'gmail');
      expect(p.imap.host, 'imap.gmail.com');
      expect(p.imap.port, 993);
      expect(p.imap.security, ConnectionSecurity.tls);
      expect(p.smtp.host, 'smtp.gmail.com');
      expect(p.smtp.port, 465);
      expect(p.auth, AuthMethod.oauth2);
      expect(p.oauthIdp, OAuthIdp.google);
      expect(p.allowsAppPasswordFallback, isTrue);
      expect(detectProviderForEmail('x@googlemail.com')?.id, 'gmail');
    });

    test('Outlook/Hotmail/Live: OAuth only, no password path', () {
      for (final d in ['outlook.com', 'hotmail.com', 'live.com', 'hotmail.co.uk']) {
        final p = detectProviderForEmail('u@$d');
        expect(p?.id, 'outlook', reason: d);
        expect(p?.auth, AuthMethod.oauth2);
        expect(p?.oauthIdp, OAuthIdp.microsoft);
        expect(p?.allowsAppPasswordFallback, isFalse);
        expect(p?.imap.host, 'outlook.office365.com');
        expect(p?.smtp.host, 'smtp.office365.com');
        expect(p?.smtp.port, 587);
        expect(p?.smtp.security, ConnectionSecurity.starttls);
      }
    });

    test('Yahoo and AOL: app password', () {
      final y = detectProviderForEmail('u@yahoo.co.uk')!;
      expect(y.id, 'yahoo');
      expect(y.auth, AuthMethod.appPassword);
      expect(y.imap.host, 'imap.mail.yahoo.com');
      expect(y.smtp.host, 'smtp.mail.yahoo.com');
      expect(y.appPasswordSteps, isNotEmpty);
      expect(y.helpUrl, startsWith('https://'));
      expect(detectProviderForEmail('u@aol.com')?.imap.host, 'imap.aol.com');
    });

    test('iCloud: app-specific password, SMTP 587 STARTTLS', () {
      for (final d in ['icloud.com', 'me.com', 'mac.com']) {
        final p = detectProviderForEmail('u@$d')!;
        expect(p.id, 'icloud', reason: d);
        expect(p.auth, AuthMethod.appPassword);
        expect(p.imap.host, 'imap.mail.me.com');
        expect(p.smtp, isA<ServerSettings>()
            .having((s) => s.host, 'host', 'smtp.mail.me.com')
            .having((s) => s.port, 'port', 587)
            .having((s) => s.security, 'security', ConnectionSecurity.starttls));
      }
    });

    test('Fastmail: app password on 993/465', () {
      final p = detectProviderForEmail('u@fastmail.com')!;
      expect(p.id, 'fastmail');
      expect(p.auth, AuthMethod.appPassword);
      expect(p.imap.host, 'imap.fastmail.com');
      expect(p.smtp.port, 465);
    });

    test('unknown domains and non-addresses fall through', () {
      expect(detectProviderForEmail('u@example.org'), isNull);
      expect(detectProviderForEmail('not an email'), isNull);
      expect(detectProviderForEmail('@gmail.com'), isNull);
      expect(detectProviderForEmail('u@'), isNull);
    });

    test('every table entry has a complete, consistent record', () {
      final seenDomains = <String>{};
      for (final p in providerTable) {
        expect(p.domains, isNotEmpty, reason: p.id);
        for (final d in p.domains) {
          expect(seenDomains.add(d), isTrue, reason: 'duplicate domain $d');
          expect(d, equals(d.toLowerCase()));
        }
        expect(p.helpUrl, startsWith('https://'), reason: p.id);
        if (p.auth == AuthMethod.oauth2) {
          expect(p.oauthIdp, isNotNull, reason: '${p.id} needs an IdP');
        }
        if (p.auth == AuthMethod.appPassword) {
          expect(p.appPasswordSteps, isNotEmpty, reason: '${p.id} needs steps');
        }
      }
    });

    test('email validation and domain extraction', () {
      expect(isValidEmail('a@b.co'), isTrue);
      expect(isValidEmail('  a@b.co  '), isTrue);
      expect(isValidEmail('a@b'), isFalse);
      expect(isValidEmail('a b@c.d'), isFalse);
      expect(domainOf('Alice@Example.COM'), 'example.com');
      expect(domainOf('alice'), isNull);
    });
  });
}
