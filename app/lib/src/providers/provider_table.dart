/// Dart-side mirror of the built-in provider table (docs/PROVIDERS.md).
///
/// The authoritative table lives in `crates/sealbox-mail` (gate G5) and is what
/// the engine uses to connect. This copy exists so the onboarding UI can show
/// "what will happen" instantly and offline, and so widget tests need no
/// native code. Keep the two in sync; unknown domains fall through to the
/// engine's autodiscover (ISPDB › SRV › guesses) or to manual settings.
library;

enum AuthMethod {
  /// OAuth2 authorization-code + PKCE, then SASL XOAUTH2.
  oauth2,

  /// A provider-issued app password (requires 2FA on the account).
  appPassword,

  /// The ordinary account password (company IMAP, Fastmail legacy, …).
  password,
}

extension AuthMethodLabel on AuthMethod {
  String get label => switch (this) {
    AuthMethod.oauth2 => 'OAuth 2.0',
    AuthMethod.appPassword => 'App password',
    AuthMethod.password => 'Password',
  };
}

enum ConnectionSecurity {
  tls,
  starttls,

  /// No transport encryption at all. Only for local test servers (GreenMail);
  /// never offered by the built-in provider table.
  plain,
}

extension ConnectionSecurityLabel on ConnectionSecurity {
  String get label => switch (this) {
    ConnectionSecurity.tls => 'TLS',
    ConnectionSecurity.starttls => 'STARTTLS',
    ConnectionSecurity.plain => 'None (plain)',
  };
}

class ServerSettings {
  const ServerSettings(this.host, this.port, this.security);

  final String host;
  final int port;
  final ConnectionSecurity security;

  String get display => '$host:$port (${security.label})';
}

/// Which OAuth identity provider an [AuthMethod.oauth2] provider uses.
enum OAuthIdp { google, microsoft }

class ProviderConfig {
  const ProviderConfig({
    required this.id,
    required this.displayName,
    required this.domains,
    required this.imap,
    required this.smtp,
    required this.auth,
    required this.helpUrl,
    this.oauthIdp,
    this.appPasswordSteps = const [],
    this.note,
  });

  final String id;
  final String displayName;
  final List<String> domains;
  final ServerSettings imap;
  final ServerSettings smtp;

  /// The auth method Sealbox offers first for this provider.
  final AuthMethod auth;

  /// Provider help page for app passwords / IMAP access.
  final String helpUrl;
  final OAuthIdp? oauthIdp;
  final List<String> appPasswordSteps;
  final String? note;

  /// Gmail allows an app password as a fallback when 2-Step Verification is on;
  /// Outlook.com does not (Basic auth removed Sept 2024).
  bool get allowsAppPasswordFallback => appPasswordSteps.isNotEmpty;
}

const _tls = ConnectionSecurity.tls;
const _starttls = ConnectionSecurity.starttls;

const List<ProviderConfig> providerTable = [
  ProviderConfig(
    id: 'gmail',
    displayName: 'Gmail',
    domains: ['gmail.com', 'googlemail.com'],
    imap: ServerSettings('imap.gmail.com', 993, _tls),
    smtp: ServerSettings('smtp.gmail.com', 465, _tls),
    auth: AuthMethod.oauth2,
    oauthIdp: OAuthIdp.google,
    helpUrl: 'https://support.google.com/accounts/answer/185833',
    appPasswordSteps: [
      'Turn on 2-Step Verification for your Google Account.',
      'Open myaccount.google.com › Security › 2-Step Verification › App passwords.',
      'Create a password named "Sealbox" and paste the 16 characters below.',
    ],
    note: 'Google Workspace accounts on a custom domain also use these servers.',
  ),
  ProviderConfig(
    id: 'outlook',
    displayName: 'Outlook.com / Hotmail',
    domains: [
      'outlook.com',
      'hotmail.com',
      'live.com',
      'msn.com',
      'outlook.co.uk',
      'hotmail.co.uk',
      'live.co.uk',
      'hotmail.fr',
      'hotmail.de',
      'live.de',
    ],
    imap: ServerSettings('outlook.office365.com', 993, _tls),
    smtp: ServerSettings('smtp.office365.com', 587, _starttls),
    auth: AuthMethod.oauth2,
    oauthIdp: OAuthIdp.microsoft,
    helpUrl: 'https://support.microsoft.com/office/pop-imap-and-smtp-settings',
    note:
        'Microsoft removed password sign-in for consumer accounts in 2024; '
        'OAuth is the only path.',
  ),
  ProviderConfig(
    id: 'yahoo',
    displayName: 'Yahoo Mail',
    domains: ['yahoo.com', 'yahoo.co.uk', 'ymail.com', 'rocketmail.com'],
    imap: ServerSettings('imap.mail.yahoo.com', 993, _tls),
    smtp: ServerSettings('smtp.mail.yahoo.com', 465, _tls),
    auth: AuthMethod.appPassword,
    helpUrl: 'https://help.yahoo.com/kb/SLN15241.html',
    appPasswordSteps: [
      'Sign in at login.yahoo.com › Account info › Security.',
      'Choose "Generate app password", pick "Other app" and name it Sealbox.',
      'Paste the generated password below (spaces do not matter).',
    ],
  ),
  ProviderConfig(
    id: 'aol',
    displayName: 'AOL Mail',
    domains: ['aol.com'],
    imap: ServerSettings('imap.aol.com', 993, _tls),
    smtp: ServerSettings('smtp.aol.com', 465, _tls),
    auth: AuthMethod.appPassword,
    helpUrl: 'https://help.aol.com/articles/Create-and-manage-app-password',
    appPasswordSteps: [
      'Sign in at login.aol.com › Account Security.',
      'Choose "Generate app password" and name it Sealbox.',
      'Paste the generated password below.',
    ],
  ),
  ProviderConfig(
    id: 'icloud',
    displayName: 'iCloud Mail',
    domains: ['icloud.com', 'me.com', 'mac.com'],
    imap: ServerSettings('imap.mail.me.com', 993, _tls),
    smtp: ServerSettings('smtp.mail.me.com', 587, _starttls),
    auth: AuthMethod.appPassword,
    helpUrl: 'https://support.apple.com/102654',
    appPasswordSteps: [
      'Your Apple ID needs two-factor authentication turned on.',
      'Open account.apple.com › Sign-In and Security › App-Specific Passwords.',
      'Generate one named "Sealbox" and paste it below.',
    ],
  ),
  ProviderConfig(
    id: 'fastmail',
    displayName: 'Fastmail',
    domains: ['fastmail.com', 'fastmail.fm'],
    imap: ServerSettings('imap.fastmail.com', 993, _tls),
    smtp: ServerSettings('smtp.fastmail.com', 465, _tls),
    auth: AuthMethod.appPassword,
    helpUrl: 'https://www.fastmail.help/hc/en-us/articles/360058752854',
    appPasswordSteps: [
      'Open Fastmail Settings › Privacy & Security › Integrations.',
      'Choose "New app password", access "Mail (IMAP/SMTP)", name it Sealbox.',
      'Paste the password below.',
    ],
  ),
];

final RegExp _emailRe = RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$');

bool isValidEmail(String input) => _emailRe.hasMatch(input.trim());

/// Lower-cased domain part of an address, or `null` if it is not an address.
String? domainOf(String email) {
  final e = email.trim();
  final at = e.lastIndexOf('@');
  if (at <= 0 || at == e.length - 1) return null;
  return e.substring(at + 1).toLowerCase();
}

/// Built-in table lookup by domain. Returns `null` for unknown domains.
ProviderConfig? detectProviderForEmail(String email) {
  final domain = domainOf(email);
  if (domain == null) return null;
  for (final p in providerTable) {
    if (p.domains.contains(domain)) return p;
  }
  return null;
}

/// App passwords are often pasted with spaces ("abcd efgh ijkl mnop").
String normalizeAppPassword(String raw) => raw.replaceAll(RegExp(r'\s+'), '');

/// Expected length of [p]'s app passwords when the provider fixes it (Google:
/// 16 letters), else null.
int? appPasswordLength(ProviderConfig p) => p.oauthIdp == OAuthIdp.google ? 16 : null;

/// Plausible enough to try a login with: Google's 16 letters, otherwise at
/// least 8 characters (Yahoo/AOL 16 letters, iCloud `xxxx-xxxx-xxxx-xxxx`, …).
bool isPlausibleAppPassword(ProviderConfig p, String raw) {
  final s = normalizeAppPassword(raw);
  final n = appPasswordLength(p);
  if (n != null) return RegExp('^[A-Za-z]{$n}\$').hasMatch(s);
  return s.length >= 8;
}
