import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/core_providers.dart';
import '../../providers/provider_table.dart';
import '../../widgets/sealbox_logo.dart';
import '../recovery/recovery_copy.dart';
import 'onboarding_controller.dart';

/// Add-account flow. One screen, one controller, a step per card.
class OnboardingScreen extends ConsumerWidget {
  const OnboardingScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(onboardingControllerProvider);
    final ctl = ref.read(onboardingControllerProvider.notifier);
    final router = GoRouter.maybeOf(context);
    final canLeave = router != null && router.canPop();

    final Widget step = switch (s.step) {
      OnboardingStep.email => _EmailStep(state: s, onContinue: ctl.detect),
      OnboardingStep.detecting => _DetectingStep(email: s.email),
      OnboardingStep.detected => _DetectedStep(state: s, ctl: ctl),
      OnboardingStep.appPassword => _AppPasswordStep(state: s, ctl: ctl),
      OnboardingStep.oauth => _OAuthStep(state: s, ctl: ctl),
      OnboardingStep.manual => _ManualStep(state: s, ctl: ctl),
      OnboardingStep.connecting => _ConnectingStep(host: s.connectingTo ?? ''),
      OnboardingStep.done => _DoneStep(state: s),
    };

    return Scaffold(
      appBar: AppBar(
        // First run (nothing to go back to): welcome, not a sub-screen title.
        title: Text(canLeave ? 'Add account' : 'Welcome to Sealbox'),
        leading: s.step == OnboardingStep.email || s.step == OnboardingStep.done
            ? (canLeave
                  ? IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () => router.pop(),
                    )
                  : null)
            : BackButton(
                key: const Key('onboarding-back'),
                onPressed: ctl.back,
              ),
      ),
      body: Center(
        child: SingleChildScrollView(
          key: const Key('onboarding-scroll'),
          keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
          // The scroll extent must include the system bottom inset so the last
          // button can always be scrolled above the keyboard (Android S1).
          padding: EdgeInsets.fromLTRB(24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560),
            child: AnimatedSwitcher(
              duration: const Duration(milliseconds: 200),
              child: KeyedSubtree(key: ValueKey(s.step), child: step),
            ),
          ),
        ),
      ),
    );
  }
}

class _EmailStep extends StatefulWidget {
  const _EmailStep({required this.state, required this.onContinue});

  final OnboardingState state;
  final ValueChanged<String> onContinue;

  @override
  State<_EmailStep> createState() => _EmailStepState();
}

class _EmailStepState extends State<_EmailStep> {
  late final _ctl = TextEditingController(text: widget.state.email);

  @override
  void dispose() {
    _ctl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Center(child: SealboxLogo(size: 64)),
        const SizedBox(height: 16),
        Text(
          'Private email, without changing your email address.',
          key: const Key('onboarding-hero'),
          style: theme.textTheme.headlineSmall,
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        const _HeroSteps(),
        const SizedBox(height: 8),
        Text(
          'No DNS or MX changes, nothing to tell your IT department.',
          style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 24),
        TextField(
          key: const Key('onboarding-email'),
          controller: _ctl,
          autofocus: true,
          keyboardType: TextInputType.emailAddress,
          autocorrect: false,
          textInputAction: TextInputAction.go,
          decoration: InputDecoration(
            labelText: 'Email address',
            hintText: 'you@gmail.com',
            prefixIcon: const Icon(Icons.alternate_email),
            errorText: widget.state.error,
            border: const OutlineInputBorder(),
          ),
          onSubmitted: widget.onContinue,
        ),
        const SizedBox(height: 16),
        FilledButton(
          key: const Key('onboarding-continue'),
          onPressed: () => widget.onContinue(_ctl.text),
          child: const Text('Continue'),
        ),
        const SizedBox(height: 8),
        TextButton.icon(
          key: const Key('onboarding-restore'),
          onPressed: () => context.push('/restore'),
          icon: const Icon(Icons.settings_backup_restore),
          label: const Text(RecoveryCopy.restoreAction),
        ),
      ],
    );
  }
}

/// The three-step promise under the onboarding hero (same wording as the
/// README and docs/STORE_LISTING.md).
class _HeroSteps extends StatelessWidget {
  const _HeroSteps();

  static const steps = [
    'Connect your existing email account.',
    'Compose and send encrypted messages as usual.',
    'Write securely to other Sealbox or OpenPGP users, or send a secure guest '
        'link to anyone who uses neither. The encryption status is always shown.',
  ];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      key: const Key('onboarding-hero-steps'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (var i = 0; i < steps.length; i++)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                CircleAvatar(
                  radius: 12,
                  backgroundColor: theme.colorScheme.primary,
                  child: Text(
                    '${i + 1}',
                    style: theme.textTheme.labelLarge?.copyWith(color: theme.colorScheme.onPrimary),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(child: Text(steps[i], style: theme.textTheme.bodyMedium)),
              ],
            ),
          ),
      ],
    );
  }
}

class _DetectingStep extends StatelessWidget {
  const _DetectingStep({required this.email});

  final String email;

  @override
  Widget build(BuildContext context) {
    return Column(
      key: const Key('onboarding-detecting'),
      children: [
        const CircularProgressIndicator(),
        const SizedBox(height: 20),
        Text('Detecting provider…', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 6),
        Text(
          'Looking up the mail servers for ${domainOf(email) ?? email}',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }
}

class _ServerRows extends StatelessWidget {
  const _ServerRows({required this.imap, required this.smtp, required this.auth});

  final ServerSettings imap;
  final ServerSettings smtp;
  final AuthMethod auth;

  @override
  Widget build(BuildContext context) {
    final mono = Theme.of(context).textTheme.bodyMedium?.copyWith(fontFamily: 'monospace');
    Widget row(String k, String v, {TextStyle? style}) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 72, child: Text(k, style: Theme.of(context).textTheme.labelLarge)),
          Expanded(child: Text(v, style: style)),
        ],
      ),
    );
    return Column(
      children: [
        row('Incoming', 'IMAP ${imap.display}', style: mono),
        row('Outgoing', 'SMTP ${smtp.display}', style: mono),
        row('Sign-in', auth.label),
      ],
    );
  }
}

class _DetectedStep extends StatelessWidget {
  const _DetectedStep({required this.state, required this.ctl});

  final OnboardingState state;
  final OnboardingController ctl;

  @override
  Widget build(BuildContext context) {
    final p = state.provider!;
    final theme = Theme.of(context);
    final idp = p.oauthIdp;
    return Column(
      key: const Key('onboarding-detected'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.check_circle, color: theme.colorScheme.primary),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '${p.displayName} detected',
                        key: const Key('onboarding-provider-name'),
                        style: theme.textTheme.titleMedium,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(state.email, style: theme.textTheme.bodySmall),
                const Divider(height: 24),
                _ServerRows(imap: p.imap, smtp: p.smtp, auth: p.auth),
                if (p.note != null) ...[
                  const SizedBox(height: 8),
                  Text(p.note!, style: theme.textTheme.bodySmall),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 20),
        if (p.auth == AuthMethod.oauth2 && idp != null)
          FilledButton.icon(
            key: const Key('onboarding-oauth'),
            onPressed: ctl.chooseOAuth,
            // Neutral key icon and "Continue with …" until the official
            // provider button assets are chosen (lead review L7, Android S2-4).
            icon: const Icon(Icons.key),
            label: Text(
              'Continue with ${idp == OAuthIdp.google ? 'Google' : 'Microsoft'}',
            ),
          ),
        if (p.auth == AuthMethod.appPassword)
          FilledButton.icon(
            key: const Key('onboarding-app-password'),
            onPressed: ctl.chooseAppPassword,
            icon: const Icon(Icons.password),
            label: const Text('Continue with an app password'),
          )
        else if (p.allowsAppPasswordFallback)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: OutlinedButton.icon(
              key: const Key('onboarding-app-password'),
              onPressed: ctl.chooseAppPassword,
              icon: const Icon(Icons.password),
              label: const Text('Use an app password instead'),
            ),
          ),
        if (p.auth == AuthMethod.password)
          FilledButton.icon(
            key: const Key('onboarding-password'),
            onPressed: ctl.chooseManual,
            icon: const Icon(Icons.password),
            label: const Text('Continue with your password'),
          ),
        const SizedBox(height: 8),
        TextButton(
          key: const Key('onboarding-manual'),
          onPressed: ctl.chooseManual,
          child: const Text('Enter server settings manually'),
        ),
      ],
    );
  }
}

class _HelpLink extends StatelessWidget {
  const _HelpLink({required this.url, required this.providerName});

  final String url;
  final String providerName;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // The address itself is behind the buttons (P10: it used to be printed above them
        // as well, which read as the same thing said twice); "Copy link" puts it on the
        // clipboard and the open button carries it as its tooltip.
        Row(
          children: [
            TextButton.icon(
              key: const Key('onboarding-help-open'),
              onPressed: () async {
                final messenger = ScaffoldMessenger.of(context);
                final ok = await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
                if (!ok) {
                  messenger.showSnackBar(
                    const SnackBar(content: Text('Could not open a browser; copy the link instead')),
                  );
                }
              },
              icon: const Icon(Icons.open_in_new, size: 18),
              label: Tooltip(message: url, child: Text('Open $providerName help')),
            ),
            TextButton.icon(
              key: const Key('onboarding-help-copy'),
              onPressed: () async {
                final messenger = ScaffoldMessenger.of(context);
                await Clipboard.setData(ClipboardData(text: url));
                messenger.showSnackBar(const SnackBar(content: Text('Link copied')));
              },
              icon: const Icon(Icons.copy, size: 18),
              label: const Text('Copy link'),
            ),
          ],
        ),
      ],
    );
  }
}

class _AppPasswordStep extends StatefulWidget {
  const _AppPasswordStep({required this.state, required this.ctl});

  final OnboardingState state;
  final OnboardingController ctl;

  @override
  State<_AppPasswordStep> createState() => _AppPasswordStepState();
}

class _AppPasswordStepState extends State<_AppPasswordStep> {
  final _secret = TextEditingController();
  bool _show = false;

  @override
  void dispose() {
    _secret.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.state.provider!;
    final theme = Theme.of(context);
    return Column(
      key: const Key('onboarding-app-password-step'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('${p.displayName} app password', style: theme.textTheme.titleLarge),
        const SizedBox(height: 8),
        Consumer(
          builder: (context, ref, _) {
            // Only claim encryption at rest when the engine reports it (G27).
            final encrypted =
                ref.watch(profileKeyStatusProvider).value?.encryptedAtRest ?? false;
            return Text(
              'An app password is a separate password ${p.displayName} issues for one '
              'app. ${encrypted ? 'It is stored encrypted in your Sealbox profile' : 'It is stored only in your Sealbox profile on this device'} '
              'and can be revoked any time without touching your main password.',
              key: const Key('onboarding-app-password-storage'),
              style: theme.textTheme.bodyMedium,
            );
          },
        ),
        const SizedBox(height: 16),
        for (var i = 0; i < p.appPasswordSteps.length; i++)
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: CircleAvatar(radius: 12, child: Text('${i + 1}')),
            title: Text(p.appPasswordSteps[i]),
          ),
        const SizedBox(height: 8),
        _HelpLink(url: p.helpUrl, providerName: p.displayName),
        const SizedBox(height: 16),
        TextField(
          key: const Key('onboarding-secret'),
          controller: _secret,
          // Focusing scrolls the Connect button below into view too.
          scrollPadding: const EdgeInsets.fromLTRB(20, 20, 20, 120),
          buildCounter: (context, {required currentLength, required isFocused, maxLength}) {
            final n = appPasswordLength(p);
            if (n == null) return null;
            return Text(
              '${normalizeAppPassword(_secret.text).length}/$n',
              key: const Key('onboarding-secret-counter'),
              style: theme.textTheme.bodySmall,
            );
          },
          onChanged: (_) => setState(() {}),
          obscureText: !_show,
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: 'App password',
            border: const OutlineInputBorder(),
            errorText: widget.state.error,
            suffixIcon: IconButton(
              tooltip: _show ? 'Hide password' : 'Show password',
              icon: Icon(_show ? Icons.visibility_off : Icons.visibility),
              onPressed: () => setState(() => _show = !_show),
            ),
          ),
          onSubmitted: (v) => isPlausibleAppPassword(p, v) ? widget.ctl.connectWithAppPassword(v) : null,
        ),
        const SizedBox(height: 16),
        FilledButton(
          key: const Key('onboarding-connect'),
          // L5: enabled only for a plausible app password (spaces stripped).
          onPressed: isPlausibleAppPassword(p, _secret.text)
              ? () => widget.ctl.connectWithAppPassword(_secret.text)
              : null,
          child: const Text('Connect'),
        ),
      ],
    );
  }
}

class _OAuthStep extends StatelessWidget {
  const _OAuthStep({required this.state, required this.ctl});

  final OnboardingState state;
  final OnboardingController ctl;

  @override
  Widget build(BuildContext context) {
    final p = state.provider!;
    final theme = Theme.of(context);
    final idp = p.oauthIdp == OAuthIdp.google ? 'Google' : 'Microsoft';
    return Column(
      key: const Key('onboarding-oauth-step'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('Continue with $idp', style: theme.textTheme.titleLarge),
        const SizedBox(height: 8),
        Text(
          'Your browser opens the $idp sign-in page. Sealbox never sees your '
          'password: it receives a token limited to reading and sending mail '
          '(OAuth 2.0 with PKCE, then IMAP/SMTP XOAUTH2). You can revoke it in '
          'your $idp account at any time.',
          style: theme.textTheme.bodyMedium,
        ),
        const SizedBox(height: 16),
        Card(
          color: theme.colorScheme.surfaceContainerHigh,
          child: const Padding(
            padding: EdgeInsets.all(12),
            child: Row(
              children: [
                Icon(Icons.construction, size: 20),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Signing in with this provider is not set up in this build yet, so '
                    'the sign-in cannot complete. Use an app password or manual server '
                    'settings for now.',
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        if (state.error != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              state.error!,
              key: const Key('onboarding-oauth-error'),
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
            ),
          ),
        FilledButton.icon(
          key: const Key('onboarding-oauth-go'),
          onPressed: OnboardingController.oauthAvailable ? ctl.connectWithOAuth : null,
          icon: const Icon(Icons.open_in_browser),
          label: Text(
            OnboardingController.oauthAvailable
                ? 'Continue to $idp'
                : 'Continue to $idp (not available yet)',
          ),
        ),
        if (p.allowsAppPasswordFallback) ...[
          const SizedBox(height: 8),
          FilledButton.tonalIcon(
            key: const Key('onboarding-oauth-app-password'),
            onPressed: ctl.chooseAppPassword,
            icon: const Icon(Icons.password),
            label: const Text('Use an app password instead'),
          ),
        ] else ...[
          const SizedBox(height: 8),
          OutlinedButton.icon(
            key: const Key('onboarding-oauth-manual'),
            onPressed: ctl.chooseManual,
            icon: const Icon(Icons.dns_outlined),
            label: const Text('Enter server settings manually'),
          ),
        ],
      ],
    );
  }
}

class _ManualStep extends StatefulWidget {
  const _ManualStep({required this.state, required this.ctl});

  final OnboardingState state;
  final OnboardingController ctl;

  @override
  State<_ManualStep> createState() => _ManualStepState();
}

class _ManualStepState extends State<_ManualStep> {
  late final TextEditingController _imapHost;
  late final TextEditingController _imapPort;
  late final TextEditingController _smtpHost;
  late final TextEditingController _smtpPort;
  late final TextEditingController _user;
  final _secret = TextEditingController();
  late ConnectionSecurity _imapSec;
  late ConnectionSecurity _smtpSec;

  @override
  void initState() {
    super.initState();
    final p = widget.state.provider;
    final domain = domainOf(widget.state.email) ?? '';
    _imapHost = TextEditingController(text: p?.imap.host ?? (domain.isEmpty ? '' : 'imap.$domain'));
    _imapPort = TextEditingController(text: '${p?.imap.port ?? 993}');
    _smtpHost = TextEditingController(text: p?.smtp.host ?? (domain.isEmpty ? '' : 'smtp.$domain'));
    _smtpPort = TextEditingController(text: '${p?.smtp.port ?? 587}');
    _user = TextEditingController(text: widget.state.email);
    _imapSec = p?.imap.security ?? ConnectionSecurity.tls;
    _smtpSec = p?.smtp.security ?? ConnectionSecurity.starttls;
  }

  @override
  void dispose() {
    for (final c in [_imapHost, _imapPort, _smtpHost, _smtpPort, _user, _secret]) {
      c.dispose();
    }
    super.dispose();
  }

  void _connect() {
    widget.ctl.connectManual(
      imap: ServerSettings(
        _imapHost.text.trim(),
        int.tryParse(_imapPort.text.trim()) ?? 993,
        _imapSec,
      ),
      smtp: ServerSettings(
        _smtpHost.text.trim(),
        int.tryParse(_smtpPort.text.trim()) ?? 587,
        _smtpSec,
      ),
      username: _user.text.trim(),
      secret: _secret.text,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final unknown = widget.state.provider == null;
    Widget server(
      String label,
      TextEditingController host,
      TextEditingController port,
      ConnectionSecurity sec,
      ValueChanged<ConnectionSecurity> onSec,
      String keyPrefix,
    ) {
      return Column(
        children: [
          Row(
            children: [
              Expanded(
                flex: 3,
                child: TextField(
                  key: Key('$keyPrefix-host'),
                  controller: host,
                  decoration: InputDecoration(
                    labelText: '$label host',
                    border: const OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  key: Key('$keyPrefix-port'),
                  controller: port,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                    labelText: 'Port',
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          DropdownButtonFormField<ConnectionSecurity>(
            key: Key('$keyPrefix-security'),
            initialValue: sec,
            isExpanded: true,
            decoration: InputDecoration(
              labelText: '$label security',
              border: const OutlineInputBorder(),
            ),
            items: [
              for (final s in ConnectionSecurity.values)
                DropdownMenuItem(value: s, child: Text(s.label)),
            ],
            onChanged: (v) => v == null ? null : onSec(v),
          ),
        ],
      );
    }

    return Column(
      key: const Key('onboarding-manual-step'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('Server settings', style: theme.textTheme.titleLarge),
        const SizedBox(height: 8),
        Text(
          unknown
              ? 'We could not find ${domainOf(widget.state.email) ?? 'this domain'} in the '
                    'built-in list, Mozilla\'s ISPDB or DNS. Enter the settings from your '
                    'provider; "None (plain)" is only for local test servers.'
              : 'Pre-filled from the detected provider. Change anything that differs.',
          style: theme.textTheme.bodyMedium,
        ),
        const SizedBox(height: 16),
        server('IMAP', _imapHost, _imapPort, _imapSec, (v) => setState(() => _imapSec = v), 'manual-imap'),
        const SizedBox(height: 12),
        server('SMTP', _smtpHost, _smtpPort, _smtpSec, (v) => setState(() => _smtpSec = v), 'manual-smtp'),
        const SizedBox(height: 12),
        TextField(
          key: const Key('manual-username'),
          controller: _user,
          decoration: const InputDecoration(labelText: 'Username', border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        TextField(
          key: const Key('manual-secret'),
          controller: _secret,
          obscureText: true,
          scrollPadding: const EdgeInsets.fromLTRB(20, 20, 20, 160),
          decoration: const InputDecoration(
            labelText: 'Password',
            border: OutlineInputBorder(),
          ),
          onSubmitted: (_) => _connect(),
        ),
        if (widget.state.error != null) ...[
          const SizedBox(height: 12),
          Container(
            key: const Key('manual-error'),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: theme.colorScheme.errorContainer,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.error_outline, size: 20, color: theme.colorScheme.onErrorContainer),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    widget.state.error!,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onErrorContainer,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 16),
        FilledButton(
          key: const Key('manual-connect'),
          onPressed: _connect,
          child: const Text('Connect'),
        ),
      ],
    );
  }
}

class _ConnectingStep extends StatelessWidget {
  const _ConnectingStep({required this.host});

  final String host;

  @override
  Widget build(BuildContext context) => Column(
    key: const Key('onboarding-connecting'),
    children: [
      const CircularProgressIndicator(),
      const SizedBox(height: 20),
      Text('Connecting to $host…', style: Theme.of(context).textTheme.titleMedium),
    ],
  );
}

class _DoneStep extends StatelessWidget {
  const _DoneStep({required this.state});

  final OnboardingState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final a = state.account;
    return Column(
      key: const Key('onboarding-done'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Icon(Icons.verified, size: 64, color: theme.colorScheme.primary),
        const SizedBox(height: 16),
        Text(
          '${a?.email ?? state.email} is ready',
          style: theme.textTheme.headlineSmall,
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 8),
        Text(
          'Your OpenPGP key is generated on this device. Replies to anything you '
          'send from Sealbox can be encrypted automatically (Autocrypt); contacts '
          'without a key get a guest link.',
          style: theme.textTheme.bodyMedium,
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 24),
        FilledButton.icon(
          key: const Key('onboarding-open-inbox'),
          onPressed: () => context.go('/inbox'),
          icon: const Icon(Icons.inbox),
          label: const Text('Open inbox'),
        ),
      ],
    );
  }
}
