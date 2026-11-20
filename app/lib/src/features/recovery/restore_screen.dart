import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import 'recovery_copy.dart';

enum _RestoreStep { form, credential, done }

/// Onboarding → "Restore from recovery phrase" (docs/RECOVERY.md): address +
/// 12 words + server → `restore_from_server`; then the mailbox credential
/// (never in the backup by default) → `set_account_credential`; then sync.
class RestoreScreen extends ConsumerStatefulWidget {
  const RestoreScreen({super.key});

  @override
  ConsumerState<RestoreScreen> createState() => _RestoreScreenState();
}

class _RestoreScreenState extends ConsumerState<RestoreScreen> {
  final _email = TextEditingController();
  final _phrase = TextEditingController();
  final _server = TextEditingController();
  final _password = TextEditingController();
  final _lookupPassword = TextEditingController();
  _RestoreStep _step = _RestoreStep.form;
  String? _phraseError;
  String? _error;
  bool _busy = false;
  bool _offerMailboxLookup = false;
  bool _serverPrefilled = false;
  Account? _account;

  @override
  void dispose() {
    for (final c in [_email, _phrase, _server, _password, _lookupPassword]) {
      c.dispose();
    }
    super.dispose();
  }

  bool get _formReady =>
      _email.text.contains('@') &&
      _phraseError == null &&
      _phrase.text.split(RegExp(r'[^A-Za-z]+')).where((t) => t.isNotEmpty).length == 12 &&
      _server.text.trim().isNotEmpty;

  Future<void> _validatePhrase(String v) async {
    final e = await phraseFieldError(ref.read(coreApiProvider), v);
    if (mounted) setState(() => _phraseError = e);
  }

  Future<void> _restore() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final password = _offerMailboxLookup ? _lookupPassword.text : null;
    try {
      final account = await ref
          .read(coreApiProvider)
          .restoreFromServer(
            _server.text.trim(),
            _email.text.trim(),
            _phrase.text,
            password: password == null || password.isEmpty ? null : password,
          );
      _phrase.clear();
      if (!mounted) return;
      ref.invalidate(accountsProvider);
      ref.invalidate(identityProvider);
      setState(() {
        _busy = false;
        _account = account;
        // With a mailbox password the engine already tested and stored it.
        _step = password == null || password.isEmpty ? _RestoreStep.credential : _RestoreStep.done;
      });
      if (_step == _RestoreStep.done) await _fetch();
    } catch (e) {
      if (!mounted) return;
      final msg = friendlyRecoveryError(e);
      setState(() {
        _busy = false;
        _error = msg;
        if (msg == RecoveryCopy.noBackup) _offerMailboxLookup = true;
      });
    }
  }

  Future<void> _saveCredential() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(coreApiProvider).setAccountCredential(_account!.email, _password.text);
      _password.clear();
      if (!mounted) return;
      setState(() {
        _busy = false;
        _step = _RestoreStep.done;
      });
      await _fetch();
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = 'Could not save the password: $e';
        });
      }
    }
  }

  Future<void> _fetch() async {
    final router = GoRouter.of(context);
    await ref.read(syncControllerProvider.notifier).syncNow();
    ref.invalidate(threadsProvider);
    if (mounted) router.go('/inbox');
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final configured = ref.watch(serverUrlProvider).value;
    if (!_serverPrefilled && configured != null) {
      _serverPrefilled = true;
      _server.text = configured;
    }
    return Scaffold(
      appBar: AppBar(
        title: const Text(RecoveryCopy.restoreTitle),
        leading: BackButton(
          key: const Key('restore-back'),
          onPressed: () => context.canPop() ? context.pop() : context.go('/onboarding'),
        ),
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: ListView(
            key: const Key('restore-list'),
            padding: const EdgeInsets.all(24),
            children: switch (_step) {
              _RestoreStep.form => _form(theme),
              _RestoreStep.credential => _credential(theme),
              _RestoreStep.done => [
                Icon(Icons.cloud_done, size: 48, color: LockColors.ofContext(context).encrypted),
                const SizedBox(height: 12),
                Text(
                  RecoveryCopy.restored,
                  key: const Key('restore-done'),
                  textAlign: TextAlign.center,
                  style: theme.textTheme.titleMedium,
                ),
                const SizedBox(height: 16),
                const Center(child: CircularProgressIndicator()),
              ],
            },
          ),
        ),
      ),
    );
  }

  List<Widget> _form(ThemeData theme) => [
    Text(
      'On a new device, your address and the 12 words from your recovery phrase bring back '
      'your keys, contacts and settings from your Sealbox backup. Type the words separated by '
      'spaces; the first four letters of each are enough.',
      style: theme.textTheme.bodyMedium,
    ),
    const SizedBox(height: 20),
    TextField(
      key: const Key('restore-email'),
      controller: _email,
      keyboardType: TextInputType.emailAddress,
      autocorrect: false,
      decoration: const InputDecoration(
        labelText: RecoveryCopy.emailLabel,
        prefixIcon: Icon(Icons.alternate_email),
        border: OutlineInputBorder(),
      ),
      onChanged: (_) => setState(() {}),
    ),
    const SizedBox(height: 16),
    TextField(
      key: const Key('restore-phrase'),
      controller: _phrase,
      minLines: 3,
      maxLines: 4,
      autocorrect: false,
      enableSuggestions: false,
      keyboardType: TextInputType.visiblePassword,
      decoration: InputDecoration(
        labelText: RecoveryCopy.phraseLabel,
        alignLabelWithHint: true,
        border: const OutlineInputBorder(),
        errorText: _phraseError,
        errorMaxLines: 2,
      ),
      onChanged: (v) {
        setState(() {});
        _validatePhrase(v);
      },
    ),
    const SizedBox(height: 16),
    TextField(
      key: const Key('restore-server'),
      controller: _server,
      keyboardType: TextInputType.url,
      autocorrect: false,
      decoration: const InputDecoration(
        labelText: 'Sealbox server',
        hintText: 'https://sealbox.example',
        prefixIcon: Icon(Icons.dns_outlined),
        border: OutlineInputBorder(),
      ),
      onChanged: (_) => setState(() {}),
    ),
    if (_offerMailboxLookup) ...[
      const SizedBox(height: 16),
      Text(
        'If you never published your key, Sealbox can find it in mail you sent. Enter your mail '
        'password (or app password) and try again.',
        style: theme.textTheme.bodySmall,
      ),
      const SizedBox(height: 8),
      TextField(
        key: const Key('restore-lookup-password'),
        controller: _lookupPassword,
        obscureText: true,
        decoration: const InputDecoration(
          labelText: 'Mail password or app password',
          border: OutlineInputBorder(),
        ),
      ),
    ],
    if (_error != null) ...[
      const SizedBox(height: 12),
      Text(
        _error!,
        key: const Key('restore-error'),
        style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
      ),
    ],
    const SizedBox(height: 20),
    FilledButton(
      key: const Key('restore-submit'),
      onPressed: _busy || !_formReady ? null : _restore,
      child: _busy
          ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
          : const Text(RecoveryCopy.restoreButton),
    ),
  ];

  List<Widget> _credential(ThemeData theme) => [
    Row(
      children: [
        Icon(Icons.key, color: LockColors.ofContext(context).encrypted),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            'Keys restored for ${_account?.email}',
            key: const Key('restore-credential-title'),
            style: theme.textTheme.titleMedium,
          ),
        ),
      ],
    ),
    const SizedBox(height: 12),
    Text(
      'Your mail password is not part of the backup. Sign in to your mailbox once more so '
      'Sealbox can fetch your mail${_account == null ? '' : ' from ${_account!.imapHost}'}.',
      style: theme.textTheme.bodyMedium,
    ),
    const SizedBox(height: 16),
    TextField(
      key: const Key('restore-password'),
      controller: _password,
      obscureText: true,
      autocorrect: false,
      decoration: const InputDecoration(
        labelText: 'Password or app password',
        prefixIcon: Icon(Icons.password),
        border: OutlineInputBorder(),
      ),
      onChanged: (_) => setState(() {}),
    ),
    if (_error != null) ...[
      const SizedBox(height: 12),
      Text(_error!, style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error)),
    ],
    const SizedBox(height: 20),
    Row(
      children: [
        TextButton(
          key: const Key('restore-later'),
          onPressed: _busy ? null : () => context.go('/inbox'),
          child: const Text('Later'),
        ),
        const Spacer(),
        FilledButton(
          key: const Key('restore-credential-save'),
          onPressed: _busy || _password.text.isEmpty ? null : _saveCredential,
          child: const Text('Continue'),
        ),
      ],
    ),
  ];
}
