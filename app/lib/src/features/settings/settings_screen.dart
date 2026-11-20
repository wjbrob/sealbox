import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../lock/app_lock.dart';
import '../../lock/lock_providers.dart';
import '../../providers/provider_table.dart';
import '../../widgets/lock_badge.dart';
import '../compose/recipient_pill.dart' show keySourceLabel;
import '../identity/fingerprint_qr.dart';
import '../identity/identity_widgets.dart';
import '../identity/kt_card.dart';
import '../inbox/inbox_list_pane.dart' show describeLiveStatus, fullTime;
import '../recovery/recovery_copy.dart';
import '../recovery/recovery_phrase_screen.dart';
import 'account_picker.dart';
import 'directory_publish.dart';
import 'server_section.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key, this.section});

  /// `server` (`/settings?section=server`): scroll the Server section into view,
  /// e.g. from the guest-link panel's "Open Settings".
  final String? section;

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  final _scroll = ScrollController();
  final _serverKey = GlobalKey();

  @override
  void initState() {
    super.initState();
    if (widget.section == 'server') {
      WidgetsBinding.instance.addPostFrameCallback((_) => _showServer());
    }
  }

  @override
  void didUpdateWidget(covariant SettingsScreen old) {
    super.didUpdateWidget(old);
    if (widget.section == 'server' && old.section != 'server') {
      WidgetsBinding.instance.addPostFrameCallback((_) => _showServer());
    }
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  /// The Server card sits near the end of a lazy list: scroll down until it is
  /// built, then bring it into view.
  Future<void> _showServer() async {
    for (var i = 0; i < 20 && mounted; i++) {
      final ctx = _serverKey.currentContext;
      if (ctx != null && ctx.mounted) {
        await Scrollable.ensureVisible(
          ctx,
          alignment: 0.1,
          duration: const Duration(milliseconds: 300),
        );
        return;
      }
      if (!_scroll.hasClients) return;
      final p = _scroll.position;
      if (p.pixels >= p.maxScrollExtent) return;
      _scroll.jumpTo((p.pixels + 600).clamp(0, p.maxScrollExtent));
      await WidgetsBinding.instance.endOfFrame;
    }
  }

  @override
  Widget build(BuildContext context) {
    final accounts = ref.watch(accountsProvider);
    final identity = ref.watch(identityProvider);
    final backup = ref.watch(backupStatusProvider);
    final info = ref.watch(coreInfoProvider);
    final contacts = ref.watch(contactsProvider);
    final themeMode = ref.watch(themeModeProvider);
    final live = ref.watch(liveUpdatesProvider);
    final watchers = ref.watch(liveWatchProvider);
    final theme = Theme.of(context);
    final accountList = accounts.value ?? const <Account>[];
    final keyAccount = selectedSettingsAccount(ref, accountList);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 820),
          child: ListView(
            key: const Key('settings-list'),
            controller: _scroll,
            padding: const EdgeInsets.all(16),
            children: [
              _SectionTitle('Accounts'),
              Card(
                child: Column(
                  children: [
                    ...accounts.when(
                      loading: () => const [
                        ListTile(title: LinearProgressIndicator()),
                      ],
                      error: (e, _) => [ListTile(title: Text('Error: $e'))],
                      data: (list) => [
                        if (list.isEmpty)
                          const ListTile(
                            leading: Icon(Icons.info_outline),
                            title: Text('No accounts yet'),
                          ),
                        for (final a in list) _AccountTile(account: a),
                      ],
                    ),
                    const Divider(height: 1),
                    ListTile(
                      key: const Key('settings-add-account'),
                      leading: const Icon(Icons.add),
                      title: const Text('Add account'),
                      subtitle: const Text(
                        'Gmail, Outlook, Yahoo, iCloud, Fastmail or any IMAP server',
                      ),
                      onTap: () => context.push('/onboarding'),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('My key'),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: identity.when(
                    loading: () => const Row(
                      children: [
                        SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                        SizedBox(width: 12),
                        Expanded(child: Text('Loading your key…')),
                      ],
                    ),
                    error: (e, _) => Text('Could not load the key: $e'),
                    data: (id) => id.isEmpty || keyAccount == null
                        ? const ListTile(
                            key: Key('settings-no-key'),
                            contentPadding: EdgeInsets.zero,
                            leading: Icon(Icons.key_off),
                            title: Text('No key yet'),
                            subtitle: Text(
                              'Your OpenPGP key is generated on this device when you add '
                              'the first account.',
                            ),
                          )
                        : Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              if (accountList.length > 1) ...[
                                SettingsAccountPicker(
                                  key: const Key('my-key-account'),
                                  accounts: accountList,
                                ),
                                const SizedBox(height: 16),
                              ],
                              _IdentityView(
                                accountId: keyAccount.id,
                                identity: IdentityPreview(
                                  // FakeCore accounts carry no fingerprint: the profile's key.
                                  fingerprint: keyAccount.fingerprint ?? id.fingerprint,
                                  createdAt: keyAccount.fingerprint == null
                                      ? id.createdAt
                                      : (keyAccount.createdAt ?? id.createdAt),
                                  email: keyAccount.email,
                                ),
                              ),
                              const Divider(height: 32),
                              DirectoryPublishPanel(
                                account: keyAccount,
                                onSetServer: _showServer,
                              ),
                            ],
                          ),
                  ),
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('Security'),
              const _SecuritySection(),
              const SizedBox(height: 12),
              const _IdentityRecoverySection(),
              const SizedBox(height: 24),
              _SectionTitle('Mail handling'),
              Card(
                key: const Key('settings-mail-handling'),
                child: accounts.when(
                  loading: () => const ListTile(title: LinearProgressIndicator()),
                  error: (e, _) => ListTile(title: Text('Error: $e')),
                  data: (list) => list.isEmpty
                      ? const ListTile(
                          leading: Icon(Icons.info_outline),
                          title: Text(
                            'Add an account to set a signature, an auto-reply, spam '
                            'filtering and filter rules',
                          ),
                        )
                      : Column(
                          children: [
                            for (final a in list) ...[
                              _SignatureTile(account: a),
                              _AutoReplyTile(account: a),
                              _SpamTile(account: a),
                              _FiltersTile(account: a),
                              if (a != list.last) const Divider(height: 1),
                            ],
                          ],
                        ),
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('Contacts & keys'),
              Card(
                child: Column(
                  children: [
                    ...contacts.when(
                      loading: () => const [ListTile(title: LinearProgressIndicator())],
                      error: (e, _) => [ListTile(title: Text('Error: $e'))],
                      data: (list) => [
                        if (list.isEmpty)
                          const ListTile(
                            key: Key('settings-no-contacts'),
                            leading: Icon(Icons.people_outline),
                            title: Text('No keys known yet'),
                            subtitle: Text(
                              'Keys arrive automatically with mail from other Sealbox or '
                              'Autocrypt users, or paste one below.',
                            ),
                          ),
                        for (final c in list) _ContactTile(contact: c),
                      ],
                    ),
                    const Divider(height: 1),
                    ListTile(
                      key: const Key('settings-import-key'),
                      leading: const Icon(Icons.key),
                      title: const Text('Import a contact\'s public key'),
                      subtitle: const Text('Paste an ASCII-armored OpenPGP public key'),
                      onTap: () async {
                        final imported = await showImportKeyDialog(context);
                        if (imported != null) {
                          ref.invalidate(contactsProvider);
                        }
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('Appearance & sync'),
              Card(
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(Icons.brightness_6_outlined),
                      title: const Text('Theme'),
                      trailing: SegmentedButton<ThemeMode>(
                        key: const Key('settings-theme'),
                        showSelectedIcon: false,
                        segments: const [
                          ButtonSegment(value: ThemeMode.system, label: Text('System')),
                          ButtonSegment(value: ThemeMode.light, label: Text('Light')),
                          ButtonSegment(value: ThemeMode.dark, label: Text('Dark')),
                        ],
                        selected: {themeMode},
                        onSelectionChanged: (s) =>
                            ref.read(themeModeProvider.notifier).set(s.first),
                      ),
                    ),
                    const Divider(height: 1),
                    SwitchListTile(
                      key: const Key('settings-live-updates'),
                      secondary: const Icon(Icons.bolt_outlined),
                      title: const Text('Live updates (IMAP IDLE)'),
                      subtitle: !live
                          ? const Text(_liveUpdatesExplanation)
                          : Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(_liveUpdatesExplanation),
                                const SizedBox(height: 4),
                                Text(
                                  describeLiveStatus(watchers, {
                                    for (final a in accountList) a.id: a.email,
                                  }).details,
                                  key: const Key('settings-live-status'),
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ),
                      value: live,
                      onChanged: (v) => ref.read(liveUpdatesProvider.notifier).set(v),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('Backup'),
              Card(
                child: backup.when(
                  loading: () => const ListTile(title: LinearProgressIndicator()),
                  error: (e, _) => ListTile(title: Text('Error: $e')),
                  data: (b) => Column(
                    children: [
                      if (b.reminder != null && b.available)
                        Padding(
                          padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
                          child: BackupReminderBanner(status: b),
                        ),
                      ListTile(
                        key: const Key('settings-backup'),
                        leading: Icon(
                          b.backedUp ? Icons.cloud_done : Icons.cloud_off,
                          color: b.backedUp ? theme.colorScheme.primary : null,
                        ),
                        title: Text(
                          b.backedUp ? 'Encrypted key backup is on' : 'Key not backed up',
                        ),
                        subtitle: Text(
                          !b.available
                              ? 'Backup to the Sealbox server is not wired into this build yet. '
                                    'Until then, keep a copy of the profile directory somewhere safe.'
                              : b.backedUp && b.lastBackup != null
                              ? 'Last backup ${fullTime(b.lastBackup!)}'
                                    '${b.serverUrl == null ? '' : ' to ${b.serverUrl}'}. Encrypted '
                                    'on this device with your recovery phrase; the server cannot '
                                    'read it.'
                              : 'Lose this device and you lose the ability to read your '
                                    'encrypted mail. Back up to the Sealbox server, encrypted '
                                    'with a recovery phrase only you know.',
                        ),
                        isThreeLine: true,
                        trailing: b.available
                            ? FilledButton.tonal(
                                key: const Key('settings-backup-now'),
                                onPressed: () => startBackup(context, ref, b),
                                child: Text(b.backedUp ? 'Back up again' : 'Back up now'),
                              )
                            : null,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 24),
              _SectionTitle('Server'),
              ServerSection(key: _serverKey),
              const SizedBox(height: 24),
              _SectionTitle('Engine'),
              Card(
                child: info.when(
                  loading: () => const ListTile(title: LinearProgressIndicator()),
                  error: (e, _) => ListTile(title: Text('Bridge error: $e')),
                  data: (i) => ListTile(
                    key: const Key('settings-core-info'),
                    leading: const Icon(Icons.memory),
                    title: Text('Rust core ${i.version}'),
                    subtitle: Text(
                      '${i.greeting}\nOpenPGP via rPGP; bridged with flutter_rust_bridge.',
                    ),
                    isThreeLine: true,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

const _liveUpdatesExplanation =
    'Keep one more connection open per account so new mail appears '
    'without pressing fetch. The engine runs one sync per account at a '
    'time, so a push and a manual fetch never overlap.';

/// Paste-a-key dialog. Returns the imported contact, or null when dismissed.
Future<ContactKey?> showImportKeyDialog(BuildContext context) {
  return showDialog<ContactKey>(
    context: context,
    builder: (context) => const _ImportKeyDialog(),
  );
}

class _ImportKeyDialog extends ConsumerStatefulWidget {
  const _ImportKeyDialog();

  @override
  ConsumerState<_ImportKeyDialog> createState() => _ImportKeyDialogState();
}

class _ImportKeyDialogState extends ConsumerState<_ImportKeyDialog> {
  final _address = TextEditingController();
  final _armored = TextEditingController();
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _address.dispose();
    _armored.dispose();
    super.dispose();
  }

  Future<void> _import() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final c = await ref
          .read(coreApiProvider)
          .importPeerKey(_address.text.trim(), _armored.text);
      if (mounted) Navigator.of(context).pop(c);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = '$e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      key: const Key('import-key-dialog'),
      title: const Text('Import a public key'),
      content: SizedBox(
        width: 520,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              key: const Key('import-key-address'),
              controller: _address,
              keyboardType: TextInputType.emailAddress,
              autocorrect: false,
              decoration: const InputDecoration(
                labelText: 'Contact\'s email address',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('import-key-armored'),
              controller: _armored,
              minLines: 6,
              maxLines: 10,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: InputDecoration(
                labelText: 'Public key (armored)',
                hintText: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                border: const OutlineInputBorder(),
                errorText: _error,
                errorMaxLines: 4,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('import-key-confirm'),
          onPressed: _busy ? null : _import,
          child: const Text('Import'),
        ),
      ],
    );
  }
}

/// App lock (PIN / biometrics / auto-lock / Lock now) and how secrets are
/// protected at rest, as the engine reports it.
class _SecuritySection extends ConsumerWidget {
  const _SecuritySection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final lock = ref.watch(appLockProvider);
    final status = ref.watch(profileKeyStatusProvider).value;
    final theme = Theme.of(context);
    final atRest = switch (status) {
      null => 'Checking…',
      final s when s.encryptedAtRest =>
        'Account passwords, tokens, keys and messages are stored encrypted '
            '(profile key: ${s.sourceLabel}).',
      final s when s.known =>
        'Not encrypted yet: ${s.plaintextRows} item(s) are stored in plaintext in the profile, '
            'protected by file permissions only (profile key: ${s.sourceLabel}).',
      _ =>
        'This engine build does not encrypt the profile yet: account passwords, tokens and '
            'messages are protected by file permissions only. The app lock covers the screen.',
    };
    return Card(
      key: const Key('settings-security'),
      child: Column(
        children: [
          ListTile(
            key: const Key('settings-at-rest'),
            leading: Icon(
              status?.encryptedAtRest == true ? Icons.lock : Icons.lock_open,
              color: status?.encryptedAtRest == true
                  ? LockColors.ofContext(context).encrypted
                  : LockColors.ofContext(context).plaintext,
            ),
            title: const Text('Data on this device'),
            subtitle: Text(atRest),
          ),
          if (lock == null)
            const ListTile(
              key: Key('settings-app-lock-off'),
              leading: Icon(Icons.no_encryption_gmailerrorred_outlined),
              title: Text('App lock is off for this run'),
              subtitle: Text('Started without the lock (test or scripted session).'),
            )
          else
            ListenableBuilder(
              listenable: lock,
              builder: (context, _) => Column(
                key: const Key('settings-app-lock'),
                children: [
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.pin_outlined),
                    title: const Text('App lock'),
                    subtitle: Text(
                      'PIN${lock.biometricsEnabled ? ' or biometrics' : ''} when Sealbox opens. '
                      'Profile key: ${lock.hasProfileKey ? 'kept in the ${lock.keyStorage}' : lock.keyStorage}'
                      '${status != null && !status.known && lock.hasProfileKey ? ' (not yet used by this engine build)' : ''}.',
                    ),
                    trailing: FilledButton.tonalIcon(
                      key: const Key('settings-lock-now'),
                      onPressed: lock.lock,
                      icon: const Icon(Icons.lock_outline),
                      label: const Text('Lock now'),
                    ),
                  ),
                  ListTile(
                    leading: const Icon(Icons.timer_outlined),
                    title: const Text('Lock automatically'),
                    subtitle: Text('After ${_minutes(lock.autoLockMinutes)} away or without input'),
                    trailing: DropdownButton<int>(
                      key: const Key('settings-auto-lock'),
                      value: lock.autoLockMinutes,
                      underline: const SizedBox.shrink(),
                      items: [
                        for (final m in {...AppLockController.autoLockChoices, lock.autoLockMinutes})
                          DropdownMenuItem(value: m, child: Text(_minutes(m))),
                      ],
                      onChanged: (m) => m == null ? null : lock.setAutoLockMinutes(m),
                    ),
                  ),
                  if (lock.biometricsAvailable)
                    SwitchListTile(
                      key: const Key('settings-biometrics'),
                      secondary: const Icon(Icons.fingerprint),
                      title: const Text('Unlock with biometrics'),
                      value: lock.biometricsEnabled,
                      onChanged: lock.setBiometricsEnabled,
                    ),
                ],
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Text(
              lock == null
                  ? 'The PIN locks the app; it is not your encryption key.'
                  : 'The PIN locks the app; it is not your encryption key. The app-lock key is '
                        '${lock.hasProfileKey ? 'kept in the ${lock.keyStorage}' : 'not available on this device'}.',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }

  static String _minutes(int m) => m == 1 ? '1 minute' : (m == 60 ? '1 hour' : '$m minutes');
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text);

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(left: 4, bottom: 8),
    child: Text(
      text,
      style: Theme.of(context).textTheme.titleMedium?.copyWith(
        color: Theme.of(context).colorScheme.primary,
      ),
    ),
  );
}

class _AccountTile extends ConsumerWidget {
  const _AccountTile({required this.account});

  final Account account;

  Future<void> _exportKey(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    final String armored;
    try {
      armored = await ref.read(coreApiProvider).exportPublicKey(account.id);
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not export: $e')));
      return;
    }
    if (!context.mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        key: const Key('export-key-dialog'),
        title: Text('Public key of ${account.email}'),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(
            child: SelectableText(
              armored,
              key: const Key('export-key-armored'),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ),
        ),
        actions: [
          TextButton.icon(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: armored));
              messenger.showSnackBar(const SnackBar(content: Text('Public key copied')));
            },
            icon: const Icon(Icons.copy),
            label: const Text('Copy'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _remove(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Remove ${account.email}?'),
        content: const Text(
          'Sealbox forgets the credentials, the key and the local copy of this '
          'mailbox. Nothing on the provider changes.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await ref.read(coreApiProvider).removeAccount(account.id);
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not remove: $e')));
      return;
    }
    ref.invalidate(accountsProvider);
    ref.invalidate(threadsProvider);
    ref.invalidate(identityProvider);
    messenger.showSnackBar(SnackBar(content: Text('${account.email} removed')));
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fp = account.fingerprint;
    final key = fp == null ? null : 'key …${fp.substring(fp.length - 8)}';
    // Phones (≤ 600 dp): one item per line instead of a wrap mid-item (review B3).
    final phone = MediaQuery.sizeOf(context).width <= 600;
    return ListTile(
      key: ValueKey('account-tile-${account.id}'),
      leading: CircleAvatar(
        child: Text(account.displayName.isEmpty ? '?' : account.displayName[0]),
      ),
      title: Text(account.email),
      subtitle: Text(
        phone
            ? [
                '${account.providerName} · ${account.authMethod.label}',
                'IMAP ${account.imapLabel}',
                'SMTP ${account.smtpLabel}',
                ?key,
              ].join('\n')
            : '${account.providerName} · ${account.authMethod.label}\n'
                  'IMAP ${account.imapLabel} · SMTP ${account.smtpLabel}'
                  '${key == null ? '' : ' · $key'}',
      ),
      isThreeLine: true,
      trailing: PopupMenuButton<String>(
        key: ValueKey('account-menu-${account.id}'),
        onSelected: (v) async {
          switch (v) {
            case 'export':
              await _exportKey(context, ref);
            case 'remove':
              await _remove(context, ref);
          }
        },
        itemBuilder: (_) => const [
          PopupMenuItem(value: 'export', child: Text('Export public key')),
          PopupMenuItem(value: 'remove', child: Text('Remove account')),
        ],
      ),
    );
  }
}

class _SignatureTile extends ConsumerWidget {
  const _SignatureTile({required this.account});

  final Account account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final sig = ref.watch(signatureProvider(account.id));
    final state = sig.when(
      loading: () => 'loading…',
      error: (e, _) => 'unavailable',
      data: (s) => !s.enabled ? 'off' : (s.isEmpty ? 'on, but empty' : 'on'),
    );
    return ListTile(
      key: ValueKey('settings-signature-${account.id}'),
      leading: const Icon(Icons.draw_outlined),
      title: const Text('Signature'),
      subtitle: Text('${account.email} · $state'),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => context.go('/settings/signature?account=${Uri.encodeQueryComponent(account.id)}'),
    );
  }
}

class _AutoReplyTile extends ConsumerWidget {
  const _AutoReplyTile({required this.account});

  final Account account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ar = ref.watch(autoReplyProvider(account.id));
    final state = ar.when(
      loading: () => 'loading…',
      error: (e, _) => 'unavailable',
      data: (s) => !s.enabled
          ? 'off'
          : s.isActiveNow
          ? 'active now'
          : 'scheduled${s.start == null ? '' : ' from ${fullTime(s.start!)}'}',
    );
    return ListTile(
      key: ValueKey('settings-autoreply-${account.id}'),
      leading: const Icon(Icons.beach_access_outlined),
      title: const Text('Out of office'),
      subtitle: Text('${account.email} · $state'),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => context.go('/settings/autoreply?account=${Uri.encodeQueryComponent(account.id)}'),
    );
  }
}

class _SpamTile extends ConsumerWidget {
  const _SpamTile({required this.account});

  final Account account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final spam = ref.watch(spamSettingsProvider(account.id));
    final state = spam.when(
      loading: () => 'loading…',
      error: (e, _) => 'unavailable',
      data: (s) => !s.enabled
          ? 'off'
          : 'on${s.dnsblEnabled ? ' · DNS blocklists' : ''}'
                '${s.allowlist.isEmpty && s.blocklist.isEmpty ? '' : ' · ${s.allowlist.length} allowed, ${s.blocklist.length} blocked'}',
    );
    return ListTile(
      key: ValueKey('settings-spam-${account.id}'),
      leading: const Icon(Icons.report_outlined),
      title: const Text('Spam'),
      subtitle: Text('${account.email} · $state'),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => context.go('/settings/spam?account=${Uri.encodeQueryComponent(account.id)}'),
    );
  }
}

class _FiltersTile extends ConsumerWidget {
  const _FiltersTile({required this.account});

  final Account account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final rules = ref.watch(filterRulesProvider(account.id));
    final state = rules.when(
      loading: () => 'loading…',
      error: (e, _) => 'unavailable',
      data: (r) {
        final on = r.where((x) => x.enabled).length;
        if (r.isEmpty) return 'no rules';
        return '${r.length} rule${r.length == 1 ? '' : 's'}${on == r.length ? '' : ' ($on on)'}';
      },
    );
    return ListTile(
      key: ValueKey('settings-filters-${account.id}'),
      leading: const Icon(Icons.filter_alt_outlined),
      title: const Text('Filters'),
      subtitle: Text('${account.email} · $state'),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => context.go('/settings/filters?account=${Uri.encodeQueryComponent(account.id)}'),
    );
  }
}

class _ContactTile extends StatelessWidget {
  const _ContactTile({required this.contact});

  final ContactKey contact;

  @override
  Widget build(BuildContext context) {
    final c = contact;
    final fp = c.fingerprint;
    final scheme = Theme.of(context).colorScheme;
    return ListTile(
      key: ValueKey('contact-tile-${c.address}'),
      leading: Icon(
        c.hasKey ? Icons.lock : Icons.lock_open,
        color: c.hasKey ? LockColors.ofContext(context).encrypted : scheme.outline,
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [IdentityBadge(contact: c), const Icon(Icons.chevron_right)],
      ),
      onTap: () => context.go(contactRoute(c.address)),
      title: Text(c.address),
      subtitle: Text(
        c.keyChangePending
            ? 'Key changed ${fullTime(c.keyChangedAt!)} · compare fingerprints'
            : c.hasKey
            ? '${c.verified ? 'Verified · ' : ''}${keySourceLabel(c.source)}'
                  '${c.preferEncrypt ? ' · prefers encryption' : ''}'
                  '${fp == null ? '' : ' · …${fp.substring(fp.length - 8)}'}'
            : 'No usable key${c.lastSeen == null ? '' : ' · last seen ${fullTime(c.lastSeen!)}'}',
      ),
    );
  }
}

class _IdentityView extends ConsumerWidget {
  const _IdentityView({required this.identity, required this.accountId});

  final IdentityPreview identity;
  final String accountId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final payload = ref.watch(fingerprintQrProvider(accountId)).value;
    final theme = Theme.of(context);
    final grouped = identity.grouped;
    final half = (grouped.length / 2).ceil();
    final split = grouped.indexOf(' ', half);
    final lines = split < 0
        ? grouped
        : '${grouped.substring(0, split)}\n${grouped.substring(split + 1)}';

    return Wrap(
      spacing: 24,
      runSpacing: 16,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        if (payload != null)
          FingerprintQr(key: const Key('my-fingerprint-qr'), payload: payload)
        else
          const SizedBox(width: 184, height: 184),
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 440),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                identity.email == null
                    ? 'OpenPGP fingerprint'
                    : 'OpenPGP fingerprint · ${identity.email}',
                style: theme.textTheme.titleSmall,
              ),
              const SizedBox(height: 6),
              SelectableText(
                lines,
                key: const Key('my-fingerprint'),
                style: theme.textTheme.titleMedium?.copyWith(
                  fontFamily: 'monospace',
                  letterSpacing: 1,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'Ed25519 signing key with a Curve25519 encryption subkey, created '
                '${fullTime(identity.createdAt)}. Contacts verify you by scanning the QR '
                'code or comparing this fingerprint in person or on a call.',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                children: [
                  OutlinedButton.icon(
                    onPressed: () async {
                      final messenger = ScaffoldMessenger.of(context);
                      await Clipboard.setData(
                        ClipboardData(text: identity.fingerprint),
                      );
                      messenger.showSnackBar(
                        const SnackBar(content: Text('Fingerprint copied')),
                      );
                    },
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy'),
                  ),
                  if (payload != null)
                    OutlinedButton.icon(
                      key: const Key('my-fingerprint-copy-code'),
                      onPressed: () async {
                        final messenger = ScaffoldMessenger.of(context);
                        await Clipboard.setData(ClipboardData(text: payload));
                        messenger.showSnackBar(
                          const SnackBar(content: Text('Code copied (OPENPGP4FPR:…)')),
                        );
                      },
                      icon: const Icon(Icons.qr_code),
                      label: const Text('Copy code'),
                    ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }
}


/// Settings → Security, second card: key transparency (G30), the recovery
/// phrase and device transfer (G15) for the selected account (an account
/// picker appears with several; the same selection as "My key").
class _IdentityRecoverySection extends ConsumerWidget {
  const _IdentityRecoverySection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    if (accounts.isEmpty) return const SizedBox.shrink();
    final account = selectedSettingsAccount(ref, accounts)!;
    final status = ref.watch(recoveryStatusProvider(account.id)).value;
    return Card(
      key: const Key('settings-identity-recovery'),
      child: Column(
        children: [
          if (accounts.length > 1)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
              child: SettingsAccountPicker(
                key: const Key('identity-account'),
                accounts: accounts,
              ),
            ),
          KeyTransparencyCard(accountId: account.id),
          const Divider(height: 1),
          ListTile(
            key: const Key('settings-recovery-phrase'),
            leading: const Icon(Icons.password),
            title: const Text('Recovery phrase'),
            subtitle: Text(
              status?.phraseCreatedAt == null
                  ? '12 words that bring your keys back on a new device. Not created yet.'
                  : 'Created ${fullTime(status!.phraseCreatedAt!)}. Shown once; create a new one '
                        'if you lost it.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => context.go(recoveryPhraseRoute(account.id)),
          ),
          const Divider(height: 1),
          ListTile(
            key: const Key('settings-transfer'),
            leading: const Icon(Icons.send_to_mobile),
            title: const Text(RecoveryCopy.transferTitle),
            subtitle: const Text(
              'Move your key with an Autocrypt Setup Message: works with Sealbox, Delta Chat and '
              'Thunderbird, no server needed.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => context.go(
              '/settings/transfer?account=${Uri.encodeQueryComponent(account.id)}',
            ),
          ),
        ],
      ),
    );
  }
}
