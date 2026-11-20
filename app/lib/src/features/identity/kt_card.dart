import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import '../inbox/inbox_list_pane.dart' show fullTime;

/// Settings → Security → Key transparency: the five states of
/// `Engine::kt_audit` for the first account (docs/IDENTITY.md §3).
class KeyTransparencyCard extends ConsumerWidget {
  const KeyTransparencyCard({super.key, required this.accountId});

  final String accountId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final palette = LockColors.ofContext(context);
    final audit = ref.watch(ktAuditProvider(accountId));
    final a = audit.value;
    final running = audit.isLoading;
    final state = running ? KtState.unchecked : (a?.state ?? KtState.unchecked);

    final (IconData icon, Color color, String title, String body) = switch (state) {
      KtState.noServer => (
        Icons.cloud_off_outlined,
        theme.colorScheme.onSurfaceVariant,
        'Key transparency: not available',
        'No Sealbox server is configured, so there is no public key log to check. Key-change '
            'warnings still work for every contact.',
      ),
      KtState.unchecked => (
        Icons.manage_search,
        theme.colorScheme.onSurfaceVariant,
        running ? 'Checking the key log…' : 'Key transparency: not checked yet',
        'Sealbox checks that the server\'s public key log lists your real key, so the server '
            'cannot hand out a fake key for you unnoticed.',
      ),
      KtState.verified => (
        Icons.verified_user,
        palette.encrypted,
        'Your key is in the public log',
        'The log (${a!.logSize} entries) lists your current key, its signed tree head verified, '
            'and it only grew since this device last looked'
            '${a.checkedAt == null ? '' : '. Checked ${fullTime(a.checkedAt!)}'}.',
      ),
      KtState.alert => (
        Icons.gpp_bad_outlined,
        palette.undecryptable,
        a!.substitution ? 'The log lists a different key for you' : 'Key transparency alert',
        a.substitution
            ? 'The server\'s key log says your address uses a key that is not yours. Someone may '
                  'be handing out a fake key for you. Tell your contacts to verify your '
                  'fingerprint before sending anything sensitive.'
            : 'The key log did not pass every check: '
                  '${[if (!a.sthVerified) 'tree head signature', if (!a.consistencyOk) 'consistency with the last check', if (!a.ownKeyIncluded) 'your key\'s entry'].join(', ')}.',
      ),
      KtState.unreachable => (
        Icons.wifi_off,
        palette.plaintext,
        'Could not check the key log',
        'The server did not answer${a?.error == null ? '' : ' (${a!.error})'}. This is not a '
            'sign of an attack by itself; try again later.',
      ),
    };

    return ListTile(
      key: Key('settings-kt-${state.name}'),
      leading: Icon(icon, color: color),
      title: Text(title, style: TextStyle(color: state == KtState.alert ? color : null)),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(body),
          if (a != null && a.alerts.isNotEmpty && state == KtState.alert)
            for (final line in a.alerts)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  line,
                  style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', color: color),
                ),
              ),
        ],
      ),
      trailing: state == KtState.noServer
          ? null
          : TextButton(
              key: const Key('settings-kt-check'),
              onPressed: running ? null : () => ref.invalidate(ktAuditProvider(accountId)),
              child: Text(state == KtState.unchecked ? 'Check now' : 'Check again'),
            ),
    );
  }
}
