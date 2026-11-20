import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:share_plus/share_plus.dart';

import '../../core/models.dart';
import '../../widgets/lock_badge.dart';

/// Per-message "Guest link" selector (G29): how recipients without a key get
/// the message. Each mode carries its honest one-line explanation; a mode the
/// engine of this build does not implement is shown as "coming soon" and
/// cannot be chosen.
class GuestLinkPanel extends StatelessWidget {
  const GuestLinkPanel({
    super.key,
    required this.mode,
    required this.supported,
    required this.guests,
    required this.onChanged,
    this.serverConfigured = true,
  });

  final GuestMode mode;
  final Set<GuestMode> supported;
  final List<String> guests;
  final ValueChanged<GuestMode> onChanged;

  /// False when the engine has no Sealbox server URL: the link cannot be
  /// created and the send will fail for the guest recipients.
  final bool serverConfigured;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final who = guests.join(', ');
    final selectedSupported = supported.contains(mode);
    return Card(
      key: const Key('guest-link-panel'),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.link, color: LockColors.ofContext(context).guestLink),
                const SizedBox(width: 8),
                Expanded(child: Text('Guest link', style: theme.textTheme.titleSmall)),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              '$who ${guests.length == 1 ? 'has' : 'have'} no encryption key, so they get an '
              'email with a link to read the message in their browser. The server only '
              'stores ciphertext. Choose how the link is protected:',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 4),
            Semantics(
              container: true,
              explicitChildNodes: true,
              label: 'Guest link protection',
              child: Column(
                children: [
                  for (final m in GuestMode.values)
                    _ModeTile(
                      mode: m,
                      selected: m == mode,
                      available: supported.contains(m),
                      onTap: () => onChanged(m),
                    ),
                ],
              ),
            ),
            if (!selectedSupported)
              Padding(
                padding: const EdgeInsets.only(top: 4, bottom: 8),
                child: Text(
                  '${mode.label} links are not available in this build yet. Choose an '
                  'available mode to send to $who.',
                  key: const Key('guest-mode-unavailable'),
                  style: theme.textTheme.bodySmall?.copyWith(color: scheme.error),
                ),
              ),
            if (mode == GuestMode.passphrase && selectedSupported)
              Container(
                key: const Key('guest-passphrase-panel'),
                width: double.infinity,
                margin: const EdgeInsets.only(top: 4, bottom: 8),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: scheme.surfaceContainerHigh,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.key, size: 20, color: LockColors.ofContext(context).guestLink),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Sealbox creates a passphrase when you send and shows it to you '
                        'once. Share it with $who by another channel — a call or a chat '
                        'message, not this email.',
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                  ],
                ),
              ),
            if (!serverConfigured)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  key: const Key('guest-server-missing'),
                  children: [
                    Icon(Icons.cloud_off_outlined, size: 18, color: scheme.onSurfaceVariant),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Guest links need a Sealbox server, and this app has none set up. '
                        'Until then $who can only get encrypted mail once they have a key.',
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                    TextButton(
                      key: const Key('guest-server-settings'),
                      onPressed: () => GoRouter.of(context).go('/settings?section=server'),
                      child: const Text('Open Settings'),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _ModeTile extends StatelessWidget {
  const _ModeTile({
    required this.mode,
    required this.selected,
    required this.available,
    required this.onTap,
  });

  final GuestMode mode;
  final bool selected;
  final bool available;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Semantics(
      inMutuallyExclusiveGroup: true,
      checked: selected,
      enabled: available,
      child: ListTile(
        key: Key('guest-mode-${mode.name}'),
        contentPadding: EdgeInsets.zero,
        dense: true,
        enabled: available,
        selected: selected,
        onTap: available ? onTap : null,
        leading: Icon(
          selected ? Icons.radio_button_checked : Icons.radio_button_unchecked,
          color: selected && available ? scheme.primary : scheme.onSurfaceVariant,
        ),
        title: Row(
          children: [
            Flexible(
              child: Text(
                mode == GuestMode.passphrase ? '${mode.label} (recommended)' : mode.label,
                style: theme.textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600),
              ),
            ),
            if (!available) ...[
              const SizedBox(width: 8),
              Text(
                'coming soon',
                key: Key('guest-mode-${mode.name}-soon'),
                style: theme.textTheme.labelSmall?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ],
        ),
        subtitle: Text(
          mode.explanation,
          style: theme.textTheme.bodySmall?.copyWith(color: scheme.onSurfaceVariant),
        ),
      ),
    );
  }
}

/// After a send that created guest links: what was sent, and for passphrase
/// links the passphrase — shown this once, with copy and share. (The engine
/// keeps the secret in the local `guest_links` table for resends; the server
/// never gets it — docs/GUEST_LINKS.md.) Not dismissible by tapping outside.
Future<void> showGuestLinkSentDialog(BuildContext context, List<GuestLinkResult> links) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => GuestLinkSentDialog(links: links),
  );
}

class GuestLinkSentDialog extends StatelessWidget {
  const GuestLinkSentDialog({super.key, required this.links});

  final List<GuestLinkResult> links;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final needsShare = links.any((l) => l.passphrase != null);
    return AlertDialog(
      key: const Key('guest-sent-dialog'),
      icon: Icon(Icons.link, color: LockColors.ofContext(context).guestLink),
      title: const Text('Guest link sent'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final l in links) _LinkResult(link: l),
            if (needsShare)
              Text(
                'Shown only now. A copy stays in your profile on this device (for resending '
                'the link); it is never sent to the server.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
          ],
        ),
      ),
      actions: [
        FilledButton(
          key: const Key('guest-sent-done'),
          onPressed: () => Navigator.of(context).pop(),
          child: Text(needsShare ? 'I have shared it' : 'Done'),
        ),
      ],
    );
  }
}

class _LinkResult extends StatelessWidget {
  const _LinkResult({required this.link});

  final GuestLinkResult link;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final who = link.recipients.join(', ');
    final expires = link.expiresAt;
    final what = switch (link.mode) {
      GuestMode.passphrase => '$who received a link that needs this passphrase. Send it to '
          'them by another channel:',
      GuestMode.emailCode => '$who received a link. Before it opens they confirm their '
          'address with a one-time code mailed to them — this protects against a forwarded '
          'or leaked link, not against someone who can read their email.',
      GuestMode.oneClick => '$who received a link that opens the message directly. Anyone '
          'who can read that email can read the message.',
    };
    final p = link.passphrase;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(what, style: theme.textTheme.bodyMedium),
          if (p != null) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: SelectableText(
                    p,
                    key: const Key('guest-passphrase'),
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontFamily: 'monospace',
                      letterSpacing: 0.5,
                    ),
                  ),
                ),
                IconButton(
                  key: const Key('guest-passphrase-copy'),
                  tooltip: 'Copy passphrase',
                  icon: const Icon(Icons.copy),
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.maybeOf(context);
                    await Clipboard.setData(ClipboardData(text: p));
                    messenger?.showSnackBar(const SnackBar(content: Text('Passphrase copied')));
                  },
                ),
                IconButton(
                  key: const Key('guest-passphrase-share'),
                  tooltip: 'Share passphrase',
                  icon: const Icon(Icons.share),
                  onPressed: () async {
                    final box = context.findRenderObject() as RenderBox?;
                    try {
                      await SharePlus.instance.share(
                        ShareParams(
                          text: p,
                          sharePositionOrigin: box == null
                              ? null
                              : box.localToGlobal(Offset.zero) & box.size,
                        ),
                      );
                    } catch (_) {
                      // No share sheet on this platform (e.g. some Linux
                      // desktops): copying is the fallback.
                      await Clipboard.setData(ClipboardData(text: p));
                    }
                  },
                ),
              ],
            ),
          ],
          if (link.secretInLink && link.mode == GuestMode.passphrase)
            Text(
              'Warning: this link contains the key to the message.',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
            ),
          if (expires != null)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                'Expires ${expires.toLocal().toString().substring(0, 16)}',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
        ],
      ),
    );
  }
}
