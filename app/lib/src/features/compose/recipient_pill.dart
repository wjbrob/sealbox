import 'package:flutter/material.dart';

import '../../core/models.dart';
import '../../policy/encryption_policy.dart';
import '../../widgets/lock_badge.dart';

extension RecipientStatusUi on RecipientStatus {
  IconData get icon => switch (this) {
    RecipientStatus.encrypted => Icons.lock,
    RecipientStatus.guestLink => Icons.link,
    RecipientStatus.plaintext => Icons.warning_amber_rounded,
  };

  /// Base tone (theme-independent; use [colorIn] for anything with text).
  Color get color => switch (this) {
    RecipientStatus.encrypted => LockColors.encrypted,
    RecipientStatus.guestLink => LockColors.guestLink,
    RecipientStatus.plaintext => LockColors.plaintext,
  };

  /// Text-safe tone for the current theme.
  Color colorIn(BuildContext context) {
    final p = LockColors.ofContext(context);
    return switch (this) {
      RecipientStatus.encrypted => p.encrypted,
      RecipientStatus.guestLink => p.guestLink,
      RecipientStatus.plaintext => p.plaintext,
    };
  }

  String get description => switch (this) {
    RecipientStatus.encrypted =>
      'Key known: this recipient gets the message OpenPGP-encrypted.',
    RecipientStatus.guestLink =>
      'No key found: this recipient gets a passphrase-protected guest link.',
    RecipientStatus.plaintext =>
      'You chose to send this recipient an unencrypted copy.',
  };
}

String keySourceLabel(KeySource s) => switch (s) {
  KeySource.autocrypt => 'Autocrypt',
  KeySource.gossip => 'Autocrypt gossip',
  KeySource.imported => 'imported key',
  KeySource.directory => 'Sealbox directory',
  KeySource.wkd => 'WKD',
  KeySource.keyserver => 'keys.openpgp.org',
  KeySource.own => 'your own account',
};

/// One recipient in the compose screen: address + encryption status pill +
/// a menu to switch a key-less recipient between guest link and plaintext.
class RecipientPill extends StatelessWidget {
  const RecipientPill({
    super.key,
    required this.email,
    required this.status,
    this.keySource,
    required this.onRemove,
    required this.onRequestPlaintext,
    required this.onUseGuestLink,
  });

  final String email;

  /// `null` while the key lookup is running.
  final RecipientStatus? status;
  final KeySource? keySource;
  final VoidCallback onRemove;
  final VoidCallback onRequestPlaintext;
  final VoidCallback onUseGuestLink;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final s = status;
    final color = s?.colorIn(context) ?? theme.colorScheme.outline;
    final statusText = switch (s) {
      null => 'looking up key…',
      RecipientStatus.encrypted =>
        keySource == null
            ? 'encrypted'
            : 'encrypted · ${keySourceLabel(keySource!)}',
      RecipientStatus.guestLink => 'guest link',
      RecipientStatus.plaintext => 'plaintext',
    };

    // One semantics node per pill ("address, status"); the menu stays its own
    // labelled child so a screen reader can focus either.
    return Semantics(
      container: true,
      label: '$email\n$statusText',
      child: Tooltip(
        message: s?.description ?? 'Looking up a key for $email…',
        child: Container(
        key: ValueKey('recipient-pill-$email'),
        padding: const EdgeInsets.only(left: 10, right: 2, top: 2, bottom: 2),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.10),
          border: Border.all(color: color.withValues(alpha: 0.6)),
          borderRadius: BorderRadius.circular(999),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            ExcludeSemantics(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (s == null)
                    const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  else
                    Icon(
                      s.icon,
                      key: ValueKey('recipient-status-${s.name}'),
                      size: 16,
                      color: color,
                    ),
                  const SizedBox(width: 6),
                  Text(email, style: theme.textTheme.bodyMedium),
                  const SizedBox(width: 6),
                  Text(
                    statusText,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: color,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
            PopupMenuButton<_PillAction>(
              key: ValueKey('recipient-menu-$email'),
              tooltip: 'Options for $email',
              iconSize: 18,
              padding: EdgeInsets.zero,
              onSelected: (a) => switch (a) {
                _PillAction.plaintext => onRequestPlaintext(),
                _PillAction.guestLink => onUseGuestLink(),
                _PillAction.remove => onRemove(),
              },
              itemBuilder: (_) => [
                if (s == RecipientStatus.guestLink)
                  const PopupMenuItem(
                    key: Key('pill-action-plaintext'),
                    value: _PillAction.plaintext,
                    child: ListTile(
                      leading: Icon(Icons.warning_amber_rounded),
                      title: Text('Send unencrypted instead'),
                    ),
                  ),
                if (s == RecipientStatus.plaintext)
                  const PopupMenuItem(
                    key: Key('pill-action-guest-link'),
                    value: _PillAction.guestLink,
                    child: ListTile(
                      leading: Icon(Icons.link),
                      title: Text('Use a guest link instead'),
                    ),
                  ),
                const PopupMenuItem(
                  key: Key('pill-action-remove'),
                  value: _PillAction.remove,
                  child: ListTile(
                    leading: Icon(Icons.close),
                    title: Text('Remove recipient'),
                  ),
                ),
              ],
            ),
          ],
        ),
        ),
      ),
    );
  }
}

enum _PillAction { plaintext, guestLink, remove }
