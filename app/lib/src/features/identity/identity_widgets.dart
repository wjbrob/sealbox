import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import '../inbox/inbox_list_pane.dart' show fullTime;

/// Routes of the identity screens (under Settings so the shell stays).
String verifyRoute(String address) => '/settings/verify?address=${Uri.encodeQueryComponent(address)}';
String contactRoute(String address) =>
    '/settings/contact?address=${Uri.encodeQueryComponent(address)}';

/// Last 8 hex digits, for compact references to a key.
String shortFingerprint(String? fp) {
  if (fp == null || fp.isEmpty) return '';
  final hex = fp.replaceAll(' ', '');
  return '…${hex.substring(hex.length < 8 ? 0 : hex.length - 8)}';
}

/// The engine's previous key, unless it is the current one (seen when one sync
/// meets several historical keys of a contact; reported to the core).
String? distinctPrevious(ContactKey c) {
  final p = c.previousFingerprint;
  if (p == null) return null;
  String hex(String s) => s.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '').toUpperCase();
  return c.fingerprint != null && hex(p) == hex(c.fingerprint!) ? null : p;
}

/// The amber banner on a message whose sender's key changed and the user has
/// not decided yet (docs/IDENTITY.md §1: harmless usually, but exactly what
/// an impersonator looks like; offer to verify).
class KeyChangedBanner extends ConsumerStatefulWidget {
  const KeyChangedBanner({super.key, required this.address, this.name, this.contact});

  final String address;
  final String? name;
  final ContactKey? contact;

  @override
  ConsumerState<KeyChangedBanner> createState() => _KeyChangedBannerState();
}

class _KeyChangedBannerState extends ConsumerState<KeyChangedBanner> {
  bool _busy = false;

  Future<void> _accept() async {
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _busy = true);
    try {
      await ref.read(coreApiProvider).acknowledgeKeyChange(widget.address);
      invalidateIdentity(ref);
      messenger.showSnackBar(
        SnackBar(content: Text('New key for ${widget.address} accepted')),
      );
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not accept the key: $e')));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final amber = LockColors.ofContext(context).plaintext;
    final who = (widget.name == null || widget.name!.isEmpty) ? widget.address : widget.name!;
    final prev = widget.contact == null ? null : distinctPrevious(widget.contact!);
    return Container(
      key: ValueKey('key-changed-banner-${widget.address}'),
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: amber.withValues(alpha: 0.12),
        border: Border.all(color: amber.withValues(alpha: 0.6)),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.warning_amber_rounded, color: amber),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  '$who\'s key changed',
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: amber,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'This message came with a different encryption key than earlier mail from '
            '${widget.address}${prev == null ? '' : ' (was ${shortFingerprint(prev)})'}. '
            'Usually that means they reinstalled, switched apps or got a new device. It is '
            'also what someone impersonating them would look like. Compare fingerprints to '
            'be sure.',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 4,
            children: [
              FilledButton.tonalIcon(
                key: ValueKey('key-changed-compare-${widget.address}'),
                onPressed: _busy ? null : () => context.push(verifyRoute(widget.address)),
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Compare fingerprints'),
              ),
              OutlinedButton(
                key: ValueKey('key-changed-accept-${widget.address}'),
                onPressed: _busy ? null : _accept,
                child: const Text('Accept new key'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

/// "Key changed (accepted)": the message brought a new key and the user has
/// since accepted (or verified) it. The fact stays on the message.
class KeyChangedAcceptedChip extends StatelessWidget {
  const KeyChangedAcceptedChip({super.key});

  @override
  Widget build(BuildContext context) => StatusChip(
    icon: Icons.history,
    label: 'Key changed (accepted)',
    color: LockColors.ofContext(context).plaintext,
    tooltip: 'This message brought a new key for the sender; you accepted it.',
  );
}

/// "✓ Verified": good signature by exactly the key the user verified.
class VerifiedChip extends StatelessWidget {
  const VerifiedChip({super.key});

  @override
  Widget build(BuildContext context) => StatusChip(
    // The check mark is the icon (the ✓ glyph is missing from Roboto); reads "✓ Verified".
    icon: Icons.check,
    label: 'Verified',
    color: LockColors.ofContext(context).encrypted,
    tooltip: 'Signed with the key you verified for this sender',
  );
}

/// Contact-row badge: ⚠ key changed (undecided), ✓ verified, nothing otherwise
/// (drawn as icons: Roboto has neither glyph).
class IdentityBadge extends StatelessWidget {
  const IdentityBadge({super.key, required this.contact});

  final ContactKey contact;

  @override
  Widget build(BuildContext context) {
    final palette = LockColors.ofContext(context);
    if (contact.keyChangePending) {
      return Tooltip(
        message: 'Key changed: compare fingerprints or accept the new key',
        child: Icon(
          Icons.warning_amber_rounded,
          key: ValueKey('contact-badge-changed-${contact.address}'),
          color: palette.plaintext,
          semanticLabel: 'Key changed',
        ),
      );
    }
    if (contact.verified) {
      return Tooltip(
        message: 'Verified',
        child: Icon(
          Icons.check,
          key: ValueKey('contact-badge-verified-${contact.address}'),
          color: palette.encrypted,
          semanticLabel: 'Verified',
        ),
      );
    }
    return const SizedBox.shrink();
  }
}

/// The banner at the top of a contact's detail screen.
class ContactIdentityBanner extends StatelessWidget {
  const ContactIdentityBanner({super.key, required this.contact, this.onAccept});

  final ContactKey contact;
  final VoidCallback? onAccept;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = LockColors.ofContext(context);
    final c = contact;
    final prev = distinctPrevious(c);
    final (Color color, IconData icon, String title, String body) = c.keyChangePending
        ? (
            palette.plaintext,
            Icons.warning_amber_rounded,
            'Key changed',
            'The key for ${c.address} changed on ${fullTime(c.keyChangedAt!)}'
                '${prev == null ? '' : ' (was ${shortFingerprint(prev)})'}. '
                'Mail you send now is encrypted to the new key. Compare fingerprints with them, or '
                'accept the new key if you know why it changed.',
          )
        : c.verified
        ? (
            palette.encrypted,
            Icons.check_circle,
            'Verified',
            'You compared this key with ${c.address}'
                '${c.verifiedAt == null ? '' : ' on ${fullTime(c.verifiedAt!)}'}. '
                'Sealbox warns you if it ever changes.',
          )
        : (
            theme.colorScheme.onSurfaceVariant,
            Icons.shield_outlined,
            'Not verified',
            'Sealbox learned this key automatically. To be sure it really belongs to '
                '${c.address}, compare fingerprints in person or on a call.',
          );
    return Container(
      key: ValueKey('contact-banner-${c.address}'),
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        border: Border.all(color: color.withValues(alpha: 0.5)),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color),
              const SizedBox(width: 8),
              Text(
                title,
                style: theme.textTheme.titleSmall?.copyWith(color: color, fontWeight: FontWeight.w700),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(body, style: theme.textTheme.bodyMedium),
          if (c.keyChangePending) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                FilledButton.tonalIcon(
                  key: const Key('contact-compare'),
                  onPressed: () => context.push(verifyRoute(c.address)),
                  icon: const Icon(Icons.qr_code_scanner),
                  label: const Text('Compare fingerprints'),
                ),
                OutlinedButton(
                  key: const Key('contact-accept'),
                  onPressed: onAccept,
                  child: const Text('Accept new key'),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
