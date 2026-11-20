import 'package:flutter/material.dart';

import '../core/models.dart';
import '../core/signer_mismatch.dart';

/// Colours with a fixed *meaning* across the app. The meaning never changes
/// between themes, but the tone does: text on a 10–12 % tint needs 4.5:1
/// against the surface it sits on, so each meaning has a darker tone for light
/// surfaces and a lighter one for dark surfaces (`LockColors.of(brightness)`).
/// The static constants are the saturated base tones for graphics (icons need
/// only 3:1) and for code that has no theme at hand.
class LockColors {
  const LockColors._();
  static const encrypted = Color(0xFF1B8A5A);
  static const signed = Color(0xFF2F6FDE);
  static const plaintext = Color(0xFFB7791F);
  static const guestLink = Color(0xFF6B5BD2);
  static const undecryptable = Color(0xFFC62828);

  /// The text-safe palette for [brightness].
  static LockPalette of(Brightness brightness) =>
      brightness == Brightness.dark ? LockPalette.dark : LockPalette.light;

  /// The text-safe palette for the current theme.
  static LockPalette ofContext(BuildContext context) => of(Theme.of(context).brightness);
}

/// One tone per meaning, chosen so 11–12 sp w600 text passes WCAG AA (4.5:1)
/// on a 10–12 % tint of itself over the theme surface.
class LockPalette {
  const LockPalette({
    required this.encrypted,
    required this.signed,
    required this.plaintext,
    required this.guestLink,
    required this.undecryptable,
  });

  static const light = LockPalette(
    encrypted: Color(0xFF0F6B45),
    signed: Color(0xFF2457B8),
    plaintext: Color(0xFF8A5A10),
    guestLink: Color(0xFF5243B5),
    undecryptable: Color(0xFFB3261E),
  );

  static const dark = LockPalette(
    encrypted: Color(0xFF6FD3A3),
    signed: Color(0xFF9DBBFF),
    plaintext: Color(0xFFE0B35A),
    guestLink: Color(0xFFB9AEFF),
    undecryptable: Color(0xFFFFB4AB),
  );

  final Color encrypted;
  final Color signed;
  final Color plaintext;
  final Color guestLink;
  final Color undecryptable;

  Color forState(EncryptionState s) => switch (s) {
    EncryptionState.encrypted => encrypted,
    EncryptionState.signed => signed,
    EncryptionState.plaintext => plaintext,
    EncryptionState.undecryptable => undecryptable,
  };
}

extension EncryptionStateUi on EncryptionState {
  IconData get icon => switch (this) {
    EncryptionState.encrypted => Icons.lock,
    EncryptionState.signed => Icons.verified_user_outlined,
    EncryptionState.plaintext => Icons.lock_open,
    EncryptionState.undecryptable => Icons.no_encryption_gmailerrorred,
  };

  /// Base tone (theme-independent; use [colorIn] for anything with text).
  Color get color => switch (this) {
    EncryptionState.encrypted => LockColors.encrypted,
    EncryptionState.signed => LockColors.signed,
    EncryptionState.plaintext => LockColors.plaintext,
    EncryptionState.undecryptable => LockColors.undecryptable,
  };

  /// Text-safe tone for the current theme.
  Color colorIn(BuildContext context) => LockColors.ofContext(context).forState(this);

  String get label => switch (this) {
    EncryptionState.encrypted => 'Encrypted',
    EncryptionState.signed => 'Signed',
    EncryptionState.plaintext => 'Not encrypted',
    EncryptionState.undecryptable => 'Cannot decrypt',
  };

  String get description => switch (this) {
    EncryptionState.encrypted =>
      'End-to-end encrypted with OpenPGP; only you and the sender can read it.',
    EncryptionState.signed =>
      'Not encrypted, but carries a valid OpenPGP signature from the sender.',
    EncryptionState.plaintext =>
      'Sent in the clear: the provider and anyone on the path could read it.',
    EncryptionState.undecryptable =>
      'Encrypted, but not to a key on this device: the body cannot be shown.',
  };
}

/// The lock badge used in the inbox list and the thread view.
///
/// Widget tests find it by `ValueKey('lock-badge-<state>')`.
class LockBadge extends StatelessWidget {
  const LockBadge({super.key, required this.state, this.showLabel = false});

  final EncryptionState state;
  final bool showLabel;

  @override
  Widget build(BuildContext context) {
    final color = state.colorIn(context);
    final child = Container(
      key: ValueKey('lock-badge-${state.name}'),
      padding: EdgeInsets.symmetric(horizontal: showLabel ? 8 : 4, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(state.icon, size: 16, color: color),
          if (showLabel) ...[
            const SizedBox(width: 4),
            Text(
              state.label,
              style: Theme.of(context).textTheme.labelMedium?.copyWith(
                color: color,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ],
      ),
    );
    return Semantics(
      label: state.label,
      child: Tooltip(message: state.description, child: child),
    );
  }
}

/// R4: the inbox row's signature glyph for a message whose good signature was made with a
/// key that is not the sender's — an amber pill beside the [LockBadge] (which keeps its
/// encryption meaning); the thread view's chip says the same in words.
///
/// Widget tests find it by `ValueKey('thread-signer-mismatch-<thread id>')` (set by the row).
class SignerMismatchGlyph extends StatelessWidget {
  const SignerMismatchGlyph({super.key, required this.mismatch});

  final SignerMismatch mismatch;

  @override
  Widget build(BuildContext context) {
    final amber = LockColors.ofContext(context).plaintext;
    return Semantics(
      label: 'Signature warning: ${mismatch.label}',
      child: Tooltip(
        message: mismatch.label,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 3),
          decoration: BoxDecoration(
            color: amber.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(999),
          ),
          child: Icon(Icons.gpp_maybe_outlined, size: 16, color: amber),
        ),
      ),
    );
  }
}

/// A status pill matching [LockBadge] (signature, folder, …) so the thread
/// header reads as one row of chips (lead review L4). [mono] is appended in a
/// monospace face — used only for fingerprints.
class StatusChip extends StatelessWidget {
  const StatusChip({
    super.key,
    required this.icon,
    required this.label,
    required this.color,
    this.mono,
    this.tooltip,
    this.maxLines,
  });

  final IconData icon;
  final String label;
  final Color color;
  final String? mono;
  final String? tooltip;

  /// Wrap the label onto up to this many lines (a rounded box then, not a pill); null:
  /// one line, ellipsised. For labels whose end matters (R4's "— but sent by …").
  final int? maxLines;

  @override
  Widget build(BuildContext context) {
    final style = Theme.of(context).textTheme.labelMedium?.copyWith(
      color: color,
      fontWeight: FontWeight.w600,
    );
    final chip = Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(maxLines == null ? 999 : 12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: color),
          const SizedBox(width: 4),
          Flexible(
            child: Text.rich(
              TextSpan(
                text: label,
                children: [
                  if (mono != null)
                    TextSpan(text: ' $mono', style: style?.copyWith(fontFamily: 'monospace')),
                ],
              ),
              style: style,
              maxLines: maxLines,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
    final t = tooltip;
    return t == null ? chip : Tooltip(message: t, child: chip);
  }
}
