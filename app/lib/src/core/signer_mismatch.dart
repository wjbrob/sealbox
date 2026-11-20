/// R4 (docs/THREAT_MODEL.md §6): a valid signature made with a key that does not belong
/// to the sender. Anyone can write any address into `From:`; a good signature only says
/// whose key signed, so the thread view must not present it as the sender's ("signed by
/// X" in green next to a message from Y reads as "Y signed this").
library;

import 'models.dart';

/// A good signature by a key that belongs to [signer], on a message from [sender].
class SignerMismatch {
  const SignerMismatch({required this.signer, required this.sender});

  /// The address the signing key belongs to.
  final String signer;

  /// The message's `From` address.
  final String sender;

  /// The amber chip of the thread view.
  String get label => 'signed by $signer — but sent by $sender';

  /// Its tooltip (and the row glyph's).
  String get explanation =>
      'The signature is valid, but it was made with a key that belongs to $signer, not to '
      'the sender $sender. It does not show that $sender wrote this message: anyone can put '
      'any address in From. Check with $sender another way before you act on it.';
}

String _address(String? a) => (a ?? '').trim().toLowerCase();

String _hex(String? fingerprint) =>
    (fingerprint ?? '').replaceAll(RegExp(r'[^0-9A-Fa-f]'), '').toUpperCase();

/// The [SignerMismatch] of [m], or null when there is none to show:
///
/// * the signature is not good (bad and unknown-key signatures have their own chips);
/// * the user verified exactly this key for the sender ([Message.signerVerified], G30);
/// * nobody else is known to own the key: the engine names no other address
///   ([Message.signerAddress], compared lower-cased and trimmed with `From`) and no
///   contact the user verified has this fingerprint under another address ([contacts]);
/// * signer and sender are both the user's own addresses ([own], lower-cased), e.g. a Sent
///   copy from a second account of the same profile.
SignerMismatch? signerMismatch(
  Message m, {
  Iterable<ContactKey> contacts = const [],
  Set<String> own = const {},
}) {
  if (m.signature != SignatureState.good || m.signerVerified) return null;
  final sender = _address(m.from.email);
  if (sender.isEmpty) return null;
  String? signer;
  final named = _address(m.signerAddress);
  if (named.isNotEmpty && named != sender) {
    signer = m.signerAddress!.trim();
  } else {
    // A key the user verified for another address is that address's key, whatever the
    // engine's own address map says (it keeps the first address a key was seen with).
    final fp = _hex(m.signer);
    if (fp.isNotEmpty) {
      for (final c in contacts) {
        if (c.verified && _hex(c.fingerprint) == fp && _address(c.address) != sender) {
          signer = c.address.trim();
          break;
        }
      }
    }
  }
  if (signer == null) return null;
  if (own.contains(_address(signer)) && own.contains(sender)) return null;
  return SignerMismatch(signer: signer, sender: m.from.email.trim());
}
