import '../../core/core_api.dart';

/// The strings of docs/RECOVERY.md ("App flow" and "Phrase handling advice"),
/// verbatim, in one place.
class RecoveryCopy {
  RecoveryCopy._();

  static const restoreAction = 'Restore from recovery phrase';
  static const restoreTitle = 'Restore your account';
  static const emailLabel = 'Email address';
  static const phraseLabel = 'Recovery phrase (12 words)';
  static const restoreButton = 'Restore';
  static const wrongOrSwapped = 'One of the words is wrong, or two words are swapped';
  static const wrongPhrase = 'This recovery phrase does not match the backup for this address.';
  static const noBackup = 'No backup found for this address on this server.';
  static const restored = 'Your keys and contacts are back. Fetching your mail…';

  static const showOnceTitle = 'Your recovery phrase';
  static const showOnceBody =
      'Write these 12 words down on paper, in order. They are the only way to get your '
      'encrypted mail back if you lose this device. Sealbox does not keep a copy.';
  static const confirmPrompt = 'Type words 3, 7 and 11 to confirm you wrote them down.';
  static const backupSaved =
      'Backup saved. Your keys, contacts and settings are encrypted with your phrase; the '
      'server cannot read them.';

  // Platform-neutral: the same banner shows on desktop windows (review D1).
  static const reminder =
      "Back up your keys so you don't lose your encrypted mail with this device.";

  static const transferTitle = 'Transfer to another device';
  static const transferInstruction =
      'Open Sealbox, Delta Chat or Thunderbird on the other device and enter this code when '
      'it asks.';

  static const advice = [
    'Write the 12 words on paper, in order, and keep it where you keep important documents. '
        'Do not store them in your mail, cloud notes or a screenshot.',
    'Anyone with the words and your address can restore your keys from the server. Treat them '
        'like the key to your house.',
    'If you think someone saw them, create a new phrase and back up again: the old phrase '
        'stops working at once.',
    'Sealbox never asks for your phrase except in "Restore from recovery phrase" on a new '
        'device.',
  ];
}

/// Engine errors of backup / restore in the documented words.
String friendlyRecoveryError(Object e) {
  final m = '$e';
  final l = m.toLowerCase();
  if (l.contains('401') || l.contains('refused the recovery token')) return RecoveryCopy.wrongPhrase;
  if (l.contains('no backup')) return RecoveryCopy.noBackup;
  if (l.contains('checksum')) return RecoveryCopy.wrongOrSwapped;
  final word = RegExp(r'word (\d+) of the recovery phrase is not in the word list').firstMatch(m);
  if (word != null) return 'Word ${word.group(1)} is not in the word list.';
  if (l.contains('connection') || l.contains('error sending request')) {
    return 'The server could not be reached. Check the address and your connection.';
  }
  return m.replaceFirst(RegExp(r'^(AnyhowException\()|(Invalid argument\(s\): )'), '');
}

/// Live validation of a typed phrase (`recovery_phrase_validate`, no
/// network): null while incomplete or fine, else the message to show.
Future<String?> phraseFieldError(CoreApi core, String text) async {
  final n = text.split(RegExp(r'[^A-Za-z]+')).where((t) => t.isNotEmpty).length;
  if (n < 12) return null;
  if (n > 12) return 'A recovery phrase has 12 words; this has $n.';
  try {
    final check = await core.recoveryPhraseValidate(text);
    return check.checksumOk ? null : RecoveryCopy.wrongOrSwapped;
  } catch (e) {
    return friendlyRecoveryError(e);
  }
}
