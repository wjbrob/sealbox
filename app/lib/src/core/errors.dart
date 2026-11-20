/// ` (os error 111)`: the errno suffix Rust's `std::io::Error` appends.
final RegExp _osErrorSuffix = RegExp(r'\s*\(os error -?\d+\)');

/// Turns bridge/engine exceptions into something a person can read.
///
/// `AnyhowException(IMAP: connect to 127.0.0.1:1 failed: Connection refused (os error 111))`
/// becomes `IMAP: connect to 127.0.0.1:1 failed: Connection refused`: the
/// wrapper goes, and so does every ` (os error N)` errno suffix (review D5);
/// Dart's own `Bad state:` / `Unsupported operation:` prefixes are dropped too.
String friendlyError(Object error) {
  var s = error.toString().trim();
  const wrappers = ['AnyhowException(', 'PanicException('];
  for (final w in wrappers) {
    if (s.startsWith(w) && s.endsWith(')')) {
      s = s.substring(w.length, s.length - 1).trim();
    }
  }
  const prefixes = [
    'Bad state: ',
    'Unsupported operation: ',
    'Invalid argument(s): ',
    'Exception: ',
  ];
  for (final p in prefixes) {
    if (s.startsWith(p)) s = s.substring(p.length);
  }
  s = s.replaceAll(_osErrorSuffix, '').trim();
  return s.isEmpty ? 'unknown error' : s;
}

/// The engine refused to open the profile: it is encrypted at rest (G27) and
/// the key offered is missing or wrong (`Error::ProfileLocked`). Nothing was
/// read.
class ProfileLockedException implements Exception {
  ProfileLockedException(this.detail);

  final String detail;

  /// The engine's error crosses the bridge as `profile locked: …`.
  static bool matches(Object e) => e is ProfileLockedException || '$e'.contains('profile locked:');

  @override
  String toString() => 'ProfileLockedException: ${friendlyError(detail)}';
}
