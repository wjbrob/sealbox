import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app_lock.dart';

/// The app lock, when the app runs with one (`main.dart`). `null` in widget
/// tests and the integration tests that start the app without it.
final appLockProvider = Provider<AppLockController?>((_) => null);
