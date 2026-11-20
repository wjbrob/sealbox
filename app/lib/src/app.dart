import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/core_providers.dart';
import 'lock/lock_providers.dart';
import 'lock/lock_screen.dart';
import 'router.dart';

ThemeData buildTheme(Brightness brightness) => ThemeData(
  colorSchemeSeed: const Color(0xFF0E7C6B),
  brightness: brightness,
  visualDensity: VisualDensity.standard,
);

class SealboxApp extends ConsumerWidget {
  const SealboxApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(routerProvider);
    final mode = ref.watch(themeModeProvider);
    final lock = ref.watch(appLockProvider);
    return MaterialApp.router(
      title: 'Sealbox',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      themeMode: mode,
      routerConfig: router,
      builder: lock == null
          ? null
          : (context, child) => AppLockScope(lock: lock, child: child ?? const SizedBox.shrink()),
    );
  }
}
