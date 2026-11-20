import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/core_providers.dart' show ThemePreference;
import '../widgets/sealbox_logo.dart';
import 'app_lock.dart';

/// PIN setup (first launch) and unlock (every launch, after "Lock now" and
/// after auto-lock). Biometrics are offered where the device has them.
class LockScreen extends StatefulWidget {
  const LockScreen({super.key, required this.lock});

  final AppLockController lock;

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _pin = TextEditingController();
  final _confirm = TextEditingController();
  final _pinFocus = FocusNode();
  String? _error;
  bool _busy = false;
  bool _triedBiometrics = false;
  Timer? _tick;

  AppLockController get lock => widget.lock;

  @override
  void initState() {
    super.initState();
    _pin.addListener(_changed);
    _confirm.addListener(_changed);
    lock.addListener(_lockChanged);
    // Offer biometrics once automatically when the screen opens.
    WidgetsBinding.instance.addPostFrameCallback((_) => _autoBiometrics());
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && lock.lockoutRemaining != null) setState(() {});
    });
  }

  void _changed() => setState(() => _error = null);

  void _lockChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _tick?.cancel();
    lock.removeListener(_lockChanged);
    _pin.dispose();
    _confirm.dispose();
    _pinFocus.dispose();
    super.dispose();
  }

  Future<void> _autoBiometrics() async {
    if (_triedBiometrics || !mounted) return;
    if (lock.phase == LockPhase.locked && lock.biometricsEnabled) {
      _triedBiometrics = true;
      await lock.unlockWithBiometrics();
    }
  }

  Future<void> _submit() async {
    if (_busy) return;
    final pin = _pin.text.trim();
    if (lock.phase == LockPhase.setup) {
      if (!AppLockController.isPlausiblePin(pin)) {
        setState(() => _error =
            'Use ${AppLockController.minPinLength}–${AppLockController.maxPinLength} digits');
        return;
      }
      if (pin != _confirm.text.trim()) {
        setState(() => _error = 'The two PINs do not match');
        return;
      }
      setState(() => _busy = true);
      try {
        await lock.setPin(pin);
      } finally {
        if (mounted) setState(() => _busy = false);
      }
      return;
    }
    if (pin.isEmpty) return;
    setState(() => _busy = true);
    final ok = await lock.unlockWithPin(pin);
    if (!mounted) return;
    setState(() {
      _busy = false;
      if (!ok) {
        _pin.clear();
        _error = lock.lockoutRemaining != null
            ? null
            : 'Wrong PIN${lock.failedAttempts >= 3 ? ' (${lock.failedAttempts} attempts)' : ''}';
      }
    });
    if (!ok) _pinFocus.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final setup = lock.phase == LockPhase.setup;
    final lockout = lock.lockoutRemaining;
    final pinOk = AppLockController.isPlausiblePin(_pin.text.trim());
    final canSubmit = !_busy &&
        lockout == null &&
        (setup ? pinOk && _confirm.text.trim().length >= AppLockController.minPinLength : _pin.text.isNotEmpty);
    final digitsOnly = [
      FilteringTextInputFormatter.digitsOnly,
      LengthLimitingTextInputFormatter(AppLockController.maxPinLength),
    ];
    return Scaffold(
      key: const Key('lock-screen'),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: EdgeInsets.fromLTRB(
              24,
              24,
              24,
              24 + MediaQuery.viewInsetsOf(context).bottom,
            ),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Center(child: SealboxLogo(size: 64)),
                  const SizedBox(height: 16),
                  Text(
                    setup ? 'Protect Sealbox with a PIN' : 'Sealbox is locked',
                    style: theme.textTheme.headlineSmall,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    setup
                        ? 'You will enter it each time Sealbox opens and after it locks '
                              'itself. ${AppLockController.minPinLength}–${AppLockController.maxPinLength} digits.'
                        : 'Enter your PIN${lock.biometricsEnabled ? ' or use biometrics' : ''} to open your mail.',
                    style: theme.textTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 24),
                  TextField(
                    key: const Key('lock-pin'),
                    controller: _pin,
                    focusNode: _pinFocus,
                    autofocus: !lock.biometricsEnabled || setup,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    inputFormatters: digitsOnly,
                    enabled: lockout == null,
                    textInputAction: setup ? TextInputAction.next : TextInputAction.done,
                    decoration: InputDecoration(
                      labelText: setup ? 'New PIN' : 'PIN',
                      border: const OutlineInputBorder(),
                      prefixIcon: const Icon(Icons.pin_outlined),
                    ),
                    onSubmitted: (_) => setup ? null : _submit(),
                  ),
                  if (setup) ...[
                    const SizedBox(height: 12),
                    TextField(
                      key: const Key('lock-pin-confirm'),
                      controller: _confirm,
                      obscureText: true,
                      keyboardType: TextInputType.number,
                      inputFormatters: digitsOnly,
                      textInputAction: TextInputAction.done,
                      scrollPadding: const EdgeInsets.only(bottom: 120),
                      decoration: const InputDecoration(
                        labelText: 'Repeat the PIN',
                        border: OutlineInputBorder(),
                        prefixIcon: Icon(Icons.pin_outlined),
                      ),
                      onSubmitted: (_) => _submit(),
                    ),
                  ],
                  if (_error != null || lockout != null) ...[
                    const SizedBox(height: 12),
                    Text(
                      lockout != null
                          ? 'Too many wrong PINs. Try again in ${lockout.inSeconds + 1} s.'
                          : _error!,
                      key: const Key('lock-error'),
                      style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.error),
                      textAlign: TextAlign.center,
                    ),
                  ],
                  const SizedBox(height: 16),
                  FilledButton(
                    key: const Key('lock-submit'),
                    onPressed: canSubmit ? _submit : null,
                    child: _busy
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : Text(setup ? 'Set PIN' : 'Unlock'),
                  ),
                  if (!setup && lock.biometricsEnabled) ...[
                    const SizedBox(height: 8),
                    OutlinedButton.icon(
                      key: const Key('lock-biometric'),
                      onPressed: lockout == null ? lock.unlockWithBiometrics : null,
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Use biometrics'),
                    ),
                  ],
                  if (setup) ...[
                    const SizedBox(height: 16),
                    Text(
                      lock.hasProfileKey
                          ? 'A random key for your Sealbox profile was created and is kept '
                                'in the ${lock.keyStorage}.'
                          : 'This device offers no OS keystore to Sealbox '
                                '(${lock.store.backend}); the PIN still locks the app.',
                      key: const Key('lock-key-storage'),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Covers the app while it is locked and runs auto-lock: any pointer activity
/// counts as use; going to the background for [AppLockController.autoLockMinutes]
/// (or that long without input in the foreground) locks it.
class AppLockScope extends StatefulWidget {
  const AppLockScope({super.key, required this.lock, required this.child});

  final AppLockController lock;
  final Widget child;

  @override
  State<AppLockScope> createState() => _AppLockScopeState();
}

class _AppLockScopeState extends State<AppLockScope> with WidgetsBindingObserver {
  Timer? _idle;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _idle = Timer.periodic(const Duration(seconds: 15), (_) => widget.lock.checkIdle());
  }

  @override
  void dispose() {
    _idle?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
        widget.lock.onBackground();
      case AppLifecycleState.resumed:
        widget.lock.onForeground();
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: (_) => widget.lock.touch(),
      child: ListenableBuilder(
        listenable: widget.lock,
        builder: (context, child) {
          final locked = widget.lock.isLocked;
          return Stack(
            fit: StackFit.expand,
            children: [
              // The app keeps its state but is neither painted nor reachable.
              Offstage(offstage: locked, child: TickerMode(enabled: !locked, child: child!)),
              if (locked)
                Overlay(
                  initialEntries: [
                    OverlayEntry(builder: (_) => LockScreen(lock: widget.lock)),
                  ],
                ),
            ],
          );
        },
        child: widget.child,
      ),
    );
  }
}

/// Before the engine is open: the lock alone, in its own MaterialApp, in the theme chosen in
/// Settings (kept in the lock's own store, [ThemePreference]) rather than the system's, so a
/// light app never opens behind a dark lock screen (review P6). The stored choice is read
/// before the first frame: like `Localizations` while its resources load, the gate holds
/// that frame until the read is done, for at most [themeWait].
class LockGateApp extends StatefulWidget {
  const LockGateApp({super.key, required this.lock, required this.theme, required this.darkTheme});

  final AppLockController lock;
  final ThemeData theme;
  final ThemeData darkTheme;

  /// The longest the first frame waits for the stored theme. A slower store leaves the
  /// system theme on screen until it answers; the stored one is applied then.
  static const themeWait = Duration(seconds: 1);

  @override
  State<LockGateApp> createState() => _LockGateAppState();
}

class _LockGateAppState extends State<LockGateApp> {
  ThemePreference get _theme => ThemePreference.of(widget.lock.store);

  /// This gate deferred the app's first frame and has not released it yet.
  bool _holdingFirstFrame = false;

  @override
  void initState() {
    super.initState();
    if (_theme.settled) return;
    WidgetsBinding.instance.deferFirstFrame();
    _holdingFirstFrame = true;
    _theme.load().timeout(LockGateApp.themeWait, onTimeout: () {}).whenComplete(_releaseFirstFrame);
  }

  void _releaseFirstFrame() {
    if (!_holdingFirstFrame) return;
    _holdingFirstFrame = false;
    WidgetsBinding.instance.allowFirstFrame();
  }

  @override
  void dispose() {
    _releaseFirstFrame();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final lock = widget.lock;
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: _theme,
      builder: (context, mode, _) => MaterialApp(
        title: 'Sealbox',
        debugShowCheckedModeBanner: false,
        theme: widget.theme,
        darkTheme: widget.darkTheme,
        themeMode: mode,
        home: ListenableBuilder(
          listenable: lock,
          builder: (context, _) => lock.phase == LockPhase.unlocked
              ? const Scaffold(
                  body: Center(child: CircularProgressIndicator(key: Key('lock-opening'))),
                )
              : LockScreen(lock: lock),
        ),
      ),
    );
  }
}

/// The engine refused the profile key (G27 `ProfileLocked`): the profile on
/// disk was encrypted with a key this device no longer offers (keystore reset,
/// app data restored onto another device, profile copied in). Nothing was read;
/// the PIN cannot help because it does not derive the key.
class ProfileLockedApp extends StatelessWidget {
  const ProfileLockedApp({super.key, required this.detail, required this.theme, required this.darkTheme});

  final String detail;
  final ThemeData theme;
  final ThemeData darkTheme;

  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    theme: theme,
    darkTheme: darkTheme,
    home: Builder(
      builder: (context) {
        final t = Theme.of(context);
        return Scaffold(
          key: const Key('profile-locked'),
          body: SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 480),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Icon(Icons.lock_person_outlined, size: 56, color: t.colorScheme.error),
                      const SizedBox(height: 16),
                      Text(
                        'This profile cannot be opened on this device',
                        style: t.textTheme.headlineSmall,
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Your mail data is encrypted with a key kept in this device\'s secure '
                        'storage, and that key is missing or different (for example after a '
                        'reset of the device\'s keystore, or when app data was copied from '
                        'another device). Nothing was read or changed.',
                        style: t.textTheme.bodyMedium,
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 12),
                      SelectableText(
                        detail,
                        style: t.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      },
    ),
  );
}
