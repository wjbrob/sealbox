import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';
import '../../providers/provider_table.dart';

enum OnboardingStep {
  email,
  detecting,
  detected,
  appPassword,
  oauth,
  manual,
  connecting,
  done,
}

class OnboardingState {
  const OnboardingState({
    this.step = OnboardingStep.email,
    this.email = '',
    this.detection,
    this.error,
    this.account,
    this.connectingTo,
  });

  final OnboardingStep step;
  final String email;
  final ProviderDetection? detection;
  final String? error;
  final Account? account;
  final String? connectingTo;

  ProviderConfig? get provider => detection?.provider;

  OnboardingState copyWith({
    OnboardingStep? step,
    String? email,
    ProviderDetection? detection,
    String? error,
    bool clearError = false,
    Account? account,
    String? connectingTo,
  }) => OnboardingState(
    step: step ?? this.step,
    email: email ?? this.email,
    detection: detection ?? this.detection,
    error: clearError ? null : (error ?? this.error),
    account: account ?? this.account,
    connectingTo: connectingTo ?? this.connectingTo,
  );
}

/// Drives the add-account flow: email → detect → auth → connect → done.
class OnboardingController extends Notifier<OnboardingState> {
  /// Flips to true once the Google/Microsoft OAuth client ids exist and the
  /// engine runs the PKCE flow (docs/PROVIDERS_CONFORMANCE.md). Until then the OAuth
  /// button is disabled and the app-password path is the primary action.
  static const bool oauthAvailable = false;

  @override
  OnboardingState build() => const OnboardingState();

  CoreApi get _core => ref.read(coreApiProvider);

  Future<void> detect(String rawEmail) async {
    final email = rawEmail.trim();
    if (!isValidEmail(email)) {
      state = state.copyWith(
        email: email,
        error: 'Enter a full email address, like name@example.com',
      );
      return;
    }
    state = state.copyWith(
      step: OnboardingStep.detecting,
      email: email,
      clearError: true,
    );
    final detection = await _core.detectProvider(email);
    if (!ref.mounted) return;
    state = state.copyWith(
      step: detection.found ? OnboardingStep.detected : OnboardingStep.manual,
      detection: detection,
    );
  }

  void chooseOAuth() => state = state.copyWith(step: OnboardingStep.oauth);

  void chooseAppPassword() =>
      state = state.copyWith(step: OnboardingStep.appPassword);

  void chooseManual() => state = state.copyWith(step: OnboardingStep.manual);

  void back() {
    state = switch (state.step) {
      OnboardingStep.detected ||
      OnboardingStep.detecting => state.copyWith(step: OnboardingStep.email, clearError: true),
      OnboardingStep.appPassword ||
      OnboardingStep.oauth ||
      OnboardingStep.manual =>
        state.copyWith(
          step: state.provider != null
              ? OnboardingStep.detected
              : OnboardingStep.email,
          clearError: true,
        ),
      _ => state,
    };
  }

  /// OAuth 2.0 (PKCE) sign-in. The real flow opens the system browser and is
  /// completed by `sealbox-core`; it needs the client ids listed in
  /// docs/PROVIDERS_CONFORMANCE.md. Until then the engine's fake completes at once.
  Future<void> connectWithOAuth() async {
    final p = state.provider;
    if (p == null) return;
    await _connect(
      AccountSetup(
        email: state.email,
        displayName: _nameFromEmail(state.email),
        authMethod: AuthMethod.oauth2,
        imap: p.imap,
        smtp: p.smtp,
        providerName: p.displayName,
        username: state.email,
      ),
    );
  }

  Future<void> connectWithAppPassword(String secret) async {
    final p = state.provider;
    if (p == null) return;
    if (secret.trim().isEmpty) {
      state = state.copyWith(error: 'Paste the app password first');
      return;
    }
    await _connect(
      AccountSetup(
        email: state.email,
        displayName: _nameFromEmail(state.email),
        authMethod: AuthMethod.appPassword,
        imap: p.imap,
        smtp: p.smtp,
        providerName: p.displayName,
        username: state.email,
        secret: normalizeAppPassword(secret),
      ),
    );
  }

  Future<void> connectManual({
    required ServerSettings imap,
    required ServerSettings smtp,
    required String username,
    required String secret,
  }) async {
    if (imap.host.isEmpty || smtp.host.isEmpty) {
      state = state.copyWith(error: 'IMAP and SMTP hosts are required');
      return;
    }
    if (secret.isEmpty) {
      state = state.copyWith(error: 'A password is required');
      return;
    }
    await _connect(
      AccountSetup(
        email: state.email,
        displayName: _nameFromEmail(state.email),
        authMethod: AuthMethod.password,
        imap: imap,
        smtp: smtp,
        providerName: state.provider?.displayName,
        username: username.isEmpty ? state.email : username,
        secret: secret,
      ),
    );
  }

  Future<void> _connect(AccountSetup setup) async {
    final previous = state.step;
    state = state.copyWith(
      step: OnboardingStep.connecting,
      connectingTo: setup.imap.host,
      clearError: true,
    );
    try {
      final account = await _core.addAccount(setup);
      if (!ref.mounted) return;
      ref.invalidate(accountsProvider);
      ref.invalidate(threadsProvider);
      state = state.copyWith(step: OnboardingStep.done, account: account);
    } catch (e) {
      if (!ref.mounted) return;
      state = state.copyWith(step: previous, error: 'Could not connect: ${friendlyError(e)}');
    }
  }

  static String _nameFromEmail(String email) {
    final local = email.split('@').first;
    return local
        .split(RegExp(r'[._-]+'))
        .where((p) => p.isNotEmpty)
        .map((p) => '${p[0].toUpperCase()}${p.substring(1)}')
        .join(' ');
  }
}

final onboardingControllerProvider =
    NotifierProvider.autoDispose<OnboardingController, OnboardingState>(
      OnboardingController.new,
    );
