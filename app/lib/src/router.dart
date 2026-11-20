import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'features/compose/compose_screen.dart';
import 'features/inbox/home_shell.dart';
import 'features/inbox/thread_screen.dart';
import 'features/onboarding/onboarding_screen.dart';
import 'features/identity/contact_screen.dart';
import 'features/identity/verify_screen.dart';
import 'features/recovery/recovery_phrase_screen.dart';
import 'features/recovery/restore_screen.dart';
import 'features/recovery/transfer_screen.dart';
import 'features/search/search_screen.dart';
import 'features/settings/autoreply_screen.dart';
import 'features/settings/settings_screen.dart';
import 'features/settings/signature_screen.dart';
import 'features/spam/filter_rules_screen.dart';
import 'features/spam/spam_settings_screen.dart';

/// Where the app opens. `main.dart` overrides this with `/onboarding` when no
/// account exists yet; tests override it to jump straight to a screen.
final initialLocationProvider = Provider<String>((_) => '/inbox');

final routerProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: ref.watch(initialLocationProvider),
    routes: [
      GoRoute(path: '/', redirect: (_, _) => '/inbox'),
      GoRoute(
        path: '/onboarding',
        builder: (_, _) => const OnboardingScreen(),
      ),
      GoRoute(
        path: '/restore',
        builder: (_, _) => const RestoreScreen(),
      ),
      ShellRoute(
        builder: (context, state, child) => HomeShell(
          location: state.uri.path,
          search: HomeShell.searchActive(state.uri),
          child: child,
        ),
        routes: [
          GoRoute(
            path: '/inbox',
            builder: (_, _) => const InboxDetailPlaceholder(),
            routes: [
              GoRoute(
                path: 't/:id',
                builder: (_, state) =>
                    ThreadScreen(threadId: state.pathParameters['id']!),
              ),
            ],
          ),
          // Search (local, in memory): results open their conversation at
          // `/inbox/t/<id>?from=search`, which keeps them in the wide list pane.
          GoRoute(path: '/search', builder: (_, _) => const SearchScreen()),
          GoRoute(
            path: '/compose',
            builder: (_, state) => ComposeScreen(
              replyToThreadId: state.uri.queryParameters['reply'],
              forwardMessageId: state.uri.queryParameters['forward'],
              // A saved draft (the Drafts chip): `/compose?draft=<id>`.
              draftId: int.tryParse(state.uri.queryParameters['draft'] ?? ''),
            ),
          ),
          GoRoute(
            path: '/settings',
            builder: (_, state) => SettingsScreen(section: state.uri.queryParameters['section']),
            routes: [
              // Mail handling: per-account spam settings and filter rules (a new
              // State per account, so switching accounts starts from that one's data).
              GoRoute(
                path: 'spam',
                builder: (_, state) {
                  final id = state.uri.queryParameters['account'] ?? '';
                  return SpamSettingsScreen(key: ValueKey('spam-$id'), accountId: id);
                },
              ),
              GoRoute(
                path: 'filters',
                builder: (_, state) {
                  final id = state.uri.queryParameters['account'] ?? '';
                  return FilterRulesScreen(key: ValueKey('filters-$id'), accountId: id);
                },
              ),
              GoRoute(
                path: 'signature',
                builder: (_, state) => SignatureSettingsScreen(
                  accountId: state.uri.queryParameters['account'] ?? '',
                ),
              ),
              GoRoute(
                path: 'contact',
                builder: (_, state) =>
                    ContactScreen(address: state.uri.queryParameters['address'] ?? ''),
              ),
              GoRoute(
                path: 'verify',
                builder: (_, state) =>
                    VerifyScreen(address: state.uri.queryParameters['address'] ?? ''),
              ),
              GoRoute(
                path: 'recovery-phrase',
                builder: (_, state) =>
                    RecoveryPhraseScreen(accountId: state.uri.queryParameters['account']),
              ),
              GoRoute(
                path: 'transfer',
                builder: (_, state) =>
                    TransferScreen(accountId: state.uri.queryParameters['account']),
              ),
              GoRoute(
                path: 'autoreply',
                builder: (_, state) => AutoReplySettingsScreen(
                  accountId: state.uri.queryParameters['account'] ?? '',
                ),
              ),
            ],
          ),
        ],
      ),
    ],
  );
});

/// Shown in the detail pane on wide screens when no thread is selected.
class InboxDetailPlaceholder extends StatelessWidget {
  const InboxDetailPlaceholder({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ColoredBox(
      color: scheme.surfaceContainerLow,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.mark_email_read_outlined, size: 64, color: scheme.outline),
            const SizedBox(height: 12),
            Text(
              'Select a conversation',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: scheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
