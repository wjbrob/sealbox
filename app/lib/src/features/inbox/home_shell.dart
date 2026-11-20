import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../widgets/sealbox_logo.dart';
import '../search/search_screen.dart' show SearchPane;
import 'inbox_list_pane.dart';

/// Responsive frame around the inbox / compose / settings sections.
///
/// * ≥ [wideBreakpoint] px: navigation rail + (for the inbox) the thread list
///   and the detail pane side by side;
/// * narrower: bottom navigation bar, list and detail stacked.
///
/// While searching ([search]) the results take the list pane's place on a wide
/// window; on a narrow one `/search` is a screen of its own.
class HomeShell extends StatelessWidget {
  const HomeShell({super.key, required this.location, required this.child, this.search = false});

  /// The search results own the list pane: at `/search`, and beside a conversation
  /// opened from them ([searchActive]).
  final bool search;

  /// `/search`, or a conversation opened from its results (`/inbox/t/<id>?from=search`).
  static bool searchActive(Uri uri) =>
      uri.path == '/search' ||
      (uri.path.startsWith('/inbox/t/') && uri.queryParameters['from'] == 'search');

  /// Material 3 "expanded" window class starts at 840 dp.
  static const double wideBreakpoint = 840;
  static const double listPaneWidth = 380;

  final String location;
  final Widget child;

  static final RegExp _threadRe = RegExp(r'^/inbox/t/([^/]+)');

  static const _sections = ['/inbox', '/compose', '/settings'];

  int get _sectionIndex {
    for (var i = 0; i < _sections.length; i++) {
      if (location == _sections[i] || location.startsWith('${_sections[i]}/')) {
        return i;
      }
    }
    return 0;
  }

  String? get _selectedThreadId => _threadRe.firstMatch(location)?.group(1);

  static bool isWide(BuildContext context) =>
      MediaQuery.sizeOf(context).width >= wideBreakpoint;

  @override
  Widget build(BuildContext context) {
    final wide = isWide(context);
    final section = _sectionIndex;
    final threadId = _selectedThreadId;
    void select(int i) => context.go(_sections[i]);

    if (wide) {
      return Scaffold(
        body: Row(
          children: [
            NavigationRail(
              key: const Key('home-rail'),
              selectedIndex: section,
              onDestinationSelected: select,
              labelType: NavigationRailLabelType.all,
              leading: const Padding(
                padding: EdgeInsets.only(top: 8, bottom: 16),
                child: _Wordmark(),
              ),
              destinations: const [
                NavigationRailDestination(
                  icon: Icon(Icons.inbox_outlined),
                  selectedIcon: Icon(Icons.inbox),
                  label: Text('Inbox'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.edit_outlined),
                  selectedIcon: Icon(Icons.edit),
                  label: Text('Compose'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.settings_outlined),
                  selectedIcon: Icon(Icons.settings),
                  label: Text('Settings'),
                ),
              ],
            ),
            const VerticalDivider(width: 1, thickness: 1),
            if (section == 0) ...[
              SizedBox(
                width: listPaneWidth,
                child: search
                    ? SearchPane(selectedThreadId: threadId, besideConversation: true)
                    : InboxListPane(selectedThreadId: threadId),
              ),
              const VerticalDivider(width: 1, thickness: 1),
            ],
            Expanded(child: child),
          ],
        ),
      );
    }

    final showList = section == 0 && threadId == null && location != '/search';
    return Scaffold(
      body: showList ? const InboxListPane() : child,
      bottomNavigationBar: threadId != null
          ? null
          : NavigationBar(
              key: const Key('home-bottom-nav'),
              selectedIndex: section,
              onDestinationSelected: select,
              destinations: const [
                NavigationDestination(
                  icon: Icon(Icons.inbox_outlined),
                  selectedIcon: Icon(Icons.inbox),
                  label: 'Inbox',
                ),
                NavigationDestination(
                  icon: Icon(Icons.edit_outlined),
                  selectedIcon: Icon(Icons.edit),
                  label: 'Compose',
                ),
                NavigationDestination(
                  icon: Icon(Icons.settings_outlined),
                  selectedIcon: Icon(Icons.settings),
                  label: 'Settings',
                ),
              ],
            ),
    );
  }
}

class _Wordmark extends StatelessWidget {
  const _Wordmark();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      children: [
        const SealboxLogo(size: 28, semanticLabel: null),
        const SizedBox(height: 2),
        Text(
          'Sealbox',
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
            color: scheme.primary,
            fontWeight: FontWeight.w700,
          ),
        ),
      ],
    );
  }
}
