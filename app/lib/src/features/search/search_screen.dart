import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import '../../widgets/message_subject.dart';
import '../inbox/home_shell.dart';
import '../inbox/inbox_list_pane.dart' show avatarColorFor, relativeTime;
import '../inbox/thread_actions.dart' show isOwnMessage, ownAddressesOf;
import 'search_controller.dart';

/// Where a search result opens: its conversation, marked as opened from search so the wide
/// layout keeps the results in the list pane beside it.
String searchResultLocation(SearchResult r) => '/inbox/t/${r.message.threadId}?from=search';

/// The chip label of a folder: the inbox chip's name when the folder plays that role
/// (`[Gmail]/Sent Mail` reads "Sent"), otherwise the folder's last path segment.
String folderLabel(String folder) {
  for (final f in MailFolder.values) {
    if (f != MailFolder.all && f.matches(folder)) return f.label;
  }
  final leaf = folder.split(RegExp(r'[/.]')).last.trim();
  return leaf.isEmpty ? folder : leaf;
}

/// `/search`. On a phone-sized window this is the search screen; on a wide one the search
/// runs in the list pane (`HomeShell`) and this fills the detail pane until a result opens.
class SearchScreen extends StatelessWidget {
  const SearchScreen({super.key});

  @override
  Widget build(BuildContext context) =>
      HomeShell.isWide(context) ? const _SearchDetailPlaceholder() : const SearchPane();
}

/// The search: a focused field, results 300 ms after typing stops, and honest states — a
/// hint before there is anything to search for, "No results for …", the error with Retry.
/// Results look like the inbox rows (sender, subject, the body snippet with the matched
/// words in bold, folder, date) and open their conversation. Escape clears the field, and
/// on an empty field closes the search.
class SearchPane extends ConsumerStatefulWidget {
  const SearchPane({super.key, this.selectedThreadId, this.besideConversation = false});

  /// The conversation open beside the results (wide layout), highlighted in the list.
  final String? selectedThreadId;

  /// In the wide layout's list pane: results open beside it (`go`), and closing keeps the
  /// open conversation. Full screen (phone) results are pushed, so Back returns to them.
  final bool besideConversation;

  @override
  ConsumerState<SearchPane> createState() => _SearchPaneState();
}

class _SearchPaneState extends ConsumerState<SearchPane> {
  late final TextEditingController _text = TextEditingController(
    text: ref.read(mailSearchProvider).query,
  );
  final FocusNode _focus = FocusNode(debugLabel: 'search-field');

  @override
  void initState() {
    super.initState();
    // Build the engine's index while the user types (once per app run).
    ref.read(searchWarmUpProvider);
  }

  @override
  void dispose() {
    _text.dispose();
    _focus.dispose();
    super.dispose();
  }

  void _clear() {
    _text.clear();
    ref.read(mailSearchProvider.notifier).clear();
    _focus.requestFocus();
  }

  void _close() {
    final open = widget.selectedThreadId;
    context.go(widget.besideConversation && open != null ? '/inbox/t/$open' : '/inbox');
  }

  void _escape() => _text.text.isEmpty ? _close() : _clear();

  void _open(SearchResult r) {
    if (widget.besideConversation) {
      context.go(searchResultLocation(r));
    } else {
      context.push(searchResultLocation(r));
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(mailSearchProvider);
    final ctl = ref.read(mailSearchProvider.notifier);
    final theme = Theme.of(context);
    // Keep the field in step with the state (a programmatic query, a cleared search).
    if (!_focus.hasFocus && _text.text != s.query) _text.text = s.query;
    final pane = CallbackShortcuts(
      bindings: {const SingleActivator(LogicalKeyboardKey.escape): _escape},
      child: Scaffold(
        appBar: AppBar(
          leading: IconButton(
            key: const Key('search-close'),
            tooltip: 'Close search',
            icon: const Icon(Icons.arrow_back),
            onPressed: _close,
          ),
          titleSpacing: 0,
          title: TextField(
            key: const Key('search-field'),
            controller: _text,
            focusNode: _focus,
            autofocus: true,
            autocorrect: false,
            textInputAction: TextInputAction.search,
            style: theme.textTheme.titleMedium,
            // Not dense: the field is a 48 dp tap target like every other control.
            decoration: const InputDecoration(hintText: 'Search mail', border: InputBorder.none),
            onChanged: ctl.setQuery,
            onSubmitted: (_) => ctl.searchNow(),
          ),
          actions: [
            if (s.query.isNotEmpty)
              IconButton(
                key: const Key('search-clear'),
                tooltip: 'Clear search',
                icon: const Icon(Icons.close),
                onPressed: _clear,
              ),
          ],
          bottom: PreferredSize(
            preferredSize: const Size.fromHeight(3),
            child: SizedBox(
              height: 3,
              child: s.loading
                  ? const LinearProgressIndicator(key: Key('search-progress'), minHeight: 3)
                  : null,
            ),
          ),
        ),
        body: _body(context, s, ctl),
      ),
    );
    if (widget.besideConversation) return pane;
    // Full screen, reached with `go`: the system Back closes the search instead of the app.
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) _close();
      },
      child: pane,
    );
  }

  Widget _body(BuildContext context, MailSearchState s, MailSearchController ctl) {
    final results = s.results;
    if (!s.searchable) {
      return const _SearchMessage(
        key: Key('search-hint'),
        icon: Icons.manage_search,
        title: 'Search your mail',
        body:
            'Subjects, senders, recipients and message text, in every folder Sealbox has '
            'fetched. The search runs on this device: what you type is not sent anywhere.',
      );
    }
    if (s.error != null) {
      return _SearchMessage(
        key: const Key('search-error'),
        icon: Icons.error_outline,
        error: true,
        title: 'Search failed',
        body: s.error!,
        action: FilledButton.tonalIcon(
          key: const Key('search-retry'),
          onPressed: ctl.searchNow,
          icon: const Icon(Icons.refresh),
          label: const Text('Try again'),
        ),
      );
    }
    if (results == null) {
      return const _SearchMessage(
        key: Key('search-loading'),
        icon: Icons.manage_search,
        title: 'Searching…',
        busy: true,
      );
    }
    if (results.isEmpty) {
      return _SearchMessage(
        key: const Key('search-empty'),
        icon: Icons.search_off,
        title: 'No results for “${s.resultsFor.trim()}”',
        body:
            'Every word has to match. Only mail Sealbox has fetched can be found: '
            'fetch new mail, or open a folder once, to include it.',
      );
    }
    final accounts = ref.watch(accountsProvider).value ?? const <Account>[];
    final byId = {for (final a in accounts) a.id: a};
    final own = ownAddressesOf(accounts);
    final n = results.length;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 10, 16, 6),
          child: Semantics(
            liveRegion: true,
            child: Text(
              '$n result${n == 1 ? '' : 's'}',
              key: const Key('search-count'),
              style: Theme.of(context).textTheme.labelLarge
                  ?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
            ),
          ),
        ),
        Expanded(
          child: ListView.separated(
            key: const Key('search-results'),
            padding: EdgeInsets.only(bottom: 16 + MediaQuery.paddingOf(context).bottom),
            itemCount: n,
            separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
            itemBuilder: (context, i) {
              final r = results[i];
              return SearchResultTile(
                result: r,
                own: own,
                account: byId[r.message.accountId],
                showAccount: accounts.length > 1,
                selected: r.message.threadId == widget.selectedThreadId,
                onTap: () => _open(r),
              );
            },
          ),
        ),
      ],
    );
  }
}

/// One search result in the look of an inbox row: sender (or "To …" for mail we sent),
/// date, subject, the body snippet with the matched words in bold, lock badge and folder.
class SearchResultTile extends StatelessWidget {
  const SearchResultTile({
    super.key,
    required this.result,
    required this.onTap,
    this.own = const {},
    this.account,
    this.showAccount = false,
    this.selected = false,
  });

  final SearchResult result;
  final VoidCallback onTap;

  /// Our own addresses: a message from one of them shows its recipients.
  final Set<String> own;
  final Account? account;
  final bool showAccount;
  final bool selected;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final m = result.message;
    final weight = m.unread ? FontWeight.w700 : FontWeight.w400;
    final outgoing = isOwnMessage(m, own) && m.to.isNotEmpty;
    final sender = outgoing ? 'To ${m.to.map((c) => c.display).join(', ')}' : m.from.display;
    final avatarOf = outgoing ? m.to.first : m.from;
    final title = messageSubjectTitle(m);
    final folder = folderLabel(m.folder);
    final snippetStyle = theme.textTheme.bodySmall?.copyWith(color: scheme.onSurfaceVariant);
    final matchStyle = TextStyle(fontWeight: FontWeight.w700, color: scheme.onSurface);
    return MergeSemantics(
      child: ListTile(
        key: ValueKey('search-result-${m.id}'),
        selected: selected,
        selectedTileColor: scheme.secondaryContainer.withValues(alpha: 0.5),
        onTap: onTap,
        leading: ExcludeSemantics(
          child: CircleAvatar(
            backgroundColor: avatarColorFor(avatarOf.email, scheme),
            foregroundColor: Colors.white,
            child: Text(avatarOf.initial),
          ),
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                sender,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.titleSmall?.copyWith(fontWeight: weight),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              relativeTime(m.date),
              style: theme.textTheme.labelSmall?.copyWith(
                color: m.unread ? scheme.primary : scheme.onSurfaceVariant,
                fontWeight: weight,
              ),
            ),
          ],
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title.text,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: subjectTitleStyle(
                context,
                theme.textTheme.bodyMedium?.copyWith(fontWeight: weight),
                placeholder: title.placeholder,
              ),
            ),
            if (result.snippet.isNotEmpty) ...[
              const SizedBox(height: 2),
              Text.rich(
                TextSpan(
                  children: [
                    for (final span in result.snippet)
                      TextSpan(text: span.text, style: span.isMatch ? matchStyle : null),
                  ],
                ),
                key: ValueKey('search-snippet-${m.id}'),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: snippetStyle,
              ),
            ],
            const SizedBox(height: 4),
            Row(
              children: [
                LockBadge(state: m.state),
                const SizedBox(width: 6),
                Flexible(
                  child: _Tag(
                    key: ValueKey('search-folder-${m.id}'),
                    label: folder,
                    tooltip: 'In $folder',
                  ),
                ),
                if (showAccount && account != null) ...[
                  const SizedBox(width: 6),
                  Flexible(
                    child: _Tag(label: account!.providerName, tooltip: account!.email),
                  ),
                ],
              ],
            ),
          ],
        ),
        isThreeLine: true,
      ),
    );
  }
}

/// A small outlined label (the folder, the account) like the inbox row's account tag.
class _Tag extends StatelessWidget {
  const _Tag({super.key, required this.label, required this.tooltip});

  final String label;
  final String tooltip;

  @override
  Widget build(BuildContext context) => Tooltip(
    message: tooltip,
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: Theme.of(context).textTheme.labelSmall,
      ),
    ),
  );
}

/// The centred icon + title + text of the search's non-result states.
class _SearchMessage extends StatelessWidget {
  const _SearchMessage({
    super.key,
    required this.icon,
    required this.title,
    this.body,
    this.action,
    this.error = false,
    this.busy = false,
  });

  final IconData icon;
  final String title;
  final String? body;
  final Widget? action;
  final bool error;
  final bool busy;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (busy)
              const SizedBox(width: 40, height: 40, child: CircularProgressIndicator())
            else
              Icon(icon, size: 48, color: error ? scheme.error : scheme.outline),
            const SizedBox(height: 12),
            Text(title, style: theme.textTheme.titleMedium, textAlign: TextAlign.center),
            if (body != null) ...[
              const SizedBox(height: 6),
              Text(
                body!,
                textAlign: TextAlign.center,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: error ? scheme.error : scheme.onSurfaceVariant,
                ),
              ),
            ],
            if (action != null) ...[const SizedBox(height: 16), action!],
          ],
        ),
      ),
    );
  }
}

/// The detail pane beside the search results until one is opened (wide layout).
class _SearchDetailPlaceholder extends StatelessWidget {
  const _SearchDetailPlaceholder();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ColoredBox(
      key: const Key('search-detail-placeholder'),
      color: scheme.surfaceContainerLow,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.manage_search, size: 64, color: scheme.outline),
            const SizedBox(height: 12),
            Text(
              'Open a result to read it here',
              style: Theme.of(context).textTheme.titleMedium
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }
}
