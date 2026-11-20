import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../policy/encryption_policy.dart';
import '../../providers/provider_table.dart' show isValidEmail;
import '../inbox/inbox_list_pane.dart' show avatarColorFor;
import 'recipient_pill.dart';

/// At most this many suggestions are shown under a recipient field.
const kMaxRecipientSuggestions = 5;

/// One suggested recipient and where the typed text matched its address.
class RecipientSuggestion {
  const RecipientSuggestion(this.contact, {required this.matchStart, required this.matchLength});

  final ContactKey contact;

  /// The matched part of [address] (for bold highlighting).
  final int matchStart;
  final int matchLength;

  String get address => contact.address;
}

/// The contacts whose address matches [query] (case-insensitive), best first: the address
/// itself, then addresses starting with it, then a word of the address starting with it
/// (after `@ . _ - +`, so "proton" finds carol@proton.me), then anything containing it;
/// alphabetical within each rank. Addresses in [exclude] (lower case: our own accounts,
/// recipients already added) and duplicates are left out.
List<RecipientSuggestion> recipientSuggestions(
  String query,
  Iterable<ContactKey> contacts, {
  Set<String> exclude = const {},
  int limit = kMaxRecipientSuggestions,
}) {
  final q = query.trim().toLowerCase();
  if (q.isEmpty || limit <= 0) return const [];
  final ranked = <(int, String, RecipientSuggestion)>[];
  final seen = <String>{};
  for (final c in contacts) {
    final a = c.address.trim().toLowerCase();
    if (a.isEmpty || exclude.contains(a) || !seen.add(a)) continue;
    final int rank;
    var at = 0;
    if (a == q) {
      rank = 0;
    } else if (a.startsWith(q)) {
      rank = 1;
    } else if ((at = _wordStart(a, q)) >= 0) {
      rank = 2;
    } else if ((at = a.indexOf(q)) >= 0) {
      rank = 3;
    } else {
      continue;
    }
    ranked.add((rank, a, RecipientSuggestion(c, matchStart: at, matchLength: q.length)));
  }
  ranked.sort((x, y) => x.$1 != y.$1 ? x.$1.compareTo(y.$1) : x.$2.compareTo(y.$2));
  return [for (final r in ranked.take(limit)) r.$3];
}

/// Where [q] starts a word of [a] (right after `@ . _ - +`), or -1.
int _wordStart(String a, String q) {
  for (var i = a.indexOf(q, 1); i > 0; i = a.indexOf(q, i + 1)) {
    if ('@._-+'.contains(a[i - 1])) return i;
  }
  return -1;
}

/// What a suggestion says about the contact's key, in the recipient pill's words.
({RecipientStatus status, String text}) suggestionStatus(ContactKey c) {
  if (!c.hasKey) return (status: RecipientStatus.guestLink, text: 'guest link · no key yet');
  final source = keySourceLabel(c.source);
  if (c.keyChangePending) {
    return (status: RecipientStatus.plaintext, text: 'key changed · compare fingerprints');
  }
  return (
    status: RecipientStatus.encrypted,
    text: c.verified ? 'encrypted · verified · $source' : 'encrypted · $source',
  );
}

/// A recipient field (To) that suggests addresses from the contacts the engine knows
/// (`contacts()`) while typing.
///
/// * Suggestions appear under the field (`Key('recipient-suggestions')`), best match first,
///   never one of [exclude] (our own accounts, recipients already added).
/// * Arrow down / up move the highlight, Enter adds the highlighted address, Escape hides
///   the list; a tap adds an address too and keeps the focus for the next one.
/// * The best suggestion is highlighted, unless the text already is a complete address that
///   no suggestion equals or starts with (`rik@posteo.de` while erik@posteo.de is suggested):
///   then Enter adds exactly what was typed, and the arrows still pick a suggestion. What is
///   highlighted is always what Enter adds.
class RecipientField extends ConsumerStatefulWidget {
  const RecipientField({
    super.key,
    required this.controller,
    required this.onSubmitted,
    required this.onPicked,
    this.fieldKey = const Key('compose-to'),
    this.label = 'To',
    this.errorText,
    this.exclude = const {},
    this.onChanged,
    this.suffix,
    this.helperText,
  });

  final TextEditingController controller;

  /// Enter without a highlighted suggestion: the typed text.
  final ValueChanged<String> onSubmitted;

  /// A suggestion was chosen (tap or Enter): its address.
  final ValueChanged<String> onPicked;
  final ValueChanged<String>? onChanged;
  final Key fieldKey;
  final String label;
  final String? errorText;

  /// Lower-cased addresses never suggested.
  final Set<String> exclude;

  /// At the end of the field (compose's "Cc" / "Bcc" links, a field's close button).
  final Widget? suffix;

  /// Under the field (what the Bcc field does).
  final String? helperText;

  @override
  ConsumerState<RecipientField> createState() => _RecipientFieldState();
}

class _RecipientFieldState extends ConsumerState<RecipientField> {
  late final FocusNode _focus = FocusNode(debugLabel: 'recipient-field', onKeyEvent: _onKey);

  /// The highlight moved by the arrow keys (null: the default, see [RecipientField]).
  int? _chosen;

  /// Escape hid the list; typing shows it again.
  bool _dismissed = false;

  /// The list as last built (the key handler and Enter act on what is on screen).
  List<RecipientSuggestion> _shown = const [];

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_textChanged);
    _focus.addListener(_focusChanged);
  }

  @override
  void didUpdateWidget(covariant RecipientField old) {
    super.didUpdateWidget(old);
    if (old.controller != widget.controller) {
      old.controller.removeListener(_textChanged);
      widget.controller.addListener(_textChanged);
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_textChanged);
    _focus.dispose();
    super.dispose();
  }

  void _textChanged() {
    if (!mounted) return;
    setState(() {
      _chosen = null;
      _dismissed = false;
    });
  }

  void _focusChanged() {
    if (mounted) setState(() {});
  }

  int _highlightOf(List<RecipientSuggestion> list) {
    if (list.isEmpty) return -1;
    final chosen = _chosen;
    if (chosen != null) return chosen.clamp(-1, list.length - 1);
    final typed = widget.controller.text.trim().toLowerCase();
    final exact = list.indexWhere((s) => s.address.toLowerCase() == typed);
    if (exact >= 0) return exact;
    // Ranked: a suggestion that completes the text comes first.
    final completes = list.first.address.toLowerCase().startsWith(typed);
    return completes || !isValidEmail(typed) ? 0 : -1;
  }

  KeyEventResult _onKey(FocusNode node, KeyEvent event) {
    if (_shown.isEmpty || event is KeyUpEvent) return KeyEventResult.ignored;
    final n = _shown.length;
    final current = _highlightOf(_shown);
    switch (event.logicalKey) {
      case LogicalKeyboardKey.arrowDown:
        setState(() => _chosen = current + 1 >= n ? 0 : current + 1);
        return KeyEventResult.handled;
      case LogicalKeyboardKey.arrowUp:
        setState(() => _chosen = current <= 0 ? n - 1 : current - 1);
        return KeyEventResult.handled;
      case LogicalKeyboardKey.escape when event is KeyDownEvent:
        setState(() => _dismissed = true);
        return KeyEventResult.handled;
      default:
        return KeyEventResult.ignored;
    }
  }

  void _submitted(String value) {
    final i = _highlightOf(_shown);
    if (_shown.isNotEmpty && i >= 0) {
      widget.onPicked(_shown[i].address);
    } else {
      widget.onSubmitted(value);
    }
  }

  void _tapped(RecipientSuggestion s) {
    widget.onPicked(s.address);
    _focus.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final contacts = ref.watch(contactsProvider).value ?? const <ContactKey>[];
    final query = widget.controller.text;
    final list = _focus.hasFocus && !_dismissed
        ? recipientSuggestions(query, contacts, exclude: widget.exclude)
        : const <RecipientSuggestion>[];
    _shown = list;
    final highlight = _highlightOf(list);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        TextField(
          key: widget.fieldKey,
          controller: widget.controller,
          focusNode: _focus,
          keyboardType: TextInputType.emailAddress,
          autocorrect: false,
          textInputAction: TextInputAction.done,
          decoration: InputDecoration(
            labelText: widget.label,
            hintText: 'Type an address and press Enter',
            errorText: widget.errorText,
            helperText: widget.helperText,
            helperMaxLines: 2,
            prefixIcon: const Icon(Icons.person_add_alt),
            suffixIcon: widget.suffix,
            border: const OutlineInputBorder(),
          ),
          onSubmitted: _submitted,
          onChanged: widget.onChanged,
        ),
        if (list.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            // Part of the field's tap region: a tap on a suggestion is not a tap outside
            // (which would unfocus the field and drop the list before the tap lands).
            child: TextFieldTapRegion(
              child: _SuggestionList(
                suggestions: list,
                highlight: highlight,
                query: query.trim(),
                onTap: _tapped,
              ),
            ),
          ),
      ],
    );
  }
}

class _SuggestionList extends StatelessWidget {
  const _SuggestionList({
    required this.suggestions,
    required this.highlight,
    required this.query,
    required this.onTap,
  });

  final List<RecipientSuggestion> suggestions;
  final int highlight;
  final String query;
  final ValueChanged<RecipientSuggestion> onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final n = suggestions.length;
    return Material(
      key: const Key('recipient-suggestions'),
      color: scheme.surfaceContainerHigh,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      child: Semantics(
        container: true,
        liveRegion: true,
        explicitChildNodes: true,
        label: '$n suggested recipient${n == 1 ? '' : 's'} for "$query"',
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            for (var i = 0; i < n; i++)
              _SuggestionTile(
                suggestion: suggestions[i],
                highlighted: i == highlight,
                position: '${i + 1} of $n',
                onTap: () => onTap(suggestions[i]),
              ),
          ],
        ),
      ),
    );
  }
}

class _SuggestionTile extends StatelessWidget {
  const _SuggestionTile({
    required this.suggestion,
    required this.highlighted,
    required this.position,
    required this.onTap,
  });

  final RecipientSuggestion suggestion;
  final bool highlighted;
  final String position;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final s = suggestion;
    final address = s.address;
    final status = suggestionStatus(s.contact);
    final end = (s.matchStart + s.matchLength).clamp(0, address.length);
    final start = s.matchStart.clamp(0, end);
    // One node per row: address, status, selected, tap, and the position as a hint.
    return MergeSemantics(
      child: Semantics(
        hint: 'Suggestion $position: adds the address as a recipient',
        child: ListTile(
          key: ValueKey('recipient-suggestion-$address'),
          selected: highlighted,
          selectedTileColor: scheme.secondaryContainer,
          selectedColor: scheme.onSecondaryContainer,
          onTap: onTap,
          // The initial repeats the address: not read out.
          leading: ExcludeSemantics(
            child: CircleAvatar(
              backgroundColor: avatarColorFor(address, scheme),
              foregroundColor: Colors.white,
              child: Text(address.isEmpty ? '?' : address[0].toUpperCase()),
            ),
          ),
          title: Text.rich(
            TextSpan(
              children: [
                TextSpan(text: address.substring(0, start)),
                TextSpan(
                  text: address.substring(start, end),
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                TextSpan(text: address.substring(end)),
              ],
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: Text(status.text, maxLines: 1, overflow: TextOverflow.ellipsis),
          trailing: Icon(
            s.contact.keyChangePending ? Icons.warning_amber_rounded : status.status.icon,
            color: status.status.colorIn(context),
          ),
        ),
      ),
    );
  }
}
