import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/core_providers.dart';
import '../../core/errors.dart';
import '../../core/models.dart';

final RegExp _letterOrDigit = RegExp(r'[\p{L}\p{N}]', unicode: true);

/// Text worth asking the engine about: it finds nothing for text without a letter or digit.
bool isSearchable(String text) => _letterOrDigit.hasMatch(text);

/// What the search screen shows.
class MailSearchState {
  const MailSearchState({
    this.query = '',
    this.results,
    this.resultsFor = '',
    this.loading = false,
    this.error,
  });

  /// The text in the search field.
  final String query;

  /// The answer for [resultsFor]; null until the first answer (or after the field emptied).
  final List<SearchResult>? results;

  /// The query [results] (or [error]) belong to.
  final String resultsFor;

  /// A search is on its way (the previous results stay visible meanwhile).
  final bool loading;

  /// Why the last search failed (shown with a Retry button).
  final String? error;

  bool get searchable => isSearchable(query);

  MailSearchState copyWith({
    String? query,
    List<SearchResult>? results,
    String? resultsFor,
    bool? loading,
    String? error,
    bool clearError = false,
  }) => MailSearchState(
    query: query ?? this.query,
    results: results ?? this.results,
    resultsFor: resultsFor ?? this.resultsFor,
    loading: loading ?? this.loading,
    error: clearError ? null : (error ?? this.error),
  );
}

/// Runs the searches of the search screen: [debounce] after the last keystroke, one at a
/// time in effect (an answer for older text is dropped), entirely on this device.
class MailSearchController extends Notifier<MailSearchState> {
  /// How long typing must pause before the engine is asked.
  static const debounce = Duration(milliseconds: 300);

  Timer? _timer;
  int _seq = 0;

  @override
  MailSearchState build() {
    ref.onDispose(() => _timer?.cancel());
    return const MailSearchState();
  }

  /// The search field changed.
  void setQuery(String text) {
    if (text == state.query) return;
    _timer?.cancel();
    if (!isSearchable(text)) {
      _seq++; // an answer still on its way belongs to older text
      state = MailSearchState(query: text);
      return;
    }
    state = state.copyWith(query: text);
    _timer = Timer(debounce, () => _run(text));
  }

  /// Enter or Retry: search now.
  Future<void> searchNow() async {
    _timer?.cancel();
    await _run(state.query);
  }

  /// Back to an empty field.
  void clear() {
    _timer?.cancel();
    _seq++;
    state = const MailSearchState();
  }

  Future<void> _run(String text) async {
    if (!isSearchable(text)) return;
    final seq = ++_seq;
    state = state.copyWith(loading: true, clearError: true);
    try {
      final results = await ref.read(coreApiProvider).search(text);
      if (!ref.mounted || seq != _seq) return;
      state = state.copyWith(loading: false, results: results, resultsFor: text);
    } catch (e) {
      if (!ref.mounted || seq != _seq) return;
      state = state.copyWith(loading: false, error: friendlyError(e), resultsFor: text);
    }
  }
}

/// The search of the open search screen; it goes away with the screen.
final mailSearchProvider = NotifierProvider.autoDispose<MailSearchController, MailSearchState>(
  MailSearchController.new,
);

/// Builds the engine's in-memory index the first time search opens in this app run, so the
/// first query does not pay for it (0.13 s per 10,000 messages in a release build, more in
/// debug). A failure is ignored: the first search builds the index anyway.
final searchWarmUpProvider = FutureProvider<SearchIndexInfo?>((ref) async {
  try {
    return await ref.watch(coreApiProvider).warmSearchIndex();
  } catch (_) {
    return null;
  }
});
