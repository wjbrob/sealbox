import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/models.dart';

/// The account Settings shows key, directory, transparency and recovery
/// details for when the profile has several (null: the first one).
final settingsAccountProvider = NotifierProvider<SettingsAccountController, String?>(
  SettingsAccountController.new,
);

class SettingsAccountController extends Notifier<String?> {
  @override
  String? build() => null;

  void select(String accountId) => state = accountId;
}

/// The selected account among [accounts] (the first when none or a removed one
/// is selected); null without accounts.
Account? selectedSettingsAccount(WidgetRef ref, List<Account> accounts) {
  if (accounts.isEmpty) return null;
  final id = ref.watch(settingsAccountProvider);
  return accounts.where((a) => a.id == id).firstOrNull ?? accounts.first;
}

/// A compact "Account ▾" chooser; renders nothing for a single account.
class SettingsAccountPicker extends ConsumerWidget {
  const SettingsAccountPicker({super.key, required this.accounts, this.label = 'Account'});

  final List<Account> accounts;
  final String label;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (accounts.length < 2) return const SizedBox.shrink();
    final selected = selectedSettingsAccount(ref, accounts)!;
    final menu = DropdownMenu<String>(
      // Keyed by the selection: the other picker (My key / Security) may change it.
      key: ValueKey('settings-account-${selected.id}'),
      initialSelection: selected.id,
      label: Text(label),
      expandedInsets: EdgeInsets.zero,
      trailingIcon: const Tooltip(
        message: 'Choose the account',
        child: Icon(Icons.arrow_drop_down),
      ),
      selectedTrailingIcon: const Tooltip(
        message: 'Choose the account',
        child: Icon(Icons.arrow_drop_up),
      ),
      onSelected: (id) {
        if (id != null) ref.read(settingsAccountProvider.notifier).select(id);
      },
      dropdownMenuEntries: [
        for (final a in accounts) DropdownMenuEntry(value: a.id, label: a.email),
      ],
    );
    // Not wider than a long address needs, left-aligned in the card.
    return Align(
      alignment: AlignmentDirectional.centerStart,
      child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 480), child: menu),
    );
  }
}
