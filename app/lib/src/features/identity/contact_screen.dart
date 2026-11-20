import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../compose/recipient_pill.dart' show keySourceLabel;
import '../inbox/inbox_list_pane.dart' show fullTime;
import 'identity_widgets.dart';

/// Settings → Contacts & keys → one contact: the identity banner (key
/// changed / verified / not verified), the current and previous key, and the
/// verify / accept / remove-verification actions.
class ContactScreen extends ConsumerWidget {
  const ContactScreen({super.key, required this.address});

  final String address;

  Future<void> _accept(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ref.read(coreApiProvider).acknowledgeKeyChange(address);
      invalidateIdentity(ref);
      messenger.showSnackBar(SnackBar(content: Text('New key for $address accepted')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not accept the key: $e')));
    }
  }

  Future<void> _unverify(BuildContext context, WidgetRef ref) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ref.read(coreApiProvider).unverifyContact(address);
      invalidateIdentity(ref);
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not remove: $e')));
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final contact = ref.watch(contactProvider(address));
    return Scaffold(
      appBar: AppBar(title: Text(address)),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 820),
          child: contact.when(
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, _) => Center(child: Text('Could not load the contact: $e')),
            data: (c) => c == null
                ? Center(child: Text('Sealbox holds no key for $address.'))
                : ListView(
                    key: const Key('contact-detail'),
                    padding: const EdgeInsets.all(16),
                    children: [
                      ContactIdentityBanner(contact: c, onAccept: () => _accept(context, ref)),
                      const SizedBox(height: 16),
                      Card(
                        child: Column(
                          children: [
                            ListTile(
                              leading: const Icon(Icons.key),
                              title: const Text('Current key'),
                              subtitle: SelectableText(
                                c.fingerprint == null ? 'none' : groupFingerprint(c.fingerprint!),
                                key: const Key('contact-fingerprint'),
                                style: const TextStyle(fontFamily: 'monospace'),
                              ),
                            ),
                            ListTile(
                              leading: const Icon(Icons.source_outlined),
                              title: const Text('Learned from'),
                              subtitle: Text(
                                '${keySourceLabel(c.source)}'
                                '${c.lastSeen == null ? '' : ' · last mail ${fullTime(c.lastSeen!)}'}',
                              ),
                            ),
                            if (distinctPrevious(c) != null)
                              ListTile(
                                leading: const Icon(Icons.history),
                                title: const Text('Previous key'),
                                subtitle: SelectableText(
                                  groupFingerprint(distinctPrevious(c)!),
                                  style: const TextStyle(fontFamily: 'monospace'),
                                ),
                              ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          if (!c.keyChangePending && c.fingerprint != null)
                            FilledButton.icon(
                              key: const Key('contact-verify'),
                              onPressed: () => context.push(verifyRoute(c.address)),
                              icon: const Icon(Icons.qr_code_scanner),
                              label: Text(c.verified ? 'Compare again' : 'Verify'),
                            ),
                          if (c.verified)
                            OutlinedButton(
                              key: const Key('contact-unverify'),
                              onPressed: () => _unverify(context, ref),
                              child: const Text('Remove verification'),
                            ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Verification is local to this device and never sent anywhere.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
          ),
        ),
      ),
    );
  }
}
