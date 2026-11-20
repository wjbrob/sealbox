import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/core_providers.dart';
import '../../core/models.dart';
import '../../widgets/lock_badge.dart';
import 'fingerprint_qr.dart';
import 'identity_widgets.dart';
import 'qr_scan_page.dart';

/// Phones scan with the camera; desktops paste the payload instead.
bool get scannerAvailable =>
    !kIsWeb &&
    (defaultTargetPlatform == TargetPlatform.android ||
        defaultTargetPlatform == TargetPlatform.iOS);

/// Upper-case hex in groups of four (`ABCD 1234 …`), at most 64 digits.
class FingerprintGroupsFormatter extends TextInputFormatter {
  const FingerprintGroupsFormatter();

  @override
  TextEditingValue formatEditUpdate(TextEditingValue oldValue, TextEditingValue newValue) {
    var hex = newValue.text.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '').toUpperCase();
    if (hex.length > 64) hex = hex.substring(0, 64);
    final text = groupFingerprint(hex);
    return TextEditingValue(
      text: text,
      selection: TextSelection.collapsed(offset: text.length),
    );
  }
}

/// Settings → contact → "Compare fingerprints" (also from the key-changed
/// banner). Shows our QR code, scans or takes theirs, or accepts the
/// fingerprint typed in groups of four, and calls `verify_contact`, which
/// refuses anything but the contact's current key (docs/IDENTITY.md §2).
class VerifyScreen extends ConsumerStatefulWidget {
  const VerifyScreen({super.key, required this.address});

  final String address;

  @override
  ConsumerState<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends ConsumerState<VerifyScreen> {
  final _paste = TextEditingController();
  final _manual = TextEditingController();
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _paste.dispose();
    _manual.dispose();
    super.dispose();
  }

  Future<void> _verify(String fingerprintOrPayload) async {
    final core = ref.read(coreApiProvider);
    final messenger = ScaffoldMessenger.of(context);
    final router = GoRouter.of(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      var fp = fingerprintOrPayload.trim();
      if (fp.toUpperCase().startsWith('OPENPGP4FPR:')) {
        fp = await core.parseFingerprintQr(fp);
      }
      await core.verifyContact(widget.address, fp);
      invalidateIdentity(ref);
      messenger.showSnackBar(SnackBar(content: Text('${widget.address} verified')));
      if (router.canPop()) {
        router.pop();
      } else {
        router.go(contactRoute(widget.address));
      }
    } catch (e) {
      final msg = '$e';
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = msg.contains('mismatch')
            ? 'This is not the key Sealbox has for ${widget.address}. Do not mark them as '
                  'verified: ask them to check the code in their app, and be careful with what '
                  'you send until it matches.'
            : msg.contains('OPENPGP4FPR') || msg.contains('payload') || msg.contains('fingerprint')
            ? 'That is not a fingerprint code. It should start with OPENPGP4FPR: followed by '
                  '40 characters.'
            : 'Could not verify: $msg';
      });
    }
  }

  Future<void> _scan() async {
    final payload = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const QrScanPage()),
    );
    if (payload != null) await _verify(payload);
  }

  Future<void> _unverify() async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ref.read(coreApiProvider).unverifyContact(widget.address);
      invalidateIdentity(ref);
      messenger.showSnackBar(SnackBar(content: Text('Verification removed for ${widget.address}')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not remove: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final contact = ref.watch(contactProvider(widget.address));
    final me = ref.watch(identityProvider).value;
    final myQr = me?.email == null ? null : ref.watch(fingerprintQrProvider(me!.email!));
    final c = contact.value;
    final manualHex = _manual.text.replaceAll(' ', '');

    Widget section(String title, List<Widget> children, {Key? key}) => Card(
      key: key,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            ...children,
          ],
        ),
      ),
    );

    return Scaffold(
      appBar: AppBar(title: Text('Verify ${widget.address}')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 820),
          child: ListView(
            key: const Key('verify-list'),
            padding: const EdgeInsets.all(16),
            children: [
              Text(
                'Compare the fingerprint of the key Sealbox uses for ${widget.address} with '
                'the one their own app shows. Do it in person or on a call you trust, not by '
                'email.',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 12),
              if (c != null && c.keyChangePending) ...[
                ContactIdentityBanner(
                  contact: c,
                  onAccept: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    try {
                      await ref.read(coreApiProvider).acknowledgeKeyChange(widget.address);
                      invalidateIdentity(ref);
                    } catch (e) {
                      messenger.showSnackBar(SnackBar(content: Text('Could not accept the key: $e')));
                    }
                  },
                ),
                const SizedBox(height: 12),
              ],
              section('Their key in Sealbox', [
                if (contact.isLoading)
                  const LinearProgressIndicator()
                else if (c?.fingerprint == null)
                  Text('Sealbox has no key for ${widget.address} yet.')
                else ...[
                  SelectableText(
                    groupFingerprint(c!.fingerprint!),
                    key: const Key('verify-their-fingerprint'),
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontFamily: 'monospace',
                      letterSpacing: 1,
                    ),
                  ),
                  if (c.verified) ...[
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        const VerifiedChip(),
                        const Spacer(),
                        TextButton(
                          key: const Key('verify-unverify'),
                          onPressed: _unverify,
                          child: const Text('Remove verification'),
                        ),
                      ],
                    ),
                  ],
                ],
              ], key: const Key('verify-their-key')),
              const SizedBox(height: 12),
              section('Your code', [
                Wrap(
                  spacing: 16,
                  runSpacing: 12,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    if (myQr?.value != null)
                      FingerprintQr(key: const Key('verify-my-qr'), payload: myQr!.value!)
                    else if (myQr == null)
                      const Text('Add an account first: you have no key yet.')
                    else
                      const SizedBox(
                        width: 184,
                        height: 184,
                        child: Center(child: CircularProgressIndicator()),
                      ),
                    ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 420),
                      child: Text(
                        'Let them scan this with Sealbox, Delta Chat or OpenKeychain. Your '
                        'fingerprint: ${me == null || me.isEmpty ? '–' : me.grouped}',
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                  ],
                ),
              ], key: const Key('verify-your-code')),
              const SizedBox(height: 12),
              section('Check their code', [
                if (scannerAvailable)
                  FilledButton.icon(
                    key: const Key('verify-scan'),
                    onPressed: _busy || c?.fingerprint == null ? null : _scan,
                    icon: const Icon(Icons.qr_code_scanner),
                    label: const Text('Scan their code'),
                  )
                else ...[
                  Text(
                    'No camera scanning on this computer. Ask them for the text of their code '
                    '(in their Settings, under My key: Copy code) and paste it here.',
                    style: theme.textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    key: const Key('verify-paste'),
                    controller: _paste,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'Their code',
                      hintText: 'OPENPGP4FPR:…',
                      border: OutlineInputBorder(),
                    ),
                    onChanged: (_) => setState(() {}),
                    onSubmitted: (v) => _verify(v),
                  ),
                  const SizedBox(height: 8),
                  FilledButton(
                    key: const Key('verify-paste-check'),
                    onPressed: _busy || _paste.text.trim().isEmpty || c?.fingerprint == null
                        ? null
                        : () => _verify(_paste.text),
                    child: const Text('Check'),
                  ),
                ],
              ], key: const Key('verify-check-code')),
              const SizedBox(height: 12),
              section('Or read it out', [
                Text(
                  'They read their fingerprint aloud, four characters at a time; type it here.',
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 8),
                TextField(
                  key: const Key('verify-manual'),
                  controller: _manual,
                  autocorrect: false,
                  enableSuggestions: false,
                  textCapitalization: TextCapitalization.characters,
                  inputFormatters: const [FingerprintGroupsFormatter()],
                  style: const TextStyle(fontFamily: 'monospace', letterSpacing: 1),
                  decoration: InputDecoration(
                    labelText: 'Their fingerprint',
                    hintText: 'ABCD 1234 …',
                    helperText: '${manualHex.length} / 40',
                    border: const OutlineInputBorder(),
                  ),
                  onChanged: (_) => setState(() {}),
                ),
                const SizedBox(height: 8),
                FilledButton(
                  key: const Key('verify-manual-confirm'),
                  onPressed:
                      _busy ||
                          !(manualHex.length == 40 || manualHex.length == 64) ||
                          c?.fingerprint == null
                      ? null
                      : () => _verify(manualHex),
                  child: const Text('Mark as verified'),
                ),
              ], key: const Key('verify-manual-section')),
              if (_error != null) ...[
                const SizedBox(height: 12),
                Container(
                  key: const Key('verify-error'),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: LockColors.ofContext(context).undecryptable.withValues(alpha: 0.10),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    _error!,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: LockColors.ofContext(context).undecryptable,
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
