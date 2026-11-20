import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Full-screen camera scanner (Android / iOS only). Pops with the first QR
/// payload that starts with `OPENPGP4FPR:`; other codes are ignored with a
/// hint. Camera permission is requested by `mobile_scanner` on first use
/// (strings in AndroidManifest.xml / Info.plist).
class QrScanPage extends StatefulWidget {
  const QrScanPage({super.key});

  @override
  State<QrScanPage> createState() => _QrScanPageState();
}

class _QrScanPageState extends State<QrScanPage> {
  final _controller = MobileScannerController(formats: const [BarcodeFormat.qrCode]);
  bool _done = false;
  String? _hint;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_done) return;
    for (final b in capture.barcodes) {
      final v = b.rawValue;
      if (v == null) continue;
      if (v.trim().toUpperCase().startsWith('OPENPGP4FPR:')) {
        _done = true;
        Navigator.of(context).pop(v.trim());
        return;
      }
      setState(() => _hint = 'That QR code is not a Sealbox / OpenPGP fingerprint code.');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan their code')),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  error.errorCode == MobileScannerErrorCode.permissionDenied
                      ? 'Sealbox needs the camera to scan the code. Allow camera access in the '
                            'system settings, or type the fingerprint instead.'
                      : 'The camera could not start (${error.errorCode.name}). Type the '
                            'fingerprint instead.',
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ),
          Align(
            alignment: Alignment.bottomCenter,
            child: Container(
              width: double.infinity,
              color: Colors.black54,
              padding: const EdgeInsets.all(16),
              child: Text(
                _hint ?? 'Point the camera at the QR code in their Sealbox (Settings, My key).',
                style: const TextStyle(color: Colors.white),
                textAlign: TextAlign.center,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
