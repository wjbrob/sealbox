import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// A scannable QR code of an `OPENPGP4FPR:<hex>` payload (the OpenKeychain /
/// Delta Chat convention, from `Engine::fingerprint_qr_payload`). Always dark
/// modules on white with a quiet zone, also in the dark theme, so phone
/// cameras read it.
class FingerprintQr extends StatelessWidget {
  const FingerprintQr({super.key, required this.payload, this.size = 168});

  final String payload;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'QR code of your key fingerprint',
      image: true,
      child: Container(
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
        ),
        padding: const EdgeInsets.all(8),
        child: QrImageView(
          data: payload,
          version: QrVersions.auto,
          size: size,
          padding: EdgeInsets.zero,
          backgroundColor: Colors.white,
          errorCorrectionLevel: QrErrorCorrectLevel.M,
          eyeStyle: const QrEyeStyle(eyeShape: QrEyeShape.square, color: Colors.black),
          dataModuleStyle: const QrDataModuleStyle(
            dataModuleShape: QrDataModuleShape.square,
            color: Colors.black,
          ),
        ),
      ),
    );
  }
}
