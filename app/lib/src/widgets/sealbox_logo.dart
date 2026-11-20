import 'package:flutter/material.dart';

/// The app icon (packaging/linux/sealbox.svg: an envelope sealed with a
/// padlock) drawn natively, so the hero, the rail wordmark and the lock screen
/// use the real brand mark without an SVG dependency. Same fill-only shapes and
/// colours as the SVG, on its 256×256 grid.
class SealboxLogo extends StatelessWidget {
  const SealboxLogo({super.key, this.size = 56, this.semanticLabel = 'Sealbox'});

  final double size;
  final String? semanticLabel;

  @override
  Widget build(BuildContext context) => Semantics(
    label: semanticLabel,
    image: true,
    child: SizedBox.square(
      dimension: size,
      child: const CustomPaint(painter: _LogoPainter()),
    ),
  );
}

class _LogoPainter extends CustomPainter {
  const _LogoPainter();

  static const _teal = Color(0xFF0E7C6B);
  static const _paper = Color(0xFFF4FBF9);
  static const _flapDark = Color(0xFF0B5F52);
  static const _flapLight = Color(0xFFCDE8E2);
  static const _ink = Color(0xFF1F2A2E);
  static const _gold = Color(0xFFF2B134);

  @override
  void paint(Canvas canvas, Size size) {
    canvas.scale(size.width / 256, size.height / 256);
    final p = Paint()..isAntiAlias = true;
    void rrect(double x, double y, double w, double h, double r, Color c) {
      canvas.drawRRect(
        RRect.fromRectAndRadius(Rect.fromLTWH(x, y, w, h), Radius.circular(r)),
        p..color = c,
      );
    }

    void tri(List<Offset> pts, Color c) {
      canvas.drawPath(Path()..addPolygon(pts, true), p..color = c);
    }

    rrect(8, 8, 240, 240, 52, _teal);
    rrect(40, 76, 176, 116, 14, _paper);
    tri(const [Offset(40, 90), Offset(216, 90), Offset(128, 156)], _flapDark);
    tri(const [Offset(52, 90), Offset(204, 90), Offset(128, 142)], _flapLight);
    rrect(96, 108, 64, 60, 32, _ink);
    rrect(108, 120, 40, 40, 20, _paper);
    rrect(84, 146, 88, 66, 12, _ink);
    rrect(90, 152, 76, 54, 9, _gold);
    canvas.drawCircle(const Offset(128, 174), 8, p..color = _ink);
    rrect(124, 178, 8, 16, 3, _ink);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
