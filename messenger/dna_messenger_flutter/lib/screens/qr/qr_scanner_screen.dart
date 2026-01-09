/// QR Scanner Screen - Camera-based QR code scanning
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../../theme/dna_theme.dart';
import '../../utils/qr_payload_parser.dart';
import 'qr_result_screen.dart';

class QrScannerScreen extends ConsumerStatefulWidget {
  final VoidCallback? onMenuPressed;

  const QrScannerScreen({super.key, this.onMenuPressed});

  @override
  ConsumerState<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends ConsumerState<QrScannerScreen> {
  MobileScannerController? _controller;
  bool _hasScanned = false;
  bool _torchOn = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _initController();
  }

  void _initController() {
    _controller = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
      torchEnabled: false,
    );
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned) return;

    final barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    final barcode = barcodes.first;
    final value = barcode.rawValue;
    if (value == null || value.isEmpty) return;

    setState(() => _hasScanned = true);

    // Parse the QR payload
    final payload = parseQrPayload(value);

    // Navigate to result screen
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => QrResultScreen(payload: payload),
      ),
    ).then((_) {
      // Reset scan state when returning
      if (mounted) {
        setState(() => _hasScanned = false);
      }
    });
  }

  void _toggleTorch() async {
    await _controller?.toggleTorch();
    setState(() => _torchOn = !_torchOn);
  }

  void _switchCamera() async {
    await _controller?.switchCamera();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: widget.onMenuPressed != null
            ? IconButton(
                icon: const FaIcon(FontAwesomeIcons.bars),
                onPressed: widget.onMenuPressed,
              )
            : null,
        title: const Text('Scan QR'),
        actions: [
          IconButton(
            icon: FaIcon(_torchOn ? FontAwesomeIcons.lightbulb : FontAwesomeIcons.solidLightbulb),
            onPressed: _toggleTorch,
            tooltip: 'Toggle Flash',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.cameraRotate),
            onPressed: _switchCamera,
            tooltip: 'Switch Camera',
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_errorMessage != null) {
      return _buildErrorState();
    }

    return Stack(
      children: [
        // Camera preview
        MobileScanner(
          controller: _controller,
          onDetect: _onDetect,
          errorBuilder: (context, error, child) {
            return _buildCameraError(error);
          },
        ),
        // Scanning overlay
        _buildScanOverlay(),
        // Instructions
        Positioned(
          bottom: 80,
          left: 0,
          right: 0,
          child: _buildInstructions(),
        ),
      ],
    );
  }

  Widget _buildScanOverlay() {
    return CustomPaint(
      painter: _ScanOverlayPainter(
        borderColor: DnaColors.primary,
        overlayColor: Colors.black54,
      ),
      child: const SizedBox.expand(),
    );
  }

  Widget _buildInstructions() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 32),
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      decoration: BoxDecoration(
        color: DnaColors.surface.withAlpha(230),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            'Point camera at a QR code',
            style: Theme.of(context).textTheme.titleMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),
          Text(
            'Supports contact sharing, authorization requests, and plain text',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: DnaColors.textMuted,
                ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildCameraError(MobileScannerException error) {
    String message;
    IconData icon;

    switch (error.errorCode) {
      case MobileScannerErrorCode.permissionDenied:
        message = 'Camera permission denied.\nPlease enable camera access in Settings.';
        icon = FontAwesomeIcons.lock;
        break;
      case MobileScannerErrorCode.unsupported:
        message = 'Camera not supported on this device.';
        icon = Icons.no_photography;
        // icon = FontAwesomeIcons.cameraSlash; //don't use this as linux does not have camera
        break;
      default:
        message = 'Camera error: ${error.errorDetails?.message ?? 'Unknown error'}';
        icon = FontAwesomeIcons.circleExclamation;
    }

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(icon, size: 64, color: DnaColors.textWarning),
            const SizedBox(height: 24),
            Text(
              message,
              style: Theme.of(context).textTheme.titleMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: () {
                _controller?.dispose();
                _initController();
                setState(() {});
              },
              icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 16),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const FaIcon(FontAwesomeIcons.circleExclamation, size: 64, color: DnaColors.textWarning),
            const SizedBox(height: 24),
            Text(
              _errorMessage!,
              style: Theme.of(context).textTheme.titleMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: () {
                setState(() {
                  _errorMessage = null;
                });
                _initController();
              },
              icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 16),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

/// Custom painter for scan overlay with cutout
class _ScanOverlayPainter extends CustomPainter {
  final Color borderColor;
  final Color overlayColor;

  _ScanOverlayPainter({
    required this.borderColor,
    required this.overlayColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final scanAreaSize = size.width * 0.7;
    final left = (size.width - scanAreaSize) / 2;
    final top = (size.height - scanAreaSize) / 2 - 40;

    final scanRect = RRect.fromRectAndRadius(
      Rect.fromLTWH(left, top, scanAreaSize, scanAreaSize),
      const Radius.circular(16),
    );

    // Draw overlay with cutout
    final path = Path()
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height))
      ..addRRect(scanRect)
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(path, Paint()..color = overlayColor);

    // Draw border corners
    final borderPaint = Paint()
      ..color = borderColor
      ..strokeWidth = 4
      ..style = PaintingStyle.stroke;

    final cornerLength = 30.0;
    final rect = scanRect.outerRect;

    // Top-left corner
    canvas.drawLine(
      Offset(rect.left, rect.top + cornerLength),
      Offset(rect.left, rect.top + 8),
      borderPaint,
    );
    canvas.drawLine(
      Offset(rect.left, rect.top),
      Offset(rect.left + cornerLength, rect.top),
      borderPaint,
    );

    // Top-right corner
    canvas.drawLine(
      Offset(rect.right - cornerLength, rect.top),
      Offset(rect.right, rect.top),
      borderPaint,
    );
    canvas.drawLine(
      Offset(rect.right, rect.top),
      Offset(rect.right, rect.top + cornerLength),
      borderPaint,
    );

    // Bottom-left corner
    canvas.drawLine(
      Offset(rect.left, rect.bottom - cornerLength),
      Offset(rect.left, rect.bottom),
      borderPaint,
    );
    canvas.drawLine(
      Offset(rect.left, rect.bottom),
      Offset(rect.left + cornerLength, rect.bottom),
      borderPaint,
    );

    // Bottom-right corner
    canvas.drawLine(
      Offset(rect.right - cornerLength, rect.bottom),
      Offset(rect.right, rect.bottom),
      borderPaint,
    );
    canvas.drawLine(
      Offset(rect.right, rect.bottom - cornerLength),
      Offset(rect.right, rect.bottom),
      borderPaint,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
