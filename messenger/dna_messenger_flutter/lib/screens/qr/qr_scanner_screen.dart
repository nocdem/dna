/// QR Scanner Screen - Camera-based QR code scanning
/// Handles lifecycle properly: stops camera when not visible (tab switch, route push, app pause)
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../../main.dart' show routeObserver;
import '../../theme/dna_theme.dart';
import '../../utils/qr_payload_parser.dart';
import '../home_screen.dart' show currentTabProvider;
import 'qr_auth_screen.dart';
import 'qr_result_screen.dart';

/// QR Scanner tab index in the home screen IndexedStack
const _kQrScannerTabIndex = 3;

class QrScannerScreen extends ConsumerStatefulWidget {
  final VoidCallback? onMenuPressed;

  const QrScannerScreen({super.key, this.onMenuPressed});

  @override
  ConsumerState<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends ConsumerState<QrScannerScreen>
    with RouteAware, WidgetsBindingObserver {
  MobileScannerController? _controller;
  bool _torchOn = false;
  String? _errorMessage;
  DateTime? _lastScanAt;

  // Visibility and scanning state
  bool _isTabActive = false;
  bool _isRouteCovered = false;
  bool _isAppPaused = false;
  bool _scannerArmed = true; // false after scan, requires manual re-arm
  bool _controllerStarted = false;
  bool _isNavigating = false; // guard against concurrent scan handling
  bool _isStarting = false; // guard against concurrent start() calls

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initController();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Subscribe to route observer
    final route = ModalRoute.of(context);
    if (route != null) {
      routeObserver.subscribe(this, route);
    }
  }

  @override
  void dispose() {
    routeObserver.unsubscribe(this);
    WidgetsBinding.instance.removeObserver(this);
    // Stop scanner synchronously before dispose (can't await in dispose)
    if (_controllerStarted && _controller != null) {
      _controller!.stop();
      _controllerStarted = false;
    }
    _controller?.dispose();
    super.dispose();
  }

  void _initController() {
    _controller = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
      torchEnabled: false,
    );
    _controllerStarted = false;
    _isStarting = false;
  }

  /// Compute whether scanner should be running
  bool get _shouldScannerRun {
    return _isTabActive && !_isRouteCovered && !_isAppPaused;
  }

  /// Update scanner state based on visibility
  void _updateScannerState() {
    if (_shouldScannerRun) {
      _startScanner();
    } else {
      _stopScanner();
    }
  }

  Future<void> _startScanner() async {
    // Guard against concurrent start calls (race condition fix)
    if (_controllerStarted || _isStarting) return;
    if (_controller == null) return;

    _isStarting = true;
    try {
      await _controller!.start();
      _controllerStarted = true;
    } catch (e) {
      // Camera start failed, ignore (errorBuilder will handle it)
    } finally {
      _isStarting = false;
    }
  }

  Future<void> _stopScanner() async {
    // Wait for any in-progress start to complete first
    while (_isStarting) {
      await Future.delayed(const Duration(milliseconds: 10));
    }
    if (!_controllerStarted) return;
    if (_controller == null) return;

    try {
      await _controller!.stop();
      _controllerStarted = false;
    } catch (e) {
      // Ignore stop errors
    }
  }

  // ==========================================================================
  // RouteAware - detect when covered by another route
  // ==========================================================================

  @override
  void didPushNext() {
    // Another route was pushed on top - stop camera
    _isRouteCovered = true;
    _updateScannerState();
  }

  @override
  void didPopNext() {
    // Returned to this route - but don't auto-start, require re-arm
    _isRouteCovered = false;
    // Scanner stays disarmed until user taps to re-arm
    _updateScannerState();
  }

  // ==========================================================================
  // WidgetsBindingObserver - app lifecycle
  // ==========================================================================

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
      case AppLifecycleState.hidden:
        _isAppPaused = true;
        _updateScannerState();
        break;
      case AppLifecycleState.resumed:
        _isAppPaused = false;
        _updateScannerState();
        break;
    }
  }

  // ==========================================================================
  // Tab switching detection (for IndexedStack)
  // ==========================================================================

  void _onTabChanged(int? previous, int current) {
    final wasActive = _isTabActive;
    _isTabActive = (current == _kQrScannerTabIndex);

    if (wasActive != _isTabActive) {
      _updateScannerState();
    }
  }

  // ==========================================================================
  // Scanning logic
  // ==========================================================================

  void _onDetect(BarcodeCapture capture) {
    // Don't process if scanner is not armed, not running, or already navigating
    if (!_scannerArmed) return;
    if (!_shouldScannerRun) return;
    if (_isNavigating) return;

    // Throttle: ignore detections if last scan was < 700ms ago
    final now = DateTime.now();
    if (_lastScanAt != null &&
        now.difference(_lastScanAt!).inMilliseconds < 700) {
      return;
    }

    final barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    // Pick the first barcode with non-null, non-empty rawValue
    String? value;
    for (final barcode in barcodes) {
      final raw = barcode.rawValue?.trim();
      if (raw != null && raw.isNotEmpty) {
        value = raw;
        break;
      }
    }
    if (value == null) return;

    // Set navigation guard FIRST to prevent re-entry
    _isNavigating = true;
    _lastScanAt = now;
    _scannerArmed = false;

    // Stop scanner and navigate (async but we don't block UI)
    _handleScanResult(value);
  }

  /// Handle scan result asynchronously - stops scanner before navigating
  Future<void> _handleScanResult(String value) async {
    // Stop scanner BEFORE navigation to prevent "already started" error on return
    await _stopScanner();

    if (!mounted) return;
    setState(() {});

    // Parse the QR payload
    final payload = parseQrPayload(value);

    // Haptic feedback on successful scan
    HapticFeedback.mediumImpact();

    // Navigate based on payload type on ROOT navigator (scanner is in IndexedStack, not a route)
    // Auth payloads go directly to QrAuthScreen (no intermediate route that can re-push)
    // Other payloads go to QrResultScreen
    final rootNav = Navigator.of(context, rootNavigator: true);
    if (payload.type == QrPayloadType.auth) {
      debugPrint('QR_SCANNER: auth payload, navigating directly to QrAuthScreen');
      rootNav.push(
        MaterialPageRoute(
          builder: (context) => QrAuthScreen(payload: payload),
        ),
      );
    } else {
      debugPrint('QR_SCANNER: ${payload.type} payload, navigating to QrResultScreen');
      rootNav.push(
        MaterialPageRoute(
          builder: (context) => QrResultScreen(payload: payload),
        ),
      );
    }
    // Note: Scanner stays disarmed. User must tap "Tap to scan" overlay to re-arm.
    // _isNavigating stays true until re-arm
  }

  /// Re-arm the scanner (called when user taps the overlay)
  void _rearmScanner() {
    setState(() {
      _scannerArmed = true;
      _isNavigating = false;
    });
    _updateScannerState();
  }

  void _toggleTorch() async {
    try {
      await _controller?.toggleTorch();
      setState(() => _torchOn = !_torchOn);
    } catch (e) {
      // Torch toggle failed, don't update state
    }
  }

  void _switchCamera() async {
    await _controller?.switchCamera();
  }

  @override
  Widget build(BuildContext context) {
    // Watch tab changes to detect when we become visible/hidden
    ref.listen<int>(currentTabProvider, _onTabChanged);

    // Also check current tab state on build (but don't trigger scanner update here -
    // that's handled by _onTabChanged listener to avoid redundant calls)
    final currentTab = ref.watch(currentTabProvider);
    final wasActive = _isTabActive;
    _isTabActive = (currentTab == _kQrScannerTabIndex);

    // Only update scanner on INITIAL build when tab is active (not on every rebuild)
    if (_isTabActive && !wasActive && !_controllerStarted && !_isStarting) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          _updateScannerState();
        }
      });
    }

    // Intercept Android back button: close scanner and return to Chats tab
    // instead of backgrounding the app. Also ensures camera is stopped cleanly.
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, result) async {
        if (didPop) return;
        await _stopScanner();
        if (mounted) {
          ref.read(currentTabProvider.notifier).state = 0; // Switch to Chats
        }
      },
      child: Scaffold(
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
      ),
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
        // "Tap to scan" overlay when disarmed (prevents jam loop)
        if (!_scannerArmed)
          Positioned.fill(
            child: GestureDetector(
              onTap: _rearmScanner,
              child: Container(
                color: Colors.black54,
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const FaIcon(
                        FontAwesomeIcons.qrcode,
                        size: 64,
                        color: Colors.white70,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'Tap to scan again',
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                              color: Colors.white,
                            ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Move the QR code away first',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                              color: Colors.white70,
                            ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
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
              onPressed: () async {
                // Stop scanner before dispose to prevent "already started" error
                if (_controllerStarted && _controller != null) {
                  await _controller!.stop();
                  _controllerStarted = false;
                }
                _controller?.dispose();
                _initController();
                _isNavigating = false;
                _scannerArmed = true;
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
              onPressed: () async {
                // Stop scanner before reinit to prevent "already started" error
                if (_controllerStarted && _controller != null) {
                  await _controller!.stop();
                  _controllerStarted = false;
                }
                _controller?.dispose();
                setState(() {
                  _errorMessage = null;
                });
                _initController();
                _isNavigating = false;
                _scannerArmed = true;
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
    // Clamp top to at least 24.0 so it never goes negative on small screens
    final rawTop = (size.height - scanAreaSize) / 2 - 40;
    final top = rawTop < 24.0 ? 24.0 : rawTop;

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
