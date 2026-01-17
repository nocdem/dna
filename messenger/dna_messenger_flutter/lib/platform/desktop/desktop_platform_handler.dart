// Desktop Platform Handler - Linux/Windows/macOS behavior

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';

/// Desktop-specific platform handler (Linux, Windows, macOS)
///
/// Desktop differences from Android:
/// - No ForegroundService needed (app keeps running)
/// - No JNI - Flutter handles all notifications
/// - Event callback stays attached (no JNI fallback)
/// - Flutter must call checkOfflineMessages() to fetch
class DesktopPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Desktop: callback stays attached, nothing to do
  }

  @override
  void onPause(DnaEngine engine) {
    // Desktop: callback stays attached, nothing to do
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine) async {
    // Desktop: Flutter must fetch messages ourselves
    // No JNI background_fetch_thread to do it for us
    await engine.checkOfflineMessages();
  }

  @override
  bool get supportsForegroundService => false;

  @override
  bool get supportsNativeNotifications => false; // TODO: libnotify, Win32 Toast

  @override
  bool get supportsQrScanner => false;
}
