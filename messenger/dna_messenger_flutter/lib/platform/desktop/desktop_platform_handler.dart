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
  Future<void> onResumePreEngine() async {
    // Desktop: no service to notify, nothing to do
  }

  @override
  Future<void> onResume(DnaEngine engine) async {
    // Desktop: callback stays attached, nothing to do
  }

  @override
  void onPause(DnaEngine engine) {
    // Desktop: callback stays attached, nothing to do
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine, Set<String> contactFingerprints) async {
    // Fetch messages only from contacts whose outboxes triggered the event.
    // Much faster than checkOfflineMessages() which checks ALL contacts.
    for (final fp in contactFingerprints) {
      await engine.checkOfflineMessagesFrom(fp);
    }
  }

  @override
  bool get supportsForegroundService => false;

  @override
  bool get supportsNativeNotifications => false; // TODO: libnotify, Win32 Toast

  @override
  bool get supportsCamera => false;
}
