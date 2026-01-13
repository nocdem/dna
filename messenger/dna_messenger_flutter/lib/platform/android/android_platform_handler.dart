// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';

/// Android-specific platform handler
///
/// Android differences from Desktop:
/// - ForegroundService keeps DHT alive when app backgrounded
/// - JNI notification helper handles background notifications
/// - Event callback must be detached when backgrounded (JNI takes over)
/// - Native code fetches messages via background_fetch_thread
class AndroidPlatformHandler implements PlatformHandler {
  @override
  void onResume(DnaEngine engine) {
    // Re-attach Flutter event callback
    // Was detached on pause so JNI could handle background notifications
    engine.attachEventCallback();
  }

  @override
  void onPause(DnaEngine engine) {
    // Detach Flutter event callback
    // JNI notification helper handles background notifications directly
    // via native Android NotificationManager
    engine.detachEventCallback();
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine) async {
    // On Android, native code already fetched messages via background_fetch_thread
    // JNI notification helper shows notifications directly
    // Flutter just needs to sync UI state - no need to call checkOfflineMessages()
  }

  @override
  bool get supportsForegroundService => true;

  @override
  bool get supportsNativeNotifications => true;
}
