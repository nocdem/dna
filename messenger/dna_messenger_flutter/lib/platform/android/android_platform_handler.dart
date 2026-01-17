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
  Future<void> onResume(DnaEngine engine) async {
    // Re-attach Flutter event callback
    // Was detached on pause so JNI could handle background notifications
    engine.attachEventCallback();

    // Fetch any messages that arrived while app was backgrounded
    // Notifications were shown but messages not fetched (to avoid race condition)
    await engine.checkOfflineMessages();
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
    // Flutter handles message fetching on all platforms (unified behavior).
    // C auto-fetch only runs when Flutter is detached (app backgrounded/killed).
    // This avoids race conditions between C and Flutter both trying to fetch.
    await engine.checkOfflineMessages();
  }

  @override
  bool get supportsForegroundService => true;

  @override
  bool get supportsNativeNotifications => true;

  @override
  bool get supportsQrScanner => true;
}
