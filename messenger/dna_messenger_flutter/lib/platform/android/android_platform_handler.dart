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
  Future<void> onOutboxUpdated(DnaEngine engine, Set<String> contactFingerprints) async {
    // Fetch messages only from contacts whose outboxes triggered the event.
    // Much faster than checkOfflineMessages() which checks ALL contacts.
    for (final fp in contactFingerprints) {
      await engine.checkOfflineMessagesFrom(fp);
    }
  }

  @override
  bool get supportsForegroundService => true;

  @override
  bool get supportsNativeNotifications => true;

  @override
  bool get supportsCamera => true;
}
