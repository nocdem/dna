// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService
// v0.6.8+: Flutter keeps engine during pause, service is backup for when Flutter dies

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';
import 'foreground_service.dart';

/// Android-specific platform handler
///
/// Android differences from Desktop:
/// - ForegroundService keeps DHT alive when app backgrounded
/// - JNI notification helper handles background notifications
/// - Single-owner model: Flutter owns engine when open, Service owns when closed
class AndroidPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Tell service Flutter is active (service releases engine if it took over)
    await ForegroundServiceManager.setFlutterActive(true);

    // v0.6.8+: Callback stays attached during pause, no need to re-attach
    // Just fetch any messages that might have arrived
    await engine.checkOfflineMessages();
  }

  @override
  void onPause(DnaEngine engine) {
    // v0.6.8+: Keep callback attached - Flutter handles notifications during pause
    // Dart VM stays active, so callbacks still fire and show notifications.
    // No need to detach callback or destroy engine on every app switch!

    // Tell service Flutter is pausing (service is backup if Flutter dies)
    // Service auto-takeover will detect if Flutter truly dies
    ForegroundServiceManager.setFlutterActive(false);
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
