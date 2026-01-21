// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService
// v0.100.23+: Destroy engine on pause, reinit on resume for clean listener state

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';
import 'foreground_service.dart';

/// Android-specific platform handler
///
/// Android differences from Desktop:
/// - ForegroundService keeps DHT alive when app backgrounded
/// - JNI notification helper handles background notifications
/// - Engine destroyed on pause (listeners canceled), recreated on resume
class AndroidPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResumePreEngine() async {
    // Tell service Flutter is active BEFORE creating engine
    // Service releases its engine (and DHT lock) so Flutter can create new one
    await ForegroundServiceManager.setFlutterActive(true);
  }

  @override
  Future<void> onResume(DnaEngine engine) async {
    // Attach callback (engine is freshly created)
    engine.attachEventCallback();

    // Fetch any messages that arrived while backgrounded
    await engine.checkOfflineMessages();
  }

  @override
  void onPause(DnaEngine engine) {
    // Callback already detached by lifecycle_observer before calling this

    // Tell service to take over (handles notifications while Flutter is paused)
    // Service loads identity in minimal mode (polling only, no listeners)
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
