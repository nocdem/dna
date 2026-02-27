// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService
// v0.100.82+: Engine destroyed on pause, fresh engine created on resume (mobile only)

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';
import 'foreground_service.dart';

/// Android-specific platform handler
///
/// Android differences from Desktop:
/// - ForegroundService takes over when Flutter is backgrounded (has its own minimal engine)
/// - JNI notification helper handles background notifications
/// - v0.100.82+: Engine destroyed on pause, fresh engine created on resume
///   (lifecycle_observer handles destroy/create, this handler does service coordination)
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
  void onPauseComplete() {
    // v0.100.83+: Called AFTER engine dispose (DHT lock released)
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
