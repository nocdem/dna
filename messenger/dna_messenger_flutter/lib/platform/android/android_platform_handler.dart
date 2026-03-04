// Android Platform Handler - Android-specific behavior
// v0.101.25+: Engine stays alive in background (pause/resume pattern)
// ForegroundService is just a process keep-alive — no engine management

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';
import 'foreground_service.dart';

/// Android-specific platform handler
///
/// v0.101.25+: Engine stays alive when backgrounded (pause/resume).
/// ForegroundService keeps the process alive but does NOT manage its own engine.
/// Background notifications come via JNI callback (g_android_notification_cb).
class AndroidPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Clear background notifications when user opens the app
    await ForegroundServiceManager.clearNotifications();

    // Attach Dart event callback (replaces JNI notification routing)
    engine.attachEventCallback();

    // Fetch any messages that arrived between pause and listener re-registration
    await engine.checkOfflineMessages();
  }

  @override
  void onPauseComplete() {
    // Signal service that Flutter is paused (for notification clearing logic only)
    ForegroundServiceManager.setFlutterPaused(true);
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine, Set<String> contactFingerprints) async {
    // Fetch messages only from contacts whose outboxes triggered the event.
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
