// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService
// v0.6.9+: Keep engine alive during pause, but detach callback to prevent crash on swipe-away

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';
import 'foreground_service.dart';

/// Android-specific platform handler
///
/// Android differences from Desktop:
/// - ForegroundService keeps DHT alive when app backgrounded
/// - JNI notification helper handles background notifications
/// - Engine stays alive during pause (faster resume), but callback detached
class AndroidPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Tell service Flutter is active (service releases engine if it took over)
    await ForegroundServiceManager.setFlutterActive(true);

    // Re-attach callback (was detached in onPause to prevent crash on swipe-away)
    engine.attachEventCallback();

    // Fetch any messages that arrived while backgrounded
    await engine.checkOfflineMessages();
  }

  @override
  void onPause(DnaEngine engine) {
    // Detach callback BEFORE app might be killed (swipe-away)
    // Prevents SIGABRT when C code calls freed Dart NativeCallable
    engine.detachEventCallback();

    // Tell service to take over (handles notifications while Flutter is paused)
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
