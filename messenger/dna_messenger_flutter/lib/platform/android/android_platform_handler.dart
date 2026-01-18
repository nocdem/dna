// Android Platform Handler - Android-specific behavior
// Phase 14: DHT-only messaging with ForegroundService
// v0.5.24+: Single-owner model - Flutter and Service never share engine

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
    // Tell service to stop DHT operations - Flutter is taking over
    await ForegroundServiceManager.setFlutterActive(true);

    // Reattach event callback (was detached in onPause)
    engine.attachEventCallback();

    // Fetch any messages that arrived while app was backgrounded
    await engine.checkOfflineMessages();
  }

  @override
  void onPause(DnaEngine engine) {
    // Detach callback BEFORE Flutter is destroyed to prevent crash
    // when DHT listener fires after Dart NativeCallable is freed
    engine.detachEventCallback();

    // Tell service it can take over DHT operations
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
