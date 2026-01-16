// Platform Handler - Abstract interface for platform-specific behavior
// Separates Android-specific code from shared code

import '../ffi/dna_engine.dart';
import '../utils/platform_utils.dart';
import 'android/android_platform_handler.dart';
import 'desktop/desktop_platform_handler.dart';

/// Abstract interface for platform-specific behavior
///
/// Android and Desktop have different requirements for:
/// - Lifecycle handling (callback attach/detach)
/// - Background message fetching
/// - Notification handling
abstract class PlatformHandler {
  /// Singleton instance - returns Android or Desktop handler based on platform
  static PlatformHandler? _instance;

  static PlatformHandler get instance {
    _instance ??= PlatformUtils.isAndroid
        ? AndroidPlatformHandler()
        : DesktopPlatformHandler();
    return _instance!;
  }

  /// Called when app comes to foreground (resumed)
  ///
  /// Android: Re-attach Flutter event callback, fetch offline messages
  /// Desktop: No-op (callback stays attached)
  Future<void> onResume(DnaEngine engine);

  /// Called when app goes to background (paused)
  ///
  /// Android: Detach Flutter event callback (JNI handles background notifications)
  /// Desktop: No-op (callback stays attached)
  void onPause(DnaEngine engine);

  /// Called when outbox has new messages
  ///
  /// Android: Native code already fetched via background_fetch_thread, just sync UI
  /// Desktop: Must call checkOfflineMessages() to fetch
  Future<void> onOutboxUpdated(DnaEngine engine);

  /// Whether this platform supports foreground service
  bool get supportsForegroundService;

  /// Whether this platform supports native notifications
  bool get supportsNativeNotifications;
}
