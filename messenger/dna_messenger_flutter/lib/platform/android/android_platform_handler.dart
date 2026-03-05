// Android Platform Handler - Android-specific behavior
// v0.9.7+: No background service or notifications. Engine runs while app is open.

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';

/// Android-specific platform handler
///
/// v0.9.7+: No background service. Engine runs while app is open,
/// destroyed when app closes (same as desktop).
class AndroidPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Attach Dart event callback
    engine.attachEventCallback();

    // Fetch any messages that arrived while backgrounded
    await engine.checkOfflineMessages();
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine, Set<String> contactFingerprints) async {
    for (final fp in contactFingerprints) {
      await engine.checkOfflineMessagesFrom(fp);
    }
  }

  @override
  bool get supportsCamera => true;
}
