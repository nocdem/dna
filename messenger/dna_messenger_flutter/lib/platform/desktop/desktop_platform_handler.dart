// Desktop Platform Handler - Linux/Windows/macOS behavior

import '../../ffi/dna_engine.dart';
import '../platform_handler.dart';

/// Desktop-specific platform handler (Linux, Windows, macOS)
///
/// Desktop differences from Android:
/// - No lifecycle pause/resume (app keeps running)
/// - Event callback stays attached
/// - Flutter must call checkOfflineMessages() to fetch
class DesktopPlatformHandler implements PlatformHandler {
  @override
  Future<void> onResume(DnaEngine engine) async {
    // Desktop: callback stays attached, nothing to do
  }

  @override
  Future<void> onOutboxUpdated(DnaEngine engine, Set<String> contactFingerprints) async {
    for (final fp in contactFingerprints) {
      await engine.checkOfflineMessagesFrom(fp);
    }
  }

  @override
  bool get supportsCamera => false;
}
