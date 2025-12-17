// Engine Provider - Core DNA Engine state management
import 'dart:async';
import 'dart:io';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import '../ffi/dna_engine.dart';

/// Main engine provider - singleton instance
final engineProvider = AsyncNotifierProvider<EngineNotifier, DnaEngine>(
  EngineNotifier.new,
);

class EngineNotifier extends AsyncNotifier<DnaEngine> {
  @override
  Future<DnaEngine> build() async {
    // Desktop: use ~/.dna for consistency with ImGui app
    // Mobile: use app-specific files directory
    final String dataDir;
    if (Platform.isLinux || Platform.isMacOS || Platform.isWindows) {
      final home = Platform.environment['HOME'] ??
          Platform.environment['USERPROFILE'] ??
          '.';
      dataDir = '$home/.dna';
    } else if (Platform.isAndroid) {
      // Android: use getApplicationSupportDirectory() which maps to filesDir
      // This matches where MainActivity.kt copies cacert.pem for SSL
      final appDir = await getApplicationSupportDirectory();
      dataDir = '${appDir.path}/dna_messenger';
    } else {
      // iOS: use documents directory
      final appDir = await getApplicationDocumentsDirectory();
      dataDir = '${appDir.path}/dna_messenger';
    }

    // Ensure directory exists
    final dir = Directory(dataDir);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    final engine = await DnaEngine.create(dataDir: dataDir);

    ref.onDispose(() {
      engine.dispose();
    });

    return engine;
  }
}

/// Event stream provider
final engineEventsProvider = StreamProvider<DnaEvent>((ref) async* {
  final engine = await ref.watch(engineProvider.future);
  yield* engine.events;
});

/// Current fingerprint (null if no identity loaded) - set explicitly when loadIdentity is called
final currentFingerprintProvider = StateProvider<String?>((ref) => null);

/// Current identity fingerprint (from engine state - may be stale after invalidation)
final currentIdentityProvider = Provider<String?>((ref) {
  final engineAsync = ref.watch(engineProvider);
  return engineAsync.whenOrNull(data: (engine) => engine.fingerprint);
});

/// Identity loaded state - uses currentFingerprintProvider which is set explicitly
/// when loadIdentity is called (avoids relying on engine state which can be invalidated)
final identityLoadedProvider = Provider<bool>((ref) {
  final fingerprint = ref.watch(currentFingerprintProvider);
  return fingerprint != null && fingerprint.isNotEmpty;
});
