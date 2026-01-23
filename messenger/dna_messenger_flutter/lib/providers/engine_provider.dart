// Engine Provider - Core DNA Engine state management
import 'dart:async';
import 'dart:io';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import '../ffi/dna_engine.dart';
import '../utils/logger.dart';

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
    if (Platform.isLinux || Platform.isMacOS) {
      final home = Platform.environment['HOME'] ?? '.';
      dataDir = '$home/.dna';
    } else if (Platform.isWindows) {
      // Windows: use USERPROFILE with backslashes
      final home = Platform.environment['USERPROFILE'] ?? 'C:\\Users';
      dataDir = '$home\\.dna';
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

    // Copy CA certificate bundle for Android HTTPS (curl needs this)
    if (Platform.isAndroid) {
      await _copyCACertBundle(dataDir);
    }

    final engine = await DnaEngine.create(dataDir: dataDir);

    // Initialize logger with engine for Flutter -> dna.log logging
    logSetEngine(engine);

    ref.onDispose(() {
      engine.dispose();
    });

    return engine;
  }

  /// Copy CA certificate bundle from Flutter assets to data directory
  Future<void> _copyCACertBundle(String dataDir) async {
    final destFile = File('$dataDir/cacert.pem');

    // Check if already exists and up-to-date
    if (await destFile.exists()) {
      final size = await destFile.length();
      if (size > 200000) {
        // Already copied (cacert.pem is ~225KB)
        return;
      }
    }

    try {
      // Load from Flutter assets
      final data = await rootBundle.load('assets/cacert.pem');
      await destFile.writeAsBytes(data.buffer.asUint8List());
    } catch (_) {
      // Silently ignore CA cert copy failures
    }
  }
}

/// Event stream provider
final engineEventsProvider = StreamProvider<DnaEvent>((ref) async* {
  final engine = await ref.watch(engineProvider.future);
  yield* engine.events;
});

/// Current fingerprint (null if no identity loaded) - set explicitly when loadIdentity is called
final currentFingerprintProvider = StateProvider<String?>((ref) => null);

/// Identity ready flag - set true AFTER loadIdentity() completes (DHT ready, contacts synced)
/// Data providers should watch this, not currentFingerprintProvider
final identityReadyProvider = StateProvider<bool>((ref) => false);

/// Current identity fingerprint (from engine state - may be stale after invalidation)
final currentIdentityProvider = Provider<String?>((ref) {
  final engineAsync = ref.watch(engineProvider);
  return engineAsync.whenOrNull(data: (engine) => engine.fingerprint);
});

/// Identity loaded state - true when identity is ready for data operations
/// Uses identityReadyProvider which is set AFTER loadIdentity() completes
final identityLoadedProvider = Provider<bool>((ref) {
  return ref.watch(identityReadyProvider);
});
