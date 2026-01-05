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
    print('[EngineProvider] build() started');

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
      print('[EngineProvider] Getting Android app directory...');
      final appDir = await getApplicationSupportDirectory();
      dataDir = '${appDir.path}/dna_messenger';
      print('[EngineProvider] Android dataDir: $dataDir');
    } else {
      // iOS: use documents directory
      final appDir = await getApplicationDocumentsDirectory();
      dataDir = '${appDir.path}/dna_messenger';
    }

    // Ensure directory exists
    print('[EngineProvider] Creating directory: $dataDir');
    final dir = Directory(dataDir);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    // Copy CA certificate bundle for Android HTTPS (curl needs this)
    if (Platform.isAndroid) {
      print('[EngineProvider] Copying CA cert bundle...');
      await _copyCACertBundle(dataDir);
    }

    print('[EngineProvider] Creating DnaEngine...');
    final engine = await DnaEngine.create(dataDir: dataDir);
    print('[EngineProvider] DnaEngine created successfully');

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
      // ignore: avoid_print
      print('[DNA] Copied cacert.pem to $dataDir (${data.lengthInBytes} bytes)');
    } catch (e) {
      // ignore: avoid_print
      print('[DNA] Failed to copy cacert.pem: $e');
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
