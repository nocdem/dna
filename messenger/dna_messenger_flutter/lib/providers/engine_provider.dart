// Engine Provider - Core DNA Engine state management
import 'dart:async';
import 'dart:io';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import '../ffi/dna_engine.dart';
import '../services/media_cache_service.dart';
import '../services/media_outbox_service.dart';
import '../utils/logger.dart';

/// Main engine provider - singleton instance
final engineProvider = AsyncNotifierProvider<EngineNotifier, DnaEngine>(
  EngineNotifier.new,
);

class EngineNotifier extends AsyncNotifier<DnaEngine> {
  /// Cached engine instance that survives Android Activity recreation.
  /// When Android destroys and recreates the Activity without killing the process,
  /// the old C engine still holds the identity file lock (flock per-fd).
  /// Creating a new engine would fail to acquire the lock → identity load fails
  /// → user sees "Create Account" screen instead of their chats.
  static DnaEngine? _cachedEngine;

  @override
  Future<DnaEngine> build() async {
    // Android: reuse existing engine across Activity recreations.
    // The C engine and its flock are per-process, not per-Activity.
    if (Platform.isAndroid && _cachedEngine != null && !_cachedEngine!.isDisposed) {
      final engine = _cachedEngine!;
      logSetEngine(engine);
      engine.debugLog('STARTUP', 'Reusing cached engine (Activity recreation)');
      // Do NOT register onDispose — engine outlives the ProviderScope
      return engine;
    }

    // Desktop: use ~/.dna as the standard data directory
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
      dataDir = '${appDir.path}/dna';
      // Migrate from old directory name if it exists
      final oldDir = Directory('${appDir.path}/dna_messenger');
      final newDir = Directory(dataDir);
      if (await oldDir.exists() && !await newDir.exists()) {
        await oldDir.rename(dataDir);
      }
    } else {
      // iOS: use documents directory
      final appDir = await getApplicationDocumentsDirectory();
      dataDir = '${appDir.path}/dna';
      // Migrate from old directory name if it exists
      final oldDir = Directory('${appDir.path}/dna_messenger');
      final newDir = Directory(dataDir);
      if (await oldDir.exists() && !await newDir.exists()) {
        await oldDir.rename(dataDir);
      }
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

    // Initialize media disk cache (must be ready before messages load)
    await MediaCacheService.getInstance();

    // Resume any pending media uploads from previous session
    MediaOutboxService.instance.processPendingUploads(engine);

    // Log version info at startup (Lib from C library, App from pubspec.yaml)
    final packageInfo = await PackageInfo.fromPlatform();
    engine.debugLog('STARTUP', 'Lib v${engine.version} | App v${packageInfo.version}');

    if (Platform.isAndroid) {
      // Cache for Activity recreation. Do NOT dispose on provider teardown —
      // the OS cleans up when the process dies.
      _cachedEngine = engine;
    } else {
      ref.onDispose(() {
        engine.dispose();
      });
    }

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

/// App fully ready flag - set true AFTER initial DHT operations complete (presence lookups, etc.)
/// UI should show loading spinner until this is true to avoid showing stale data
final appFullyReadyProvider = StateProvider<bool>((ref) => false);

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
