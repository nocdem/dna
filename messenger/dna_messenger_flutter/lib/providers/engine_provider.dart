// Engine Provider - Core DNA Engine state management
import 'dart:async';
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
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/dna_messenger';

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
