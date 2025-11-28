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

/// Current identity fingerprint
final currentIdentityProvider = Provider<String?>((ref) {
  final engineAsync = ref.watch(engineProvider);
  return engineAsync.whenOrNull(data: (engine) => engine.fingerprint);
});

/// Identity loaded state
final identityLoadedProvider = Provider<bool>((ref) {
  final identity = ref.watch(currentIdentityProvider);
  return identity != null && identity.isNotEmpty;
});
