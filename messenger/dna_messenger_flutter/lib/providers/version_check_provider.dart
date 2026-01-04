// Version Check Provider - DHT-based version checking
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Version check result provider
/// Checks DHT for latest version info and compares with current version.
/// Returns null if check fails (no DHT connection, no version published).
final versionCheckProvider = FutureProvider<VersionCheckResult?>((ref) async {
  final engine = await ref.watch(engineProvider.future);
  return engine.checkVersionDht();
});
