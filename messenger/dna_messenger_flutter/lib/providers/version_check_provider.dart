// Version Check Provider - DHT-based version checking
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'event_handler.dart';

/// Compare two semantic version strings (e.g., "0.99.100" vs "0.99.104")
/// Returns: positive if a > b, negative if a < b, 0 if equal
int _compareVersions(String a, String b) {
  final aParts = a.split('.').map((s) => int.tryParse(s) ?? 0).toList();
  final bParts = b.split('.').map((s) => int.tryParse(s) ?? 0).toList();

  // Pad to same length
  while (aParts.length < 3) {
    aParts.add(0);
  }
  while (bParts.length < 3) {
    bParts.add(0);
  }

  for (int i = 0; i < 3; i++) {
    if (aParts[i] > bParts[i]) return 1;
    if (aParts[i] < bParts[i]) return -1;
  }
  return 0;
}

/// Version check result with app version comparison done in Dart
/// (C library only compares library version, not app version)
class VersionCheckResultWithAppCompare {
  final VersionCheckResult native;
  final bool appUpdateAvailable;
  final bool appBelowMinimum;

  VersionCheckResultWithAppCompare({
    required this.native,
    required this.appUpdateAvailable,
    required this.appBelowMinimum,
  });

  // Delegate to native result
  bool get libraryUpdateAvailable => native.libraryUpdateAvailable;
  bool get nodusUpdateAvailable => native.nodusUpdateAvailable;
  bool get libraryBelowMinimum => native.libraryBelowMinimum;
  String get libraryCurrent => native.libraryCurrent;
  String get libraryMinimum => native.libraryMinimum;
  String get appCurrent => native.appCurrent;
  String get appMinimum => native.appMinimum;
  String get nodusCurrent => native.nodusCurrent;
  String get nodusMinimum => native.nodusMinimum;
  int get publishedAt => native.publishedAt;
  String get publisher => native.publisher;

  /// Check if any update is available (with corrected app check)
  bool get hasUpdate => libraryUpdateAvailable || appUpdateAvailable || nodusUpdateAvailable;

  /// Check if app is below required minimum — BLOCKS APP USAGE
  bool get isBelowMinimum => libraryBelowMinimum || appBelowMinimum;
}

/// Version check result provider
/// Watches dhtConnectedAtProvider so it re-runs when DHT connects.
/// Returns null if DHT not connected or check fails.
final versionCheckProvider = FutureProvider<VersionCheckResultWithAppCompare?>((ref) async {
  // Watch DHT connection state — re-runs when DHT connects
  final dhtConnectedAt = ref.watch(dhtConnectedAtProvider);
  if (dhtConnectedAt == null) {
    return null; // DHT not connected yet, will re-run when it connects
  }

  final engine = await ref.watch(engineProvider.future);
  final nativeResult = engine.checkVersionDht();

  if (nativeResult == null) {
    return null;
  }

  // Get local app version and compare with DHT version
  // (C library doesn't know app version, only library version)
  final packageInfo = await PackageInfo.fromPlatform();
  final localAppVersion = packageInfo.version;
  final dhtAppVersion = nativeResult.appCurrent;
  final dhtAppMinimum = nativeResult.appMinimum;

  // Compare: if DHT version > local version, update is available
  final appUpdateAvailable = dhtAppVersion.isNotEmpty &&
      _compareVersions(dhtAppVersion, localAppVersion) > 0;

  // Compare: if local version < DHT minimum, app is blocked
  final appBelowMin = dhtAppMinimum.isNotEmpty &&
      _compareVersions(localAppVersion, dhtAppMinimum) < 0;

  return VersionCheckResultWithAppCompare(
    native: nativeResult,
    appUpdateAvailable: appUpdateAvailable,
    appBelowMinimum: appBelowMin,
  );
});
