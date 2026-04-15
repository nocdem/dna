// Version Check Provider - DHT-based version checking
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'event_handler.dart';

/// Parse RC number from version string: "1.0.0-rc23" → 23, "1.0.0" → null
int? _parseRc(String version) {
  final dash = version.indexOf('-rc');
  if (dash == -1) return null;
  return int.tryParse(version.substring(dash + 3));
}

/// Compare two semantic version strings with RC support
/// "1.0.0-rc23" < "1.0.0-rc24" < "1.0.0" (final > any RC)
/// Returns: positive if a > b, negative if a < b, 0 if equal
int _compareVersions(String a, String b) {
  // Strip RC suffix for major.minor.patch parsing
  final aBase = a.contains('-') ? a.substring(0, a.indexOf('-')) : a;
  final bBase = b.contains('-') ? b.substring(0, b.indexOf('-')) : b;

  final aParts = aBase.split('.').map((s) => int.tryParse(s) ?? 0).toList();
  final bParts = bBase.split('.').map((s) => int.tryParse(s) ?? 0).toList();

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

  // Same major.minor.patch — compare RC: final > any RC, rc24 > rc23
  final aRc = _parseRc(a);
  final bRc = _parseRc(b);
  if (aRc == null && bRc == null) return 0; // both final
  if (aRc == null) return 1;  // a is final, b is RC
  if (bRc == null) return -1; // a is RC, b is final
  return aRc.compareTo(bRc);  // both RC, compare numbers
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

/// Whether the user dismissed the update-available dialog this session.
/// Resets on app restart. When true, the dialog won't show again.
final updateDismissedProvider = StateProvider<bool>((ref) => false);

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
