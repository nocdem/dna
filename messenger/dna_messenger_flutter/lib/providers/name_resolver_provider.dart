// Name Resolver Provider - Async fingerprint → name resolution with caching
// v0.6.94: Replaces comment author proof with simple DHT lookup + cache
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'engine_provider.dart';

/// Cache of resolved fingerprint → display name mappings
/// Uses engine.getDisplayName() which checks local cache then DHT
final nameResolverProvider =
    StateNotifierProvider<NameResolverNotifier, Map<String, String>>(
  (ref) => NameResolverNotifier(ref),
);

class NameResolverNotifier extends StateNotifier<Map<String, String>> {
  final Ref _ref;

  /// Track in-flight lookups to avoid duplicate requests
  final Set<String> _pendingLookups = {};

  NameResolverNotifier(this._ref) : super({});

  /// Get cached name for fingerprint, or null if not yet resolved
  String? getName(String fingerprint) {
    return state[fingerprint];
  }

  /// Resolve a single fingerprint to display name
  /// Returns cached value immediately if available, otherwise triggers lookup
  Future<String?> resolveName(String fingerprint) async {
    // Return cached value if available
    if (state.containsKey(fingerprint)) {
      return state[fingerprint];
    }

    // Skip if already pending
    if (_pendingLookups.contains(fingerprint)) {
      return null;
    }

    // Skip if no identity loaded
    final currentFp = _ref.read(currentFingerprintProvider);
    if (currentFp == null) {
      return null;
    }

    _pendingLookups.add(fingerprint);

    try {
      final engine = await _ref.read(engineProvider.future);
      final displayName = await engine.getDisplayName(fingerprint);

      // Cache result (use spread + new map to use variable as key)
      if (mounted && displayName.isNotEmpty) {
        final newState = Map<String, String>.from(state);
        newState[fingerprint] = displayName;
        state = newState;
      }

      return displayName;
    } catch (_) {
      return null;
    } finally {
      _pendingLookups.remove(fingerprint);
    }
  }

  /// Resolve multiple fingerprints in parallel
  /// Triggers lookups for any uncached fingerprints
  Future<void> resolveNames(List<String> fingerprints) async {
    // Skip if no identity loaded
    final currentFp = _ref.read(currentFingerprintProvider);
    if (currentFp == null) {
      return;
    }

    // Filter to uncached fingerprints not already pending
    final toResolve = fingerprints
        .where((fp) => !state.containsKey(fp) && !_pendingLookups.contains(fp))
        .toSet()
        .toList();

    if (toResolve.isEmpty) return;

    // Mark all as pending
    _pendingLookups.addAll(toResolve);

    try {
      final engine = await _ref.read(engineProvider.future);

      // Resolve in parallel batches to avoid overloading
      const batchSize = 10;
      for (var i = 0; i < toResolve.length; i += batchSize) {
        // Re-check identity before each batch
        if (_ref.read(currentFingerprintProvider) == null) {
          return;
        }

        final batch = toResolve.skip(i).take(batchSize).toList();
        final results = await Future.wait(
          batch.map((fp) async {
            try {
              final name = await engine.getDisplayName(fp);
              return MapEntry(fp, name);
            } catch (_) {
              return MapEntry(fp, '');
            }
          }),
        );

        // Update state with resolved names
        if (mounted) {
          final newEntries = <String, String>{};
          for (final entry in results) {
            if (entry.value.isNotEmpty) {
              newEntries[entry.key] = entry.value;
            }
          }
          if (newEntries.isNotEmpty) {
            state = {...state, ...newEntries};
          }
        }
      }
    } catch (_) {
      // Engine not available
    } finally {
      _pendingLookups.removeAll(toResolve);
    }
  }

  /// Clear cache (e.g., on identity switch)
  void clear() {
    state = {};
    _pendingLookups.clear();
  }
}
