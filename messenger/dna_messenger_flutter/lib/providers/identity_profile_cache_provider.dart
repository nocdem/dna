// Identity Profile Cache Provider - Cache identity profiles with SQLite persistence
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../services/cache_database.dart';
import 'engine_provider.dart';

/// Cache staleness threshold - refetch profiles older than this
const _cacheMaxAge = Duration(hours: 24);

/// Cache of identity profiles keyed by fingerprint
/// Uses SQLite for persistence with in-memory overlay for performance
final identityProfileCacheProvider =
    StateNotifierProvider<IdentityProfileCacheNotifier, Map<String, CachedIdentity>>(
  (ref) => IdentityProfileCacheNotifier(ref),
);

class IdentityProfileCacheNotifier extends StateNotifier<Map<String, CachedIdentity>> {
  final Ref _ref;
  final CacheDatabase _db = CacheDatabase.instance;
  bool _initialized = false;

  IdentityProfileCacheNotifier(this._ref) : super({}) {
    _init();
  }

  /// Initialize cache from SQLite
  Future<void> _init() async {
    if (_initialized) return;
    _initialized = true;

    try {
      // Load all cached identities from SQLite
      final cached = await _db.getAllIdentities();
      if (cached.isNotEmpty && mounted) {
        state = cached;
      }
    } catch (e) {
      // Database not ready yet, will populate as we go
    }
  }

  /// Get cached identity for a fingerprint, or null if not cached
  CachedIdentity? getIdentity(String fingerprint) {
    return state[fingerprint];
  }

  /// Fetch identity from DHT and cache it
  /// Returns the cached identity if successful, null if failed
  Future<CachedIdentity?> fetchAndCache(String fingerprint) async {
    // Check if we have a fresh cache
    final cached = state[fingerprint];
    if (cached != null) {
      // Check if stale in background
      _refreshIfStale(fingerprint);
      return cached;
    }

    // Try to load from SQLite first
    try {
      final dbIdentity = await _db.getIdentity(fingerprint);
      if (dbIdentity != null) {
        // Update in-memory cache
        if (mounted) {
          state = {...state, fingerprint: dbIdentity};
        }
        // Refresh in background if stale
        _refreshIfStale(fingerprint);
        return dbIdentity;
      }
    } catch (_) {}

    // Fetch from DHT
    return await _fetchFromDht(fingerprint);
  }

  /// Force refresh identity from DHT
  Future<CachedIdentity?> refreshIdentity(String fingerprint) async {
    return await _fetchFromDht(fingerprint);
  }

  /// Fetch identity from DHT and save to cache
  Future<CachedIdentity?> _fetchFromDht(String fingerprint) async {
    try {
      final engine = await _ref.read(engineProvider.future);

      // Fetch display name
      final displayName = await engine.getDisplayName(fingerprint);

      // Fetch avatar (optional)
      String avatarBase64 = '';
      try {
        avatarBase64 = await engine.getAvatar(fingerprint) ?? '';
      } catch (_) {}

      final identity = CachedIdentity(
        fingerprint: fingerprint,
        displayName: displayName,
        avatarBase64: avatarBase64,
        cachedAt: DateTime.now(),
      );

      // Update in-memory cache
      if (mounted) {
        state = {...state, fingerprint: identity};
      }
      // Persist to SQLite (fire and forget)
      _db.saveIdentity(fingerprint, displayName, avatarBase64);

      return identity;
    } catch (e) {
      // Lookup failed, return null
      return null;
    }
  }

  /// Refresh identity if it's stale
  Future<void> _refreshIfStale(String fingerprint) async {
    try {
      final isStale = await _db.isIdentityStale(fingerprint, _cacheMaxAge);
      if (isStale) {
        // Refresh in background
        _fetchFromDht(fingerprint);
      }
    } catch (_) {}
  }

  /// Prefetch identities for multiple fingerprints in parallel
  Future<void> prefetchIdentities(List<String> fingerprints) async {
    // Filter out already cached WITH valid displayName
    // (re-fetch if cached but displayName is empty - may have failed before DHT connected)
    final toFetch = fingerprints.where((fp) {
      final cached = state[fp];
      return cached == null || cached.displayName.isEmpty;
    }).toList();
    if (toFetch.isEmpty) return;

    // First try to load from SQLite (only if displayName is valid)
    try {
      for (final fp in toFetch.toList()) {
        final dbIdentity = await _db.getIdentity(fp);
        if (dbIdentity != null && dbIdentity.displayName.isNotEmpty && mounted) {
          state = {...state, fp: dbIdentity};
          toFetch.remove(fp);
        }
      }
    } catch (_) {}

    if (toFetch.isEmpty) return;

    // Fetch remaining from DHT in parallel
    try {
      await Future.wait(
        toFetch.map((fp) => _fetchFromDht(fp)),
      );
    } catch (_) {
      // Engine not available
    }
  }

  /// Update a specific identity in cache (e.g., after profile edit)
  Future<void> updateIdentity(String fingerprint, String displayName, String avatarBase64) async {
    final identity = CachedIdentity(
      fingerprint: fingerprint,
      displayName: displayName,
      avatarBase64: avatarBase64,
      cachedAt: DateTime.now(),
    );
    state = {...state, fingerprint: identity};
    try {
      await _db.saveIdentity(fingerprint, displayName, avatarBase64);
    } catch (_) {}
  }

  /// Remove an identity from cache
  Future<void> removeIdentity(String fingerprint) async {
    final newState = Map<String, CachedIdentity>.from(state);
    newState.remove(fingerprint);
    state = newState;
    try {
      await _db.deleteIdentity(fingerprint);
    } catch (_) {}
  }

  /// Clear all cached identities
  Future<void> clear() async {
    state = {};
    try {
      await _db.clearIdentities();
    } catch (_) {}
  }
}
