// Contact Profile Cache Provider - Cache contact profiles with SQLite persistence
import 'dart:typed_data';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../services/cache_database.dart';
import 'engine_provider.dart';
import 'identity_provider.dart' show currentFingerprintProvider;

/// Cache staleness threshold - refetch profiles older than this
const _cacheMaxAge = Duration(hours: 24);

/// Cache of contact profiles keyed by fingerprint
/// Uses SQLite for persistence with in-memory overlay for performance
final contactProfileCacheProvider =
    StateNotifierProvider<ContactProfileCacheNotifier, Map<String, UserProfile>>(
  (ref) => ContactProfileCacheNotifier(ref),
);

class ContactProfileCacheNotifier extends StateNotifier<Map<String, UserProfile>> {
  final Ref _ref;
  final CacheDatabase _db = CacheDatabase.instance;
  bool _initialized = false;

  ContactProfileCacheNotifier(this._ref) : super({}) {
    _init();
  }

  /// Initialize cache from SQLite
  Future<void> _init() async {
    if (_initialized) return;
    _initialized = true;

    try {
      // Load all cached profiles from SQLite
      final cached = await _db.getAllProfiles();
      if (cached.isNotEmpty && mounted) {
        state = cached;
      }

      // Clean up old entries (fire and forget)
      _db.cleanupOldProfiles(const Duration(days: 7));
    } catch (e) {
      // Database not ready yet, will populate as we go
    }
  }

  /// Get cached profile for a fingerprint, or null if not cached
  UserProfile? getProfile(String fingerprint) {
    return state[fingerprint];
  }

  /// Get avatar bytes for a fingerprint, or null if not available
  Uint8List? getAvatarBytes(String fingerprint) {
    final profile = state[fingerprint];
    if (profile == null) return null;
    return profile.decodeAvatar();
  }

  /// Fetch profile from DHT and cache it
  /// Returns the profile if successful, null if failed
  Future<UserProfile?> fetchAndCache(String fingerprint) async {
    // Check if we have a fresh cache
    final cached = state[fingerprint];
    if (cached != null) {
      // Check if stale in background
      _refreshIfStale(fingerprint);
      return cached;
    }

    // Try to load from SQLite first
    try {
      final dbProfile = await _db.getProfile(fingerprint);
      if (dbProfile != null) {
        // Update in-memory cache
        if (mounted) {
          state = {...state, fingerprint: dbProfile};
        }
        // Refresh in background if stale
        _refreshIfStale(fingerprint);
        return dbProfile;
      }
    } catch (_) {}

    // Fetch from DHT
    return await _fetchFromDht(fingerprint);
  }

  /// Force refresh profile from DHT
  Future<UserProfile?> refreshProfile(String fingerprint) async {
    return await _fetchFromDht(fingerprint);
  }

  /// Fetch profile from DHT and save to cache
  Future<UserProfile?> _fetchFromDht(String fingerprint) async {
    // Skip if no identity loaded (DHT may not be available)
    final currentFp = _ref.read(currentFingerprintProvider);
    if (currentFp == null) {
      return null;
    }

    try {
      final engine = await _ref.read(engineProvider.future);
      engine.debugLog('PROFILE_CACHE', '_fetchFromDht START fp=${fingerprint.substring(0, 16)}...');
      final profile = await engine.lookupProfile(fingerprint);
      engine.debugLog('PROFILE_CACHE', '_fetchFromDht DONE fp=${fingerprint.substring(0, 16)}... profile=${profile != null}');

      if (profile != null) {
        // Update in-memory cache
        if (mounted) {
          state = {...state, fingerprint: profile};
        }
        // Persist to SQLite (fire and forget)
        _db.saveProfile(fingerprint, profile);
      }

      return profile;
    } catch (e) {
      // Lookup failed, return null
      return null;
    }
  }

  /// Refresh profile if it's stale
  Future<void> _refreshIfStale(String fingerprint) async {
    try {
      final isStale = await _db.isProfileStale(fingerprint, _cacheMaxAge);
      if (isStale) {
        // Refresh in background
        _fetchFromDht(fingerprint);
      }
    } catch (_) {}
  }

  /// Prefetch profiles for multiple contacts in parallel
  Future<void> prefetchProfiles(List<String> fingerprints) async {
    // Skip if no identity loaded (DHT may not be available)
    final currentFp = _ref.read(currentFingerprintProvider);
    if (currentFp == null) {
      return;
    }

    // Filter out already cached
    final toFetch = fingerprints.where((fp) => !state.containsKey(fp)).toList();
    if (toFetch.isEmpty) return;

    // First try to load from SQLite
    try {
      final dbProfiles = await _db.getProfiles(toFetch);
      if (dbProfiles.isNotEmpty && mounted) {
        state = {...state, ...dbProfiles};
      }
      // Remove found profiles from fetch list
      toFetch.removeWhere((fp) => dbProfiles.containsKey(fp));
    } catch (_) {}

    if (toFetch.isEmpty) return;

    // Fetch remaining from DHT
    try {
      final engine = await _ref.read(engineProvider.future);
      engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: ${toFetch.length} profiles to fetch from DHT');

      // Fetch in parallel with a limit to avoid overloading
      const batchSize = 5;
      for (var i = 0; i < toFetch.length; i += batchSize) {
        // Re-check identity before each batch (may have been unloaded)
        if (_ref.read(currentFingerprintProvider) == null) {
          engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: identity unloaded, stopping');
          return;
        }

        final batch = toFetch.skip(i).take(batchSize).toList();
        engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: fetching batch ${i ~/ batchSize + 1}');
        await Future.wait(
          batch.map((fp) async {
            try {
              engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: lookupProfile(${fp.substring(0, 16)}...)');
              final profile = await engine.lookupProfile(fp);
              if (profile != null && mounted) {
                state = {...state, fp: profile};
                // Persist to SQLite (fire and forget)
                _db.saveProfile(fp, profile);
              }
            } catch (e) {
              engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: FAILED ${fp.substring(0, 16)}... error=$e');
            }
          }),
        );
      }
      engine.debugLog('PROFILE_CACHE', 'prefetchProfiles: DONE');
    } catch (e) {
      // Engine not available - can't log without engine
    }
  }

  /// Clear all cached profiles (e.g., on identity switch)
  Future<void> clear() async {
    state = {};
    try {
      await _db.clearProfiles();
    } catch (_) {}
  }

  /// Update a specific profile in cache
  Future<void> updateProfile(String fingerprint, UserProfile profile) async {
    state = {...state, fingerprint: profile};
    try {
      await _db.saveProfile(fingerprint, profile);
    } catch (_) {}
  }

  /// Remove a profile from cache
  Future<void> removeProfile(String fingerprint) async {
    final newState = Map<String, UserProfile>.from(state);
    newState.remove(fingerprint);
    state = newState;
    try {
      await _db.deleteProfile(fingerprint);
    } catch (_) {}
  }
}
