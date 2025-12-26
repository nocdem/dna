// Contact Profile Cache Provider - Cache contact profiles from DHT
import 'dart:typed_data';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Cache of contact profiles keyed by fingerprint
/// Stores UserProfile objects fetched from DHT
final contactProfileCacheProvider =
    StateNotifierProvider<ContactProfileCacheNotifier, Map<String, UserProfile>>(
  (ref) => ContactProfileCacheNotifier(ref),
);

class ContactProfileCacheNotifier extends StateNotifier<Map<String, UserProfile>> {
  final Ref _ref;

  ContactProfileCacheNotifier(this._ref) : super({});

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
    // Already cached?
    if (state.containsKey(fingerprint)) {
      return state[fingerprint];
    }

    try {
      final engine = await _ref.read(engineProvider.future);
      final profile = await engine.lookupProfile(fingerprint);

      if (profile != null) {
        // Cache it
        state = {...state, fingerprint: profile};
      }

      return profile;
    } catch (e) {
      // Lookup failed, return null
      return null;
    }
  }

  /// Prefetch profiles for multiple contacts in parallel
  Future<void> prefetchProfiles(List<String> fingerprints) async {
    // Filter out already cached
    final toFetch = fingerprints.where((fp) => !state.containsKey(fp)).toList();
    if (toFetch.isEmpty) return;

    try {
      final engine = await _ref.read(engineProvider.future);

      // Fetch in parallel with a limit to avoid overloading
      const batchSize = 5;
      for (var i = 0; i < toFetch.length; i += batchSize) {
        final batch = toFetch.skip(i).take(batchSize).toList();
        await Future.wait(
          batch.map((fp) async {
            try {
              final profile = await engine.lookupProfile(fp);
              if (profile != null && mounted) {
                state = {...state, fp: profile};
              }
            } catch (_) {
              // Ignore individual failures
            }
          }),
        );
      }
    } catch (_) {
      // Engine not available
    }
  }

  /// Clear cache (e.g., on identity switch)
  void clear() {
    state = {};
  }

  /// Update a specific profile in cache
  void updateProfile(String fingerprint, UserProfile profile) {
    state = {...state, fingerprint: profile};
  }
}
