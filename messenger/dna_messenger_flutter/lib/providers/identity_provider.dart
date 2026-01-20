// Identity Provider - Identity management state
import 'dart:io' show Platform;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/cache_database.dart';
import 'engine_provider.dart';
import 'identity_profile_cache_provider.dart';
import 'profile_provider.dart' show fullProfileProvider;

/// List of available identities (fingerprints)
/// v0.3.0: In single-user model, this returns at most 1 identity.
/// Still used by IdentitySelectionScreen for onboarding UI.
final identitiesProvider = AsyncNotifierProvider<IdentitiesNotifier, List<String>>(
  IdentitiesNotifier.new,
);

class IdentitiesNotifier extends AsyncNotifier<List<String>> {
  final CacheDatabase _db = CacheDatabase.instance;

  @override
  Future<List<String>> build() async {
    // v0.3.0: First check if identity actually exists on disk
    // This prevents using stale cache after account deletion
    final engine = await ref.watch(engineProvider.future);
    final hasIdentity = engine.hasIdentity();

    if (!hasIdentity) {
      // No identity on disk - clear any stale cache and return empty
      _db.saveIdentityList([]);
      return [];
    }

    // Step 1: Try to load cached identity list immediately (fast startup)
    List<String> cachedIdentities = [];
    try {
      cachedIdentities = await _db.getIdentityList();
      if (cachedIdentities.isNotEmpty) {
        // Prefetch profiles for cached identities
        ref.read(identityProfileCacheProvider.notifier).prefetchIdentities(cachedIdentities);

        // Return cached list immediately, then refresh in background
        _refreshFromEngineInBackground();
        return cachedIdentities;
      }
    } catch (_) {
      // Cache not ready, continue to engine
    }

    // Step 2: No cache - get from engine
    final identities = await engine.listIdentities();

    // Cache the list for next startup
    _db.saveIdentityList(identities);

    // Prefetch identity profiles in background (for names/avatars)
    if (identities.isNotEmpty) {
      ref.read(identityProfileCacheProvider.notifier).prefetchIdentities(identities);
    }

    return identities;
  }

  /// Refresh identity list from engine in background (after showing cached data)
  Future<void> _refreshFromEngineInBackground() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final identities = await engine.listIdentities();

      // Update cache
      _db.saveIdentityList(identities);

      // Update state if different
      final current = state.valueOrNull ?? [];
      if (!_listEquals(current, identities)) {
        state = AsyncValue.data(identities);
        // Prefetch profiles for new identities
        ref.read(identityProfileCacheProvider.notifier).prefetchIdentities(identities);
      }
    } catch (_) {
      // Background refresh failed, keep cached data
    }
  }

  bool _listEquals(List<String> a, List<String> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final identities = await engine.listIdentities();
      // Update cache
      _db.saveIdentityList(identities);
      return identities;
    });
  }

  /// Generate a 24-word BIP39 mnemonic
  Future<String> generateMnemonic() async {
    final engine = await ref.read(engineProvider.future);
    return engine.generateMnemonic();
  }

  /// Validate a BIP39 mnemonic
  Future<bool> validateMnemonic(String mnemonic) async {
    final engine = await ref.read(engineProvider.future);
    return engine.validateMnemonic(mnemonic);
  }

  /// Check if name is available in DHT
  /// Returns true if available, false if taken
  Future<bool> isNameAvailable(String name) async {
    final engine = await ref.read(engineProvider.future);
    final result = await engine.lookupName(name);
    return result.isEmpty; // empty = not found = available
  }

  /// Create identity from mnemonic with required name (for NEW identities)
  Future<String> createIdentityFromMnemonic(String name, String mnemonic, {String passphrase = ''}) async {
    final engine = await ref.read(engineProvider.future);

    // Derive seeds from mnemonic (includes masterSeed for multi-chain wallets)
    final seeds = engine.deriveSeedsWithMaster(mnemonic, passphrase: passphrase);

    // Create identity with derived seeds
    // - ETH/SOL use masterSeed via BIP-44/SLIP-10
    // - Cellframe uses SHA3-256(mnemonic) to match official Cellframe wallet app
    final fingerprint = await engine.createIdentity(
      name,
      seeds.signingSeed,
      seeds.encryptionSeed,
      masterSeed: seeds.masterSeed,
      mnemonic: mnemonic, // Pass mnemonic for Cellframe wallet
    );

    await refresh();

    // Cache own profile immediately so UI shows name without waiting for DHT propagation
    // (DHT PUT is async and may not be queryable yet)
    await ref.read(identityProfileCacheProvider.notifier).updateIdentity(fingerprint, name, '');

    // Android: Store fingerprint for background service
    if (Platform.isAndroid) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('identity_fingerprint', fingerprint);
      engine.debugLog('IDENTITY', 'createIdentityFromMnemonic - fingerprint stored for service');
    }

    // Invalidate profile providers to fetch fresh profile with name
    ref.invalidate(userProfileProvider);
    ref.invalidate(fullProfileProvider);

    return fingerprint;
  }

  /// Restore identity from mnemonic (creates keys/wallets without DHT registration)
  /// Returns fingerprint. Profile can be looked up from DHT after this.
  Future<String> restoreIdentityFromMnemonic(String mnemonic, {String passphrase = ''}) async {
    final engine = await ref.read(engineProvider.future);

    // Derive seeds from mnemonic (includes masterSeed for multi-chain wallets)
    final seeds = engine.deriveSeedsWithMaster(mnemonic, passphrase: passphrase);

    // Restore identity locally (no DHT registration - identity already exists)
    // - ETH/SOL use masterSeed via BIP-44/SLIP-10
    // - Cellframe uses SHA3-256(mnemonic) to match official Cellframe wallet app
    final fingerprint = await engine.restoreIdentity(
      seeds.signingSeed,
      seeds.encryptionSeed,
      masterSeed: seeds.masterSeed,
      mnemonic: mnemonic, // Pass mnemonic for Cellframe wallet
    );

    await refresh();

    // Android: Store fingerprint for background service
    if (Platform.isAndroid) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('identity_fingerprint', fingerprint);
      engine.debugLog('IDENTITY', 'restoreIdentityFromMnemonic - fingerprint stored for service');
    }

    // Invalidate profile providers to fetch fresh profile from DHT
    ref.invalidate(userProfileProvider);
    ref.invalidate(fullProfileProvider);

    return fingerprint;
  }

  Future<String> createIdentity(String name, List<int> signingSeed, List<int> encryptionSeed) async {
    final engine = await ref.read(engineProvider.future);
    final fingerprint = await engine.createIdentity(name, signingSeed, encryptionSeed);
    await refresh();

    // Android: Store fingerprint for background service
    if (Platform.isAndroid) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('identity_fingerprint', fingerprint);
      engine.debugLog('IDENTITY', 'createIdentity - fingerprint stored for service');
    }

    // Invalidate profile providers to fetch fresh profile with name
    ref.invalidate(userProfileProvider);
    ref.invalidate(fullProfileProvider);

    return fingerprint;
  }

  /// Check if an identity exists (v0.3.0 single-user model)
  ///
  /// Returns true if keys/identity.dsa exists in the data directory.
  /// Use this to determine if onboarding is needed.
  Future<bool> hasIdentity() async {
    final engine = await ref.read(engineProvider.future);
    return engine.hasIdentity();
  }

  /// Load identity (v0.3.0 single-user model)
  ///
  /// [fingerprint] - Optional. If not provided, fingerprint is computed from flat key file.
  Future<void> loadIdentity([String? fingerprint]) async {
    final engine = await ref.read(engineProvider.future);

    if (fingerprint != null) {
      engine.debugLog('IDENTITY', 'loadIdentity START fp=${fingerprint.substring(0, 16)}...');
    } else {
      engine.debugLog('IDENTITY', 'loadIdentity START (auto-detect fingerprint)');
    }

    await engine.loadIdentity(fingerprint: fingerprint);

    // Get actual fingerprint after loading (important when auto-detected)
    final loadedFp = engine.fingerprint;
    engine.debugLog('IDENTITY', 'loadIdentity DONE - loaded fp=${loadedFp?.substring(0, 16) ?? "null"}');

    // Android v0.5.5+: Store fingerprint for background service
    // Service reads this when it starts fresh after process killed
    if (Platform.isAndroid && loadedFp != null) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('identity_fingerprint', loadedFp);
      engine.debugLog('IDENTITY', 'loadIdentity - fingerprint stored for service');
    }

    // Set fingerprint AFTER identity is loaded - this triggers UI rebuild
    // via identityLoadedProvider which watches currentFingerprintProvider
    // NOTE: Do NOT invalidate engineProvider here - it would destroy the engine
    // and lose the loaded identity state
    ref.read(currentFingerprintProvider.notifier).state = loadedFp;
    engine.debugLog('IDENTITY', 'loadIdentity - currentFingerprintProvider set');

    // Start all listeners in background (waits for DHT to become ready)
    // This runs asynchronously so UI isn't blocked while waiting for DHT peers.
    // Includes: outbox listeners, presence listeners, watermark listeners, contact request listener
    Future.microtask(() {
      engine.debugLog('IDENTITY', 'Starting all listeners in background...');
      final count = engine.listenAllContacts();
      engine.debugLog('IDENTITY', 'Background listeners started for $count contacts');
    });

    // Invalidate profile providers to fetch fresh profile from DHT
    ref.invalidate(userProfileProvider);
    ref.invalidate(fullProfileProvider);
  }

  /// Register a nickname for the current identity
  Future<void> registerName(String name) async {
    final engine = await ref.read(engineProvider.future);
    await engine.registerName(name);

    // Cache profile locally so UI shows name without waiting for DHT propagation
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint != null && name.isNotEmpty) {
      // Update SQLite-backed cache (used by userProfileProvider)
      await ref.read(identityProfileCacheProvider.notifier).updateIdentity(fingerprint, name, '');
    }

    // Invalidate profile providers to refresh with new name
    ref.invalidate(userProfileProvider);
    ref.invalidate(fullProfileProvider);
  }

  /// v0.3.0: Deprecated - in single-user model, unloading is only used
  /// for account deletion, which clears fingerprint and returns to onboarding.
  void unloadIdentity() {
    ref.read(currentFingerprintProvider.notifier).state = null;
    ref.invalidate(engineProvider);
  }
}

/// Identity creation wizard state
enum CreateIdentityStep { name, seedPhrase, creating }

class CreateIdentityState {
  final CreateIdentityStep step;
  final String name;
  final String mnemonic;
  final bool seedConfirmed;
  final bool isLoading;
  final String? error;

  const CreateIdentityState({
    this.step = CreateIdentityStep.name,
    this.name = '',
    this.mnemonic = '',
    this.seedConfirmed = false,
    this.isLoading = false,
    this.error,
  });

  CreateIdentityState copyWith({
    CreateIdentityStep? step,
    String? name,
    String? mnemonic,
    bool? seedConfirmed,
    bool? isLoading,
    String? error,
  }) {
    return CreateIdentityState(
      step: step ?? this.step,
      name: name ?? this.name,
      mnemonic: mnemonic ?? this.mnemonic,
      seedConfirmed: seedConfirmed ?? this.seedConfirmed,
      isLoading: isLoading ?? this.isLoading,
      error: error,
    );
  }
}

final createIdentityStateProvider =
    StateNotifierProvider<CreateIdentityStateNotifier, CreateIdentityState>(
  (ref) => CreateIdentityStateNotifier(),
);

/// User profile data
class UserProfile {
  final String? nickname;
  final String? avatar;

  UserProfile({this.nickname, this.avatar});
}

final userProfileProvider = FutureProvider<UserProfile?>((ref) async {
  final fingerprint = ref.watch(currentFingerprintProvider);
  if (fingerprint == null) return null;

  // Check local cache first (faster, and works before DHT propagation)
  final cache = ref.watch(identityProfileCacheProvider);
  final cached = cache[fingerprint];
  if (cached != null && cached.displayName.isNotEmpty) {
    return UserProfile(nickname: cached.displayName, avatar: cached.avatarBase64);
  }

  // Fall back to DHT lookup
  final engine = await ref.read(engineProvider.future);
  try {
    final registeredName = await engine.getRegisteredName();
    return UserProfile(nickname: registeredName);
  } catch (e) {
    // If fetching fails, return empty profile
    return UserProfile();
  }
});

/// Cache for identity avatars (fingerprint -> base64 avatar)
final identityAvatarCacheProvider = StateProvider<Map<String, String>>((ref) => {});

/// Provider to fetch and cache display name for a fingerprint
final identityDisplayNameProvider = FutureProvider.family<String?, String>((ref, fingerprint) async {
  // Watch SQLite-backed cache so provider rebuilds when cache updates
  final cache = ref.watch(identityProfileCacheProvider);
  final cached = cache[fingerprint];
  if (cached != null && cached.displayName.isNotEmpty) {
    return cached.displayName;
  }

  // Fetch from DHT via cache provider
  try {
    final identity = await ref.read(identityProfileCacheProvider.notifier).fetchAndCache(fingerprint);
    if (identity != null && identity.displayName.isNotEmpty) {
      return identity.displayName;
    }
  } catch (e) {
    // DHT lookup failed, return null
  }

  return null;
});

/// Provider to fetch and cache avatar for a fingerprint
final identityAvatarProvider = FutureProvider.family<String?, String>((ref, fingerprint) async {
  // Watch SQLite-backed cache so provider rebuilds when cache updates
  final cache = ref.watch(identityProfileCacheProvider);
  final cached = cache[fingerprint];
  if (cached != null && cached.avatarBase64.isNotEmpty) {
    return cached.avatarBase64;
  }

  // Also check legacy in-memory cache for backwards compatibility
  final legacyCache = ref.watch(identityAvatarCacheProvider);
  if (legacyCache.containsKey(fingerprint)) {
    return legacyCache[fingerprint];
  }

  // Fetch from DHT via cache provider
  try {
    final identity = await ref.read(identityProfileCacheProvider.notifier).fetchAndCache(fingerprint);
    if (identity != null && identity.avatarBase64.isNotEmpty) {
      return identity.avatarBase64;
    }
  } catch (_) {
    // Avatar fetch failed, return null
  }

  return null;
});

class CreateIdentityStateNotifier extends StateNotifier<CreateIdentityState> {
  CreateIdentityStateNotifier() : super(const CreateIdentityState());

  void setName(String name) {
    state = state.copyWith(name: name);
  }

  void setMnemonic(String mnemonic) {
    state = state.copyWith(mnemonic: mnemonic);
  }

  void nextStep() {
    if (state.step == CreateIdentityStep.name) {
      state = state.copyWith(step: CreateIdentityStep.seedPhrase);
    } else if (state.step == CreateIdentityStep.seedPhrase) {
      state = state.copyWith(step: CreateIdentityStep.creating);
    }
  }

  void previousStep() {
    if (state.step == CreateIdentityStep.seedPhrase) {
      state = state.copyWith(step: CreateIdentityStep.name);
    } else if (state.step == CreateIdentityStep.creating) {
      state = state.copyWith(step: CreateIdentityStep.seedPhrase);
    }
  }

  void confirmSeed() {
    state = state.copyWith(seedConfirmed: true);
  }

  void setLoading(bool loading) {
    state = state.copyWith(isLoading: loading);
  }

  void setError(String? error) {
    state = state.copyWith(error: error);
  }

  void reset() {
    state = const CreateIdentityState();
  }
}
