// Identity Provider - Identity management state
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'engine_provider.dart';

/// List of available identities (fingerprints)
final identitiesProvider = AsyncNotifierProvider<IdentitiesNotifier, List<String>>(
  IdentitiesNotifier.new,
);

class IdentitiesNotifier extends AsyncNotifier<List<String>> {
  @override
  Future<List<String>> build() async {
    final engine = await ref.watch(engineProvider.future);
    return engine.listIdentities();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.listIdentities();
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

  /// Create identity from mnemonic
  Future<String> createIdentityFromMnemonic(String mnemonic, {String passphrase = ''}) async {
    final engine = await ref.read(engineProvider.future);

    // Derive seeds from mnemonic
    final seeds = engine.deriveSeeds(mnemonic, passphrase: passphrase);

    // Create identity with derived seeds
    final fingerprint = await engine.createIdentity(
      seeds.signingSeed,
      seeds.encryptionSeed,
    );

    await refresh();
    return fingerprint;
  }

  Future<String> createIdentity(List<int> signingSeed, List<int> encryptionSeed) async {
    final engine = await ref.read(engineProvider.future);
    final fingerprint = await engine.createIdentity(signingSeed, encryptionSeed);
    await refresh();
    return fingerprint;
  }

  Future<void> loadIdentity(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.loadIdentity(fingerprint);
    // Set fingerprint AFTER identity is loaded - this triggers UI rebuild
    // via identityLoadedProvider which watches currentFingerprintProvider
    // NOTE: Do NOT invalidate engineProvider here - it would destroy the engine
    // and lose the loaded identity state
    ref.read(currentFingerprintProvider.notifier).state = fingerprint;
  }

  /// Register a nickname for the current identity
  Future<void> registerName(String name) async {
    final engine = await ref.read(engineProvider.future);
    await engine.registerName(name);

    // Update identity name cache so it shows immediately in identity selection
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint != null && name.isNotEmpty) {
      final newCache = Map<String, String>.from(ref.read(identityNameCacheProvider));
      newCache[fingerprint] = name;
      ref.read(identityNameCacheProvider.notifier).state = newCache;
    }

    // Invalidate user profile to refresh
    ref.invalidate(userProfileProvider);
  }

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

  final engine = await ref.read(engineProvider.future);
  try {
    final registeredName = await engine.getRegisteredName();
    return UserProfile(nickname: registeredName);
  } catch (e) {
    // If fetching fails, return empty profile
    return UserProfile();
  }
});

/// Cache for identity display names (fingerprint -> registered name)
/// This is used by the identity selection screen to show names instead of fingerprints
final identityNameCacheProvider = StateProvider<Map<String, String>>((ref) => {});

/// Provider to fetch and cache display name for a fingerprint
final identityDisplayNameProvider = FutureProvider.family<String?, String>((ref, fingerprint) async {
  // Check cache first
  final cache = ref.read(identityNameCacheProvider);
  if (cache.containsKey(fingerprint)) {
    return cache[fingerprint];
  }

  // Fetch from DHT
  try {
    final engine = await ref.read(engineProvider.future);
    final displayName = await engine.getDisplayName(fingerprint);

    if (displayName.isNotEmpty) {
      // Update cache
      final newCache = Map<String, String>.from(ref.read(identityNameCacheProvider));
      newCache[fingerprint] = displayName;
      ref.read(identityNameCacheProvider.notifier).state = newCache;
      return displayName;
    }
  } catch (e) {
    // DHT lookup failed, return null
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
