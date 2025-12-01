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
    ref.read(currentFingerprintProvider.notifier).state = fingerprint;
    // Invalidate to trigger UI rebuild
    ref.invalidate(engineProvider);
  }

  /// Register a nickname for the current identity
  Future<void> registerName(String name) async {
    final engine = await ref.read(engineProvider.future);
    await engine.registerName(name);
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

/// Current fingerprint (null if no identity loaded)
final currentFingerprintProvider = StateProvider<String?>((ref) => null);

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
