// Profile Provider - Full user profile management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'identity_provider.dart' show currentFingerprintProvider, identityAvatarCacheProvider;

/// Full user profile data from DHT (wallets, socials, bio, avatar)
final fullProfileProvider = AsyncNotifierProvider<ProfileNotifier, UserProfile?>(
  ProfileNotifier.new,
);

class ProfileNotifier extends AsyncNotifier<UserProfile?> {
  @override
  Future<UserProfile?> build() async {
    print('[AVATAR_DEBUG] ProfileNotifier.build() STARTED');
    final fingerprint = ref.watch(currentFingerprintProvider);
    if (fingerprint == null) {
      print('[AVATAR_DEBUG] ProfileNotifier.build: no fingerprint');
      return null;
    }

    print('[AVATAR_DEBUG] ProfileNotifier.build: waiting for engine');
    final engine = await ref.watch(engineProvider.future);
    print('[AVATAR_DEBUG] ProfileNotifier.build: calling getProfile');
    try {
      final profile = await engine.getProfile();
      // DEBUG: Log avatar data in profile provider
      print('[AVATAR_DEBUG] ProfileNotifier.build: DONE avatarBase64.length=${profile.avatarBase64.length}');
      return profile;
    } catch (e) {
      // If fetching fails, return empty profile
      print('[AVATAR_DEBUG] ProfileNotifier.build: FAILED with error=$e');
      return UserProfile();
    }
  }

  /// Refresh profile from DHT
  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final fingerprint = ref.read(currentFingerprintProvider);
      if (fingerprint == null) return null;

      final engine = await ref.read(engineProvider.future);
      return engine.getProfile();
    });
  }

  /// Save profile to DHT
  Future<void> save(UserProfile profile) async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      await engine.updateProfile(profile);
      return profile;
    });
  }

  /// Update state directly (for optimistic updates after save)
  void updateState(UserProfile profile) {
    state = AsyncValue.data(profile);
  }
}

/// Profile editor state for the edit screen
class ProfileEditorState {
  final UserProfile profile;
  final bool isLoading;
  final bool isSaving;
  final String? error;
  final String? successMessage;

  const ProfileEditorState({
    required this.profile,
    this.isLoading = false,
    this.isSaving = false,
    this.error,
    this.successMessage,
  });

  ProfileEditorState copyWith({
    UserProfile? profile,
    bool? isLoading,
    bool? isSaving,
    String? error,
    String? successMessage,
  }) {
    return ProfileEditorState(
      profile: profile ?? this.profile,
      isLoading: isLoading ?? this.isLoading,
      isSaving: isSaving ?? this.isSaving,
      error: error,
      successMessage: successMessage,
    );
  }
}

/// Profile editor notifier for managing edit state
final profileEditorProvider =
    StateNotifierProvider.autoDispose<ProfileEditorNotifier, ProfileEditorState>(
  (ref) => ProfileEditorNotifier(ref),
);

class ProfileEditorNotifier extends StateNotifier<ProfileEditorState> {
  final Ref _ref;

  ProfileEditorNotifier(this._ref)
      : super(ProfileEditorState(profile: UserProfile())) {
    _loadProfile();
  }

  Future<void> _loadProfile() async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      final engine = await _ref.read(engineProvider.future);
      final profile = await engine.getProfile();
      state = state.copyWith(profile: profile, isLoading: false);
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: 'Failed to load profile: $e',
      );
    }
  }

  /// Update a field in the profile
  void updateField(String field, String value) {
    final p = state.profile;
    UserProfile newProfile;

    switch (field) {
      // Wallets
      case 'backbone':
        newProfile = p.copyWith(backbone: value);
        break;
      case 'alvin':
        newProfile = p.copyWith(alvin: value);
        break;
      case 'btc':
        newProfile = p.copyWith(btc: value);
        break;
      case 'eth':
        newProfile = p.copyWith(eth: value);
        break;
      case 'sol':
        newProfile = p.copyWith(sol: value);
        break;
      case 'trx':
        newProfile = p.copyWith(trx: value);
        break;
      // Socials
      case 'telegram':
        newProfile = p.copyWith(telegram: value);
        break;
      case 'twitter':
        newProfile = p.copyWith(twitter: value);
        break;
      case 'github':
        newProfile = p.copyWith(github: value);
        break;
      case 'facebook':
        newProfile = p.copyWith(facebook: value);
        break;
      case 'instagram':
        newProfile = p.copyWith(instagram: value);
        break;
      case 'linkedin':
        newProfile = p.copyWith(linkedin: value);
        break;
      case 'google':
        newProfile = p.copyWith(google: value);
        break;
      // Profile info
      case 'displayName':
        newProfile = p.copyWith(displayName: value);
        break;
      case 'bio':
        newProfile = p.copyWith(bio: value);
        break;
      case 'location':
        newProfile = p.copyWith(location: value);
        break;
      case 'website':
        newProfile = p.copyWith(website: value);
        break;
      case 'avatarBase64':
        newProfile = p.copyWith(avatarBase64: value);
        break;
      default:
        return;
    }

    state = state.copyWith(profile: newProfile, successMessage: null);
  }

  /// Set avatar base64
  void setAvatar(String base64) {
    state = state.copyWith(
      profile: state.profile.copyWith(avatarBase64: base64),
      successMessage: null,
    );
  }

  /// Remove avatar
  void removeAvatar() {
    state = state.copyWith(
      profile: state.profile.copyWith(avatarBase64: ''),
      successMessage: null,
    );
  }

  /// Save profile to DHT
  Future<bool> save() async {
    state = state.copyWith(isSaving: true, error: null, successMessage: null);
    try {
      final engine = await _ref.read(engineProvider.future);
      await engine.updateProfile(state.profile);

      // Optimistic update: use local data instead of re-fetching from DHT
      // This avoids race condition where GET happens before PUT propagates
      _ref.read(fullProfileProvider.notifier).updateState(state.profile);

      // Update avatar cache for identity selector (in-memory Flutter cache)
      final fingerprint = _ref.read(currentFingerprintProvider);
      if (fingerprint != null && state.profile.avatarBase64.isNotEmpty) {
        final newCache = Map<String, String>.from(_ref.read(identityAvatarCacheProvider));
        newCache[fingerprint] = state.profile.avatarBase64;
        _ref.read(identityAvatarCacheProvider.notifier).state = newCache;
      }

      state = state.copyWith(
        isSaving: false,
        successMessage: 'Profile saved successfully',
      );
      return true;
    } catch (e) {
      state = state.copyWith(
        isSaving: false,
        error: 'Failed to save profile: $e',
      );
      return false;
    }
  }

  /// Reload profile from DHT (discard changes)
  Future<void> reload() async {
    await _loadProfile();
  }
}
