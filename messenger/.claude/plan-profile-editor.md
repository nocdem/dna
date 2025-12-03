# Profile Editor Implementation Plan

## Summary

Add a Profile Editor screen to Flutter that allows users to:
- Edit wallet addresses (Cellframe + external chains)
- Edit social links (Telegram, Twitter, GitHub)
- Edit bio (max 512 chars)
- Upload/remove avatar (64x64, base64 encoded)
- Save profile to DHT with Dilithium5 signature

## Required Changes

### 1. C API Layer (dna_engine.h)

Add two new async functions to the public API:

```c
// Get current identity's profile from DHT
dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
);

// Update current identity's profile in DHT
dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_data_t *profile,
    dna_completion_cb callback,
    void *user_data
);
```

Add profile data struct for FFI:
```c
typedef struct {
    // Wallets
    char backbone[120];
    char kelvpn[120];
    char subzero[120];
    char cpunk_testnet[120];
    char btc[128];
    char eth[128];
    char sol[128];
    // Socials
    char telegram[128];
    char x[128];
    char github[128];
    // Bio
    char bio[512];
    // Avatar
    char avatar_base64[20484];
} dna_engine_profile_t;
```

### 2. C API Implementation (dna_engine.c)

Implement the two functions using existing `dna_load_identity()` and `dna_update_profile()` from dht_keyserver.

### 3. Flutter FFI Bindings (dna_bindings.dart)

Add:
- `dna_engine_profile_t` struct definition
- `dna_profile_cb` callback typedef
- `dna_engine_get_profile` function binding
- `dna_engine_update_profile` function binding

### 4. Flutter Engine Wrapper (dna_engine.dart)

Add:
```dart
class UserProfile {
  // Wallets
  String backbone;
  String kelvpn;
  String subzero;
  String cpunkTestnet;
  String btc;
  String eth;
  String sol;
  // Socials
  String telegram;
  String twitter;
  String github;
  // Bio & Avatar
  String bio;
  String? avatarBase64;
}

Future<UserProfile> getProfile();
Future<void> updateProfile(UserProfile profile);
```

### 5. Flutter Provider (profile_provider.dart)

New provider file:
```dart
final userProfileProvider = AsyncNotifierProvider<ProfileNotifier, UserProfile?>(
  ProfileNotifier.new,
);

class ProfileNotifier extends AsyncNotifier<UserProfile?> {
  Future<UserProfile?> build() async {
    final engine = await ref.watch(engineProvider.future);
    return engine.getProfile();
  }

  Future<void> save(UserProfile profile) async {
    state = const AsyncLoading();
    final engine = await ref.read(engineProvider.future);
    await engine.updateProfile(profile);
    state = AsyncData(profile);
  }
}
```

### 6. Flutter Screen (profile_editor_screen.dart)

New screen at `lib/screens/profile/profile_editor_screen.dart`:

**Features:**
- Collapsible sections (same as ImGui):
  - Cellframe Network Addresses (backbone, kelvpn, subzero, testnet)
  - External Wallet Addresses (btc, eth, sol)
  - Social Media Links (telegram, twitter, github)
  - Avatar Upload (64x64)
  - Bio (multiline, 512 char limit)
- Load profile on open (from DHT)
- Save button publishes to DHT
- Cancel button discards changes
- Status message display
- Loading indicator during DHT operations

**Avatar handling:**
- Use `image_picker` package for file selection
- Resize to 64x64 using native code or Dart package
- Convert to base64
- Preview before save

### 7. Navigation Integration

Add "Edit Profile" button to Settings screen that opens profile editor.

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| include/dna/dna_engine.h | Modify | Add profile struct + 2 functions |
| src/dna_engine.c | Modify | Implement get/update profile |
| lib/ffi/dna_bindings.dart | Modify | Add FFI bindings |
| lib/ffi/dna_engine.dart | Modify | Add Dart wrapper + UserProfile class |
| lib/providers/profile_provider.dart | Create | New provider |
| lib/providers/providers.dart | Modify | Export profile_provider |
| lib/screens/profile/profile_editor_screen.dart | Create | New screen |
| lib/screens/settings/settings_screen.dart | Modify | Add edit profile button |

## Dependencies

Already in pubspec.yaml:
- `image_picker: ^1.0.0` - For avatar file selection
- `flutter_riverpod` - State management

## Implementation Order

1. C API changes (dna_engine.h + dna_engine.c)
2. Flutter FFI bindings
3. Flutter engine wrapper
4. Flutter provider
5. Flutter screen UI
6. Settings integration
7. Testing

## Notes

- The ImGui implementation uses `dna_load_identity()` and `dna_update_profile()` directly
- We need to wrap these in dna_engine.h for clean FFI access
- Avatar resizing may need native implementation for Android
- Bio limit: 512 characters (enforced in UI + validated on save)
