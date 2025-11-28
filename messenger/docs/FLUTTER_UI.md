# DNA Messenger Flutter UI

**Last Updated:** 2025-11-28
**Status:** Phase 1 Complete (FFI Foundation)
**Target:** Android first, all platforms from single codebase

---

## Executive Summary

DNA Messenger is migrating from ImGui to Flutter for cross-platform UI. Flutter was chosen for:
- **Mobile-first**: First-class Android/iOS support
- **Single codebase**: Android, iOS, Linux, Windows, macOS (+ Web)
- **Dart FFI**: Clean interop with existing C API (`dna_engine.h`)
- **No Rust requirement**: Unlike Slint which requires Rust for Android

### Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | FFI Foundation | ✅ Complete |
| 2 | Core Screens | ✅ Complete |
| 3 | Full Features | 📋 Planned |
| 4 | Platform Builds | 📋 Planned |
| 5 | Testing & Polish | 📋 Planned |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Flutter UI Layer                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │   Screens (chat, contacts, wallet, groups, settings)       ││
│  │   Widgets (message_bubble, avatar, buttons)                ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                    Riverpod Providers                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │   EngineProvider | ContactsProvider | MessagesProvider     ││
│  │   IdentityProvider | WalletProvider | GroupsProvider       ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                   DnaEngine Wrapper (Dart)                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │   - Converts C callbacks → Dart Futures/Streams            ││
│  │   - Type-safe Dart API                                     ││
│  │   - Memory management                                       ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                    dart:ffi Bindings                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │   dna_bindings.dart (manual bindings, 600+ lines)          ││
│  └─────────────────────────────────────────────────────────────┘│
└──────────────────────────────│──────────────────────────────────┘
                               │ FFI
┌──────────────────────────────▼──────────────────────────────────┐
│                  dna_engine.h (C API - unchanged)               │
│                  25+ async functions, callback-based            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
dna_messenger_flutter/
├── android/                    # Android platform (jniLibs for .so)
├── ios/                        # iOS platform (Frameworks for .a)
├── linux/                      # Linux platform (libs for .so)
├── windows/                    # Windows platform (libs for .dll)
├── macos/                      # macOS platform (Frameworks for .a)
├── lib/
│   ├── main.dart               # ✅ Entry point with Riverpod
│   ├── ffi/
│   │   ├── dna_bindings.dart   # ✅ Manual FFI bindings (600+ lines)
│   │   └── dna_engine.dart     # ✅ High-level Dart wrapper (940 lines)
│   ├── providers/              # ✅ Riverpod state management
│   │   ├── engine_provider.dart
│   │   ├── identity_provider.dart
│   │   ├── contacts_provider.dart
│   │   ├── messages_provider.dart
│   │   └── theme_provider.dart
│   ├── screens/                # ✅ UI screens
│   │   ├── identity/identity_selection_screen.dart
│   │   ├── contacts/contacts_screen.dart
│   │   ├── chat/chat_screen.dart
│   │   └── home_screen.dart
│   ├── widgets/                # 📋 Reusable widgets
│   └── theme/
│       └── dna_theme.dart      # ✅ DNA/Club themes
├── ffigen.yaml                 # FFI generator config (reference)
└── pubspec.yaml                # Dependencies
```

---

## Phase Details

### Phase 1: FFI Foundation ✅ COMPLETE

**Completed:**
1. Created Flutter project with all platform targets
2. Configured ffigen.yaml (reference, manual bindings used)
3. Created manual FFI bindings (`dna_bindings.dart`)
   - All struct definitions (dna_contact_t, dna_message_t, etc.)
   - All callback typedefs (Native and Dart variants)
   - DnaBindings class with function lookups
4. Created high-level DnaEngine wrapper (`dna_engine.dart`)
   - Dart model classes (Contact, Message, Group, etc.)
   - Event sealed classes for stream
   - Callback-to-Future conversion using NativeCallable
   - All 25+ API functions wrapped

**Key Implementation Pattern:**
```dart
Future<List<Contact>> getContacts() async {
  final completer = Completer<List<Contact>>();
  final localId = _nextLocalId++;

  void onComplete(int requestId, int error, Pointer<dna_contact_t> contacts,
                  int count, Pointer<Void> userData) {
    if (error == 0) {
      final result = <Contact>[];
      for (var i = 0; i < count; i++) {
        result.add(Contact.fromNative((contacts + i).ref));
      }
      if (count > 0) {
        _bindings.dna_free_contacts(contacts, count);
      }
      completer.complete(result);
    } else {
      completer.completeError(DnaEngineException.fromCode(error, _bindings));
    }
    _cleanupRequest(localId);
  }

  final callback = NativeCallable<DnaContactsCbNative>.listener(onComplete);
  _pendingRequests[localId] = _PendingRequest(callback: callback);

  final requestId = _bindings.dna_engine_get_contacts(
    _engine,
    callback.nativeFunction.cast(),
    nullptr,
  );

  if (requestId == 0) {
    _cleanupRequest(localId);
    throw DnaEngineException(-1, 'Failed to submit request');
  }

  return completer.future;
}
```

---

### Phase 2: Core Screens ✅ COMPLETE

**Completed:**
1. Identity selection screen with create/restore wizards
2. Contacts list with online status indicators
3. Chat conversation with message bubbles
4. Message sending with status indicators
5. Theme provider with DNA/Club switching

**State Management (Riverpod):**
```dart
// Engine provider - singleton with cleanup
final engineProvider = AsyncNotifierProvider<EngineNotifier, DnaEngine>(
  EngineNotifier.new,
);

// Contacts with auto-refresh when identity changes
final contactsProvider = AsyncNotifierProvider<ContactsNotifier, List<Contact>>(
  ContactsNotifier.new,
);

// Conversation by contact fingerprint
final conversationProvider = AsyncNotifierProviderFamily<ConversationNotifier, List<Message>, String>(
  ConversationNotifier.new,
);
```

**Screens Implemented:**
- `IdentitySelectionScreen`: List identities, create with 3-step wizard, restore from seed
- `ContactsScreen`: List with online/offline indicators, pull-to-refresh, add contact dialog
- `ChatScreen`: Message bubbles, timestamps, status icons, input with send button
- `HomeScreen`: Routes between identity selection and contacts based on state

---

### Phase 3: Full Features (Planned)

**Tasks:**
1. Groups: list, create, invite, group chat
2. Wallet: balances, send tokens, QR receive, history
3. Profile: editor, viewer, avatar handling
4. Settings: theme switching
5. Name registration
6. Message wall / DNA Board

---

### Phase 4: Platform Builds (Planned)

**Tasks:**
1. **Android**: Copy libdna_lib.so to jniLibs/, test on devices
2. **Linux**: Link libdna_lib.so, test desktop layout
3. **Windows**: Cross-compile dna_lib.dll, bundle
4. **macOS**: Build universal binary, sign
5. **iOS**: Build framework, TestFlight (lower priority)

**Native Library Locations:**
```
dna_messenger_flutter/
├── android/app/src/main/jniLibs/
│   ├── arm64-v8a/libdna_lib.so
│   ├── armeabi-v7a/libdna_lib.so
│   └── x86_64/libdna_lib.so
├── linux/libs/libdna_lib.so
├── windows/libs/dna_lib.dll
├── macos/Frameworks/libdna_lib.a
└── ios/Frameworks/libdna_lib.a
```

---

### Phase 5: Testing & Polish (Planned)

**Tasks:**
1. Integration testing with DHT network
2. Performance profiling
3. Responsive layouts (mobile vs desktop)
4. Platform-specific polish
5. Documentation
6. Deprecate ImGui GUI (keep as fallback)

---

## Dependencies

```yaml
# pubspec.yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_riverpod: ^2.4.0
  riverpod_annotation: ^2.3.0
  ffi: ^2.1.0
  path_provider: ^2.1.0
  shared_preferences: ^2.2.0
  qr_flutter: ^4.1.0
  image_picker: ^1.0.0
  emoji_picker_flutter: ^1.6.0
  intl: ^0.19.0

dev_dependencies:
  ffigen: ^9.0.0
  riverpod_generator: ^2.3.0
  build_runner: ^2.4.0
```

---

## Building & Running

**Prerequisites:**
- Flutter SDK (3.11+)
- Native library built for target platform

**Development (Linux Desktop):**
```bash
cd dna_messenger_flutter

# Copy native library
cp ../build/libdna_lib.so linux/libs/

# Run
flutter run -d linux
```

**Android Build:**
```bash
# Build native library for Android
../build-android.sh arm64-v8a

# Copy to jniLibs
cp ../build-android-arm64-v8a/libdna_lib.so \
   android/app/src/main/jniLibs/arm64-v8a/

# Build APK
flutter build apk --release
```

---

## Theming

```dart
class DnaTheme {
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    colorScheme: ColorScheme.dark(
      surface: Color(0xFF151719),
      primary: Color(0xFF00FFCC),
      onPrimary: Color(0xFF151719),
    ),
    scaffoldBackgroundColor: Color(0xFF151719),
  );
}

class ClubTheme {
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    colorScheme: ColorScheme.dark(
      surface: Color(0xFF1A1816),
      primary: Color(0xFFF97834),
    ),
  );
}
```

---

## Reference Files

| File | Purpose |
|------|---------|
| `include/dna/dna_engine.h` | C API - FFI binding source |
| `imgui_gui/core/app_state.h` | State structure reference |
| `imgui_gui/helpers/engine_wrapper.h` | Callback patterns reference |
| `imgui_gui/screens/*.cpp` | UI reference for screens |
| `imgui_gui/theme_colors.h` | Theme colors to port |
| `build-android.sh` | Android NDK build |

---

## Known Issues

1. **ffigen libclang**: On some systems, ffigen can't find libclang.so. Workaround: use manual bindings (already done).

2. **Flutter SDK version**: Requires Flutter 3.11+ for latest ffi features. Check with `flutter --version`.

---

## Next Steps

1. Implement real-time event handling (DHT events → UI updates)
2. Add BIP39 mnemonic generation/parsing
3. Build groups screen and wallet screen
4. Test on Android device with native library
5. Add settings screen with theme toggle
