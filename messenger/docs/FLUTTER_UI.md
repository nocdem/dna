# DNA Messenger Flutter UI

**Last Updated:** 2025-12-06
**Status:** Phase 3 Complete (Full Features)
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
| 3 | Full Features | ✅ Complete |
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
├── assets/
│   └── fonts/                  # ✅ Bundled fonts
│       ├── NotoSans-Regular.ttf
│       ├── NotoSans-Bold.ttf
│       ├── NotoSans-Italic.ttf
│       ├── NotoSans-BoldItalic.ttf
│       ├── NotoSansMono-Regular.ttf
│       └── NotoSansMono-Bold.ttf
├── lib/
│   ├── main.dart               # ✅ Entry point with Riverpod
│   ├── ffi/
│   │   ├── dna_bindings.dart   # ✅ Manual FFI bindings (1000+ lines)
│   │   └── dna_engine.dart     # ✅ High-level Dart wrapper (1400+ lines)
│   ├── providers/              # ✅ Riverpod state management
│   │   ├── engine_provider.dart
│   │   ├── identity_provider.dart  # ✅ BIP39 methods
│   │   ├── contacts_provider.dart
│   │   ├── messages_provider.dart  # ✅ Async queue, optimistic UI
│   │   ├── groups_provider.dart    # ✅ Group actions
│   │   ├── wallet_provider.dart    # ✅ Send/transactions
│   │   ├── profile_provider.dart   # ✅ User profile
│   │   ├── theme_provider.dart
│   │   ├── event_handler.dart      # ✅ Real-time event handling
│   │   ├── background_tasks_provider.dart  # ✅ DHT offline message polling
│   │   └── feed_provider.dart      # 🔒 Disabled (placeholder)
│   ├── screens/                # ✅ UI screens
│   │   ├── identity/identity_selection_screen.dart  # ✅ BIP39 integrated
│   │   ├── contacts/contacts_screen.dart
│   │   ├── chat/chat_screen.dart   # ✅ Selectable text, status icons
│   │   ├── groups/groups_screen.dart   # ✅ + GroupChatScreen
│   │   ├── wallet/wallet_screen.dart   # ✅ Send dialog
│   │   ├── settings/settings_screen.dart  # ✅ Name registration
│   │   ├── feed/feed_screen.dart   # 🔒 Disabled (placeholder)
│   │   └── home_screen.dart
│   ├── widgets/                # ✅ Reusable widgets
│   │   ├── emoji_shortcode_field.dart  # ✅ Enter to send, :shortcode:
│   │   └── formatted_text.dart     # ✅ Markdown + selectable
│   └── theme/
│       └── dna_theme.dart      # ✅ cpunk.io theme + Noto Sans font
├── ffigen.yaml                 # FFI generator config (reference)
└── pubspec.yaml                # Dependencies + font declarations
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
- `ContactsScreen`: List with last seen timestamps, pull-to-refresh, add contact dialog, DHT status indicator
- `ChatScreen`: Message bubbles, timestamps, status icons, input with send button
- `HomeScreen`: Routes between identity selection and contacts based on state

**Event Handling:**
- `EventHandler`: Listens to engine event stream, updates providers
- Contact online/offline status updates in real-time
- New messages added to conversations automatically
- DHT connection state tracked and displayed

**Presence Lookup (Last Seen):**
- On contacts load/refresh, queries DHT for each contact's presence
- `engine.lookupPresence(fingerprint)` returns DateTime when contact was last online
- Contacts sorted by most recently seen first
- 5-second timeout per lookup to avoid blocking UI
- Falls back to local data if DHT query fails

```dart
// ContactsNotifier queries DHT presence for each contact
Future<List<Contact>> _updateContactsPresence(DnaEngine engine, List<Contact> contacts) async {
  final futures = contacts.map((contact) async {
    try {
      final lastSeen = await engine
          .lookupPresence(contact.fingerprint)
          .timeout(const Duration(seconds: 5));
      if (lastSeen.millisecondsSinceEpoch > 0) {
        return Contact(..., lastSeen: lastSeen);
      }
    } catch (e) { /* timeout or error */ }
    return contact;
  });
  return Future.wait(futures);
}
```

---

### Phase 3: Full Features ✅ COMPLETE

**Completed:**

1. **BIP39 Integration:**
   - Real mnemonic generation via native library
   - Mnemonic validation
   - Seed derivation from mnemonic
   - Identity creation from mnemonic

2. **Groups:**
   - Create groups with name
   - Accept/reject invitations
   - Group chat screen with message sending
   - Group list with member counts

3. **Wallet:**
   - Send tokens with recipient, amount selection
   - Supported tokens: **CPUNK, CELL only** (Backbone network)
   - Transaction history UI with full details dialog
   - Balances display per wallet (fetched via Cellframe RPC)

4. **Profile/Identity:**
   - Nickname registration on DHT
   - Get registered name for current identity
   - Display name lookup for contacts

5. **Settings:**
   - Nickname registration works
   - Export seed phrase (placeholder)
   - Switch identity

**FFI Functions Added (11 new):**
```dart
// BIP39
generateMnemonic()           // 24-word mnemonic
validateMnemonic(mnemonic)   // Validate words
deriveSeeds(mnemonic)        // Derive signing/encryption seeds

// Identity
registerName(name)           // Register on DHT
getDisplayName(fingerprint)  // Lookup name
getRegisteredName()          // Current identity's name

// Groups
createGroup(name, members)   // Create new group
sendGroupMessage(uuid, msg)  // Send to group
acceptInvitation(uuid)       // Accept invite
rejectInvitation(uuid)       // Decline invite

// Wallet
sendTokens(...)              // Send tokens
getTransactions(index, net)  // Transaction history
```

**Screens Updated:**
- `identity_selection_screen.dart`: Real BIP39 mnemonic generation/validation
- `groups_screen.dart`: Create, accept, reject, open group chat
- `GroupChatScreen`: New screen for group messaging
- `wallet_screen.dart`: Send dialog (CPUNK/CELL on Backbone) + Transaction History UI
- `settings_screen.dart`: Nickname registration works

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

## Recent UI Changes (2025-12-06)

**Feed Disabled (PLACEHOLDER):**
- Feed feature temporarily disabled pending reimplementation
- Files preserved: `feed_screen.dart`, `feed_provider.dart`
- Will be reimplemented in future update

**Navigation:**
- Hamburger drawer navigation
- Chats is now the default landing page (index 0)
- Drawer header shows: Avatar + display name + "Switch Identity" button
- Navigation order: Chats, Groups, Wallet, Settings

**Typography:**
- Custom fonts bundled: Noto Sans (regular, bold, italic, bold-italic)
- Monospace font: Noto Sans Mono for code blocks
- Fonts located in `assets/fonts/`

**Chat Improvements:**
- Selectable message text with copy support (Ctrl+C, context menu)
- Selection highlight uses theme primary color
- Markdown-style formatting: `*bold*`, `_italic_`, `~strikethrough~`
- Code formatting: inline \`code\` and \`\`\`code blocks\`\`\` with monospace font
- Async message queue with optimistic UI (spinner while sending)
- Message status indicators: pending (spinner), sent (checkmark), failed (red X)
- Enter sends message, Shift+Enter adds newline
- Emoji picker with shortcode support (:smile: etc.)

**Background Tasks:**
- Periodic DHT offline message polling (2 minute interval)
- Auto-refresh contacts and conversations on new messages

**Linux Desktop:**
- Native GTK window decorations (follows system theme)
- Clean shutdown on window close button
- Minimum window size: 400x600

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

Single theme based on cpunk.io color palette with Noto Sans fonts:

```dart
class DnaColors {
  static const background = Color(0xFF050712);  // Dark navy
  static const surface = Color(0xFF111426);     // Panel blue-gray
  static const primary = Color(0xFF00F0FF);     // Cyan accent
  static const accent = Color(0xFFFF2CD8);      // Magenta
  static const text = Color(0xFFF5F7FF);        // Off-white
  static const textMuted = Color(0xFF9AA4D4);   // Light blue-gray
  static const textSuccess = Color(0xFF40FF86); // Green
  static const textWarning = Color(0xFFFF8080); // Red
}

class DnaTheme {
  static const String _fontFamily = 'NotoSans';

  static ThemeData get theme => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    fontFamily: _fontFamily,
    scaffoldBackgroundColor: DnaColors.background,
    colorScheme: ColorScheme.dark(
      surface: DnaColors.surface,
      primary: DnaColors.primary,
      secondary: DnaColors.accent,
    ),
    textSelectionTheme: TextSelectionThemeData(
      selectionColor: DnaColors.primary.withAlpha(100),
      cursorColor: DnaColors.primary,
      selectionHandleColor: DnaColors.primary,
    ),
  );
}
```

**Fonts (bundled in assets/fonts/):**
- `NotoSans` - Default UI font (Regular, Bold, Italic, BoldItalic)
- `NotoSansMono` - Code blocks and inline code (Regular, Bold)

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

1. ~~Add BIP39 mnemonic generation/parsing~~ ✅ Complete
2. ~~Build groups screen and wallet screen~~ ✅ Complete
3. Test on Android device with native library (Phase 4)
4. ~~Add settings screen with full options~~ ✅ Complete
5. Build and test on all platforms (Phase 4)
6. Add QR code generation for wallet receive
7. Add group conversation history display
8. Integration testing with DHT network
