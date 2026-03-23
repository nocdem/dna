# DNA Connect Flutter UI

**Last Updated:** 2026-03-11
**Status:** Phase 4 — Design System + UI Redesign Complete
**Target:** Mobile-first, all platforms from single codebase

---

## Executive Summary

DNA Connect uses Flutter for cross-platform UI. Flutter was chosen for:
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
| 4 | Design System + UI Redesign | ✅ Complete |
| 5 | Platform Builds | 📋 Planned |
| 6 | Testing & Polish | 📋 Planned |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Flutter UI Layer                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │   Design System (lib/design_system/)                       ││
│  │   - Theme: colors, gradients, typography, spacing          ││
│  │   - Components: card, button, avatar, badge, chip, etc.    ││
│  │   - Navigation: bottom bar, app bar, more menu             ││
│  │   - Inputs: text field, search bar, switch                 ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │   Screens (home, messages, channels, more, wallet, settings)││
│  │   Navigation: Bottom tabs (Home, Messages, Channels, More) ││
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
├── assets/                    # App assets (no custom fonts bundled)
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
│   │   ├── event_handler.dart      # ✅ Real-time event handling + local notifications
│   │   ├── background_tasks_provider.dart  # ✅ DHT offline message polling
│   │   ├── channel_provider.dart    # ✅ Channel subscriptions, posts, discovery
│   │   └── wall_provider.dart      # ✅ Wall: WallFeedItem model, batch-fetch, image cache (v0.7.0+, refactored v1.0.0-rc70)
│   ├── screens/                # ✅ UI screens
│   │   ├── identity/identity_selection_screen.dart  # ✅ BIP39 integrated
│   │   ├── contacts/contacts_screen.dart
│   │   ├── chat/chat_screen.dart   # ✅ Selectable text, status icons, view profile
│   │   ├── chat/contact_profile_dialog.dart  # ✅ View contact's DHT profile
│   │   ├── groups/groups_screen.dart   # ✅ + GroupChatScreen
│   │   ├── wallet/wallet_screen.dart   # ✅ Send dialog
│   │   ├── settings/settings_screen.dart  # ✅ Name registration
│   │   ├── channels/channel_list_screen.dart      # ✅ Lists subscribed channels
│   │   ├── channels/channel_detail_screen.dart    # ✅ Shows posts in a channel
│   │   ├── channels/create_channel_screen.dart    # ✅ Create new channel form
│   │   ├── channels/discover_channels_screen.dart # ✅ Discover and subscribe to channels
│   │   ├── wall/wall_timeline_screen.dart  # ✅ Home tab (wall timeline + image attach)
│   │   ├── wall/wall_post_detail_screen.dart  # ✅ Post detail with threaded comments
│   │   ├── messages/messages_screen.dart   # ✅ Messages tab (unified chats + groups)
│   │   └── home_screen.dart
│   ├── widgets/                # ✅ Reusable widgets
│   │   ├── emoji_shortcode_field.dart  # ✅ Enter to send, :shortcode:
│   │   ├── formatted_text.dart     # ✅ Markdown + selectable
│   │   ├── wall_post_tile.dart     # ✅ Individual wall post display (with image + reply)
│   │   └── wall_comment_tile.dart  # ✅ Single comment display (threaded)
│   └── theme/
│       └── dna_theme.dart      # ✅ cpunk.io theme (system default fonts)
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
- `IdentitySelectionScreen`: Onboarding screen for create/restore identity (v0.3.0: no identity list - single-user model)
- `ContactsScreen`: List with last seen timestamps, pull-to-refresh, add contact dialog, DHT status indicator
- `ChatScreen`: Message bubbles, timestamps, status icons, input with send button, view contact profile
- `HomeScreen`: Main navigation (v0.3.0: identity always loaded before reaching this screen)

**Event Handling:**
- `EventHandler`: Listens to engine event stream, updates providers
- Contact online/offline status updates in real-time
- New messages added to conversations automatically
- Local notifications with sound for incoming messages (background + foreground when chat not open)
- `NotificationService` (singleton): `flutter_local_notifications` — Android (NotificationChannel), Linux (libnotify/D-Bus)
- DHT connection state tracked and displayed

**Presence (Online/Offline Status):**
- C heartbeat thread (10s) queries Nodus server for all contacts' presence
- Status transitions fire `DNA_EVENT_CONTACT_ONLINE`/`DNA_EVENT_CONTACT_OFFLINE` events
- Flutter `EventHandler` receives events and calls `updateContactStatus()` on `contactsProvider`
- No Dart-side polling — all presence logic is in C (v0.9.10+)
- Initial presence loaded on contacts fetch via `lookupPresence()` (one-time, from cache)

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
   - **Group Info Dialog** - View group details, members, GEK version
   - **Member Management (v0.6.73+)** - Owner can add/remove members via UI buttons
     - "+" button next to Members header (owner only)
     - "x" button next to each non-owner member (owner only)
     - GEK automatically rotated on add/remove for forward secrecy

3. **Wallet:**
   - Send tokens with recipient, amount selection
   - Supported tokens across 4 chains: **Cellframe** (CELL, CPUNK, USDC), **Ethereum** (ETH, USDT, USDC), **Solana** (SOL, USDT, USDC), **TRON** (TRX, USDT, USDC)
   - Transaction history UI with address resolution:
     - Resolves `otherAddress` to contact name (via profile wallet fields) or address book label
     - Resolution runs once per fetch, re-resolves reactively when contacts or address book change
     - Transaction detail bottom sheet with gradient header, tap-to-copy fields
     - "Add to Address Book" button in detail sheet (hidden if already saved)
   - Balances display per wallet (fetched via Cellframe RPC)
   - **Multi-token send via chat:** Transfer tokens directly from chat conversation
     - "$" button in chat input bar opens multi-token send bottom sheet
     - Token dropdown with 12 options across 4 chains (Cellframe, Ethereum, Solana, TRON)
     - Only tokens for chains where the contact has a registered wallet address are shown
     - Transaction speed selector (slow/normal/fast) only shown for Cellframe chain
     - Transfer message JSON includes `token`, `network`, and `chain` fields
     - Transfer bubble with gradient styling and blockchain verification (orange/green/red border)
   - **Note:** "Backbone" network name has been renamed to "Cellframe" throughout the codebase

4. **Profile/Identity:**
   - Nickname registration on DHT
   - Get registered name for current identity
   - Display name lookup for contacts

5. **Settings:**
   - Nickname registration works
   - Export seed phrase (placeholder)
   - Delete Account (v0.3.0: renamed from "Delete Identity")
   - Manage Contacts (view/remove contacts)

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
syncGroup(uuid)              // Sync group metadata + GEK from DHT
addGroupMember(uuid, fp)     // Add member (owner only, rotates GEK)
removeGroupMember(uuid, fp)  // Remove member (owner only, rotates GEK)

// Wallet
sendTokens(...)              // Send tokens
getTransactions(index, net)  // Transaction history
lookupProfile(fingerprint)   // Lookup any user's profile by fingerprint (for wallet address resolution)
getDexQuotes(from, to, amt)  // DEX swap quotes (SOL/ETH/Cellframe)

// Contacts
removeContact(fingerprint)   // Remove contact from list
```

**Screens Updated:**
- `identity_selection_screen.dart`: Real BIP39 mnemonic generation/validation
- `groups_screen.dart`: Create, accept, reject, open group chat
- `GroupChatScreen`: New screen for group messaging
- `wallet_screen.dart`: Send dialog with DNA fingerprint resolution + contact picker; Swap sheet with Solana/Ethereum/Cellframe DEX quotes, stale warning banner for order book DEX; Transaction detail bottom sheet with address resolution + Add to Address Book
- `settings_screen.dart`: Nickname registration, contacts management
- `update_required_screen.dart`: Full-screen blocker shown when app/library version is below DHT-published minimum — prevents app usage until updated
- `contacts_management_screen.dart`: View/remove contacts from Settings

**Send to DNA Identity Feature:**
- Contact picker button in send dialog to select from contacts
- Auto-detect DNA fingerprints (128-char hex) in recipient field
- Lookup fingerprint via DHT to resolve wallet address
- Visual indicator showing resolved contact name and address
- Validation prevents sending until fingerprint is successfully resolved

---

### Phase 4: Platform Builds (Planned)

**Tasks:**
1. **Android**: Copy libdna.so to jniLibs/, test on devices
2. **Linux**: Link libdna.so, test desktop layout
3. **Windows**: Cross-compile dna.dll, bundle
4. **macOS**: Build universal binary, sign
5. **iOS**: Build framework, TestFlight (lower priority)

**Native Library Locations:**
```
dna_messenger_flutter/
├── android/app/src/main/jniLibs/
│   ├── arm64-v8a/libdna.so
│   ├── armeabi-v7a/libdna.so
│   └── x86_64/libdna.so
├── linux/libs/libdna.so
├── windows/libs/dna.dll
├── macos/Frameworks/libdna.a
└── ios/Frameworks/libdna.a
```

---

### Phase 5: Testing & Polish (Planned)

**Tasks:**
1. Integration testing with DHT network
2. Performance profiling
3. Responsive layouts (mobile vs desktop)
4. Platform-specific polish
5. Documentation
6. Platform-specific polish

---

## Recent UI Changes (2026-03-23)

**Wall Performance Refactor (v1.0.0-rc70):**

Complete architectural refactor of the Wall (homepage feed) for performance. Eliminated N+1 provider problem.

**New model — `WallFeedItem` (`lib/providers/wall_provider.dart`):**
- Unified data object containing: `WallPost` + `commentCount` + `previewComments` (max 3) + `likeCount` + `isLikedByMe` + `authorDisplayName` + `authorAvatar` + `decodedImage`
- Assembled once by the provider; widgets receive complete data via constructor

**Refactored provider — `wallTimelineProvider`:**
- Now returns `List<WallFeedItem>` instead of `List<WallPost>`
- Batch-fetches comments and likes for all posts via `Future.wait` (parallel)
- Batch-prefetches unique author profiles via `contactProfileCacheProvider.prefetchProfiles()`
- `likePost(uuid)` — updates specific item in list without full refresh
- `refreshComments(uuid)` — updates comment count/preview for a specific post
- Removed `wallLikesProvider` — like data is now part of `WallFeedItem`

**Image cache — `_ImageCache` (static LRU, 50 items):**
- `decodePostImage(uuid, imageJson)` — decodes base64 once, caches `Uint8List` by post UUID
- Eliminates repeated `jsonDecode` + `base64Decode` on every widget `build()`

**Refactored widget — `WallPostTile` (`lib/widgets/wall_post_tile.dart`):**
- Now a pure `StatelessWidget` (was `ConsumerWidget`) — zero `ref.watch` calls
- Receives all data via constructor: `authorDisplayName`, `authorAvatar`, `decodedImage`, `likeCount`, `isLikedByMe`
- `_FireGlow` and `_BoostGlow` wrapped in `RepaintBoundary` for paint isolation
- Uses `DecoratedBox` instead of `Container` for const optimization

**Refactored screen — `WallTimelineScreen`:**
- Removed `_WallPostWithComments` wrapper (was the N+1 source — each instance watched 3 providers)
- All data comes from `WallFeedItem`, passed directly to `WallPostTile`
- Author profile bottom sheet uses pre-fetched data from `WallFeedItem`

**Updated screen — `WallPostDetailScreen`:**
- Gets like data from `wallTimelineProvider` (single source of truth)
- Calls `wallTimelineProvider.notifier.refreshComments()` after adding a comment
- Still uses `wallCommentsProvider` for full threaded comment list

**Performance impact:**
- ~15x fewer FFI calls on load (batched vs N+1)
- ~80% fewer widget rebuilds on scroll (pure widgets)
- Zero image decoding in `build()` (LRU cached)
- Paint isolation for expensive glow effects

---

## Wall Architecture (v0.7.0+, refactored v1.0.0-rc70)

**Wall Comments and Image Attachments:**

Screen — `WallPostDetailScreen` (`lib/screens/wall/wall_post_detail_screen.dart`):
- Detail view for a single wall post with threaded comments
- Full post rendered at top via `WallPostTile`
- Comment count header ("N comments" or "No comments yet")
- Threaded comment list: top-level comments followed by their indented replies
- Reply indicator bar shows "Replying to \<author\>" when a reply is in progress; dismiss with X
- Comment input field at the bottom with paper-plane send button; shows spinner while sending
- Refresh button in app bar (`FontAwesomeIcons.arrowsRotate`) invalidates `wallCommentsProvider`

Widget — `WallCommentTile` (`lib/widgets/wall_comment_tile.dart`):
- Displays a single comment: `DnaAvatar` (sm), author name, relative timestamp, body text
- Author falls back to first 12 chars of fingerprint when no name is registered
- Reply button (`FontAwesomeIcons.reply`) shown only on top-level comments (hidden when `isReply == true`)
- Indented via left padding (`DnaSpacing.xl`) when `isReply == true`

Widget — `WallPostTile` (`lib/widgets/wall_post_tile.dart`):
- Pure `StatelessWidget` — all data received via constructor (zero provider watches)
- Displays image from pre-decoded `Uint8List` (fast path) or falls back to `post.imageJson` decode
- Image is clipped with `radiusSm` rounded corners, constrained to max height 300px
- Fire glow (1-5 levels based on likes) and boost glow wrapped in `RepaintBoundary`

Provider — `wallCommentsProvider` (`lib/providers/wall_provider.dart`):
- `AsyncNotifierProviderFamily<WallCommentsNotifier, List<WallComment>, String>`
- Parameterized by post UUID; used by detail screen for full comment list
- `addComment(body, {parentCommentUuid})` calls `engine.wallAddComment()` then refreshes

FFI wrapper methods (`lib/ffi/dna_engine.dart`):
```dart
Future<WallPost> wallPostWithImage(String text, String imageJson)
Future<WallComment> wallAddComment(String postUuid, String body, {String? parentCommentUuid})
Future<List<WallComment>> wallGetComments(String postUuid)
Future<List<WallLike>> wallGetLikes(String postUuid)
Future<List<WallLike>> wallLike(String postUuid)
```

---

## Recent UI Changes (2025-12-06)

**Channels (RSS-like):**
- Named channels (UUID-based) with flat text posts, no threading
- Open posting: anyone can post to any channel
- Day-bucket discovery: discover channels by scanning recent days
- 7 default channels: General, Technology, Help, Announcements, Trading, Off Topic, Cpunk
- Channel subscriptions with DHT sync for multi-device
- Files: `channel_list_screen.dart`, `channel_detail_screen.dart`, `create_channel_screen.dart`, `discover_channels_screen.dart`, `channel_provider.dart`

**Channel Post Daily Bucket Pagination (v0.7.5+):**

Channel posts are stored in daily DHT buckets. The `ChannelPostsNotifier` supports incremental loading:

- `_daysBack` state: tracks how many days of posts are currently loaded (starts at 3)
- `canLoadMore` getter: returns `true` if `_daysBack < 30` (max)
- `loadMore()` method: increments `_daysBack` by 3 and re-fetches posts from DHT
- `channelGetPosts(uuid, daysBack: N)` FFI call passes `days_back` parameter to C engine

UI in `ChannelDetailScreen`:
- "Load older posts" button appears at bottom of post list when `canLoadMore` is true
- Button triggers `ref.read(channelPostsProvider(uuid).notifier).loadMore()`
- Shows loading indicator while fetching, then appends older posts to the list

**Navigation:**
- Bottom tab navigation with 4 tabs: **[Home] [Messages] [Channels] [More]**
- **Home** tab: `WallTimelineScreen` — contacts' wall posts timeline with create/delete
- **Messages** tab: `MessagesScreen` — unified view with [All] [Chats] [Groups] filter chips
- **Channels** tab: `ChannelListScreen` — subscribed channels with unread indicators
- **More** tab: `MoreScreen` — wallet, settings, contacts management (unchanged)
- Home (wall timeline) is the default landing page (index 0)

**Typography:**
- The app uses system default fonts (no custom fonts are bundled)
- Font Awesome icons are used throughout the UI (`font_awesome_flutter` package)

**Chat Improvements:**
- Selectable message text with copy support (Ctrl+C, context menu)
- Selection highlight uses theme primary color
- Markdown-style formatting: `*bold*`, `_italic_`, `~strikethrough~`
- Code formatting: inline \`code\` and \`\`\`code blocks\`\`\` with monospace font
- Async message queue with optimistic UI (spinner while sending)
- Message status indicators: pending (spinner), sent (checkmark), failed (red X)
- Enter sends message, Shift+Enter adds newline
- Emoji picker with shortcode support (:smile: etc.)
- **Multi-token transfer via chat:** Send tokens from any supported chain directly from conversation via "$" button. Token dropdown shows 12 options across 4 chains (Cellframe, Ethereum, Solana, TRON), filtered by contact's available wallet addresses. Verified transfer bubble (orange=pending, green=verified, red=failed). Message type: `token_transfer`. Both sides verify independently via blockchain RPC.

**Background Tasks:**
- Initial DHT offline message poll on login (15 second delay)
- DHT listen (push notifications) for real-time message delivery
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
cp ../build/libdna.so linux/libs/

# Run
flutter run -d linux
```

**Android Build:**
```bash
# Build native library for Android
../build-android.sh arm64-v8a

# Copy to jniLibs
cp ../build-android-arm64-v8a/libdna.so \
   android/app/src/main/jniLibs/arm64-v8a/

# Build APK
flutter build apk --release
```

---

## Theming

Single theme based on cpunk.io color palette with system default fonts:

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
  static ThemeData get theme => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
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

**Fonts:** The app uses system default fonts (no custom font files are bundled). Font Awesome icons are used for all UI icons via the `font_awesome_flutter` package.

---

## Reference Files

| File | Purpose |
|------|---------|
| `include/dna/dna_engine.h` | C API - FFI binding source |
| `lib/providers/*.dart` | State management |
| `lib/screens/**/*.dart` | UI implementation |
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

---

## Internationalization (i18n)

**Framework:** Flutter gen-l10n (official Flutter solution)
**Supported Languages:** English (source), Turkish (Türkçe)
**Fallback:** English for unsupported locales

### File Structure

```
lib/l10n/
  app_en.arb              # English strings (source/template)
  app_tr.arb              # Turkish translations
  app_localizations.dart  # Generated (do not edit)
  app_localizations_en.dart  # Generated
  app_localizations_tr.dart  # Generated

l10n.yaml                 # gen-l10n configuration (project root)

lib/providers/
  locale_provider.dart    # Language selection state (SharedPreferences)
```

### How to Use in Screens

```dart
import '../../l10n/app_localizations.dart';

// In build() method:
final l10n = AppLocalizations.of(context);
Text(l10n.settingsTitle)  // "Settings" or "Ayarlar"

// Parameterized strings:
Text(l10n.contactsLastSeen('5 min ago'))
Text(l10n.walletSendTitle('ETH'))
```

### How to Add a New String

1. Add key + English value to `lib/l10n/app_en.arb`
2. Add key + Turkish value to `lib/l10n/app_tr.arb`
3. Run `flutter gen-l10n` (or just `flutter build`)
4. Use `AppLocalizations.of(context).keyName` in code

For parameterized strings, add `@key` metadata in app_en.arb only:
```json
"greeting": "Hello {name}",
"@greeting": {
  "placeholders": {
    "name": { "type": "String" }
  }
}
```

### How to Add a New Language

1. Create `lib/l10n/app_XX.arb` (copy from app_en.arb, translate values)
2. Set `"@@locale": "XX"` at the top
3. Do NOT include `@key` metadata entries (only in template file)
4. Add the language option to `_LanguageSection` in `settings_screen.dart`
5. Run `flutter gen-l10n`

### Language Selection

Users choose language in **Settings > Language**:
- **System default** — follows device language (falls back to English)
- **English** — forced English
- **Türkçe** — forced Turkish

Persisted via SharedPreferences (`app_locale` key). Managed by `localeProvider` (Riverpod StateNotifier).
