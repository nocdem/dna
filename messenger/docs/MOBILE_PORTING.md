# DNA Messenger Mobile Porting Guide

**Last Updated:** 2026-01-18
**Status:** Android SDK Complete (Phases 1-6, 14)
**Target:** Android first, iOS later

---

## Executive Summary

DNA Messenger has been successfully ported to Android. The Android SDK provides JNI bindings for all core functionality, with a complete Java API and Gradle project structure ready for app development.

### Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core Library Extraction | ✅ Complete (already separated) |
| 2 | Platform Abstraction | ✅ Complete |
| 3 | HTTP Abstraction | ✅ Complete (CURL via NDK) |
| 4 | Android NDK Build Config | ✅ Complete |
| 5 | OpenDHT-PQ Android Port | ✅ Complete (arm64-v8a) |
| 6 | JNI Bindings | ✅ Complete (26 functions) |
| 7 | Android UI | 🚧 In Progress |
| 8 | iOS Port | 📋 Future |
| **14** | **DHT-Only Messaging + ForegroundService** | ✅ **Complete** |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Android App (Phase 7)                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │        Flutter UI (Dart + dart:ffi)                     ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │     Java SDK (io.cpunk.dna.DNAEngine) ✅ COMPLETE       ││
│  │   - DNAEngine.java (singleton, callbacks)               ││
│  │   - Contact, Message, Group, Invitation classes         ││
│  │   - Wallet, Balance, Transaction classes                ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │       JNI Bridge (libdna_jni.so) ✅ COMPLETE            ││
│  │   - 26 native methods                                   ││
│  │   - 16MB stripped (arm64-v8a)                           ││
│  │   - All dependencies statically linked                  ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              dna_engine.h (C API)                       ││
│  │   - Async callbacks (non-blocking)                      ││
│  │   - Opaque types (dna_engine_t*)                        ││
│  │   - Memory management (dna_free_*)                      ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Core Libraries (C/C++)                     │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐│
│  │ libdna_lib│ │libdht_lib │ │  libkem   │ │   libdsa     ││
│  │  (1.4MB)  │ │  (DHT)    │ │ (Kyber)   │ │ (Dilithium)  ││
│  └───────────┘ └───────────┘ └───────────┘ └──────────────┘│
│  ┌───────────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │ libtransport_lib  │ │libopendht  │                      │
│  │   (P2P + DHT)     │ │   (PQ)     │                      │
│  └───────────────────┘ └────────────┘                      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│               Platform Abstraction Layer                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              qgp_platform.h API                         ││
│  │   - qgp_platform_app_data_dir()                         ││
│  │   - qgp_platform_cache_dir()                            ││
│  │   - qgp_platform_set_app_dirs()                         ││
│  │   - qgp_platform_network_state()                        ││
│  │   - qgp_platform_random()                               ││
│  └─────────────────────────────────────────────────────────┘│
│       │              │              │              │         │
│  ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐  │
│  │ Linux   │   │ Windows  │   │ Android  │   │  iOS     │  │
│  │  .c     │   │   .c     │   │   .c ✅  │   │  .c 📋   │  │
│  └─────────┘   └──────────┘   └──────────┘   └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## What's Ready for Mobile

### 1. Core Libraries (100% Portable)

| Library | Size | Purpose | Mobile Status |
|---------|------|---------|---------------|
| `libkem.a` | ~200 KB | Kyber1024 (ML-KEM-1024) | ✅ Pure C |
| `libdsa.a` | ~300 KB | Dilithium5 (ML-DSA-87) | ✅ Pure C |
| `libdna_lib.a` | 1.4 MB | Messenger core | ✅ Pure C |
| `libtransport_lib.a` | ~500 KB | P2P + NAT | ✅ POSIX sockets |
| ~~`libjuice.a`~~ | - | ICE/STUN/TURN | ❌ Removed v0.4.61 |

### 2. Public API (`include/dna/dna_engine.h`)

The engine API is designed for mobile:
- **Async/callback-based** - Non-blocking operations
- **Clean C interface** - Works with JNI (Android) and FFI (iOS)
- **Opaque types** - Memory-safe, ABI-stable
- **973 lines** of documented API

Key functions:
```c
// Lifecycle
dna_engine_t* dna_engine_create(const char *data_dir);
void dna_engine_destroy(dna_engine_t *engine);

// Identity
dna_request_id_t dna_engine_load_identity(engine, fingerprint, callback, user_data);
dna_request_id_t dna_engine_create_identity(engine, signing_seed, encryption_seed, callback, user_data);

// Messaging
dna_request_id_t dna_engine_send_message(engine, recipient, message, callback, user_data);
dna_request_id_t dna_engine_get_conversation(engine, contact, callback, user_data);

// Events (pushed from engine)
void dna_engine_set_event_callback(engine, callback, user_data);
```

### 3. Platform Abstraction (`crypto/utils/qgp_platform.h`)

Mobile-ready functions added:
```c
// Application directories (sandboxed on mobile)
const char* qgp_platform_app_data_dir(void);
const char* qgp_platform_cache_dir(void);
int qgp_platform_set_app_dirs(const char *data_dir, const char *cache_dir);

// Network state (mobile network awareness)
qgp_network_state_t qgp_platform_network_state(void);
void qgp_platform_set_network_callback(callback, user_data);

// Platform detection
#if QGP_PLATFORM_ANDROID
#if QGP_PLATFORM_IOS
#if QGP_PLATFORM_MOBILE
```

---

## Android Build Instructions

### Prerequisites

1. **Android NDK** (r21+ recommended, r25c ideal)
   ```bash
   # Via Android Studio
   Tools > SDK Manager > SDK Tools > NDK (Side by side)

   # Or direct download
   https://developer.android.com/ndk/downloads
   ```

2. **Set environment variable**
   ```bash
   export ANDROID_NDK=$HOME/Android/Sdk/ndk/25.2.9519653
   # Or wherever your NDK is installed
   ```

### Build

```bash
cd /opt/dna-messenger

# Build for ARM64 (recommended)
./build-android.sh arm64-v8a

# Build for other ABIs
./build-android.sh armeabi-v7a  # 32-bit ARM
./build-android.sh x86_64       # Emulator
```

### Output

```
build-android-arm64-v8a/
├── libdna_lib.a           # Main messenger library
├── libdht_lib.a           # DHT networking
├── libkem.a               # Kyber1024
├── libdsa.a               # Dilithium5
├── libtransport_lib.a     # P2P transport
└── libopendht.a           # OpenDHT-PQ (libjuice removed v0.4.61)
```

---

## Completed Work

### Phase 5: OpenDHT-PQ Android Build ✅

**Status:** Complete (arm64-v8a)

Successfully built OpenDHT-PQ for Android with all dependencies:
- C++17 support via NDK r26d
- Threading works correctly (std::thread)
- POSIX sockets work on Android
- getrandom() available on API 24+

**Build tested with:**
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-24 \
      -DBUILD_GUI=OFF \
      -DANDROID=ON ..
```

### Phase 6: JNI Bindings ✅

**Status:** Complete (26 native methods)

**Android SDK Structure:**
```
android/
├── app/
│   ├── build.gradle
│   ├── proguard-rules.pro
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/io/cpunk/dna/
│       │   ├── DNAEngine.java     # Main SDK class
│       │   ├── Contact.java       # Contact data class
│       │   ├── Message.java       # Message data class
│       │   ├── Group.java         # Group data class
│       │   ├── Invitation.java    # Invitation data class
│       │   ├── Wallet.java        # Wallet data class
│       │   ├── Balance.java       # Balance data class
│       │   ├── Transaction.java   # Transaction data class
│       │   └── DNAEvent.java      # Event wrapper
│       └── jniLibs/arm64-v8a/
│           ├── libdna_jni.so      # 16MB (stripped)
│           └── libc++_shared.so   # 1.8MB (NDK C++ runtime)
├── build.gradle
├── gradle.properties
└── settings.gradle
```

**JNI Native Methods (26 total):**
- `nativeCreate`, `nativeDestroy`
- `nativeCreateIdentity`, `nativeLoadIdentity`, `nativeListIdentities`
- `nativeGetFingerprint`, `nativeRegisterName`, `nativeGetDisplayName`
- `nativeGetContacts`, `nativeAddContact`, `nativeGetConversation`
- `nativeSendMessage`, `nativeSendGroupMessage`
- `nativeGetGroups`, `nativeCreateGroup`, `nativeJoinGroup`, `nativeLeaveGroup`
- `nativeGetInvitations`, `nativeAcceptInvitation`, `nativeRejectInvitation`, `nativeSendInvitation`
- `nativeListWallets`, `nativeGetBalances`, `nativeGetTransactions`
- `nativeIsPeerOnline`, `nativeRefreshPresence`

**Example Usage:**
```java
// Initialize
DNAEngine engine = DNAEngine.getInstance();
engine.initialize(context, new DNAEngine.InitCallback() {
    @Override
    public void onInitialized() {
        // Load identity
        engine.loadIdentity(fingerprint, new DNAEngine.IdentityCallback() {
            @Override
            public void onIdentityLoaded(String name, String fingerprint) {
                // Ready to use
            }
        });
    }
});

// Send message
engine.sendMessage(recipientFingerprint, "Hello!", callback);

// Clean up
engine.shutdown();
```

### Phase 14: DHT-Only Messaging + ForegroundService ✅

**Status:** Complete (2025-12-24)

Phase 14 changed the messaging architecture to use DHT-only delivery (no P2P attempts).
This required adding a ForegroundService for Android to ensure reliable background operation.

**Why DHT-Only?**
- Mobile platforms have strict background execution restrictions
- P2P connections fail when app is backgrounded (Android Doze mode, iOS suspension)
- DHT queue provides reliable, consistent delivery across all platforms
- P2P infrastructure preserved for future audio/video calls

#### Android ForegroundService

**File:** `dna_messenger_flutter/android/app/src/main/kotlin/io/cpunk/dna_messenger/DnaMessengerService.kt`

**Features:**
- Keeps DHT connection alive when app is backgrounded
- Polls for offline messages every 60 seconds
- Uses `PARTIAL_WAKE_LOCK` to prevent CPU sleep during poll
- Displays low-priority notification (required for Android 8+)
- Supports START, STOP, and POLL_NOW actions

**Service Configuration:**
```kotlin
companion object {
    private const val NOTIFICATION_ID = 1001
    private const val CHANNEL_ID = "dna_messenger_service"
    private const val POLL_INTERVAL_MS = 60_000L  // 60 seconds
}
```

**AndroidManifest.xml Permissions Required:**
```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
<uses-permission android:name="android.permission.WAKE_LOCK" />

<service
    android:name=".DnaMessengerService"
    android:enabled="true"
    android:exported="false"
    android:foregroundServiceType="remoteMessaging" />
```

**Flutter Integration:**

```dart
// Start service when app goes to background
void startBackgroundService() {
  if (Platform.isAndroid) {
    const platform = MethodChannel('io.cpunk.dna_messenger/service');
    platform.invokeMethod('startService');
  }
}

// Stop service when app comes to foreground
void stopBackgroundService() {
  if (Platform.isAndroid) {
    const platform = MethodChannel('io.cpunk.dna_messenger/service');
    platform.invokeMethod('stopService');
  }
}
```

**DHT Listen API Extensions (Phase 14):**

The DHT listen API was extended to support reliable Android background operation:

```c
// Maximum simultaneous listeners (prevents resource exhaustion)
#define DHT_MAX_LISTENERS 1024

// Extended listen with cleanup callback
size_t dht_listen_ex(ctx, key, key_len, callback, user_data, cleanup_fn);

// Cancel all listeners (for shutdown)
void dht_cancel_all_listeners(ctx);

// Re-register listeners after network restored
size_t dht_resubscribe_all_listeners(ctx);
```

**Network Change Handling (v0.3.93+):**

When network connectivity changes (WiFi ↔ Cellular), the DHT UDP socket becomes invalid.
The ForegroundService monitors network changes and triggers DHT reinitialization:

```kotlin
// DnaMessengerService.kt - Network monitoring
private val networkCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
        if (currentNetworkId != null && currentNetworkId != network.toString()) {
            // Network switched - notify Flutter to reinit DHT
            sendBroadcast(Intent("io.cpunk.dna_messenger.NETWORK_CHANGED"))
        }
        currentNetworkId = network.toString()
    }
}
```

```c
// C Layer - DHT Reinit
int dht_singleton_reinit(void);       // Restart DHT with stored identity
int dna_engine_network_changed(engine); // High-level API for network change
```

```dart
// Flutter - Handle network change
void _handleNetworkChange() async {
  final result = engine.networkChanged();
  if (result == 0) {
    await _pollOfflineMessages();  // Check for messages during switch
  }
}
```

#### Single-Owner Model with Identity Lock (v0.6.0+)

**Each owner (Flutter/Service) creates and destroys its own engine with file-based mutex.**

v0.6.0 introduces an identity lock mechanism that prevents race conditions between
Flutter and ForegroundService. When identity is loaded, the engine acquires a file lock.
Only one process can hold the lock at a time.

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│               IDENTITY (persistent storage)                  │
│  - fingerprint (SharedPreferences)                          │
│  - mnemonic → derives DHT keys on demand                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐       ┌───────────────────────┐
│   FLUTTER (foreground)│       │   SERVICE (background)│
│                       │       │                       │
│   engine->dht_ctx     │       │   engine->dht_ctx     │
│   (engine-owned)      │       │   (engine-owned)      │
│                       │       │                       │
│   identity_lock_fd    │       │   identity_lock_fd    │
│   (file-based mutex)  │       │   (file-based mutex)  │
└───────────────────────┘       └───────────────────────┘

         ▲                               ▲
         │         FILE LOCK             │
         └───────────── ⚡ ───────────────┘

    Only ONE can hold the identity lock at a time.
```

**Lifecycle Flow:**

1. **App Opens:**
   - Service checks lock: `nativeIsIdentityLocked(dataDir)` → returns true if Flutter holds it
   - Flutter creates engine with `dna_engine_create()`
   - Flutter loads identity → acquires identity lock + creates engine-owned DHT
   - Service releases its engine when `flutterActive=true`

2. **App Closes:**
   - Flutter destroys engine → releases identity lock
   - Service waits, then creates new engine
   - Service loads identity (minimal mode) → acquires lock + creates DHT
   - DHT reconnects in ~2-3 seconds

**Trade-off:** 2-3 second DHT reconnect when switching between Flutter and Service.

**Benefit:** File-based lock guarantees no race conditions. Engine owns its DHT context.

**C API:**
```c
// Full initialization (Flutter uses this)
dna_request_id_t dna_engine_load_identity(engine, fingerprint, password, callback, user_data);

// Minimal initialization - DHT + listeners only (Service uses this)
dna_request_id_t dna_engine_load_identity_minimal(engine, fingerprint, password, callback, user_data);

// Check if identity is loaded
bool dna_engine_is_identity_loaded(dna_engine_t *engine);

// Check if transport layer is ready
bool dna_engine_is_transport_ready(dna_engine_t *engine);
```

**Platform Abstraction (identity lock):**
```c
// qgp_platform.h
int qgp_platform_acquire_identity_lock(const char *data_dir);  // Returns fd or -1
void qgp_platform_release_identity_lock(int lock_fd);
int qgp_platform_is_identity_locked(const char *data_dir);     // Returns 1 if locked
```

**JNI API:**
```c
// Service uses synchronous minimal load (blocking, for simplicity)
int nativeLoadIdentityMinimalSync(fingerprint);  // Returns 0 on success, -117 if locked

// Check if identity locked by Flutter
bool nativeIsIdentityLocked(dataDir);

// Release service's engine (when Flutter takes over)
void nativeReleaseEngine();

// Check if identity loaded
bool nativeIsIdentityLoaded();
```

**What minimal mode skips:**
- P2P transport layer
- Presence heartbeat
- Contact sync from DHT
- Pending message retry
- Wallet creation

**What minimal mode keeps:**
- DHT connection (engine-owned context)
- DHT listeners (for message notifications)

#### Engine-Owned DHT Context (v0.6.0+)

Each engine now owns its own DHT context (no global singleton):

```c
struct dna_engine {
    dht_context_t *dht_ctx;      // Engine owns this
    int identity_lock_fd;         // File lock (-1 if not held)

    // v0.6.1+: Background thread tracking for clean shutdown
    pthread_t setup_listeners_thread;
    pthread_t stabilization_retry_thread;
    bool setup_listeners_running;
    bool stabilization_retry_running;
    pthread_mutex_t background_threads_mutex;
    // ... other fields
};
```

The singleton pattern is kept for backwards compatibility using "borrowed context":
- Engine creates DHT via `dht_create_context_with_identity()`
- Engine lends to singleton via `dht_singleton_set_borrowed_context(engine->dht_ctx)`
- Code using `dht_singleton_get()` still works
- On destroy: clear borrowed context, then free engine's context

#### Background Thread Tracking (v0.6.1+)

Background threads are now tracked and joined on shutdown to prevent use-after-free crashes:

1. **Listener setup thread** - spawned on DHT connect to setup listeners
2. **Stabilization retry thread** - spawned on identity load, waits 15s then retries messages

Previously these were detached (`pthread_detach`), which caused crashes when the engine was destroyed while threads were still running. Now:
- Threads check `shutdown_requested` flag after sleeps
- Engine tracks thread handles and running state
- `dna_engine_destroy()` joins threads before freeing resources

#### Coordination Summary (v0.6.0+)

Flutter and ForegroundService coordination:

1. **When Flutter opens:** Flutter acquires lock, service detects lock and releases its engine
2. **When Flutter closes:** Flutter releases lock, service acquires lock with minimal mode

**Auto-Upgrade from Minimal to Full Mode (v0.5.26+):**

If ForegroundService loads identity in minimal mode before Flutter opens:
1. Flutter's `loadIdentity()` detects transport is not ready via `isTransportReady()`
2. Flutter proceeds to call C `dna_engine_load_identity()` (full mode)
3. C code frees existing messenger and reinitializes with transport

**Platform Handler (Flutter side):**
```dart
// lib/platform/android/android_platform_handler.dart

@override
Future<void> onResume(DnaEngine engine) async {
  // Tell service to stop DHT operations - Flutter is taking over
  await ForegroundServiceManager.setFlutterActive(true);

  // Reattach event callback (was detached in onPause)
  engine.attachEventCallback();

  // Fetch any messages that arrived while app was backgrounded
  await engine.checkOfflineMessages();
}

@override
void onPause(DnaEngine engine) {
  // Detach callback BEFORE Flutter is destroyed to prevent crash
  engine.detachEventCallback();

  // Tell service it can take over DHT operations
  ForegroundServiceManager.setFlutterActive(false);
}
```

**Service Side (Kotlin):**
```kotlin
// When flutterActive=true, service skips:
// - DHT health checks
// - DHT reinitializations
// - Listen renewal timer
// - Identity loading
```

---

## Remaining Work

### Phase 7: Android UI

**Options:**

1. **Native Kotlin + Jetpack Compose** (Recommended)
   - Best UX and performance
   - Full platform integration
   - Effort: 4-6 weeks

2. **Flutter**
   - Single codebase (iOS + Android)
   - Dart FFI to C library
   - Effort: 4-5 weeks

3. **React Native**
   - JavaScript codebase
   - Native modules for C library
   - Effort: 5-6 weeks

**Screens to implement:**
- Identity selection/creation
- Chat list
- Chat conversation
- Contact management
- Group management
- Wallet (balance, send, history)
- Settings/Profile

### Phase 8: iOS Port (Future)

**Additional work needed:**
1. `crypto/utils/qgp_platform_ios.c` - iOS implementation (**Note:** This file does not yet exist. iOS support is planned but not implemented.)
2. Xcode project configuration
3. Swift/Objective-C bridge to C library
4. iOS-specific networking (background restrictions)
5. Keychain integration for key storage

---

## External Dependencies

### Mobile-Ready (No Changes Needed)

| Dependency | Purpose | Mobile Support |
|------------|---------|----------------|
| SQLite3 | Local database | ✅ Native on both |
| ~~libjuice~~ | ~~ICE/STUN/TURN~~ | ❌ Removed v0.4.61 |
| json-c | JSON parsing | ✅ Pure C |
| stb_image | Avatar processing | ✅ Header-only |

### Requires Configuration

| Dependency | Purpose | Mobile Notes |
|------------|---------|--------------|
| OpenSSL | AES, SHA, crypto | Android: Use NDK OpenSSL or BoringSSL |
| | | iOS: Use CommonCrypto or bundled OpenSSL |
| CURL | HTTP/RPC | Android: Works via NDK (requires CA bundle) |
| | | iOS: Replace with URLSession or bundle |
| CA Bundle | SSL certificates | Android: Bundle cacert.pem in assets, copy to filesDir |
| | | iOS: Uses system certificates |
| OpenDHT-PQ | DHT networking | Needs NDK/Xcode build testing |

---

## Mobile-Specific Considerations

### Android

1. **Permissions Required**
   ```xml
   <uses-permission android:name="android.permission.INTERNET" />
   <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
   <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
   ```

2. **Background Execution**
   - Use WorkManager for periodic sync
   - Foreground service for active P2P connections
   - Handle Doze mode (network restrictions)

3. **SSL CA Certificates**
   - Android doesn't provide system CA certificates to native code
   - CURL needs explicit CA bundle for HTTPS (blockchain RPCs)
   - Solution: Bundle `cacert.pem` in `assets/` and copy to `filesDir` on startup
   - The native code uses `qgp_platform_ca_bundle_path()` to locate the bundle
   - Download latest bundle from: https://curl.se/ca/cacert.pem

4. **Storage**
   - Use `Context.getFilesDir()` for keys/data
   - Use `Context.getCacheDir()` for cache
   - Call `qgp_platform_set_app_dirs()` during init

5. **Network Handling**
   - Implement ConnectivityManager listener
   - Call `qgp_platform_update_network_state()` on changes
   - Handle WiFi ↔ Cellular transitions

### iOS (Future)

1. **Background Modes**
   - Background fetch
   - Push notifications (APNs)
   - VoIP (for real-time messages)

2. **Storage**
   - Use Keychain for private keys
   - Use Documents directory for data
   - Use Caches directory for cache

3. **Networking**
   - URLSession for HTTP
   - Network.framework for advanced networking
   - Handle background restrictions

---

## Testing Checklist

### Before Mobile Release

- [ ] All crypto operations work (Kyber, Dilithium, AES)
- [ ] DHT bootstrap connects successfully
- [ ] P2P connections establish (direct + NAT traversal)
- [ ] Messages send and receive
- [ ] Offline queue works (7-day expiry)
- [ ] Group messaging works (GEK encryption)
- [ ] Identity creation from BIP39 seeds
- [ ] Contact management (add/remove)
- [ ] Network transitions handled (WiFi ↔ Cellular)
- [ ] App backgrounding doesn't break connections
- [ ] Battery consumption acceptable
- [ ] Memory usage reasonable (<100 MB)

---

## Quick Reference

### Build Commands

```bash
# Desktop (Linux)
mkdir build && cd build
cmake .. && make -j$(nproc)

# Desktop headless (no GUI)
mkdir build && cd build
cmake -DBUILD_GUI=OFF .. && make -j$(nproc)

# Android
export ANDROID_NDK=/path/to/ndk
./build-android.sh arm64-v8a
```

### Key Files

| File | Purpose |
|------|---------|
| `include/dna/dna_engine.h` | Public C API (973 lines) |
| `crypto/utils/qgp_platform.h` | Platform abstraction API |
| `crypto/utils/qgp_platform_android.c` | Android implementation |
| `cmake/AndroidBuild.cmake` | Android CMake config |
| `build-android.sh` | Android build script |

### Support

- GitLab: https://gitlab.cpunk.io/cpunk/dna-messenger
- GitHub: https://github.com/nocdem/dna-messenger
- Telegram: @chippunk_official

---

## Changelog

### 2025-12-24: Phase 14 - DHT-Only Messaging (v0.2.5)
- **Phase 14 Complete:** DHT-only messaging for all platforms
- Messages now queue directly to DHT (Spillway) without P2P attempts
- Added Android `DnaMessengerService` ForegroundService
- Background polling every 60 seconds with WakeLock
- Extended DHT listen API: `dht_listen_ex()`, `dht_cancel_all_listeners()`, `dht_resubscribe_all_listeners()`
- Added `DHT_MAX_LISTENERS` limit (1024)
- P2P infrastructure preserved for future audio/video

### 2025-11-28: Android SDK Complete (v0.1.130+)
- **Phase 6 Complete:** JNI bindings with 26 native methods
- Created Java SDK classes (DNAEngine, Contact, Message, Group, etc.)
- Built libdna_jni.so (16MB stripped) with all static dependencies
- Added Android Gradle library project structure
- All core libraries build successfully for arm64-v8a
- Zero external dependencies (only Android system libs)

### 2025-11-28: Mobile Foundation (v0.1.x)
- Added platform abstraction for mobile (app_data_dir, cache_dir, network state)
- Created Android platform implementation
- Added Android NDK build configuration
- Created build-android.sh script
- Updated CMakeLists.txt for Android detection
