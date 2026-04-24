# DNA Connect Mobile Porting Guide

**Last Updated:** 2026-04-24
**Status:** Android SDK Complete; Flutter UI shipping on Android (v1.0.0-rc235+)
**Target:** Android first, iOS later

---

## Executive Summary

DNA Connect has been successfully ported to Android. The Android SDK provides JNI bindings for all core functionality, with a complete Java API and Gradle project structure ready for app development.

### Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core Library Extraction | ✅ Complete (already separated) |
| 2 | Platform Abstraction | ✅ Complete |
| 3 | HTTP Abstraction | ✅ Complete (CURL via NDK) |
| 4 | Android NDK Build Config | ✅ Complete |
| 5 | ~~OpenDHT-PQ Android Port~~ | Removed (replaced by Nodus client SDK, pure C) |
| 6 | JNI Bindings | ✅ Complete (27 functions) |
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
│  │   - 27 native methods                                   ││
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
│                     Core Libraries (Pure C)                   │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐│
│  │ libdna│ │libdht_lib │ │  libkem   │ │   libdsa     ││
│  │  (1.4MB)  │ │  (DHT)    │ │ (Kyber)   │ │ (Dilithium)  ││
│  └───────────┘ └───────────┘ └───────────┘ └──────────────┘│
│  ┌───────────────────┐ ┌──────────────────┐                 │
│  │ libtransport_lib  │ │ libnodus_client  │                 │
│  │   (P2P + DHT)     │ │  (Nodus SDK)  │                 │
│  └───────────────────┘ └──────────────────┘                 │
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
| `libdna.a` | 1.4 MB | Messenger core | ✅ Pure C |
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
cd /opt/dna/messenger

# Build for ARM64 (recommended)
./build-android.sh arm64-v8a

# Build for other ABIs
./build-android.sh armeabi-v7a  # 32-bit ARM
./build-android.sh x86_64       # Emulator
```

### Output

```
build-android-arm64-v8a/
├── libdna.a           # Main messenger library
├── libdht_lib.a           # DHT networking
├── libkem.a               # Kyber1024
├── libdsa.a               # Dilithium5
├── libtransport_lib.a     # P2P transport
└── libnodus_client.a      # Nodus client SDK (pure C)
```

---

## Completed Work

### Phase 5: DHT Layer (Nodus Client SDK)

**Status:** Complete (replaced OpenDHT-PQ)

OpenDHT-PQ has been completely removed and replaced by the Nodus client SDK, which is pure C with no C++ dependencies. This simplifies the Android build significantly:
- No C++ runtime needed (no `libc++_shared.so`)
- No GnuTLS/nettle/hogweed dependencies
- Pure C, POSIX sockets, pthreads
- getrandom() available on API 24+

**Messenger integration:** `dht/shared/nodus_ops.c` wraps the Nodus singleton with convenience functions. Lifecycle managed by `dht/shared/nodus_init.c`.

### Phase 6: JNI Bindings ✅

**Status:** Complete (27 native methods)

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
│           └── (no C++ runtime needed — pure C)
├── build.gradle
├── gradle.properties
└── settings.gradle
```

**JNI Native Methods (27 total):**
- `nativeCreate`, `nativeDestroy`, `nativeSetEventListener`
- `nativeCreateIdentity`, `nativeLoadIdentity`, `nativeIsIdentityLoaded`
- `nativeGetFingerprint`, `nativeRegisterName`, `nativeGetDisplayName`
- `nativeGetContacts`, `nativeAddContact`, `nativeRemoveContact`, `nativeGetConversation`
- `nativeSendMessage`, `nativeSendGroupMessage`
- `nativeGetGroups`, `nativeCreateGroup`
- `nativeGetInvitations`, `nativeAcceptInvitation`, `nativeRejectInvitation`
- `nativeListWallets`, `nativeGetBalances`, `nativeGetTransactions`, `nativeSendTokens`
- `nativeIsPeerOnline`, `nativeRefreshPresence`, `nativeNetworkChanged`

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

### Phase 14: DHT-Only Messaging ✅

**Status:** Complete (2025-12-24), updated v0.9.7 (2026-03-05)

Phase 14 changed the messaging architecture to use DHT-only delivery (no P2P attempts).

**Why DHT-Only?**
- Mobile platforms have strict background execution restrictions
- P2P connections fail when app is backgrounded (Android Doze mode, iOS suspension)
- DHT queue provides reliable, consistent delivery across all platforms
- P2P infrastructure preserved for future audio/video calls

**v0.9.7: Android Service Removed**

The Android ForegroundService, notification system, and engine pause/resume lifecycle
were completely removed. Android now behaves identically to desktop:
- Engine runs while app is open, destroyed when app closes
- No background service, no offline notifications
- No pause/resume engine state — `dna_engine_pause()`/`dna_engine_resume()` are no-op stubs (ABI compat)

**DHT Listen API:**

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

When network connectivity changes (WiFi to Cellular), the DHT UDP socket becomes invalid:

```c
// C Layer - DHT Reinit
int dht_singleton_reinit(void);       // Restart DHT with stored identity
int dna_engine_network_changed(engine); // High-level API for network change
```

#### Identity Lock (v0.6.0+)

File-based identity lock prevents concurrent engine access:

```c
// qgp_platform.h
int qgp_platform_acquire_identity_lock(const char *data_dir);  // Returns fd or -1
void qgp_platform_release_identity_lock(int lock_fd);
int qgp_platform_is_identity_locked(const char *data_dir);     // Returns 1 if locked
```

#### Engine-Owned DHT Context (v0.6.0+)

Each engine owns its own DHT context:

```c
struct dna_engine {
    dht_context_t *dht_ctx;      // Engine owns this
    int identity_lock_fd;         // File lock (-1 if not held)
    // ...
};
```

The singleton pattern is kept for backwards compatibility using "borrowed context":
- Engine creates DHT via `dht_create_context_with_identity()`
- Engine lends to singleton via `dht_singleton_set_borrowed_context(engine->dht_ctx)`
- Code using `dht_singleton_get()` still works
- On destroy: clear borrowed context, then free engine's context

#### Background Thread Tracking (v0.6.1+)

Background threads are tracked and joined on shutdown to prevent use-after-free crashes:

1. **Listener setup thread** - spawned on DHT connect to setup listeners
2. **Stabilization retry thread** - spawned on identity load, waits 15s then retries messages

Threads check `shutdown_requested` flag after sleeps. Engine tracks thread handles and running state. `dna_engine_destroy()` joins threads before freeing resources.

### TEE Key Wrapping (v0.9.168+) ✅

**Status:** Complete (2026-04-05)

Private keys (Dilithium5 `.dsa`, Kyber1024 `.kem`) are wrapped using platform-specific TEE (Trusted Execution Environment) on Android.

**Android Implementation:**
- Uses Android Keystore with hardware-backed keys (StrongBox or TEE)
- AES-256-GCM wrapping key generated inside the secure element
- Key alias: `dna_key_wrap_<identity_fingerprint_prefix>`
- Wrapping is transparent to the engine — keys are unwrapped on load

**Source Files:**
- `dna_messenger_flutter/android/app/src/main/kotlin/io/cpunk/dna_connect/DnaKeyStore.kt` — Android Keystore integration (Kotlin)
- `jni/dna_jni.c` — JNI bridge for key wrapping callbacks
- `src/api/engine/dna_engine_identity.c` — Engine-side key wrapping hooks
- `tests/test_platform_keystore.c` — Unit test for platform keystore

**Desktop (Linux/Windows):** No TEE available. Keys are encrypted with the user's password via Kyber1024 KEM + AES-256-GCM (existing mechanism).

### Debug Log Send (Mobile) ✅

**Status:** Complete (v1.0.0-rc159+)

Users can send their app debug log to the developer from the Flutter UI:
- **Settings > Data & Storage > Send Debug Log to Developer**
- Log is sanitized (mnemonic, hex keys, credentials scrubbed by LogSanitizer)
- Hybrid-encrypted (Kyber1024 + AES-256-GCM) to developer's Kyber public key
- Delivered via DHT with 1-hour TTL
- Received by `dna-punk-debug-inbox.service` on the dev machine

**Mobile path fix:** APK must be >= `rc159+10509` for correct file path resolution on Android.

---

## Remaining Work

### Phase 7: Android UI

Flutter is the chosen UI framework (single codebase for all platforms).

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
| ~~OpenDHT-PQ~~ | ~~DHT networking~~ | Removed (replaced by Nodus, pure C) |

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

- GitLab: https://gitlab.cpunk.io/cpunk/dna
- GitHub: https://github.com/nocdem/dna
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
