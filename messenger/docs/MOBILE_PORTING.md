# DNA Messenger Mobile Porting Guide

**Last Updated:** 2025-11-28
**Status:** Android SDK Complete (Phases 1-6)
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
│  │ libp2p_transport  │ │libopendht  │ │    libjuice      │ │
│  │   (P2P + NAT)     │ │   (PQ)     │ │   (ICE/STUN)     │ │
│  └───────────────────┘ └────────────┘ └──────────────────┘ │
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
| `libp2p_transport.a` | ~500 KB | P2P + NAT | ✅ POSIX sockets |
| `libjuice.a` | ~300 KB | ICE/STUN/TURN | ✅ Mobile-ready |

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
├── libp2p_transport.a     # P2P transport
├── libopendht.a           # OpenDHT-PQ
└── vendor/libjuice/...    # ICE/STUN
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
1. `crypto/utils/qgp_platform_ios.c` - iOS implementation
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
| libjuice | ICE/STUN/TURN | ✅ Works on mobile |
| json-c | JSON parsing | ✅ Pure C |
| stb_image | Avatar processing | ✅ Header-only |

### Requires Configuration

| Dependency | Purpose | Mobile Notes |
|------------|---------|--------------|
| OpenSSL | AES, SHA, crypto | Android: Use NDK OpenSSL or BoringSSL |
| | | iOS: Use CommonCrypto or bundled OpenSSL |
| CURL | HTTP/RPC | Android: Works via NDK |
| | | iOS: Replace with URLSession or bundle |
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

3. **Storage**
   - Use `Context.getFilesDir()` for keys/data
   - Use `Context.getCacheDir()` for cache
   - Call `qgp_platform_set_app_dirs()` during init

4. **Network Handling**
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
- [ ] Group messaging works (GSK encryption)
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
