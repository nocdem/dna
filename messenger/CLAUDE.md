# DNA Connect - Messenger Development Guidelines

**Last Updated:** 2026-03-14 | **Status:** BETA | **Phase:** 7 (Flutter UI)

**Versions:** Library v0.9.86 | Flutter v1.0.0-rc55 | Nodus v0.9.15

**Note:** Framework rules (checkpoints, identity override, protocol mode, violations) are in root `/opt/dna/CLAUDE.md`. This file contains messenger-specific guidelines only.

---

## Engine Modules

The DNA Engine (`src/api/dna_engine.c`) is a modular async C library with 17 domain modules in `src/api/engine/`:

| Module | Domain |
|--------|--------|
| `dna_engine_addressbook.c` | Address book management |
| `dna_engine_backup.c` | DHT sync for all data types |
| `dna_engine_channels.c` | Channel CRUD, posts, subscriptions |
| `dna_engine_contacts.c` | Contact requests, blocking |
| `dna_engine_groups.c` | Group CRUD, GEK encryption, invitations |
| `dna_engine_helpers.c` | Shared utility functions |
| `dna_engine_identity.c` | Identity create/load, profiles |
| `dna_engine_lifecycle.c` | Engine pause/resume (mobile) |
| `dna_engine_listeners.c` | DHT key subscriptions |
| `dna_engine_logging.c` | Debug log control |
| `dna_engine_messaging.c` | Send/receive, conversations, retry |
| `dna_engine_presence.c` | Heartbeat, presence lookup |
| `dna_engine_signing.c` | Data signing operations |
| `dna_engine_version.c` | Version info and checking |
| `dna_engine_wall.c` | Personal wall posts |
| `dna_engine_wallet.c` | Multi-chain wallet (Cellframe, ETH, SOL, TRON) |
| `dna_engine_workers.c` | Background thread pool |

**Directory layout:**
- `src/api/` — DNA Engine core + `engine/` modules
- `messenger/` — Messaging core (identity, keys, contacts)
- `dht/` — DHT operations (`core/`, `client/`, `shared/`, `keyserver/`)
- `transport/` — P2P transport layer
- `database/` — SQLite persistence and caching
- `blockchain/` — Multi-chain wallet (`cellframe/`, `ethereum/`, `solana/`, `tron/`)
- `cli/` — CLI tool (`dna-messenger-cli`)
- `jni/` — Android JNI bindings
- `dna_messenger_flutter/` — Flutter app (Dart)
- `include/` — Public C headers
- `tests/` — Unit tests

### MODULAR ARCHITECTURE (MANDATORY)

**NEVER add monolithic code.** All new features MUST follow the modular pattern.

```c
// 1. Define implementation flag
#define DNA_ENGINE_XXX_IMPL
#include "engine_includes.h"

// 2. Task handlers (internal)
void dna_handle_xxx(dna_engine_t *engine, dna_task_t *task) { }

// 3. Public API wrappers
dna_request_id_t dna_engine_xxx(dna_engine_t *engine, ...) {
    return dna_submit_task(engine, TASK_XXX, &params, cb, user_data);
}
```

**Adding New Features:**
1. Identify the appropriate module (or create new one if domain doesn't exist)
2. Add task type to `dna_engine_internal.h`
3. Implement handler in module file
4. Add dispatch case in `dna_engine.c`
5. Declare public API in `include/dna/dna_engine.h`

**Detailed Guide:** See `src/api/engine/README.md`

---

## Flutter FFI Pattern

Flutter connects to the C library via `dart:ffi`:
- **FFI bindings:** `lib/ffi/dna_bindings.dart` (hand-written)
- **Dart wrapper:** `lib/ffi/dna_engine.dart` (converts C callbacks to Dart Futures/Streams)
- **State management:** Riverpod providers in `lib/providers/`
- **Binding generator config:** `dna_messenger_flutter/ffigen.yaml`

---

## Version Management

| Component | Version File | Current | Bump When |
|-----------|--------------|---------|-----------|
| C Library | `include/dna/version.h` | v0.9.86 | C code changes |
| Flutter App | `dna_messenger_flutter/pubspec.yaml` | v1.0.0-rc55+10405 | Flutter/Dart changes |
| Nodus | `../nodus/include/nodus/nodus_types.h` | v0.9.13 | Nodus changes |

Flutter app displays **both versions** in Settings:
- App version: from `pubspec.yaml`
- Library version: via `dna_engine_get_version()` FFI call

---

## Internationalization (i18n) — Full Guide

**All user-visible strings MUST be localized.** Supported: English (source) + Turkish.

```dart
import '../../l10n/app_localizations.dart';

final l10n = AppLocalizations.of(context);
Text(l10n.settingsTitle)           // "Settings" or "Ayarlar"
Text(l10n.contactsLastSeen('5m'))  // parameterized
```

**When adding a new screen or feature:**
1. Add ALL user-visible strings to `lib/l10n/app_en.arb` (English, source)
2. Add Turkish translations to `lib/l10n/app_tr.arb`
3. Run `flutter gen-l10n` (or `flutter build` which runs it automatically)
4. Use `AppLocalizations.of(context).keyName` — **NEVER** hardcoded `'String'`

**Key rules:**
- ARB keys are camelCase, grouped by screen (e.g., `chatTypeMessage`, `settingsDarkMode`)
- Parameterized strings use `{placeholder}` syntax in ARB, positional args in Dart
- `@key` metadata (placeholders) goes in `app_en.arb` only (not in `app_tr.arb`)
- `const Text('...')` is NOT allowed for user-visible strings
- Language picker labels ('English', 'Türkçe') stay hardcoded
- Adding a new language: create `app_XX.arb`, add option to `_LanguageSection` in settings

**Files:**
- `lib/l10n/app_en.arb` — English strings (source)
- `lib/l10n/app_tr.arb` — Turkish translations
- `lib/l10n/app_localizations.dart` — Generated (do NOT edit)
- `lib/providers/locale_provider.dart` — Language selection state

---

## Platform-Specific Code

For **C library**:
```c
#ifdef __ANDROID__
    // Android-specific
#elif defined(_WIN32)
    // Windows-specific
#else
    // Desktop Linux
#endif
```

For **Flutter app** — use the handler pattern, NOT `Platform.isAndroid`:
- `lib/platform/platform_handler.dart` — Abstract interface
- `lib/platform/android/android_platform_handler.dart`
- `lib/platform/desktop/desktop_platform_handler.dart`
- Access via `PlatformHandler.instance` singleton

---

## CLI for Debugging and Testing

```bash
CLI=/opt/dna/messenger/build/cli/dna-messenger-cli

$CLI lookup-profile <name|fp>    # View any user's full DHT profile
$CLI lookup <name>               # Check if name is registered
$CLI send <name> "message"       # Send message by name
$CLI send <full-fp> "message"    # Send using FULL 128-char fingerprint
$CLI messages <fp>               # Conversation history
$CLI check-offline               # Poll DHT for offline messages
$CLI listen                      # Subscribe to push notifications
$CLI whoami                      # Current identity
$CLI contacts                    # List contacts
```

**IMPORTANT:** `send` requires registered name or FULL 128-char fingerprint. Partial fingerprints fail.

---

## Function Reference Quick Links

| Module | File | Description |
|--------|------|-------------|
| Public API | [public-api.md](docs/functions/public-api.md) | Main engine API |
| Messenger | [messenger.md](docs/functions/messenger.md) | Core messenger + backup |
| Crypto | [crypto.md](docs/functions/crypto.md) | Kyber, Dilithium, BIP39 |
| DHT | [dht.md](docs/functions/dht.md) | Core, Shared, Client |
| Transport | [transport.md](docs/functions/transport.md) | Transport layer |
| Database | [database.md](docs/functions/database.md) | SQLite caches |
| Blockchain | [blockchain.md](docs/functions/blockchain.md) | Multi-chain wallet |
| Engine | [engine.md](docs/functions/engine.md) | Internal implementation |
| Key Sizes | [key-sizes.md](docs/functions/key-sizes.md) | Crypto sizes reference |

**Index:** [docs/functions/README.md](docs/functions/README.md)

---

## Phase Status

### Complete
- Phase 4: Desktop GUI + Wallet Integration
- Phase 5: P2P Architecture (DHT, GEK, Message Format v0.08)
- Phase 6: Android SDK (JNI bindings)
- Phase 8: DNA Wallet Integration
- Phase 9: P2P Transport, Offline Queue, DHT Migrations
- Phase 10: User Profiles, DNA Board, Avatars, Voting
- Phase 12: Message Format v0.08 - Fingerprint Privacy
- Phase 13: GEK Group Encryption
- Phase 14: DHT-Only Messaging

### In Progress
- Phase 7: Mobile/Desktop UI (Flutter + Dart)

### Planned
- Phase 15: Web Messenger (WebAssembly)
- Phase 16: Voice/Video Calls (Post-Quantum)
- Phase 17: iOS Application

---

## Project Overview

Post-quantum E2E encrypted messenger with DNA Wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging, GEK group encryption, DHT groups, per-identity contacts, user profiles, wall posts, DNA Wallet, DHT-only messaging, offline queueing (7d), BIP39 recovery, SQLite, Flutter UI, Android SDK (JNI)

---

**Priority:** Simplicity, security, cross-platform compatibility. When in doubt, ask.
