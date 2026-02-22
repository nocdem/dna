# DNA Messenger - Code Cleanup Required

**Generated:** 2025-12-07 | **Updated:** 2025-12-07 | **Status:** Phase 1 Complete | **Priority:** Medium

This document tracks all stubs, dead code, unused functions, and incomplete implementations that need cleanup before production release.

---

## FIXED (2025-12-07)

The following critical issues have been resolved:

| Item | File | Fix Applied |
|------|------|-------------|
| `mounted` property error | `background_tasks_provider.dart` | Replaced with `!_disposed` check, removed debug prints |
| Empty event handlers | `event_handler.dart` | Implemented handlers for GroupInvitation, GroupMember, Error events |
| Debug printf statements | `messenger/messages.c` | Removed ~15 debug printf statements from `messenger_send_message()` |
| Misleading placeholder | `groups_screen.dart` | Updated to show "in development" message instead of fake empty state |
| Debug prints | `transport/internal/transport_offline.c` | Removed all DEBUG FETCH and info prints |
| Debug print | `messenger/messages.c:701` | Removed signature verification DEBUG print |
| Debug prints | `blockchain/cellframe/cellframe_tx_builder.c` | Removed uint256 DEBUG prints |
| Debug prints | `blockchain/cellframe/cellframe_wallet_create.c` | Removed WALLET_DEBUG prints |
| Commented debug | `blockchain/cellframe/cellframe_wallet.c` | Removed 14+ commented fprintf statements |
| Commented debug | `blockchain/cellframe/cellframe_sign.c` | Removed 35+ commented fprintf statements, consolidated DEBUG_BLOCKCHAIN_SIGNING block |
| Debug prints | `lib/utils/window_state.dart` | Removed 5 print() statements |
| Debug prints | `lib/providers/wallet_provider.dart` | Removed 8 print() statements |
| Debug prints | `lib/providers/profile_provider.dart` | Removed 3 print() statements |
| Debug prints | `lib/providers/identity_provider.dart` | Removed 7 print() statements |

**New provider added:** `lastErrorProvider` in `event_handler.dart` for error state management.

**Note:** `#ifdef DEBUG_BLOCKCHAIN_SIGNING` blocks retained in `cellframe_sign.c` and `cellframe_send.c` (properly guarded).

---

## Summary

| Category | Count | Status | Priority |
|----------|-------|--------|----------|
| TODO/FIXME Comments | 15 | Remaining | Medium |
| Debug print() statements | 45+ | ✅ FIXED | - |
| Commented-out debug code | 130+ | ✅ FIXED | - |
| Placeholder/stub implementations | 4 | ✅ 1 FIXED | Medium |
| Silent exception handling | 8 | Remaining | Medium |
| Disabled feature code | 3 | Remaining | Low |
| **REMAINING** | **~26** | - | Medium |

---

## 1. C/C++ Core - TODOs and Stubs

### 1.1 GEK Module (HIGH PRIORITY)

**File:** `messenger/gek.c`

| Line | Issue | Description |
|------|-------|-------------|
| ~~491~~ | ~~TODO~~ | ~~Key loading hard-coded to `~/.dna/<owner>-dilithium.pqkey` instead of using messenger context~~ - **FIXED v0.4.16** |
| 559 | TODO Phase 8 | P2P notifications to group members not implemented - members discover via polling |

**Action Required:**
- [x] ~~Integrate proper key loading from messenger context (line 491)~~ - **FIXED v0.4.16: Updated to use `keys/identity.dsa`**
- [ ] Implement P2P notifications for GEK rotation (line 559) or document as Phase 8

### 1.2 Database

**File:** `database/cache_manager.c`
| Line | Issue |
|------|-------|
| 223 | TODO: Add presence_cache_count() if needed |

---

## 2. Debug Print Statements (REMOVE FOR PRODUCTION)

### 2.1 C Core - Active Debug Output

**File:** `messenger/messages.c` - ✅ **FIXED** (all debug prints removed)

**File:** `transport/internal/transport_offline.c` - ✅ **FIXED** (all DEBUG FETCH and info prints removed)

### 2.2 Blockchain Module - Commented Debug Code

**File:** `blockchain/cellframe/cellframe_wallet.c` - ✅ **FIXED** (14+ commented fprintf statements removed)

**File:** `blockchain/cellframe/cellframe_sign.c` - ✅ **FIXED** (35+ commented fprintf statements removed)

**File:** `blockchain/cellframe/cellframe_tx_builder.c` - ✅ **FIXED** (DEBUG prints removed)

**File:** `blockchain/cellframe/cellframe_wallet_create.c` - ✅ **FIXED** (WALLET_DEBUG prints removed)

### 2.3 Conditional Debug Blocks (Retained - Properly Guarded)

**File:** `blockchain/cellframe/cellframe_sign.c`
```c
#ifdef DEBUG_BLOCKCHAIN_SIGNING
// Writes to /tmp/signing_data_our.bin (for development only)
#endif
```

**File:** `blockchain/cellframe/cellframe_send.c`
```c
#ifdef DEBUG_BLOCKCHAIN_SIGNING
// Writes to /tmp/unsigned_tx_our.bin (for development only)
#endif
```

**Note:** These blocks are only compiled when DEBUG_BLOCKCHAIN_SIGNING is defined, so they're safe for production.

---

## 3. Flutter/Dart Issues

### 3.1 TODO Comments (7 items)

**File:** `dna_messenger_flutter/lib/screens/chat/chat_screen.dart`
| Line | Action |
|------|--------|
| ~441 | TODO: Show profile - IMPLEMENT |
| ~449 | TODO: Show QR - IMPLEMENT |
| ~460 | TODO: Confirm and remove contact - IMPLEMENT |

**File:** `dna_messenger_flutter/lib/screens/settings/settings_screen.dart`
| Line | Action |
|------|--------|
| ~260 | TODO: Show seed phrase with confirmation - IMPLEMENT |

**File:** `dna_messenger_flutter/lib/providers/event_handler.dart`
| Line | Action |
|------|--------|
| ~85 | TODO: Show notification for group invitation - IMPLEMENT |
| ~90 | TODO: Refresh group members on join/leave - IMPLEMENT |
| ~99 | TODO: Show error notification via snackbar - IMPLEMENT |

### 3.2 Debug print() Statements - ✅ **ALL FIXED**

All debug print() statements have been removed from:
- `lib/utils/window_state.dart` - ✅ 5 prints removed
- `lib/providers/identity_provider.dart` - ✅ 7 prints removed
- `lib/providers/wallet_provider.dart` - ✅ 8 prints removed
- `lib/providers/background_tasks_provider.dart` - ✅ prints removed (in earlier fix)
- `lib/providers/profile_provider.dart` - ✅ 3 prints removed

### 3.3 Placeholder Implementation

**File:** `lib/screens/groups/groups_screen.dart` (~Line 504)
```dart
// Messages list (placeholder)
// Returns: Center(child: Text('Group messages not yet implemented'))
```
**Action:** Implement group messaging or remove groups feature.

### 3.4 Silent Exception Handling (8 instances)

| File | Pattern | Action |
|------|---------|--------|
| `lib/ffi/dna_engine.dart` (688, 691) | `catch (_) {}` | Add specific exception types |
| `lib/screens/contacts/contacts_screen.dart` (338) | `catch (_) {}` | Log or handle properly |
| `lib/providers/feed_provider.dart` | Empty catch blocks | Add logging |

### 3.5 Disabled Feature Code - DELETE

**File:** `lib/screens/home_screen.dart`
```dart
// REMOVE these commented imports and navigation items:
// import 'feed/feed_screen.dart';
// const NavigationDrawerDestination(icon: Icon(Icons.article_outlined)...
```

**File:** `lib/providers/providers.dart`
```dart
// REMOVE:
// export 'feed_provider.dart';
```

### 3.6 Logic Error

**File:** `lib/providers/background_tasks_provider.dart` (Line 74)
```dart
if (!_disposed && mounted) {  // ERROR: 'mounted' doesn't exist on StateNotifier
```
**Action:** Fix lifecycle management - StateNotifier doesn't have `mounted` property.

---

## 4. Cleanup Checklist

### Phase 1: Critical (Before Next Release) - ✅ COMPLETE
- [x] Remove all debug printf/print statements from C and Dart code
- [x] Fix Flutter event_handler.dart - implement notification handling
- [x] Fix background_tasks_provider.dart `mounted` property error
- [x] Implement or remove group chat placeholder (shows "in development")

### Phase 2: Important (Next Sprint)
- [ ] Complete Flutter chat_screen.dart TODOs (profile, QR, remove contact)
- [ ] Complete settings_screen.dart seed phrase TODO
- [x] Clean up 130+ commented fprintf in blockchain module
- [x] Document or remove DEBUG_BLOCKCHAIN_SIGNING blocks (retained, properly guarded)

### Phase 3: Maintenance
- [ ] Address GEK module TODOs (Phase 8 features)
- [ ] Implement Windows multiple file selection
- [ ] Implement Windows/macOS focus detection
- [ ] Add presence_cache_count() function
- [ ] Remove disabled Feed feature code entirely

---

## 5. Files Summary

### C/C++ Files Requiring Cleanup
1. `messenger/gek.c` - 2 TODOs (Phase 8 features)
2. `messenger/messages.c` - ✅ debug prints FIXED
3. `transport/internal/transport_offline.c` - ✅ debug prints FIXED
4. `blockchain/cellframe/cellframe_wallet.c` - ✅ commented debugs FIXED
5. `blockchain/cellframe/cellframe_sign.c` - ✅ commented debugs FIXED
6. `blockchain/cellframe/cellframe_tx_builder.c` - ✅ active debug FIXED
7. `blockchain/cellframe/cellframe_wallet_create.c` - ✅ active debug FIXED
8. `blockchain/cellframe/cellframe_send.c` - conditional debug (retained, guarded)
9. `database/cache_manager.c` - 1 TODO

### Dart Files Requiring Cleanup
1. `lib/screens/chat/chat_screen.dart` - 3 TODOs
2. `lib/screens/settings/settings_screen.dart` - 1 TODO
3. `lib/screens/groups/groups_screen.dart` - ✅ placeholder FIXED (shows "in development")
4. `lib/screens/home_screen.dart` - disabled feature code
5. `lib/screens/contacts/contacts_screen.dart` - silent catch
6. `lib/providers/event_handler.dart` - ✅ event handlers FIXED
7. `lib/providers/identity_provider.dart` - ✅ prints FIXED
8. `lib/providers/wallet_provider.dart` - ✅ prints FIXED
9. `lib/providers/background_tasks_provider.dart` - ✅ prints + logic error FIXED
10. `lib/providers/profile_provider.dart` - ✅ prints FIXED
11. `lib/providers/feed_provider.dart` - silent catches
12. `lib/providers/providers.dart` - commented export
13. `lib/utils/window_state.dart` - ✅ prints FIXED
14. `lib/ffi/dna_engine.dart` - silent catches

---

## Notes

- **DO NOT** modify crypto primitives without security review
- **DO NOT** remove backwards compatibility code in `src/api/dna_engine.c` without migration
- Debug blocks with `#ifdef DEBUG_BLOCKCHAIN_SIGNING` can remain if documented
- All cleanup should be tested on both Linux and Windows builds
