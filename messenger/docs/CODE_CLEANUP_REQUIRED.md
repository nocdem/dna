# DNA Messenger - Code Cleanup Required

**Generated:** 2025-12-07 | **Updated:** 2025-12-07 | **Status:** In Progress | **Priority:** High

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

**New provider added:** `lastErrorProvider` in `event_handler.dart` for error state management.

---

## Summary

| Category | Count | Lines Affected | Priority |
|----------|-------|----------------|----------|
| TODO/FIXME Comments | 15 | ~50 | High |
| Debug print() statements | 45+ | ~100 | High |
| Commented-out debug code | 130+ | ~650 | Medium |
| Placeholder/stub implementations | 4 | ~20 | High |
| Silent exception handling | 8 | ~30 | Medium |
| Disabled feature code | 3 | ~15 | Low |
| **TOTAL** | **~205** | **~865** | - |

---

## 1. C/C++ Core - TODOs and Stubs

### 1.1 GSK Module (HIGH PRIORITY)

**File:** `messenger/gsk.c`

| Line | Issue | Description |
|------|-------|-------------|
| 491 | TODO | Key loading hard-coded to `~/.dna/<owner>-dilithium.pqkey` instead of using messenger context |
| 559 | TODO Phase 8 | P2P notifications to group members not implemented - members discover via polling |

**Action Required:**
- [ ] Integrate proper key loading from messenger context (line 491)
- [ ] Implement P2P notifications for GSK rotation (line 559) or document as Phase 8

### 1.2 ImGui GUI

**File:** `imgui_gui/screens/chat_screen.cpp`
| Line | Issue |
|------|-------|
| 163 | TODO: Add group message retry functionality |

**File:** `imgui_gui/screens/feed_screen.cpp`
| Line | Issue |
|------|-------|
| 515 | TODO: Expand to show comments (Phase 9) |

**File:** `imgui_gui/helpers/data_loader.cpp`
| Line | Issue |
|------|-------|
| 250 | TODO: Query member count from dht_group_members table |

**File:** `imgui_gui/helpers/file_browser.cpp`
| Line | Issue |
|------|-------|
| 294 | TODO: Implement NFD multiple selection (Windows) |

**File:** `imgui_gui/helpers/notification_manager.cpp`
| Line | Issue |
|------|-------|
| 64 | TODO: Implement proper focus detection for Windows/macOS |

### 1.3 Database

**File:** `database/cache_manager.c`
| Line | Issue |
|------|-------|
| 223 | TODO: Add presence_cache_count() if needed |

---

## 2. Debug Print Statements (REMOVE FOR PRODUCTION)

### 2.1 C Core - Active Debug Output

**File:** `messenger/messages.c` - ✅ **FIXED** (debug prints removed from `messenger_send_message()`)

**File:** `p2p/transport/transport_offline.c` (Lines 90-106) - **STILL NEEDS FIX**
```c
// REMOVE debug logging in offline queue:
printf("[P2P DEBUG FETCH] my_identity (recipient)='%s'\n", ...);
```

**File:** `messenger/messages.c` (Line 733) - **STILL NEEDS FIX**
```c
// REMOVE signature verification debug:
fprintf(stderr, "[DEBUG] ✓ Signature verified successfully...\n");
```

### 2.2 Blockchain Module - Commented Debug Code (130+ lines)

**File:** `blockchain/cellframe/cellframe_wallet.c` (Lines 171-271)
- 14+ commented `fprintf` statements - DELETE

**File:** `blockchain/cellframe/cellframe_sign.c` (Lines 42-282)
- 35+ commented `fprintf` statements - DELETE

**File:** `blockchain/cellframe/cellframe_tx_builder.c` (Lines 573-575)
- Active `printf` debug statements - REMOVE

**File:** `blockchain/cellframe/cellframe_wallet_create.c` (Lines 209-237)
- Active `fprintf` debug statements - REMOVE

### 2.3 Conditional Debug Blocks

**File:** `blockchain/cellframe/cellframe_sign.c` (Lines 190-198)
```c
#ifdef DEBUG_BLOCKCHAIN_SIGNING
// Writes to /tmp/signing_data_our.bin - DOCUMENT or REMOVE
#endif
```

**File:** `blockchain/cellframe/cellframe_send.c` (Lines 747-767)
```c
#ifdef DEBUG_BLOCKCHAIN_SIGNING
// Writes to /tmp/unsigned_tx_our.bin - DOCUMENT or REMOVE
#endif
```

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

### 3.2 Debug print() Statements (45+ instances) - REMOVE ALL

**File:** `lib/utils/window_state.dart` - 5 print() calls
**File:** `lib/providers/identity_provider.dart` - 7 print() calls
**File:** `lib/providers/wallet_provider.dart` - 6 print() calls
**File:** `lib/providers/background_tasks_provider.dart` - 6 print() calls
**File:** `lib/providers/profile_provider.dart` - 3 print() calls
**File:** `lib/ffi/dna_engine.dart` - Multiple debug logs

**Action:** Replace with proper logging framework or remove entirely.

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

### Phase 1: Critical (Before Next Release)
- [ ] Remove all debug printf/print statements from C and Dart code
- [ ] Fix Flutter event_handler.dart - implement notification handling
- [ ] Fix background_tasks_provider.dart `mounted` property error
- [ ] Implement or remove group chat placeholder

### Phase 2: Important (Next Sprint)
- [ ] Complete Flutter chat_screen.dart TODOs (profile, QR, remove contact)
- [ ] Complete settings_screen.dart seed phrase TODO
- [ ] Clean up 130+ commented fprintf in blockchain module
- [ ] Document or remove DEBUG_BLOCKCHAIN_SIGNING blocks

### Phase 3: Maintenance
- [ ] Address GSK module TODOs (Phase 8 features)
- [ ] Implement Windows multiple file selection
- [ ] Implement Windows/macOS focus detection
- [ ] Add presence_cache_count() function
- [ ] Remove disabled Feed feature code entirely

---

## 5. Files Summary

### C/C++ Files Requiring Cleanup
1. `messenger/gsk.c` - 2 TODOs
2. `messenger/messages.c` - 12 debug prints
3. `p2p/transport/transport_offline.c` - debug prints
4. `blockchain/cellframe/cellframe_wallet.c` - 14+ commented debugs
5. `blockchain/cellframe/cellframe_sign.c` - 35+ commented debugs
6. `blockchain/cellframe/cellframe_tx_builder.c` - active debug
7. `blockchain/cellframe/cellframe_wallet_create.c` - active debug
8. `blockchain/cellframe/cellframe_send.c` - conditional debug
9. `imgui_gui/screens/chat_screen.cpp` - 1 TODO
10. `imgui_gui/screens/feed_screen.cpp` - 1 TODO
11. `imgui_gui/helpers/data_loader.cpp` - 1 TODO
12. `imgui_gui/helpers/file_browser.cpp` - 1 TODO
13. `imgui_gui/helpers/notification_manager.cpp` - 1 TODO
14. `database/cache_manager.c` - 1 TODO

### Dart Files Requiring Cleanup
1. `lib/screens/chat/chat_screen.dart` - 3 TODOs
2. `lib/screens/settings/settings_screen.dart` - 1 TODO
3. `lib/screens/groups/groups_screen.dart` - placeholder
4. `lib/screens/home_screen.dart` - disabled feature code
5. `lib/screens/contacts/contacts_screen.dart` - silent catch
6. `lib/providers/event_handler.dart` - 3 TODOs
7. `lib/providers/identity_provider.dart` - 7 prints
8. `lib/providers/wallet_provider.dart` - 6 prints
9. `lib/providers/background_tasks_provider.dart` - 6 prints, logic error
10. `lib/providers/profile_provider.dart` - 3 prints
11. `lib/providers/feed_provider.dart` - silent catches
12. `lib/providers/providers.dart` - commented export
13. `lib/utils/window_state.dart` - 5 prints
14. `lib/ffi/dna_engine.dart` - silent catches, debug logs

---

## Notes

- **DO NOT** modify crypto primitives without security review
- **DO NOT** remove backwards compatibility code in `src/api/dna_engine.c` without migration
- Debug blocks with `#ifdef DEBUG_BLOCKCHAIN_SIGNING` can remain if documented
- All cleanup should be tested on both Linux and Windows builds
