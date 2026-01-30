# DNA Messenger - Missing Features

Planned features for future implementation.

---

## QR Code Deep Link Handler

**Priority:** Medium
**Status:** Not Started

### Current State
- QR codes are generated and displayed (profile editor, chat menu)
- QR contains 128-character fingerprint only
- User must scan with external app, copy text, paste in Add Contact dialog

### What's Missing
1. No `dna://` URL scheme registered in AndroidManifest.xml
2. No `onNewIntent()` handler in MainActivity.kt
3. No deep link listener in Flutter
4. No in-app QR scanner

### Desired Behavior
User scans QR code with any scanner app, tapping result opens DNA Messenger with Add Contact dialog pre-filled.

### Implementation Options

**Option 1: URL Scheme Only (Simpler)**
- Register `dna://add/<fingerprint>` scheme
- External QR scanner apps will offer to open DNA Messenger
- No camera permissions needed

**Option 2: Full QR Scanner (Better UX)**
- Add `mobile_scanner` package
- In-app camera scanning
- Requires camera permission
- More seamless experience

### Files to Modify
- `android/app/src/main/AndroidManifest.xml` - add intent filter
- `android/app/src/main/kotlin/.../MainActivity.kt` - handle incoming intent
- `lib/screens/contacts/contacts_screen.dart` - accept pre-filled fingerprint
- `pubspec.yaml` - add scanner package (Option 2 only)

### Related Code
- QR generation: `lib/screens/profile/profile_editor_screen.dart:673-745`
- QR display in chat: `lib/screens/chat/chat_screen.dart:677-776`
- Add contact dialog: `lib/screens/contacts/contacts_screen.dart:297-515`

---

## Notification Tap Navigation

**Priority:** Medium
**Status:** Not Started

### Current State
- Android notifications work via JNI (DnaNotificationHelper)
- Tapping notification opens the app
- Does NOT navigate to the correct chat - just opens main screen

### What's Missing
1. Notification PendingIntent doesn't include contact fingerprint
2. MainActivity doesn't handle intent extras
3. No MethodChannel to pass fingerprint to Flutter
4. Flutter doesn't listen for navigation requests from native

### Desired Behavior
User taps notification, app opens directly to the chat with that contact.

### Implementation Plan
1. `DnaNotificationHelper.kt` - Put fingerprint in Intent extras
2. `MainActivity.kt` - Override `onNewIntent()`, forward fingerprint via MethodChannel
3. `DnaServiceMethodChannel.kt` - Add method to send navigation request to Flutter
4. Flutter - Listen on MethodChannel, navigate to ChatScreen with correct contact

### Files to Modify
- `android/app/src/main/kotlin/.../DnaNotificationHelper.kt`
- `android/app/src/main/kotlin/.../MainActivity.kt`
- `android/app/src/main/kotlin/.../DnaServiceMethodChannel.kt`
- `lib/main.dart` or navigation handler

---

## Native Desktop Notifications

**Priority:** High
**Status:** Not Started

### Current State
- Android notifications work via JNI (DnaNotificationHelper)
- Desktop (Linux/Windows) has no working notifications
- Flutter notifications don't work when app is unfocused (Flutter pauses event loop)

### What's Missing
1. Linux: libnotify integration in C code
2. Windows: Win32 Toast notification integration in C code
3. Callback mechanism similar to Android JNI

### Desired Behavior
Native system notifications on all platforms when messages arrive, even when app is unfocused/minimized.

### Implementation Plan

**Linux (libnotify):**
1. Add libnotify dependency to CMakeLists.txt
2. Create `notification_linux.c` with `notify_init()`, `notify_notification_new()`, etc.
3. Call from message receive callback in C engine

**Windows (Win32 Toast):**
1. Use WinToast library or raw Win32 Shell_NotifyIcon API
2. Create `notification_windows.c`
3. Call from message receive callback in C engine

### Files to Create/Modify
- `src/notifications/notification_linux.c` (new)
- `src/notifications/notification_windows.c` (new)
- `src/notifications/notification.h` (new - cross-platform interface)
- `CMakeLists.txt` - add libnotify dependency for Linux
- `src/api/dna_engine.c` - call notification functions on message receive

---

## Delivery & Read Receipts

**Priority:** Medium
**Status:** Not Started

### Current State (v15)
- Message status values: PENDING(0), SENT(1), RECEIVED(2), FAILED(3)
- Functions exist to update local status: `message_backup_update_status()`
- ACK system marks messages as RECEIVED when recipient fetches from DHT
- **Missing:** Explicit READ receipts (separate from delivery confirmation)

### What's Missing
1. Receipt message type (e.g., `MESSAGE_TYPE_RECEIPT = 2`)
2. Send delivery receipt when message received from DHT
3. Send read receipt when user opens/views message
4. Listener for incoming receipts to update sender's message status
5. UI indicators (double-check for delivered, blue double-check for read)

### Desired Behavior
- **Delivered:** When recipient's device receives message, sender sees double-checkmark
- **Read:** When recipient opens chat/views message, sender sees blue double-checkmark
- Privacy option: Allow users to disable sending read receipts

### Implementation Plan

**1. Define Receipt Message Format:**
```c
// Minimal receipt payload (inside encrypted message)
typedef struct {
    uint8_t receipt_type;      // 1 = delivered, 2 = read
    uint64_t original_timestamp; // Timestamp of original message
    char original_sender[129];   // Who sent the message we're acknowledging
} receipt_payload_t;
```

**2. Send Delivery Receipt (on message receive):**
```
Recipient receives message from DHT
    │
    ├─ Save message locally
    │
    └─ Queue delivery receipt to sender's outbox (Spillway)
        └─ Encrypted with sender's Kyber pubkey
```

**3. Send Read Receipt (on message view):**
```
User opens chat screen / scrolls to unread messages
    │
    └─ For each newly-viewed message:
        └─ Queue read receipt to sender's outbox
```

**4. Process Incoming Receipts:**
```
Receive receipt from contact's outbox
    │
    ├─ Decrypt & verify signature
    │
    ├─ Find matching message by (sender, timestamp)
    │
    └─ Update status: RECEIVED(2) or add READ tracking (future)
```

### Files to Modify
- `messenger/messages.h` - Add MESSAGE_TYPE_RECEIPT
- `messenger/messages.c` - Add `messenger_send_receipt()`
- `src/api/dna_engine.c` - Call send_receipt on message receive, process incoming receipts
- `message_backup.c` - Query to find message by sender+timestamp
- `lib/screens/chat/chat_screen.dart` - Send read receipts when messages viewed
- `lib/widgets/message_bubble.dart` - Show delivered/read indicators

### Privacy Considerations
- Add user preference: "Send read receipts" (default: on)
- Delivery receipts could also be optional but are less privacy-sensitive
- Store preference in profile or local settings

---
