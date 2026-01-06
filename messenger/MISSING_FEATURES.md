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
