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
