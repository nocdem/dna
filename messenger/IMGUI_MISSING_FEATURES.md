# ImGui GUI - Migration Progress Tracker

**Last Updated:** 2025-11-09 06:05 UTC
**Branch:** feature/imgui-gui  
**Status:** Phase 1 Complete - Identity Creation & DHT Integration Working

---

## 🚀 IMPORTANT: Qt → ImGui 1:1 Port Required

**⚠️ CRITICAL:** This is a **1:1 port** from Qt to ImGui. The old Qt GUI in `gui/` directory is the **reference implementation**. All features, flows, and backend integrations must be ported exactly as they work in Qt.

**Reference Code Location:** `/home/mika/dev/dna-messenger/gui/`

### Porting Philosophy:
1. **Study Qt implementation first** - Understand how it works
2. **Port exact flow** - Same user experience, same backend calls
3. **Test against Qt behavior** - Verify results match
4. **Keep Qt code** - Don't delete, it's the reference

---

## 📊 Current Status (2025-11-09 09:18 UTC)

### ✅ Phase 1: Identity Management - COMPLETE
- ✅ **Real identity scanning** (scans ~/.dna/*.dsa files)
- ✅ **Real BIP39 seed generation** (24-word seeds)
- ✅ **Real key generation** (Kyber1024 + Dilithium5 from seeds)
- ✅ **Keys saved to disk** (~/.dna/fingerprint.{dsa,kem})
- ✅ **DHT singleton initialization** (threaded, non-blocking)
- ✅ **DHT key publishing** (forward + reverse mapping to DHT)
- ✅ **DHT reverse lookup** (displays registered names)
- ✅ **Name caching** (prevents blocking lookups)
- ✅ **Loading spinner** (animated, theme-aware, with status messages)
- ✅ **AsyncTask class** (reusable threaded operations)
- ✅ **Identity restore from seed** (BIP39 validation + key derivation)

**Working Features:**
- Create identity → generates real cryptographic keys + publishes to DHT
- Restore identity → derives keys from BIP39 seed + publishes to DHT
- Identity list → shows actual identities from ~/.dna/
- DHT lookup → finds registered names (reverse mapping)
- UI stays responsive (60fps) during DHT operations
- Contact list → loads real contacts from per-identity SQLite database

**Reference:** `gui/CreateIdentityDialog.cpp`, `gui/IdentitySelectionDialog.cpp`, `gui/main.cpp`

---

## 🛠️ Infrastructure Available for Use

### AsyncTask Class (NEW - 2025-11-09)
**Location:** `imgui_gui/async_task.h`  
**Purpose:** Run background operations without blocking UI

**How to use:**
```cpp
AsyncTask task;
task.start([](AsyncTask* task) {
    task->addMessage("Starting...");
    // Do work here (runs in background thread)
    task->addMessage("Complete!");
});

// In render loop:
if (task.isRunning()) {
    std::vector<std::string> messages = task.getMessages();
    // Show messages to user
}
```

**Features:**
- Thread-safe message passing
- Automatic thread lifecycle management
- Can be reused for multiple operations
- Used for DHT initialization (see main.cpp)

**Use cases:**
- DHT lookups (key queries, reverse lookups)
- Wallet RPC calls (balance queries, transactions)
- Message encryption/decryption (for large batches)
- Contact list sync
- Any operation that takes >100ms

### ThemedSpinner Utility
**Location:** `imgui_gui/ui_helpers.h`  
**Purpose:** Show animated loading spinner

```cpp
ThemedSpinner("my_spinner", radius, thickness);
```

**Features:**
- Automatically uses current theme colors
- Beautiful gradient arc animation
- Glowing endpoint
- Used in wallet view and DHT loading screen

### Name Caching System
**Location:** `imgui_gui/core/app_state.h` - `identity_name_cache`  
**Purpose:** Cache fingerprint → display name mappings

**How to use:**
```cpp
// Check cache first
auto cached = state.identity_name_cache.find(fingerprint);
if (cached != state.identity_name_cache.end()) {
    display_name = cached->second;
} else {
    // Do async DHT lookup, then store result:
    // state.identity_name_cache[fingerprint] = result;
}
```

**Why:** Prevents blocking DHT lookups on every frame (was causing 1fps UI!)

### DHT Singleton
**Location:** `dht/dht_singleton.h`  
**Purpose:** Global DHT context for entire app

**How to use:**
```cpp
dht_context_t *dht = dht_singleton_get();
if (dht) {
    // Use DHT functions
    dht_keyserver_lookup(dht, ...);
}
```

**Note:** Already initialized in main.cpp with threaded loading screen

---

## 🔄 Parallel Work Opportunities

**Other agents can work on these tasks simultaneously:**

### 🎯 High Priority - Can Start Now

#### Task A: Identity Restore from Seed ✅ COMPLETE (2025-11-09)
**Location:** `imgui_gui/app.cpp` - `renderRestoreStep2_Seed()` and `restoreIdentityWithSeed()`
**Qt Reference:** `gui/RestoreIdentityDialog.cpp` lines 150-250
**Status:** ✅ Done - Real BIP39 validation and key generation working

**Completed:**
- Real BIP39 mnemonic validation
- Seed derivation with qgp_derive_seeds_from_mnemonic()
- Key generation from seeds (Kyber1024 + Dilithium5)
- Secure memory wiping
- Keys saved to disk

**Commit:** 7b73864

#### Task B: Contact List Loading (2-3 hours) ✅ COMPLETE
**Location:** `imgui_gui/app.cpp` - `loadIdentity()` function (lines 809-881)
**Qt Reference:** `gui/MainWindow.cpp` lines 858-943 (`loadContacts()` function)
**Status:** ✅ Complete - Real contact loading integrated

**What was done:**
1. ✅ Added `messenger_context_t*` to AppState (stored as void* to avoid header conflicts)
2. ✅ Replaced 100-line mock contact data with real `messenger_get_contact_list()` call
3. ✅ Integrated `messenger_get_display_name()` for name resolution (DHT reverse lookup)
4. ✅ Initialize messenger context on identity load
5. ✅ Contacts now load from per-identity SQLite database
6. ⚠️  Presence system not yet integrated (all contacts show offline)

**Changes made:**
- `imgui_gui/core/app_state.h` - Added `void *messenger_ctx` member
- `imgui_gui/core/app_state.cpp` - Initialize messenger_ctx to nullptr
- `imgui_gui/app.cpp` - Rewrote `loadIdentity()` to use messenger API (73 lines)

**Backend API used:** `messenger_get_contact_list()`, `messenger_get_display_name()`
**Build status:** ✅ Compiles successfully

#### Task C: Add Contact Dialog (3-4 hours)
**Location:** Need to create modal in `imgui_gui/app.cpp`
**Qt Reference:** `gui/MainWindow.cpp` lines 500-600 (`onAddContact()` function)
**Status:** Not started

**What to do:**
1. Study Qt: Add contact flow (query DHT, save to DB)
2. Create `renderAddContactDialog()` function
3. Input field for fingerprint/name
4. Call `dht_keyserver_lookup()` to find public keys
5. Call `contacts_db_add_contact()` to save
6. Test: Should be able to add contacts and see them in list

**💡 TIP:** Use AsyncTask for DHT lookup to keep UI responsive:
```cpp
AsyncTask lookup_task;
lookup_task.start([fingerprint](AsyncTask* task) {
    task->addMessage("Looking up keys in DHT...");
    // Do dht_keyserver_lookup() here
    task->addMessage("Found!");
});
```

**Files to modify:**
- `imgui_gui/app.cpp` - Add new dialog function
- `imgui_gui/core/app_state.h` - Add dialog state

#### Task D: DHT Key Publishing ✅ COMPLETE (2025-11-09)
**Location:** `imgui_gui/app.cpp` - `createIdentityWithSeed()` function (lines 773-791)
**Qt Reference:** Look for `dht_keyserver_publish()` calls in Qt (might be in Settings)
**Status:** ✅ Complete - Keys are published to DHT with reverse mapping

**What was done:**
1. Keys published to DHT after identity creation
2. Forward mapping: fingerprint → public keys
3. Reverse mapping: fingerprint → display name
4. Success/failure handling with cache update
5. Verified working via DHT logs (3-node replication confirmed)

**Files modified:**
- `imgui_gui/app.cpp` - `createIdentityWithSeed()` now calls `dht_keyserver_publish()`

**Evidence from logs:**
```
[DHT_KEYSERVER] Publishing keys for fingerprint '711fc8a2...' to DHT
[DHT] PUT PERMANENT: ✓ Stored on 3 remote node(s)
[DHT_KEYSERVER] ✓ Signed reverse mapping published
[DHT_KEYSERVER] ✓ Keys published successfully
```

### 🎯 Medium Priority - Needs Phase 1 Complete

#### Task E: Message Loading (3-4 hours)
**Location:** `imgui_gui/app.cpp` - `renderChatView()` function
**Qt Reference:** `gui/MainWindow.cpp` lines 700-900 (message loading)
**Status:** Mock messages, needs SQLite integration

**What to do:**
1. Study Qt: How it loads messages from `~/.dna/messages.db`
2. Replace mock data with `messenger_list_messages()` calls
3. Load real timestamps and sender info
4. Test: Should see actual message history

**Files to modify:**
- `imgui_gui/app.cpp` - `renderChatView()` function

#### Task F: Send Message Integration (4-5 hours)
**Location:** `imgui_gui/app.cpp` - `renderChatView()` (send button handler)
**Qt Reference:** `gui/MainWindow.cpp` lines 1000-1100 (`onSendMessage()` function)
**Status:** Mock send, needs P2P integration

**What to do:**
1. Study Qt: How it encrypts and sends via `messenger_p2p_send()`
2. Replace mock send with real `messenger_p2p_send()` call
3. Save to database after sending
4. Update UI with sent message
5. Test: Message should appear in recipient's UI

**Files to modify:**
- `imgui_gui/app.cpp` - Send message handler

#### Task G: Receive Message Polling (3-4 hours)
**Location:** `imgui_gui/app.cpp` - Add polling timer
**Qt Reference:** `gui/MainWindow.cpp` lines 150-180 (pollTimer setup)
**Status:** Not started

**What to do:**
1. Study Qt: 5-second polling timer calls `checkForNewMessages()`
2. Add timer to check DHT offline queue
3. Call `messenger_p2p_check_offline_queue()` periodically
4. Update UI when new messages arrive
5. Test: Should receive messages when recipient sends

**Files to modify:**
- `imgui_gui/app.cpp` - Add polling system to `render()` or main loop

### 🎯 Low Priority - Polish & Features

#### Task H: Wallet Balance Loading (2-3 hours)
**Location:** `imgui_gui/app.cpp` - `renderWalletView()` function
**Qt Reference:** `gui/WalletDialog.cpp` lines 100-200 (`refreshBalances()`)
**Status:** Mock balances, needs RPC integration

**What to do:**
1. Study Qt: How it queries balances via `cellframe_rpc_call()`
2. Replace mock balances with real RPC calls
3. Show loading spinners during query (already have ThemedSpinner)
4. Handle errors gracefully
5. Test: Balances should match Cellframe CLI

**💡 TIP:** Use AsyncTask for RPC calls (they can be slow):
```cpp
AsyncTask balance_task;
balance_task.start([](AsyncTask* task) {
    task->addMessage("Querying CPUNK balance...");
    // Do cellframe_rpc_call() here
    task->addMessage("Querying CELL balance...");
    // More RPC calls
});

// In render loop, show ThemedSpinner while balance_task.isRunning()
```

**Files to modify:**
- `imgui_gui/app.cpp` - `renderWalletView()` function

---

## 📋 Backend Integration Checklist

### Phase 1: Identity Management (✅ COMPLETE - 2025-11-09)
- [x] **1.1 Identity Creation** ✅ DONE (2025-11-09)
  - [x] Integrate BIP39 seed generation (`bip39.h`, `bip39_pbkdf2.c`)
  - [x] Connect to key generation (`qgp_key.c`, `kyber_deterministic.c`)
  - [x] Wire up identity storage to `~/.dna/<fingerprint>.dsa` files
  - [x] Replace mock identity list with real filesystem scan
  - [x] DHT singleton initialization (threaded)
  - [x] Name caching for DHT reverse lookups
  - [x] DHT key publishing (forward + reverse mapping)
  - **Reference:** `gui/CreateIdentityDialog.cpp` (Qt implementation)

- [x] **1.2 Identity Restore** ✅ DONE (2025-11-09)
  - [x] Validate BIP39 seed phrase (24 words)
  - [x] Derive keys from seed phrase
  - [x] Store restored identity
  - [x] Publish to DHT
  - **Reference:** `gui/RestoreIdentityDialog.cpp`

- [x] **1.3 Identity Selection** ✅ DONE
  - [x] Load identities from `~/.dna/` directory
  - [x] Display with DHT name lookups
  - [x] Initialize messenger context with selected identity
  - **Reference:** `gui/IdentitySelectionDialog.cpp`

### Phase 2: Contacts (IN PROGRESS)
- [x] **2.1 Contact Database** ✅ DONE (2025-11-09)
  - [x] Integrate SQLite contacts DB (`contacts_db.h/c`)
  - [x] Load contacts for current identity
  - [ ] Display real online/offline status (presence system not integrated yet)
  - **Reference:** `gui/MainWindow.cpp` (loadContacts)

- [ ] **2.2 Add Contact** 🔄 IN PROGRESS (Task C - other agent)
  - [ ] Create "Add Contact" dialog
  - [ ] Validate contact identity format
  - [ ] Query DHT keyserver for public key
  - [ ] Save contact to SQLite
  - [ ] **Reference:** `gui/MainWindow.cpp` (onAddContact)

- [ ] **2.3 Contact List Sync**
  - [ ] Integrate DHT contact list sync (`dht/dht_contactlist.h/c`)
  - [ ] Auto-sync on startup
  - [ ] Manual sync button in settings
  - [ ] Show sync status indicator

### Phase 3: Messaging (HIGH PRIORITY)
- [ ] **3.1 Message Storage**
  - [ ] Integrate SQLite message DB (`~/.dna/messages.db`)
  - [ ] Load message history for selected contact
  - [ ] Display real timestamps
  - [ ] **Reference:** `messenger.h/c` (database functions)

- [ ] **3.2 Send Messages**
  - [ ] Integrate P2P transport (`messenger_p2p.h/c`)
  - [ ] Encrypt messages (Kyber1024 + AES-256-GCM)
  - [ ] Sign messages (Dilithium5)
  - [ ] Store sent messages in DB
  - [ ] **Reference:** `gui/MainWindow.cpp` (onSendMessage)

- [ ] **3.3 Receive Messages**
  - [ ] Set up P2P message listener
  - [ ] Decrypt incoming messages
  - [ ] Verify signatures
  - [ ] Store in database
  - [ ] Update UI in real-time
  - [ ] **Reference:** `messenger_p2p.c` (message receive flow)

- [ ] **3.4 Offline Message Queue**
  - [ ] Check DHT offline queue on startup
  - [ ] Poll queue periodically (2-minute timer)
  - [ ] Display offline messages
  - [ ] **Reference:** `dht/dht_offline_queue.h/c`

### Phase 4: Groups (MEDIUM PRIORITY)
- [ ] **4.1 Group Management**
  - [ ] Integrate DHT-based groups (`dht/dht_groups.h/c`)
  - [ ] Create group dialog
  - [ ] Add/remove members
  - [ ] Update group metadata
  - [ ] **Reference:** `messenger_stubs.c` (group functions)

- [ ] **4.2 Group Messaging**
  - [ ] Multi-recipient encryption
  - [ ] Group message display
  - [ ] Member list view

### Phase 5: Wallet (MEDIUM PRIORITY)
- [ ] **5.1 Wallet Loading**
  - [ ] Load Cellframe .dwallet files
  - [ ] Parse wallet addresses per network
  - [ ] **Reference:** `wallet.h/c`, `gui/WalletDialog.cpp`

- [ ] **5.2 Balance Queries**
  - [ ] Integrate Cellframe RPC (`cellframe_rpc.h/c`)
  - [ ] Query balances (CPUNK, CELL, KEL)
  - [ ] Replace mock balances with real data
  - [ ] Add loading spinners during queries
  - [ ] **Reference:** `gui/WalletDialog.cpp` (refreshBalances)

- [ ] **5.3 Send Tokens**
  - [ ] Create send dialog
  - [ ] Transaction builder integration (`cellframe_tx_builder_minimal.h/c`)
  - [ ] UTXO selection
  - [ ] Fee calculation
  - [ ] Sign and submit transaction
  - [ ] **Reference:** `gui/SendTokensDialog.cpp`

- [ ] **5.4 Receive Tokens**
  - [ ] Display wallet addresses
  - [ ] QR code generation
  - [ ] Copy to clipboard
  - [ ] **Reference:** `gui/ReceiveDialog.cpp`

- [ ] **5.5 Transaction History**
  - [ ] Query transaction history via RPC
  - [ ] Display with status colors
  - [ ] Pagination support
  - [ ] **Reference:** `gui/TransactionHistoryDialog.cpp`

### Phase 6: DHT Features (LOW PRIORITY)
- [ ] **6.1 Keyserver Integration**
  - [ ] Publish public keys to DHT
  - [ ] Query keys from DHT
  - [ ] Integrate keyserver cache (`keyserver_cache.h/c`)
  - [ ] **Reference:** `dht/dht_keyserver.h/c`

- [ ] **6.2 P2P Presence**
  - [ ] Register presence in DHT
  - [ ] Update presence periodically
  - [ ] Display peer online status
  - [ ] **Reference:** `p2p/p2p_transport.h/c`

### Phase 7: Polish & Testing (LOW PRIORITY)
- [ ] **7.1 Error Handling**
  - [ ] Add toast notifications for errors
  - [ ] Loading spinners for async operations
  - [ ] Confirmation dialogs

- [ ] **7.2 UI Refinements**
  - [ ] Unread message indicators
  - [ ] Typing indicators
  - [ ] Message status icons (sent, delivered, read)
  - [ ] File/image attachments

- [ ] **7.3 Code Refactoring**
  - [ ] Split main.cpp into modules
  - [ ] Extract dialog classes
  - [ ] Organize views into separate files

---

## ✅ Completed UI Features

### 1. Theme System (COMPLETE)
- ✅ theme_colors.h with DNA/Club theme colors
- ✅ ApplyTheme() function applies colors to all ImGui elements
- ✅ Settings page theme selector (radio buttons)
- ✅ Theme persisted to disk via SettingsManager
- ✅ Dynamic theme switching works
- **Files:** main.cpp (ApplyTheme), theme_colors.h, settings_manager.cpp/h

### 2. Contact List (COMPLETE)
- ✅ Contact list UI in sidebar (desktop) and full-screen (mobile)
- ✅ 100 mock contacts for testing
- ✅ Online/offline status with FontAwesome icons (✓ green, ✗ gray)
- ✅ Sorting: online first, then offline, then alphabetical
- ✅ Selected contact indicator (hover + active states)
- ✅ Scrollable contact area
- ✅ "Add Contact", "Create Group", and "Refresh" buttons at bottom of sidebar (40px height each)
- **Files:** main.cpp (renderSidebar, renderContactsList)

### 3. Chat Bubbles (COMPLETE)
- ✅ Speech bubble UI with down-pointing arrows
- ✅ Square bubbles with 100% width and padding (30px horizontal, 30px vertical)
- ✅ Triangle arrow pointing DOWN from bubble to sender name
- ✅ Sender name + timestamp below arrow
- ✅ Text wrapping inside bubbles (85% of available width)
- ✅ Recipient bubbles lighter (0.12 opacity) than own bubbles (0.25 opacity)
- ✅ Theme-aware bubble colors (uses DNATheme::Text()/ClubTheme::Text())
- ✅ Right-click context menu to copy message (compact, minimal padding, theme-aware hover with visible text)
- **Files:** main.cpp (renderChatView)

### 4. Identity Management (COMPLETE)
- ✅ Identity selection modal on first run
- ✅ 3-step identity creation wizard (Name → Seed Phrase → Creating)
- ✅ Restore from seed dialog with 24-word BIP39 validation (text wrapping, word count validation)
- ✅ BIP39 mock seed phrase generation
- ✅ Seed phrase copy to clipboard with visual feedback
- ✅ Identity name validation (3-20 chars, alphanumeric + underscore)
- ✅ Hover/selection states with theme colors
- ✅ Text vertically centered in identity list
- ✅ Deselect on second click
- ✅ Modal sizing optimized for 1000x600 minimum window
- **Files:** main.cpp (renderIdentitySelection, renderCreateIdentity*, renderRestoreFromSeed)

### 5. Settings Persistence (COMPLETE)
- ✅ Settings file at ~/.config/dna_messenger/settings.conf (Linux), %APPDATA%/dna_messenger (Windows), ~/Library/Application Support/dna_messenger (Mac), ~/.dna (Android)
- ✅ Cross-platform configuration support (Linux, Windows, Mac, Android)
- ✅ Save/load: theme, scale, window_width, window_height
- ✅ SettingsManager::Load() on startup
- �ingsManager::Save() on changes and exit
- ✅ Default values: theme=0, scale=0 (1.1x internal shown as 100%), window=1280x720
- ✅ Scale presets: Normal (1.1x/100%), Large (1.5x/150%)
- ✅ Restart notification when scale is changed
- **Files:** settings_manager.cpp/h

### 6. Font System (COMPLETE)
- ✅ Fonts embedded as headers (NotoSans-Regular.h, fa-solid-900.h)
- ✅ FreeType font rendering for better text quality
- ✅ Font loading with merge mode for FontAwesome icons
- ✅ Base font size: 18px * scale_multiplier (1.1x default, 1.5x large)
- ✅ Icon scaling: base_size * 0.9f
- ✅ Unicode range support for icons
- ✅ No colored emoji support (monochrome Font Awesome icons only)
- **Files:** main.cpp (main function, font atlas setup)

### 7. Responsive Layout (COMPLETE)
- ✅ Mobile layout (< 600px): Bottom nav bar + full-screen views
- ✅ Desktop layout: Sidebar + main content area
- ✅ Adaptive button sizes (mobile: 50-80px, desktop: 40px)
- ✅ Touch-friendly spacing on mobile
- ✅ Minimum window size: 1000x600 (desktop only)
- **Files:** main.cpp (renderMobileLayout, renderDesktopLayout)

### 8. Wallet View (COMPLETE)
- ✅ Token balance cards (CPUNK, CELL, KEL)
- ✅ Mock balances displayed
- ✅ Loading spinners next to balances (ThemedSpinner utility)
- ✅ Action buttons: Send, Receive, Transaction History
- ✅ Responsive layout (stacked on mobile, side-by-side on desktop)
- **Files:** main.cpp (renderWalletView)

### 9. Loading Spinner (COMPLETE)
- ✅ ThemedSpinner() utility function
- ✅ Beautiful gradient arc animation with glowing endpoint
- ✅ Theme-aware colors (cyan/orange)
- ✅ Customizable radius and thickness
- ✅ 2-second loading screen on app startup
- ✅ Used in wallet balance display
- ✅ Reusable across entire app
- **Files:** main.cpp (ThemedSpinner function)

### 10. Icon System (COMPLETE)
- ✅ Font Awesome 6 icons embedded
- ✅ ICON_FA_CIRCLE_PLUS for better visibility vs plain +
- ✅ Consistent icon sizing across UI
- **Files:** font_awesome.h, main.cpp

---

## 📁 File Organization

### Core Files
- **main.cpp** (2,100+ lines) - Main application, all views, dialogs
- **settings_manager.cpp/h** - Settings persistence
- **theme_colors.h** - Theme color definitions
- **modal_helper.h** - Modal dialog helpers
- **font_awesome.h** - Font Awesome 6 icon definitions

### Reference Files (Qt GUI - preserved for migration)
- **gui/MainWindow.cpp/h** - Main window (contact list, chat, messaging)
- **gui/WalletDialog.cpp/h** - Wallet view
- **gui/SendTokensDialog.cpp/h** - Send tokens
- **gui/ReceiveDialog.cpp/h** - Receive tokens
- **gui/TransactionHistoryDialog.cpp/h** - Transaction history
- **gui/CreateIdentityDialog.cpp/h** - Identity creation wizard
- **gui/RestoreIdentityDialog.cpp/h** - Restore from seed
- **gui/IdentitySelectionDialog.cpp/h** - Identity selection

---

## ❌ Backend Integration TODO

### 1. Text Scaling UI (COMPLETE)
- ✅ Settings page: "Normal" (1.1x) and "Large" (1.5x) radio buttons
- ✅ scale stored in AppSettings struct (0=Normal, 1=Large)
- ✅ scale persisted to disk
- ✅ Font atlas rebuilt on scale change (requires app restart)
- ✅ Restart notification shown when scale changed
- **Files:** main.cpp (renderSettingsView), settings_manager.h

### 2. UI Animations
- ❌ Smooth color transitions on hover (contacts, buttons)
- ❌ Animation system with delta time
- ❌ Fade effects for theme switching
- **Priority:** Low (polish)
- **Files:** main.cpp (custom animation logic)

### 3. Backend Integration
- ❌ DNA messenger core API integration (currently commented out)
- ❌ Real identity creation (bip39.h, messenger.h)
- ❌ Real contact list (contacts_db.h)
- ❌ Real message sending/receiving (messenger_p2p.h)
- ❌ Real wallet operations (wallet.h, cellframe_rpc.h)
- **Priority:** High (next phase)
- **Files:** main.cpp (uncomment includes, replace mock data)

### 4. Additional Dialogs (PARTIAL)
- ✅ Create Identity wizard (3-step: Name → Seed → Creating)
- ✅ Restore from Seed dialog (24-word BIP39 validation)
- ❌ Add Contact dialog
- ❌ Create Group dialog
- ❌ Send Tokens dialog
- ❌ Receive Address dialog (with QR code)
- ❌ Transaction History dialog
- **Priority:** Medium
- **Files:** main.cpp (modal dialogs)

### 5. Message Features (COMPLETE)
- ✅ Message timestamps (shown below bubbles)
- ✅ Enter to send message, Shift+Enter for newline
- ✅ Auto-focus on chat open and after send
- ✅ Emoji picker with ':' trigger (Font Awesome monochrome icons, 9 per row)
- ✅ Emoji picker closes on ESC, window resize, view change, or selection
- ✅ Auto-refocus to input after emoji selection or ESC
- ✅ Fullscreen support (F11 to toggle)
- ❌ Unread message indicators
- ❌ Typing indicators
- ❌ Message status icons (sent, delivered, read)
- ❌ File/image attachments
- **Priority:** Medium-High
- **Files:** main.cpp (Message struct, renderChatView)

### 6. UI Polish (COMPLETE)
- ✅ Emoji picker (Font Awesome monochrome icons: faces/hearts/symbols/objects, triggered with ':', 9 per row grid layout)
- ✅ Fullscreen support (F11 to toggle)
- ✅ System native context menus on right-click (ImGui fallback)
- ❌ Custom scrollbar styling (theme-aware)
- ❌ Toast notifications for errors/success
- ❌ Loading spinners for async operations
- ❌ Confirmation dialogs (delete contact, etc.)
- **Priority:** Medium
- **Files:** main.cpp (emoji picker, fullscreen toggle)

---

## 📊 Code Statistics
- **main.cpp:** 1,652 lines (monolithic, needs refactoring)
- **settings_manager.cpp:** 93 lines
- **theme_colors.h:** 32 lines
- **Total:** ~1,800 lines

---

## 🎯 Next Steps

### Phase 1: Text Scaling UI (1-2 hours)
1. Add "Text Size" section to Settings view
2. Radio buttons: "Default (1.1x)" and "Bigger (1.5x)"
3. Apply font_scale globally (replace hardcoded SetWindowFontScale)
4. Rebuild font atlas when scale changes (requires restart for now)

### Phase 2: Backend Integration (1-2 weeks)
1. Uncomment backend includes
2. Replace mock identity creation with real bip39/messenger calls
3. Replace mock contact list with contacts_db
4. Replace mock messages with messenger_p2p
5. Integrate wallet RPC calls

### Phase 3: Feature Completeness (2-3 weeks)
1. Add missing dialogs (Add Contact, Send Tokens, etc.)
2. Implement message features (timestamps, status, attachments)
3. Add UI polish (animations, toasts, confirmations)

### Phase 4: Code Refactoring (1 week)
1. Split main.cpp into separate files:
   - app.cpp/h (main application class)
   - views.cpp/h (contact list, chat, wallet, settings)
   - dialogs.cpp/h (modals)
   - theme.cpp/h (theme management)
2. Extract UI helpers (ButtonDark, ThemedButton, etc.)

---

## 📝 Notes
- All fonts are embedded (no external dependencies)
- Settings file location: `~/.config/dna_messenger/settings.conf`
- Mock data: 100 contacts (60% online), pre-populated messages
- Current mode: **UI SKETCH MODE** (backend disabled for UI development)
- Theme colors: DNA = Cyan (#00FFCC), Club = Orange (#FF7A1A)

---

## 🎯 Current Sprint

### Sprint Goal: Identity Management Integration
**Target Date:** TBD  
**Focus:** Replace mock identity system with real BIP39/key generation

**Tasks:**
1. Integrate BIP39 seed generation
2. Connect key generation (Kyber1024, Dilithium5)
3. Identity storage to filesystem
4. Identity loading from `~/.dna/`
5. Identity selection persistence

---

## 📊 Progress Metrics

- **UI Mockup:** ✅ 100% Complete
- **Backend Integration:** ⏳ 0% Complete
- **Qt GUI Migration:** 🔄 In Progress (reference code available)
- **Total Checklist Items:** 50
- **Completed:** 0
- **In Progress:** 0
- **Remaining:** 50

---

## 📝 Migration Notes

### Key Differences: Qt → ImGui
1. **No Signals/Slots** - Use direct function calls and callbacks
2. **Immediate Mode** - UI rebuilt every frame (state management critical)
3. **No Qt Widgets** - All UI built with ImGui primitives
4. **Manual Layout** - Explicit positioning vs Qt's layout managers
5. **Single File** - main.cpp vs multiple Qt dialog classes (for now)

### Backend Code Status
- ✅ All backend code available (merged from main)
- ✅ P2P transport layer complete
- ✅ DHT integration complete  
- ✅ Encryption/signing complete
- ✅ SQLite databases complete
- ✅ Wallet integration complete
- ⏳ Just needs wiring to ImGui UI

### Testing Strategy
1. Test each feature in isolation as it's integrated
2. Keep mock data alongside real data initially
3. Use debug logging to verify backend calls
4. Cross-reference Qt GUI behavior for expected results

---

## 🔗 Useful References

- **Qt GUI Code:** `gui/` directory (preserved for reference)
- **Backend Headers:** `messenger.h`, `messenger_p2p.h`, `wallet.h`, `cellframe_rpc.h`
- **DHT Layer:** `dht/dht_*.h` files
- **Encryption:** `dna_api.h`, `qgp_*.h` files
- **Database:** `contacts_db.h`, `message_backup.h`, `keyserver_cache.h`

---

## 📦 Code Organization Status (2025-11-09) - ✅ MAJOR REFACTORING IN PROGRESS

### ✅ Phase 1 Complete: Core Data Structures
- **core/data_types.h** - 22 lines ✅ EXTRACTED
  - Message struct
  - Contact struct

- **core/app_state.h** - 78 lines ✅ EXTRACTED
  - All enums (View, CreateIdentityStep, RestoreIdentityStep)
  - AppState class with all member variables

- **core/app_state.cpp** - 171 lines ✅ EXTRACTED
  - AppState constructor
  - scanIdentities() - mock data loading
  - loadIdentity() - mock contact loading

- **app.h** - 1,691 lines ✅ REFACTORED
  - Removed all member variables (now in AppState)
  - Added single `AppState state;` member
  - All references updated to use `state.` prefix

### 🔄 Phase 2-6 In Progress: Modularization
- Extracting dialogs, components, views, layouts
- See `REFACTORING_STATUS.md` for detailed progress

### Existing Helpers:
- **ui_helpers.h/cpp** - 150 lines ✅ EXTRACTED
- **settings_manager.h/cpp** - 100 lines ✅ SEPARATE
- **theme_colors.h** - 32 lines ✅ SEPARATE
- **helpers/identity_helpers.h** - 20 lines ✅ NEW

**Status: Major modular refactoring underway. Backend integration will follow completion.**

---

## 🎯 Quick Start for Other Agents

**Want to help? Pick a task and go!**

1. **Read the Qt reference code** in `gui/` directory
2. **Pick a task** from "Parallel Work Opportunities" above  
3. **Port the Qt logic** to ImGui in `imgui_gui/app.cpp`
4. **Test against Qt behavior** - results should match
5. **Commit with clear message** mentioning task letter

**Most Urgent:**
- Task A: Identity Restore (restores identities from seed)
- Task B: Contact List Loading (shows real contacts)
- Task D: DHT Key Publishing (makes identities discoverable)

**Communication:**
- Comment your code clearly
- Mark TODOs for incomplete parts
- Test thoroughly before committing

---

## 📈 Progress Summary (2025-11-09 09:18 UTC)

**Completed:**
- ✅ Phase 1: Identity Management (create + restore + DHT publishing)
- ✅ DHT Infrastructure (threaded, non-blocking, cached)
- ✅ Loading UX (spinner, status messages, 60fps)
- ✅ AsyncTask utility (reusable for all background ops)
- ✅ Contact list loading (SQLite integration)
- ✅ Identity selection modal fix (closes properly)

**In Progress:**
- 🔄 Task C: Add Contact Dialog (another agent)

**Next Priority:**
- ❌ Task E: Message Loading (SQLite message history)
- ❌ Task F: Send Message Integration (P2P + encryption)
- ❌ Task G: Receive Message Polling (DHT offline queue)
- ❌ Task H: Wallet Balance Loading (RPC integration)

**Performance:**
- ✅ 60fps smooth UI
- ✅ No blocking operations on render thread
- ✅ Threaded DHT bootstrap
- ✅ Cached DHT lookups

---

## 🔗 Key Resources

- **Qt Reference:** `/home/mika/dev/dna-messenger/gui/`
- **Backend Headers:** `messenger.h`, `messenger_p2p.h`, `contacts_db.h`, `dht/*.h`
- **ImGui GUI:** `/home/mika/dev/dna-messenger/imgui_gui/`
- **Build:** `cd build && make dna_messenger_imgui`
- **Run:** `./build/imgui_gui/dna_messenger_imgui`

---

**Last major update:** 2025-11-09 06:05 UTC - Phase 1 Complete, parallel tasks identified

