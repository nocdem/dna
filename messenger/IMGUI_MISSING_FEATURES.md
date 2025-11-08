# ImGui UI - Current Status & Missing Features

**Last Updated:** 2025-11-07
**Branch:** feature/imgui-gui

---

## ✅ Implemented Features

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
- ✅ Action buttons: Send, Receive, Transaction History
- ✅ Responsive layout (stacked on mobile, side-by-side on desktop)
- **Files:** main.cpp (renderWalletView)

---

## ❌ Missing Features (TODO)

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
