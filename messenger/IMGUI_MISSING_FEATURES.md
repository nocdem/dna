# ImGui UI - Missing Features (After main.cpp Overwrite)

## Lost Features (Need Re-implementation)

### 1. Theme System
- ✅ theme_colors.h exists (DNA/Club theme colors)
- ❌ Theme switching not fully integrated in main.cpp
- ❌ Settings page theme selector needs reconnection
- **Files affected:** main.cpp (theme application logic)

### 2. Contact List
- ❌ Contact list UI in sidebar (under Chat button)
- ❌ 50 mock contacts
- ❌ Online/offline status with FontAwesome icons (✓/✗)
- ❌ Sorting (online first, then offline)
- ❌ Selected contact indicator (bold text)
- ❌ Scrollable contact area
- ❌ Add Contact button (floats above contacts)
- **Files affected:** main.cpp (renderDesktopLayout)

### 3. Chat Bubbles
- ❌ Speech bubble UI for messages
- ❌ Square bubbles with padding
- ❌ Arrow pointing down to sender name
- ❌ Sender name + timestamp below bubble
- ❌ Text wrapping inside bubbles (using ImGui::BeginChild)
- ❌ Recipient bubbles ~5% lighter than own bubbles
- ❌ Theme-aware bubble colors
- **Files affected:** main.cpp (renderChatArea)

### 4. UI Animations
- ❌ Smooth color transitions on hover (contacts, buttons)
- ❌ Animation system for UI elements
- ❌ Identity list animations (modal)
- **Files affected:** main.cpp (custom animation logic)

### 5. Text Scaling
- ❌ Settings page: "Default" (1.1x) and "Bigger" (1.3x)
- ❌ Persistent settings (save/load)
- ❌ Button scaling with text
- ❌ Apply scaling globally
- **Files affected:** main.cpp (settings), settings_manager.cpp/h

### 6. Font System
- ✅ Fonts embedded as headers (NotoSans-Regular.h, fa-solid-900.h, NotoEmoji-Regular.h)
- ✅ Font loading code exists in main.cpp
- ❌ Emoji support not fully working
- **Files affected:** main.cpp (font atlas setup - lines ~1550)

### 7. UI Polish
- ❌ Scrollbar colors follow theme
- ❌ Separator lines follow theme (implemented in theme_colors.h, needs application)
- ❌ Border colors follow theme (implemented in theme_colors.h, needs application)
- ❌ Add Contact button same size as sidebar buttons
- ❌ Minimum window size enforcement (desktop only)

### 8. Identity List (Modal)
- ❌ Hover animations
- ❌ Selected identity has dark text (#191D21)
- ❌ Deselect on second click
- ❌ Text vertically centered
- ❌ Hover text color #191D21
- **Files affected:** main.cpp (renderIdentitySelection)

## Current Status
- **Build:** ✅ Compiles successfully
- **Run:** ⚠️ Basic UI works, missing advanced features
- **Branch:** feature/imgui-gui
- **Font Size:** Default should be 1.1x (currently 1.0x)

## Priority Implementation Order
1. **Theme system** - Make settings theme selector work
2. **Text scaling** - Default 1.1x, Bigger 1.3x with persistence
3. **Contact list** - Full contact sidebar with online/offline
4. **Chat bubbles** - Speech bubble UI with arrows
5. **Animations** - Smooth hover transitions
6. **UI Polish** - Scrollbars, separators, borders follow theme

## Notes
- All fonts are embedded (no external dependencies)
- Settings manager exists but not fully integrated
- Theme colors defined in theme_colors.h
- Mock data system in place for testing
