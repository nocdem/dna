# DNA Messenger ImGui - Coding Guidelines

**Last Updated:** 2025-11-12
**For:** ImGui GUI development (imgui_gui/)
**Branch:** bugs+ui-polish2

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Modular Structure](#modular-structure)
3. [Async Operations](#async-operations)
4. [UI Component Guidelines](#ui-component-guidelines)
5. [State Management](#state-management)
6. [Code Style](#code-style)
7. [Common Patterns](#common-patterns)
8. [Testing](#testing)
9. [Performance](#performance)
10. [Don'ts](#donts)

---

## Architecture Overview

### Design Principles

1. **Separation of Concerns** - Each module has a single, well-defined responsibility
2. **Async-First** - All I/O operations must be asynchronous
3. **Reusable Components** - DRY (Don't Repeat Yourself)
4. **Immutable State Updates** - State changes flow through AppState
5. **Mobile-First Responsive** - Support both desktop and mobile layouts

### Project Structure

```
imgui_gui/
├── app.cpp/h              # Main orchestration (767 lines - keep minimal!)
├── main.cpp               # Entry point, theme setup
├── settings_manager.cpp   # Persistent settings (theme, scale)
├── ui_helpers.cpp         # Shared UI utilities
├── core/
│   ├── app_state.h        # Central state definitions
│   ├── app_state.cpp      # State initialization
│   └── data_types.h       # Shared data structures
├── dialogs/               # Modal dialogs (user interactions)
│   ├── add_contact_dialog.cpp
│   ├── send_dialog.cpp
│   ├── receive_dialog.cpp
│   ├── transaction_history_dialog.cpp
│   ├── message_wall_dialog.cpp
│   ├── profile_editor_dialog.cpp
│   ├── register_name_dialog.cpp
│   └── identity_dialogs.cpp
├── helpers/               # Business logic (no UI)
│   ├── identity_helpers.h  # Identity utilities (header-only)
│   ├── wallet_helpers.cpp  # Wallet operations
│   ├── async_task.h        # Async task wrapper
│   └── async_task_queue.h  # Task queue management
├── ui/                    # Reusable UI components
│   ├── navigation.cpp      # Bottom navigation bar
│   ├── contacts_list.cpp   # Contact list widget
│   └── sidebar.cpp         # Desktop sidebar
└── views/                 # Main application views
    ├── chat_view.cpp       # Chat interface
    ├── wallet_view.cpp     # Wallet view
    └── settings_view.cpp   # Settings view
```

---

## Modular Structure

### When to Create a New Module

**Create a new file when:**
- ✅ Code is reused in multiple places (context menus, formatters, validators)
- ✅ A feature has >150 lines of code (dialogs, views, components)
- ✅ Logic is independent and testable (helpers, utilities)
- ✅ A clear separation of concerns exists (wallet logic, identity logic)

**Keep in app.cpp only:**
- Main render loop coordination
- Identity/contact/message loading coordination
- Layout orchestration (mobile/desktop switching)
- Thin wrapper functions that delegate to helpers

### Module Types

#### 1. **Dialogs** (`dialogs/`)
Modal windows for user interactions.

```cpp
// dialogs/example_dialog.h
#ifndef EXAMPLE_DIALOG_H
#define EXAMPLE_DIALOG_H

#include "../core/app_state.h"

class ExampleDialog {
public:
    void render(AppState& state);
};

#endif
```

**Pattern:**
- Class-based
- `render(AppState& state)` method
- Update state flags directly (`state.show_example_dialog = false`)
- Use `ui_helpers.h` for buttons (`ThemedButton()`)

#### 2. **Views** (`views/`)
Main application screens (Chat, Wallet, Settings).

```cpp
// views/example_view.h
#ifndef EXAMPLE_VIEW_H
#define EXAMPLE_VIEW_H

#include "../core/app_state.h"

class DNAMessengerApp;  // Forward declaration

class ExampleView {
public:
    void render(AppState& state, DNAMessengerApp* app);
};

#endif
```

**Pattern:**
- Class-based
- Takes `AppState&` and `DNAMessengerApp*`
- May use `friend class ExampleView;` in app.h for private access
- Handles layout switching (mobile/desktop)

#### 3. **UI Components** (`ui/`)
Reusable UI widgets (navigation, sidebar, lists).

```cpp
// ui/example_component.h
#ifndef EXAMPLE_COMPONENT_H
#define EXAMPLE_COMPONENT_H

#include "../core/app_state.h"

class DNAMessengerApp;

class ExampleComponent {
public:
    void render(AppState& state, DNAMessengerApp* app);
};

#endif
```

**Pattern:**
- Class-based
- Encapsulates UI logic
- Stateless (all state in AppState)

#### 4. **Helpers** (`helpers/`)
Business logic without UI (wallet operations, identity utilities).

```cpp
// helpers/example_helpers.h
#ifndef EXAMPLE_HELPERS_H
#define EXAMPLE_HELPERS_H

#include "../core/app_state.h"

namespace ExampleHelpers {
    void doSomething(AppState& state, const std::string& param);
    bool validateInput(const std::string& input);
    std::string formatOutput(const std::string& raw);
}

#endif
```

**Pattern:**
- Namespace-based (not classes)
- Pure functions where possible
- No ImGui calls (business logic only)
- Header-only for small utilities

---

## Async Operations

### ⚠️ CRITICAL RULE: Never Block the UI Thread

**All I/O operations MUST be asynchronous:**
- ✅ DHT operations (key lookups, data storage, retrieval)
- ✅ Message polling (offline queue checks)
- ✅ Network requests (RPC calls, balance queries)
- ✅ File operations (large reads/writes)
- ✅ Database queries (message history, contacts)
- ✅ Cryptographic operations (key generation, signing)

### Async Infrastructure

#### 1. **Task Queue System**

```cpp
#include "helpers/async_task.h"
#include "helpers/async_task_queue.h"

// Create async task
auto task = std::make_shared<AsyncTask>([&state]() {
    // Background work (runs in thread pool)
    std::string result = perform_slow_operation();
    return result;
}, [&state](const std::string& result) {
    // UI update (runs on main thread)
    state.result_message = result;
    state.operation_complete = true;
});

// Queue task
task_queue.push(task);
```

#### 2. **Task State Pattern**

```cpp
// In AppState (core/app_state.h)
struct AppState {
    bool operation_in_progress = false;
    std::string operation_result;
    std::string operation_error;
};

// In async task
auto task = std::make_shared<AsyncTask>([&state]() {
    try {
        // Background work
        auto result = dht_lookup("key");
        return std::make_pair(result, std::string(""));
    } catch (const std::exception& e) {
        return std::make_pair(std::string(""), std::string(e.what()));
    }
}, [&state](const std::pair<std::string, std::string>& result) {
    state.operation_in_progress = false;
    if (!result.second.empty()) {
        state.operation_error = result.second;
    } else {
        state.operation_result = result.first;
    }
});
```

#### 3. **Loading Indicators**

Always show visual feedback during async operations:

```cpp
if (state.operation_in_progress) {
    ThemedSpinner("Loading", 20.0f, 3.0f);
} else {
    // Show result
    ImGui::Text("%s", state.operation_result.c_str());
}
```

#### 4. **Error Handling**

```cpp
// In async completion callback
[&state](const Result& result) {
    if (result.error) {
        state.error_message = result.error_msg;
        state.show_error_dialog = true;
    } else {
        state.success_message = "Operation complete!";
    }
}
```

### Common Async Patterns

#### DHT Operations
```cpp
// ❌ WRONG - Blocks UI thread
std::string value = dht_get("key");  // UI freezes!

// ✅ CORRECT - Async with loading state
state.dht_loading = true;
auto task = std::make_shared<AsyncTask>([key]() {
    return dht_get(key);
}, [&state](const std::string& value) {
    state.dht_loading = false;
    state.dht_value = value;
});
task_queue.push(task);
```

#### Message Polling
```cpp
// Use timer for periodic polling (see app.cpp)
if (ImGui::GetTime() - state.last_message_check > 120.0) {
    state.last_message_check = ImGui::GetTime();
    checkForNewMessages();  // Async function
}
```

#### RPC Calls
```cpp
// ❌ WRONG - Blocks UI
cellframe_rpc_response_t* resp = cellframe_rpc_call(...);

// ✅ CORRECT - Async
auto task = std::make_shared<AsyncTask>([params]() {
    cellframe_rpc_response_t* resp = cellframe_rpc_call(...);
    std::string result = parse_response(resp);
    cellframe_rpc_response_free(resp);
    return result;
}, [&state](const std::string& result) {
    state.balance = result;
});
task_queue.push(task);
```

---

## UI Component Guidelines

### Responsive Design

Always support both mobile and desktop layouts:

```cpp
void ExampleView::render(AppState& state, DNAMessengerApp* app) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    float padding = is_mobile ? 15.0f : 20.0f;
    float button_height = is_mobile ? 50.0f : 40.0f;

    if (is_mobile) {
        // Full-width layout
        ImGui::Button("Action", ImVec2(-1, button_height));
    } else {
        // Fixed-width layout
        ImGui::Button("Action", ImVec2(200, button_height));
    }
}
```

### Theme Support

Use theme colors from `theme_colors.h`:

```cpp
#include "theme_colors.h"
extern AppSettings g_app_settings;

// Get themed colors
ImVec4 text_color = (g_app_settings.theme == 0)
    ? DNATheme::Text()
    : ClubTheme::Text();

ImVec4 bg_color = (g_app_settings.theme == 0)
    ? DNATheme::Background()
    : ClubTheme::Background();
```

### Reusable UI Helpers

Use shared utilities from `ui_helpers.h`:

```cpp
#include "ui_helpers.h"

// ThemedButton - Single button function for ALL UI (dialogs, main UI, etc.)
// Automatically themed, supports optional active state highlighting
if (ThemedButton("Confirm", ImVec2(200, 40))) {
    // Action - automatically themed for current theme
}

// With active state (for navigation, tabs, etc.)
if (ThemedButton("Chat", ImVec2(200, 40), is_chat_active)) {
    // Highlighted when is_chat_active == true
}

// ThemedSpinner - Loading indicator (automatically themed)
ThemedSpinner("Loading", 20.0f, 3.0f);
```

**Button Guidelines:**
- Use `ThemedButton()` for ALL buttons (dialogs, modals, navigation, actions)
- Automatically adapts to current theme (DNA cyan / Club orange)
- Optional `is_active` parameter for persistent highlighting (tabs, navigation, etc.)
- Pass `ImVec2(-1, height)` for full-width buttons (mobile-friendly)

### Font Awesome Icons

**⚠️ CRITICAL: Always use FontAwesome icons - NEVER use emoji characters!**

Emoji (🆕📥✓✗⚠️) render inconsistently across platforms and themes.
FontAwesome icons render perfectly everywhere.

```cpp
#include "font_awesome.h"

// ✅ CORRECT - FontAwesome icons
ImGui::Text(ICON_FA_USER " Profile");
ImGui::Text(ICON_FA_WALLET " Wallet");
ImGui::Text(ICON_FA_GEAR " Settings");
if (ThemedButton(ICON_FA_PLUS " Create", ImVec2(200, 40))) { }
ImGui::TextColored(color, ICON_FA_CIRCLE_CHECK " Success");
ImGui::TextColored(color, ICON_FA_CIRCLE_XMARK " Error");
ImGui::TextColored(color, ICON_FA_TRIANGLE_EXCLAMATION " Warning");

// ❌ WRONG - Emoji characters
ImGui::Text("🆕 Profile");  // DON'T DO THIS!
if (ThemedButton("✓ OK", ImVec2(200, 40))) { }  // DON'T DO THIS!
```

**Common Icon Mappings:**
- New/Create: `ICON_FA_PLUS`
- Download/Import: `ICON_FA_DOWNLOAD`
- Success/Check: `ICON_FA_CIRCLE_CHECK` or `ICON_FA_CHECK`
- Error/X: `ICON_FA_CIRCLE_XMARK` or `ICON_FA_XMARK`
- Warning: `ICON_FA_TRIANGLE_EXCLAMATION`
- Info: `ICON_FA_CIRCLE_INFO`
- User: `ICON_FA_USER`
- Wallet: `ICON_FA_WALLET`
- Send: `ICON_FA_PAPER_PLANE`
- Settings: `ICON_FA_GEAR`

See `font_awesome.h` for full icon list.

### Input Validation

Validate user input before processing:

```cpp
// Input buffer
char input_buf[256] = "";
ImGui::InputText("Address", input_buf, sizeof(input_buf));

// Validate on submit
if (ImGui::Button("Send")) {
    std::string addr(input_buf);
    if (addr.empty()) {
        state.error_message = "Address cannot be empty";
        state.show_error_dialog = true;
    } else if (!is_valid_address(addr)) {
        state.error_message = "Invalid address format";
        state.show_error_dialog = true;
    } else {
        // Process valid input
        sendTransaction(addr);
    }
}
```

### Context Menus

Pattern for reusable context menus:

```cpp
// In ui_helpers.cpp
void ShowContactContextMenu(Contact& contact, AppState& state) {
    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem(ICON_FA_TRASH " Delete")) {
            state.delete_contact_id = contact.id;
            state.show_confirm_delete = true;
        }
        if (ImGui::MenuItem(ICON_FA_USER " View Details")) {
            state.selected_contact = contact;
            state.show_contact_details = true;
        }
        ImGui::EndPopup();
    }
}

// Usage
ShowContactContextMenu(contact, state);
```

---

## State Management

### AppState Structure

All application state lives in `AppState` (core/app_state.h):

```cpp
struct AppState {
    // Identity
    std::string current_identity;
    bool identity_loaded = false;

    // UI State
    int current_view = 0;  // 0=Chat, 1=Wallet, 2=Settings
    bool show_add_contact_dialog = false;
    bool show_send_dialog = false;

    // Data
    std::vector<Contact> contacts;
    std::vector<Message> messages;
    std::map<std::string, std::string> token_balances;

    // Async State
    bool contacts_loading = false;
    bool messages_loading = false;
    std::string error_message;
};
```

### State Update Rules

1. **Single Source of Truth** - All state in AppState
2. **Immutable Updates** - Create new values, don't mutate
3. **Clear Flags** - Use boolean flags for UI state
4. **Async State** - Track loading/error states for async operations

```cpp
// ✅ GOOD - Clear state updates
state.show_dialog = true;
state.selected_contact_index = 5;
state.error_message = "Failed to load";

// ❌ BAD - Hidden state in class members
class MyDialog {
    int selected_index;  // Don't do this!
};
```

### State Access Patterns

#### Dialogs
```cpp
void ExampleDialog::render(AppState& state) {
    // Read state
    if (state.show_example_dialog) {
        // Dialog content

        // Update state
        state.show_example_dialog = false;
    }
}
```

#### Views
```cpp
void ExampleView::render(AppState& state, DNAMessengerApp* app) {
    // Read state
    for (const auto& item : state.items) {
        ImGui::Text("%s", item.name.c_str());
    }

    // Trigger actions via app methods
    if (ImGui::Button("Load More")) {
        app->loadMoreItems();  // Updates state asynchronously
    }
}
```

#### Helpers
```cpp
namespace ExampleHelpers {
    void ProcessData(AppState& state) {
        // Read and update state
        state.result = compute(state.input);
    }
}
```

---

## Code Style

### C++ Standards

- **C++17** required
- Use STL containers (`std::vector`, `std::map`, `std::string`)
- Prefer `auto` for complex types
- Use `nullptr` instead of `NULL`

### Naming Conventions

```cpp
// Classes: PascalCase
class ContactsList { };
class WalletView { };

// Functions/Methods: camelCase
void loadMessages() { }
void refreshBalances() { }

// Variables: snake_case or camelCase (be consistent in module)
int contact_index = 0;
bool isLoading = false;

// Constants: UPPER_CASE
#define MAX_MESSAGE_LENGTH 5000
const int POLLING_INTERVAL = 120;

// Namespaces: PascalCase
namespace WalletHelpers { }
namespace IdentityHelpers { }
```

### File Naming

```cpp
// Headers: snake_case.h
example_dialog.h
wallet_helpers.h

// Implementation: snake_case.cpp
example_dialog.cpp
wallet_helpers.cpp
```

### Code Organization

```cpp
// 1. Includes (grouped and sorted)
#include "header.h"
#include "../core/app_state.h"
#include "../imgui.h"
#include <string>
#include <vector>

extern "C" {
    #include "../../messenger.h"
}

// 2. Constants and macros
#define MAX_SIZE 100
const int DEFAULT_TIMEOUT = 30;

// 3. Helper functions (static/anonymous namespace)
static std::string formatValue(double value) {
    // ...
}

// 4. Class implementation
void ExampleDialog::render(AppState& state) {
    // ...
}
```

### Comments

```cpp
// Use clear, concise comments for complex logic

// ✅ GOOD - Explains "why"
// DHT operations must be async to prevent UI freezing
auto task = std::make_shared<AsyncTask>(...);

// ✅ GOOD - Documents non-obvious behavior
// Network fee is always 0.002 CELL, hardcoded by protocol
#define NETWORK_FEE_DATOSHI 2000000000000000ULL

// ❌ BAD - States the obvious
// Increment counter
counter++;
```

### Error Handling

```cpp
// Always handle errors gracefully

// ✅ GOOD - Check return codes
int ret = messenger_send_message(msg);
if (ret != 0) {
    state.error_message = "Failed to send message";
    state.show_error_dialog = true;
    return;
}

// ✅ GOOD - Try-catch for exceptions
try {
    double value = std::stod(amount_str);
} catch (const std::exception& e) {
    state.error_message = "Invalid amount format";
    return;
}

// ❌ BAD - Ignore errors
messenger_send_message(msg);  // What if it fails?
```

---

## Common Patterns

### Dialog Pattern

```cpp
// header.h
class ExampleDialog {
public:
    void render(AppState& state);
};

// implementation.cpp
void ExampleDialog::render(AppState& state) {
    if (!state.show_example_dialog) return;

    ImGui::OpenPopup("Example");
    if (ImGui::BeginPopupModal("Example", nullptr,
        ImGuiWindowFlags_AlwaysAutoResize)) {

        ImGui::Text("Dialog content");
        ImGui::Spacing();

        if (ThemedButton("Confirm", ImVec2(200, 40))) {
            // Action
            state.show_example_dialog = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine();

        if (ThemedButton("Cancel", ImVec2(200, 40))) {
            state.show_example_dialog = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}
```

### View Pattern

```cpp
void ExampleView::render(AppState& state, DNAMessengerApp* app) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("ExampleContent", ImVec2(-padding, -padding), false);

    // Header
    ImGui::Text(ICON_FA_EXAMPLE " Example View");
    ImGui::Separator();
    ImGui::Spacing();

    // Content
    // ...

    ImGui::EndChild();
}
```

### List Rendering Pattern

```cpp
// Scrollable list with items
ImGui::BeginChild("ItemList", ImVec2(0, -50), true);

for (size_t i = 0; i < state.items.size(); i++) {
    const auto& item = state.items[i];

    bool is_selected = (state.selected_item_index == i);

    if (ImGui::Selectable(item.name.c_str(), is_selected)) {
        state.selected_item_index = i;
        app->loadItemDetails(i);
    }

    // Context menu
    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem(ICON_FA_TRASH " Delete")) {
            state.delete_item_index = i;
        }
        ImGui::EndPopup();
    }
}

ImGui::EndChild();
```

### Form Input Pattern

```cpp
// Input validation example
static char input_buf[256] = "";
static std::string validation_error;

ImGui::InputText("Field", input_buf, sizeof(input_buf));

if (!validation_error.empty()) {
    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
        "%s", validation_error.c_str());
}

if (ImGui::Button("Submit")) {
    std::string value(input_buf);

    if (value.empty()) {
        validation_error = "Field cannot be empty";
    } else if (!validate(value)) {
        validation_error = "Invalid format";
    } else {
        validation_error.clear();
        // Process valid input
        processInput(value);
    }
}
```

### Async Operation Pattern

```cpp
// In app.cpp or view
void ExampleView::startAsyncOperation() {
    state.operation_in_progress = true;
    state.operation_error.clear();

    auto task = std::make_shared<AsyncTask>(
        // Background work
        [param = state.input_param]() {
            try {
                auto result = perform_operation(param);
                return std::make_pair(result, std::string(""));
            } catch (const std::exception& e) {
                return std::make_pair(Result(), std::string(e.what()));
            }
        },
        // UI update
        [&state](const std::pair<Result, std::string>& result) {
            state.operation_in_progress = false;

            if (!result.second.empty()) {
                state.operation_error = result.second;
            } else {
                state.operation_result = result.first;
            }
        }
    );

    task_queue.push(task);
}

// In render
if (state.operation_in_progress) {
    ThemedSpinner("Processing", 20.0f, 3.0f);
} else if (!state.operation_error.empty()) {
    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
        "Error: %s", state.operation_error.c_str());
} else {
    // Show result
}
```

---

## Testing

### Manual Testing Checklist

Before committing changes, test:

- ✅ Desktop layout (window > 600px wide)
- ✅ Mobile layout (window < 600px wide)
- ✅ Both themes (DNA cyan, Club orange)
- ✅ All async operations complete successfully
- ✅ Error states show appropriate messages
- ✅ Loading indicators appear during async operations
- ✅ No UI freezing during I/O operations

### Build Testing

```bash
# Clean rebuild
cd build && rm -rf imgui_gui/
cmake .. && make -j8 dna_messenger_imgui

# Should see: [100%] Built target dna_messenger_imgui
# No errors, no warnings
```

### Runtime Testing

```bash
# Run application
./build/imgui_gui/dna_messenger_imgui

# Test all features:
# - Create/load identity
# - Add contact
# - Send message
# - Load wallet
# - Send transaction
# - Theme switching
# - Settings changes
```

---

## Performance

### Optimization Guidelines

1. **Avoid Expensive Operations in Render Loop**
   ```cpp
   // ❌ BAD - Recalculates every frame
   void render() {
       auto result = expensive_calculation();  // Called 60 times/sec!
   }

   // ✅ GOOD - Cache results
   void render() {
       if (state.needs_recalculation) {
           state.cached_result = expensive_calculation();
           state.needs_recalculation = false;
       }
       auto result = state.cached_result;
   }
   ```

2. **Limit DHT Queries**
   ```cpp
   // ✅ Use timers to limit polling frequency
   if (ImGui::GetTime() - last_poll_time > 120.0) {
       last_poll_time = ImGui::GetTime();
       pollDHT();
   }
   ```

3. **Lazy Loading**
   ```cpp
   // Load data only when view is active
   if (state.current_view == VIEW_WALLET && !state.wallet_loaded) {
       loadWallet();
   }
   ```

4. **Efficient Rendering**
   ```cpp
   // Use ImGui::BeginChild for scrollable regions
   ImGui::BeginChild("List", ImVec2(0, -50), true);
   // Only visible items are rendered by ImGui
   for (const auto& item : items) {
       ImGui::Selectable(item.name.c_str());
   }
   ImGui::EndChild();
   ```

---

## Don'ts

### ❌ Never Do These

1. **Block the UI Thread**
   ```cpp
   // ❌ WRONG
   std::string result = dht_get("key");  // UI freezes!

   // ✅ CORRECT
   loadAsync([&]() { return dht_get("key"); });
   ```

2. **Store State in Class Members**
   ```cpp
   // ❌ WRONG
   class MyDialog {
       int selected_index;  // Hidden state!
   };

   // ✅ CORRECT - Use AppState
   struct AppState {
       int dialog_selected_index;
   };
   ```

3. **Hardcode Colors or Buttons**
   ```cpp
   // ❌ WRONG - Hardcoded colors
   ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.6f, 1.0f), "Text");

   // ❌ WRONG - Manual button styling
   ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.6f, 1.0f));
   ImGui::Button("Action");
   ImGui::PopStyleColor();

   // ✅ CORRECT - Use themed buttons
   ThemedButton("Action", ImVec2(200, 40));  // For dialogs
   ThemedButton("Action", ImVec2(200, 40));  // For main UI

   // ✅ CORRECT - Use theme colors for text
   ImVec4 color = (g_app_settings.theme == 0)
       ? DNATheme::Text() : ClubTheme::Text();
   ImGui::TextColored(color, "Text");
   ```

4. **Duplicate Code**
   ```cpp
   // ❌ WRONG - Copy-pasted validation
   if (addr.empty() || addr.length() < 10) { ... }  // Dialog 1
   if (addr.empty() || addr.length() < 10) { ... }  // Dialog 2

   // ✅ CORRECT - Shared helper
   bool validateAddress(const std::string& addr);
   ```

5. **Ignore Mobile Layout**
   ```cpp
   // ❌ WRONG - Desktop only
   ImGui::Button("Action", ImVec2(200, 40));

   // ✅ CORRECT - Responsive
   bool is_mobile = io.DisplaySize.x < 600.0f;
   float width = is_mobile ? -1 : 200;
   ImGui::Button("Action", ImVec2(width, 40));
   ```

6. **Create 500+ Line Files**
   ```cpp
   // ❌ WRONG - Monolithic file
   app.cpp (4,897 lines)  // Too big!

   // ✅ CORRECT - Modular
   app.cpp (767 lines)
   dialogs/ (8 files)
   views/ (3 files)
   helpers/ (2 files)
   ```

7. **Skip Error Handling**
   ```cpp
   // ❌ WRONG
   dna_encrypt_message(...);  // What if it fails?

   // ✅ CORRECT
   int ret = dna_encrypt_message(...);
   if (ret != 0) {
       state.error_message = "Encryption failed";
       state.show_error_dialog = true;
       return;
   }
   ```

8. **Use Magic Numbers**
   ```cpp
   // ❌ WRONG
   if (amount < 2000000000000000ULL) { ... }

   // ✅ CORRECT
   #define NETWORK_FEE_DATOSHI 2000000000000000ULL
   if (amount < NETWORK_FEE_DATOSHI) { ... }
   ```

9. **Use Emoji Instead of FontAwesome**
   ```cpp
   // ❌ WRONG - Emoji characters
   ImGui::Text("🆕 New");
   ImGui::Text("✓ Success");
   if (ThemedButton("📥 Import", size)) { }

   // ✅ CORRECT - FontAwesome icons
   ImGui::Text(ICON_FA_PLUS " New");
   ImGui::Text(ICON_FA_CIRCLE_CHECK " Success");
   if (ThemedButton(ICON_FA_DOWNLOAD " Import", size)) { }
   ```

---

## Examples

### Complete Dialog Example

```cpp
// dialogs/example_dialog.h
#ifndef EXAMPLE_DIALOG_H
#define EXAMPLE_DIALOG_H

#include "../core/app_state.h"

class ExampleDialog {
public:
    void render(AppState& state);
};

#endif

// dialogs/example_dialog.cpp
#include "example_dialog.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"

void ExampleDialog::render(AppState& state) {
    if (!state.show_example_dialog) return;

    ImGui::OpenPopup("Example Dialog");

    if (ImGui::BeginPopupModal("Example Dialog", nullptr,
        ImGuiWindowFlags_AlwaysAutoResize)) {

        ImGui::Text(ICON_FA_INFO " Enter your information:");
        ImGui::Spacing();

        // Input field
        static char input_buf[256] = "";
        ImGui::InputText("Name", input_buf, sizeof(input_buf));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Buttons
        if (ThemedButton("Confirm", ImVec2(200, 40))) {
            std::string name(input_buf);
            if (!name.empty()) {
                state.user_name = name;
                state.show_example_dialog = false;
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::SameLine();

        if (ThemedButton("Cancel", ImVec2(200, 40))) {
            state.show_example_dialog = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}
```

### Complete View Example

```cpp
// views/example_view.h
#ifndef EXAMPLE_VIEW_H
#define EXAMPLE_VIEW_H

#include "../core/app_state.h"

class DNAMessengerApp;

class ExampleView {
public:
    void render(AppState& state, DNAMessengerApp* app);
};

#endif

// views/example_view.cpp
#include "example_view.h"
#include "../app.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"

void ExampleView::render(AppState& state, DNAMessengerApp* app) {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("ExampleContent", ImVec2(-padding, -padding), false);

    // Header
    ImGui::Text(ICON_FA_STAR " Example View");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Content
    if (state.data_loading) {
        ThemedSpinner("Loading data", 20.0f, 3.0f);
    } else if (!state.error_message.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
            "Error: %s", state.error_message.c_str());
    } else {
        // Show data
        for (const auto& item : state.items) {
            ImGui::Text("%s", item.c_str());
        }
    }

    ImGui::Spacing();

    // Action button
    float btn_height = is_mobile ? 50.0f : 40.0f;
    if (ThemedButton("Reload", ImVec2(is_mobile ? -1 : 200, btn_height))) {
        app->reloadData();  // Async operation
    }

    ImGui::EndChild();
}
```

### Complete Helper Example

```cpp
// helpers/example_helpers.h
#ifndef EXAMPLE_HELPERS_H
#define EXAMPLE_HELPERS_H

#include <string>
#include "../core/app_state.h"

namespace ExampleHelpers {
    // Format user input for display
    std::string FormatInput(const std::string& input);

    // Validate input format
    bool ValidateInput(const std::string& input);

    // Process data (updates state)
    void ProcessData(AppState& state, const std::string& input);
}

#endif

// helpers/example_helpers.cpp
#include "example_helpers.h"
#include <algorithm>
#include <cctype>

namespace ExampleHelpers {

std::string FormatInput(const std::string& input) {
    std::string result = input;
    // Trim whitespace
    result.erase(result.begin(),
        std::find_if(result.begin(), result.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
    result.erase(
        std::find_if(result.rbegin(), result.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), result.end());
    return result;
}

bool ValidateInput(const std::string& input) {
    if (input.empty()) return false;
    if (input.length() < 3) return false;
    return true;
}

void ProcessData(AppState& state, const std::string& input) {
    std::string formatted = FormatInput(input);

    if (!ValidateInput(formatted)) {
        state.error_message = "Invalid input format";
        return;
    }

    state.processed_data = formatted;
    state.data_ready = true;
}

}  // namespace ExampleHelpers
```

---

## Quick Reference

### File Creation Checklist

When creating a new module:

1. ✅ Choose appropriate directory (dialogs/, views/, ui/, helpers/)
2. ✅ Create .h and .cpp files (or header-only for small utilities)
3. ✅ Add to CMakeLists.txt
4. ✅ Use appropriate pattern (class for UI, namespace for helpers)
5. ✅ Include in app.h if needed (with friend declaration)
6. ✅ Make async if doing I/O
7. ✅ Support mobile and desktop layouts
8. ✅ Use theme colors
9. ✅ Test both themes
10. ✅ Build and verify no errors

### Common Includes

```cpp
// UI Components
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"

// State
#include "../core/app_state.h"
#include "../core/data_types.h"

// App access
class DNAMessengerApp;

// Backend
extern "C" {
    #include "../../messenger.h"
    #include "../../messenger_p2p.h"
}

// Settings
extern AppSettings g_app_settings;
```

---

## Questions?

If you're unsure about:
- **Where to put code** → Check module structure section
- **How to make it async** → Check async operations section
- **UI patterns** → Check common patterns section
- **Code style** → Check code style section

**When in doubt, look at existing code!** The codebase follows these guidelines consistently.

---

**Remember:** Keep app.cpp minimal, make everything async, support mobile layouts, and follow the established patterns!
