// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface
// UI SKETCH MODE - Backend integration disabled for UI development

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "modal_helper.h"
#include "font_awesome.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <windows.h>
#include <direct.h>
#endif

// Comment out backend includes for UI sketch mode
/*
extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../messenger.h"
#include "../wallet.h"
#include "../messenger/keyserver_register.h"
#include "../bip39.h"
}
*/

// Global theme variable
int g_current_theme = 0; // 0 = DNA, 1 = Club

struct Message {
    std::string sender;
    std::string content;
    std::string timestamp;
    bool is_outgoing;
};

struct Contact {
    std::string name;
    std::string address;
    bool is_online;
};

// Helper function for buttons with dark text
inline bool ButtonDark(const char* label, const ImVec2& size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 1.0f, 0.8f, 1.0f));        // #00FFCC
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.9f, 0.7f, 1.0f)); // Slightly darker on hover
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.8f, 0.6f, 1.0f));  // Even darker when clicked
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.05f, 0.05f, 0.05f, 1.0f));       // Dark text
    bool result = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return result;
}

class DNAMessengerApp {
public:
    DNAMessengerApp() {
        current_view = VIEW_CONTACTS;
        selected_contact = -1;
        show_wallet = false;
        show_identity_selection = true;
        identity_loaded = false;
        selected_identity_idx = -1;
        create_identity_step = STEP_NAME;
        seed_confirmed = false;
        seed_copied = false;
        seed_copied_timer = 0.0f;
        memset(new_identity_name, 0, sizeof(new_identity_name));
        memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
    }

    void render() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Show identity selection on first run
        if (show_identity_selection) {
            renderIdentitySelection();
            return;
        }
        
        // Detect screen size for responsive layout
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        // Main window (fullscreen)
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("DNA Messenger", nullptr, 
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | 
            ImGuiWindowFlags_NoScrollbar);

        // Mobile: Full-screen views with bottom navigation
        // Desktop: Side-by-side layout
        if (is_mobile) {
            renderMobileLayout();
        } else {
            renderDesktopLayout();
        }
        
        ImGui::End();
    }

private:
    enum View {
        VIEW_CONTACTS,
        VIEW_CHAT,
        VIEW_WALLET,
        VIEW_SETTINGS
    };
    
    enum CreateIdentityStep {
        STEP_NAME,
        STEP_SEED_PHRASE,
        STEP_CREATING
    };

    View current_view;
    int selected_contact;
    bool show_wallet;
    bool show_identity_selection;
    bool identity_loaded;
    int selected_identity_idx;
    CreateIdentityStep create_identity_step;
    char generated_mnemonic[512];
    bool seed_confirmed;
    bool seed_copied;
    float seed_copied_timer;
    
    std::vector<Contact> contacts;
    std::map<int, std::vector<Message>> contact_messages;  // Per-contact message history
    std::vector<std::string> identities;
    std::string current_identity;
    char message_input[1024] = "";
    char new_identity_name[128];
    
    void renderIdentitySelection() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        // Open the modal on first render
        static bool first_render = true;
        if (first_render) {
            ImGui::OpenPopup("DNA Messenger - Select Identity");
            first_render = false;
        }
        
        // Set size before modal
        ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x * 0.9f : 500, is_mobile ? io.DisplaySize.y * 0.9f : 500));
        
        if (CenteredModal::Begin("DNA Messenger - Select Identity", nullptr, ImGuiWindowFlags_NoResize)) {
            // Add padding at top
            ImGui::Spacing();
            ImGui::Spacing();
        
        // Title
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text("Welcome to DNA Messenger");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Info text
        ImGui::TextWrapped("Select an existing identity or create a new one:");
        ImGui::Spacing();
        
        // Load identities on first render
        if (identities.empty()) {
            scanIdentities();
        }
        
        // Identity list
        ImGui::BeginChild("IdentityList", ImVec2(0, -120), true);
        
        if (identities.empty()) {
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No identities found.");
            ImGui::TextWrapped("Create a new identity to get started.");
        } else {
            for (size_t i = 0; i < identities.size(); i++) {
                ImGui::PushID(i);
                bool selected = (selected_identity_idx == (int)i);
                
                float item_height = is_mobile ? 50 : 35;
                ImVec2 cursor_pos = ImGui::GetCursorPos();
                
                // Render selectable
                if (ImGui::Selectable("##identity_select", selected, ImGuiSelectableFlags_SpanAllColumns, ImVec2(0, item_height))) {
                    selected_identity_idx = i;
                }
                
                // Calculate vertical centering
                ImVec2 text_size = ImGui::CalcTextSize(identities[i].c_str());
                float text_offset_y = (item_height - text_size.y) * 0.5f;
                
                // Draw text centered
                ImGui::SetCursorPos(ImVec2(cursor_pos.x + ImGui::GetStyle().FramePadding.x, cursor_pos.y + text_offset_y));
                ImGui::Text("%s", identities[i].c_str());
                
                ImGui::PopID();
            }
        }
        
        ImGui::EndChild();
        
        ImGui::Spacing();
        
        // Buttons
        float btn_height = is_mobile ? 50.0f : 40.0f;
        
        // Select button (only if identity selected)
        ImGui::BeginDisabled(selected_identity_idx < 0);
        if (ButtonDark(ICON_FA_USER " Select Identity", ImVec2(-1, btn_height))) {
            if (selected_identity_idx >= 0 && selected_identity_idx < (int)identities.size()) {
                current_identity = identities[selected_identity_idx];
                loadIdentity(current_identity);
            }
        }
        ImGui::EndDisabled();
        
        // Create new button
        if (ButtonDark(ICON_FA_PLUS " Create New Identity", ImVec2(-1, btn_height))) {
            create_identity_step = STEP_NAME;
            seed_confirmed = false;
            memset(new_identity_name, 0, sizeof(new_identity_name));
            memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
            ImGui::OpenPopup("Create New Identity");
        }
        
            // Create identity popup - multi-step wizard (using CenteredModal helper)
            if (CenteredModal::Begin("Create New Identity")) {
                if (create_identity_step == STEP_NAME) {
                    renderCreateIdentityStep1();
                } else if (create_identity_step == STEP_SEED_PHRASE) {
                    renderCreateIdentityStep2();
                } else if (create_identity_step == STEP_CREATING) {
                    renderCreateIdentityStep3();
                }
                
                CenteredModal::End();
            }
            
            CenteredModal::End(); // End identity selection modal
        }
    }
    
    void scanIdentities() {
        identities.clear();
        
        // UI SKETCH MODE - Add mock identities for testing
        identities.push_back("alice");
        identities.push_back("bob");
        identities.push_back("charlie");
        
        printf("[SKETCH MODE] Loaded %zu mock identities\n", identities.size());
        
        /* DISABLED FOR SKETCH MODE - Real identity scanning
        // Scan ~/.dna for *-dilithium.pqkey files
        const char* home = getenv("HOME");
        if (!home) return;
        
        std::string dna_dir = std::string(home) + "/.dna";
        
#ifdef _WIN32
        std::string search_path = dna_dir + "\\*-dilithium.pqkey";
        WIN32_FIND_DATAA find_data;
        HANDLE handle = FindFirstFileA(search_path.c_str(), &find_data);
        
        if (handle != INVALID_HANDLE_VALUE) {
            do {
                std::string filename = find_data.cFileName;
                // Remove "-dilithium.pqkey" suffix (17 chars)
                std::string identity = filename.substr(0, filename.length() - 17);
                identities.push_back(identity);
            } while (FindNextFileA(handle, &find_data));
            FindClose(handle);
        }
#else
        DIR* dir = opendir(dna_dir.c_str());
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                std::string filename = entry->d_name;
                if (filename.length() > 17 && 
                    filename.substr(filename.length() - 17) == "-dilithium.pqkey") {
                    std::string identity = filename.substr(0, filename.length() - 17);
                    identities.push_back(identity);
                }
            }
            closedir(dir);
        }
#endif
        */
    }
    
    // Input filter callback for identity name (alphanumeric + underscore only)
    static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
        if (data->EventChar < 256) {
            char c = (char)data->EventChar;
            if ((c >= 'a' && c <= 'z') || 
                (c >= 'A' && c <= 'Z') || 
                (c >= '0' && c <= '9') || 
                c == '_') {
                return 0; // Accept
            }
        }
        return 1; // Reject
    }
    
    void renderCreateIdentityStep1() {
        // Step 1: Enter identity name
        ImGui::Text("Step 1: Choose Your Identity Name");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::TextWrapped("Your identity name is your username in DNA Messenger.");
        ImGui::TextWrapped("Requirements: 3-20 characters, letters/numbers/underscore only");
        ImGui::Spacing();
        
        // Auto-focus input when step 1 is active
        if (create_identity_step == STEP_NAME && strlen(new_identity_name) == 0) {
            ImGui::SetKeyboardFocusHere();
        }
        
        bool enter_pressed = ImGui::InputText("##IdentityName", new_identity_name, sizeof(new_identity_name), 
                        ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_EnterReturnsTrue, IdentityNameInputFilter);
        
        // Validate identity name
        size_t name_len = strlen(new_identity_name);
        bool name_valid = true;
        std::string error_msg;
        
        if (name_len > 0) {
            // First check for invalid characters (highest priority)
            char invalid_char = '\0';
            for (size_t i = 0; i < name_len; i++) {
                char c = new_identity_name[i];
                if (!((c >= 'a' && c <= 'z') || 
                      (c >= 'A' && c <= 'Z') || 
                      (c >= '0' && c <= '9') || 
                      c == '_')) {
                    name_valid = false;
                    invalid_char = c;
                    char buf[64];
                    snprintf(buf, sizeof(buf), "Invalid character \"%c\"", c);
                    error_msg = buf;
                    break;
                }
            }
            
            // Then check length only if characters are valid
            if (name_valid) {
                if (name_len < 3) {
                    name_valid = false;
                    error_msg = "Too short (minimum 3 characters)";
                } else if (name_len > 20) {
                    name_valid = false;
                    error_msg = "Too long (maximum 20 characters)";
                }
            }
        } else {
            name_valid = false;
        }
        
        // Show validation feedback
        if (name_len > 0 && !name_valid) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f)); // Red
            ImGui::TextWrapped("✗ %s", error_msg.c_str());
            ImGui::PopStyleColor();
        } else if (name_len > 0 && name_valid) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
            ImGui::Text("✓ Valid identity name");
            ImGui::PopStyleColor();
        }
        
        ImGui::Spacing();
        ImGui::Spacing();
        
        // Center buttons
        float button_width = 120.0f;
        float spacing = 10.0f;
        float total_width = button_width * 2 + spacing;
        float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;
        
        if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);
        
        ImGui::BeginDisabled(!name_valid || name_len == 0);
        if (ButtonDark("Next", ImVec2(button_width, 40)) || (enter_pressed && name_valid && name_len > 0)) {
            // Generate mock seed phrase for UI sketch mode
            snprintf(generated_mnemonic, sizeof(generated_mnemonic), 
                "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual");
            create_identity_step = STEP_SEED_PHRASE;
        }
        ImGui::EndDisabled();
        
        ImGui::SameLine();
        if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
            ImGui::CloseCurrentPopup();
        }
    }
    
    void renderCreateIdentityStep2() {
        // Step 2: Display and confirm seed phrase
        ImGui::Text("Step 2: Your Recovery Seed Phrase");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f)); // Red warning
        ImGui::TextWrapped("IMPORTANT: Write down these 24 words in order!");
        ImGui::TextWrapped("This is the ONLY way to recover your identity.");
        ImGui::PopStyleColor();
        ImGui::Spacing();
        
        // Copy button - full width
        if (ButtonDark(ICON_FA_COPY " Copy All Words", ImVec2(-1, 40))) {
            ImGui::SetClipboardText(generated_mnemonic);
            seed_copied = true;
            seed_copied_timer = 3.0f; // Show message for 3 seconds
        }
        
        ImGui::Spacing();
        
        // Display seed phrase in a bordered box with proper alignment
        ImGui::BeginChild("SeedPhraseDisplay", ImVec2(0, 250), true, ImGuiWindowFlags_NoScrollbar);
        
        // Split mnemonic into words
        char* mnemonic_copy = strdup(generated_mnemonic);
        char* words[24];
        int word_count = 0;
        char* token = strtok(mnemonic_copy, " ");
        while (token != nullptr && word_count < 24) {
            words[word_count++] = token;
            token = strtok(nullptr, " ");
        }
        
        // Display in 2 columns of 12 words each for better readability
        ImGui::Columns(2, nullptr, false);
        
        for (int i = 0; i < word_count; i++) {
            // Format: " 1. word      "
            char label[32];
            snprintf(label, sizeof(label), "%2d. %-14s", i + 1, words[i]);
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "%s", label);
            
            // Switch to second column after 12 words
            if (i == 11) {
                ImGui::NextColumn();
            }
        }
        
        ImGui::Columns(1);
        
        free(mnemonic_copy);
        
        ImGui::EndChild();
        
        ImGui::Spacing();
        ImGui::Checkbox("I have written down my 24-word seed phrase securely", &seed_confirmed);
        ImGui::Spacing();
        
        // Show success message if recently copied (above buttons)
        if (seed_copied && seed_copied_timer > 0.0f) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
            ImGui::Text("✓ Words copied to clipboard!");
            ImGui::PopStyleColor();
            seed_copied_timer -= ImGui::GetIO().DeltaTime;
            if (seed_copied_timer <= 0.0f) {
                seed_copied = false;
            }
        }
        
        ImGui::Spacing();
        
        // Center buttons
        float button_width = 120.0f;
        float spacing = 10.0f;
        float total_width = button_width * 2 + spacing;
        float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;
        
        if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);
        
        if (ButtonDark("Back", ImVec2(button_width, 40))) {
            create_identity_step = STEP_NAME;
        }
        ImGui::SameLine();
        
        ImGui::BeginDisabled(!seed_confirmed);
        if (ButtonDark("Create", ImVec2(button_width, 40))) {
            create_identity_step = STEP_CREATING;
            createIdentityWithSeed(new_identity_name, generated_mnemonic);
        }
        ImGui::EndDisabled();
    }
    
    void renderCreateIdentityStep3() {
        // Step 3: Creating identity (progress)
        ImGui::Text("Creating Your Identity...");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::TextWrapped("Generating cryptographic keys and registering to keyserver...");
        ImGui::Spacing();
        
        // Simple progress indicator (spinner would be better but this works)
        static float progress = 0.0f;
        progress += 0.01f;
        if (progress > 1.0f) progress = 0.0f;
        
        ImGui::ProgressBar(progress, ImVec2(-1, 0));
        
        // This step auto-closes when createIdentityWithSeed completes
    }
    
    void createIdentityWithSeed(const char* name, const char* mnemonic) {
        // UI SKETCH MODE - Mock identity creation
        printf("[SKETCH MODE] Creating identity: %s\n", name);
        printf("[SKETCH MODE] Mnemonic: %s\n", mnemonic);
        
        // Simulate success
        identities.push_back(name);
        current_identity = name;
        identity_loaded = true;
        show_identity_selection = false;
        
        // Reset and close
        memset(new_identity_name, 0, sizeof(new_identity_name));
        memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
        seed_confirmed = false;
        ImGui::CloseCurrentPopup();
        
        printf("[SKETCH MODE] Identity created successfully\n");
    }
    
    void loadIdentity(const std::string& identity) {
        printf("[SKETCH MODE] Loading identity: %s\n", identity.c_str());
        
        // UI SKETCH MODE - Load mock contacts
        contacts.clear();
        contact_messages.clear();
        
        contacts.push_back({"Alice", "alice@dna", true});
        contacts.push_back({"Bob", "bob@dna", false});
        contacts.push_back({"Charlie", "charlie@dna", true});
        contacts.push_back({"Diana", "diana@dna", true});
        contacts.push_back({"Eve", "eve@dna", false});
        contacts.push_back({"Frank", "frank@dna", true});
        
        // Mock message history for Alice (contact 0)
        contact_messages[0].push_back({"Alice", "Hey! How are you?", "Today 10:30 AM", false});
        contact_messages[0].push_back({"Me", "I'm good! Working on DNA Messenger", "Today 10:32 AM", true});
        contact_messages[0].push_back({"Alice", "Nice! Post-quantum crypto is the future 🚀", "Today 10:33 AM", false});
        contact_messages[0].push_back({"Me", "Absolutely! Kyber512 + Dilithium3", "Today 10:35 AM", true});
        contact_messages[0].push_back({"Alice", "Can't wait to try it out!", "Today 10:36 AM", false});
        
        // Mock message history for Bob (contact 1)
        contact_messages[1].push_back({"Bob", "Are you available tomorrow?", "Yesterday 3:45 PM", false});
        contact_messages[1].push_back({"Me", "Yes, what's up?", "Yesterday 4:12 PM", true});
        contact_messages[1].push_back({"Bob", "Let's discuss the new features", "Yesterday 4:15 PM", false});
        
        // Mock message history for Charlie (contact 2)
        contact_messages[2].push_back({"Charlie", "Check out this article!", "Nov 1, 2:20 PM", false});
        contact_messages[2].push_back({"Me", "Thanks! Will read it later", "Nov 1, 2:45 PM", true});
        
        printf("[SKETCH MODE] Loaded %zu mock contacts\n", contacts.size());
        
        identity_loaded = true;
        show_identity_selection = false;
        
        printf("[SKETCH MODE] Identity loaded successfully!\n");
    }
    
    void renderMobileLayout() {
        ImGuiIO& io = ImGui::GetIO();
        float screen_height = io.DisplaySize.y;
        float bottom_nav_height = 60.0f;
        
        // Content area (full screen minus bottom nav) - use full width
        ImGui::BeginChild("MobileContent", ImVec2(-1, -bottom_nav_height), false, ImGuiWindowFlags_NoScrollbar);
        
        switch(current_view) {
            case VIEW_CONTACTS:
                renderContactsList();
                break;
            case VIEW_CHAT:
                renderChatView();
                break;
            case VIEW_WALLET:
                renderWalletView();
                break;
            case VIEW_SETTINGS:
                renderSettingsView();
                break;
        }
        
        ImGui::EndChild();
        
        // Bottom navigation bar
        renderBottomNavBar();
    }
    
    void renderDesktopLayout() {
        // Sidebar (contacts + navigation)
        renderSidebar();
        
        ImGui::SameLine();
        
        // Main content area
        ImGui::BeginChild("MainContent", ImVec2(0, 0), true);
        
        switch(current_view) {
            case VIEW_CONTACTS:
            case VIEW_CHAT:
                renderChatView();
                break;
            case VIEW_WALLET:
                renderWalletView();
                break;
            case VIEW_SETTINGS:
                renderSettingsView();
                break;
        }
        
        ImGui::EndChild();
    }
    
    void renderBottomNavBar() {
        ImGuiIO& io = ImGui::GetIO();
        float btn_width = io.DisplaySize.x / 4.0f;
        
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        
        // Contacts button
        if (current_view == VIEW_CONTACTS) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ButtonDark(ICON_FA_COMMENTS "\nChats", ImVec2(btn_width, 60))) {
            current_view = VIEW_CONTACTS;
        }
        if (current_view == VIEW_CONTACTS) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Wallet button
        if (current_view == VIEW_WALLET) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ButtonDark(ICON_FA_WALLET "\nWallet", ImVec2(btn_width, 60))) {
            current_view = VIEW_WALLET;
            selected_contact = -1;
        }
        if (current_view == VIEW_WALLET) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Settings button
        if (current_view == VIEW_SETTINGS) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ButtonDark(ICON_FA_COG "\nSettings", ImVec2(btn_width, 60))) {
            current_view = VIEW_SETTINGS;
            selected_contact = -1;
        }
        if (current_view == VIEW_SETTINGS) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Profile button (placeholder)
        if (ButtonDark(ICON_FA_USER "\nProfile", ImVec2(btn_width, 60))) {
            // TODO: Profile view
        }
        
        ImGui::PopStyleVar(2);
    }
    
    void renderContactsList() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Get full available width before any child windows
        float full_width = ImGui::GetContentRegionAvail().x;
        printf("[DEBUG] ContactsList available width: %.1f, screen width: %.1f\n", full_width, io.DisplaySize.x);
        
        // Top bar with title and add button
        ImGui::BeginChild("ContactsHeader", ImVec2(full_width, 60), true, ImGuiWindowFlags_NoScrollbar);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        
        ImGui::SetWindowFontScale(1.5f);
        ImGui::Text("  DNA Messenger");
        ImGui::SetWindowFontScale(1.0f);
        
        ImGui::SameLine(io.DisplaySize.x - 60);
        if (ButtonDark(ICON_FA_PLUS, ImVec2(50, 40))) {
            // TODO: Add contact dialog
        }
        
        ImGui::EndChild();
        
        // Contact list (large touch targets)
        ImGui::BeginChild("ContactsScrollArea", ImVec2(full_width, 0), false);
        
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Get button width
            float button_width = ImGui::GetContentRegionAvail().x;
            if (i == 0) {
                printf("[DEBUG] Contact button width: %.1f\n", button_width);
            }
            
            // Large touch-friendly buttons (80px height)
            bool selected = (int)i == selected_contact;
            if (selected) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.3f));
            }
            
            if (ButtonDark("##contact", ImVec2(button_width, 80))) {
                selected_contact = i;
                current_view = VIEW_CHAT;
            }
            
            if (selected) {
                ImGui::PopStyleColor();
            }
            
            // Draw contact info on top of button
            ImVec2 button_min = ImGui::GetItemRectMin();
            ImVec2 button_max = ImGui::GetItemRectMax();
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            
            // Online indicator (circle)
            ImVec2 circle_center = ImVec2(button_min.x + 30, button_min.y + 40);
            ImU32 status_color = contacts[i].is_online ? 
                IM_COL32(0, 255, 0, 255) : IM_COL32(128, 128, 128, 255);
            draw_list->AddCircleFilled(circle_center, 8.0f, status_color);
            
            // Contact name
            ImVec2 text_pos = ImVec2(button_min.x + 50, button_min.y + 20);
            draw_list->AddText(ImGui::GetFont(), 20.0f, text_pos, 
                IM_COL32(255, 255, 255, 255), contacts[i].name.c_str());
            
            // Status text
            const char* status = contacts[i].is_online ? "Online" : "Offline";
            ImVec2 status_pos = ImVec2(button_min.x + 50, button_min.y + 45);
            draw_list->AddText(ImGui::GetFont(), 14.0f, status_pos, 
                IM_COL32(180, 180, 180, 255), status);
            
            ImGui::PopID();
        }
        
        ImGui::EndChild();
    }
    
    void renderSidebar() {
        ImGui::BeginChild("Sidebar", ImVec2(250, 0), true);
        
        ImGui::Text("DNA Messenger");
        ImGui::Separator();
        
        // Navigation buttons
        if (ButtonDark(ICON_FA_COMMENTS " Chat", ImVec2(-1, 40))) {
            current_view = VIEW_CONTACTS;
        }
        if (ButtonDark(ICON_FA_WALLET " Wallet", ImVec2(-1, 40))) {
            current_view = VIEW_WALLET;
        }
        if (ButtonDark(ICON_FA_COG " Settings", ImVec2(-1, 40))) {
            current_view = VIEW_SETTINGS;
        }
        
        ImGui::Separator();
        ImGui::Text("Contacts");
        ImGui::Separator();
        
        // Contact list
        float list_width = ImGui::GetContentRegionAvail().x;
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Draw selectable with padding for indicator
            ImVec2 cursor_pos = ImGui::GetCursorPos();
            float item_height = 30;
            
            // Invisible selectable for full width interaction
            ImGui::SetCursorPos(cursor_pos);
            bool selected = (selected_contact == (int)i);
            if (ImGui::Selectable("##item", selected, 0, ImVec2(list_width, item_height))) {
                selected_contact = i;
                current_view = VIEW_CHAT;
            }
            
            // Draw status and contact name
            ImVec2 screen_pos = ImGui::GetItemRectMin();
            
            // Format: "✓ Name" or "✗ Name" with colored icons
            const char* icon = contacts[i].is_online ? ICON_FA_CHECK_CIRCLE : ICON_FA_TIMES_CIRCLE;
            
            char display_text[256];
            snprintf(display_text, sizeof(display_text), "%s   %s", icon, contacts[i].name.c_str());
            
            ImVec2 text_pos = ImVec2(screen_pos.x + 8, screen_pos.y + 7);
            ImU32 text_color = contacts[i].is_online ? 
                IM_COL32(0, 255, 204, 255) : IM_COL32(100, 100, 100, 255);  // Cyan if online, dark gray if offline
            ImGui::GetWindowDrawList()->AddText(text_pos, text_color, display_text);
            
            // Move cursor to next position
            ImGui::SetCursorPos(ImVec2(cursor_pos.x, cursor_pos.y + item_height));
            
            ImGui::PopID();
        }
        
        // Add contact button at bottom
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 40);
        if (ButtonDark(ICON_FA_PLUS " Add Contact", ImVec2(-1, 30))) {
            // TODO: Open add contact dialog
        }
        
        ImGui::EndChild();
    }
    
    void renderChatView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        if (selected_contact < 0 || selected_contact >= (int)contacts.size()) {
            if (is_mobile) {
                // On mobile, show contacts list
                current_view = VIEW_CONTACTS;
                return;
            } else {
                ImGui::Text("Select a contact to start chatting");
                return;
            }
        }
        
        Contact& contact = contacts[selected_contact];
        
        // Top bar (mobile: with back button)
        float header_height = is_mobile ? 60.0f : 40.0f;
        ImGui::BeginChild("ChatHeader", ImVec2(0, header_height), true, ImGuiWindowFlags_NoScrollbar);
        
        if (is_mobile) {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
            if (ButtonDark(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
                current_view = VIEW_CONTACTS;
                selected_contact = -1;
            }
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        }
        
        ImGui::SetWindowFontScale(is_mobile ? 1.3f : 1.0f);
        ImGui::Text("%s", contact.name.c_str());
        ImGui::SetWindowFontScale(1.0f);
        
        ImGui::SameLine();
        ImGui::TextColored(
            contact.is_online ? ImVec4(0.0f, 1.0f, 0.0f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f),
            contact.is_online ? "● Online" : "● Offline"
        );
        
        ImGui::EndChild();
        
        // Message area
        float input_height = is_mobile ? 100.0f : 80.0f;
        ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);
        
        // Get messages for current contact
        std::vector<Message>& messages = contact_messages[selected_contact];
        
        for (size_t i = 0; i < messages.size(); i++) {
            const auto& msg = messages[i];
            
            // Calculate bubble width based on current window size
            float available_width = ImGui::GetContentRegionAvail().x;
            float bubble_width = available_width * 0.7f;  // 70% of available width
            float indent = msg.is_outgoing ? (available_width - bubble_width) : 0.0f;
            
            if (indent > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + indent);
            }
            
            // Draw bubble background with proper padding
            ImVec4 bg_color = msg.is_outgoing ? 
                ImVec4(0.0f, 0.6f, 0.6f, 0.3f) : ImVec4(0.25f, 0.25f, 0.25f, 0.5f);
            
            ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(15.0f, 10.0f));
            
            char bubble_id[32];
            snprintf(bubble_id, sizeof(bubble_id), "bubble%zu", i);
            
            // Calculate height: text + timestamp + padding
            float content_width = bubble_width - 30.0f;  // Account for padding
            ImVec2 text_size = ImGui::CalcTextSize(msg.content.c_str(), NULL, false, content_width);
            ImVec2 timestamp_size = ImGui::CalcTextSize(msg.timestamp.c_str());
            float bubble_height = text_size.y + (timestamp_size.y * 0.85f) + 25.0f;
            
            ImGui::BeginChild(bubble_id, ImVec2(bubble_width, bubble_height), true, 
                ImGuiWindowFlags_NoScrollbar);
            
            // Message text with wrapping
            ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
            ImGui::TextWrapped("%s", msg.content.c_str());
            ImGui::PopTextWrapPos();
            
            // Timestamp
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
            ImGui::SetWindowFontScale(0.85f);
            ImGui::Text("%s", msg.timestamp.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();
            
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
            
            ImGui::Spacing();
        }
        
        // Auto-scroll to bottom
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
        
        ImGui::EndChild();
        
        // Message input area
        ImGui::Separator();
        
        if (is_mobile) {
            // Mobile: stacked layout
            ImGui::InputTextMultiline("##MessageInput", message_input, 
                sizeof(message_input), ImVec2(-1, 60));
            
            if (ButtonDark("Send", ImVec2(-1, 35))) {
                if (strlen(message_input) > 0) {
                    Message msg;
                    msg.content = message_input;
                    msg.is_outgoing = true;
                    msg.timestamp = "Now";
                    messages.push_back(msg);
                    message_input[0] = '\0';
                }
            }
        } else {
            // Desktop: side-by-side
            ImGui::InputTextMultiline("##MessageInput", message_input, 
                sizeof(message_input), ImVec2(-80, 60));
            ImGui::SameLine();
            
            if (ButtonDark("Send", ImVec2(70, 60))) {
                if (strlen(message_input) > 0) {
                    Message msg;
                    msg.content = message_input;
                    msg.is_outgoing = true;
                    msg.timestamp = "Now";
                    messages.push_back(msg);
                    message_input[0] = '\0';
                }
            }
        }
    }
    
    void renderWalletView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        float padding = is_mobile ? 15.0f : 20.0f;
        
        ImGui::SetCursorPos(ImVec2(padding, padding));
        ImGui::BeginChild("WalletContent", ImVec2(-padding, -padding), false);
        
        // Header
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text(ICON_FA_WALLET " cpunk Wallet");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Token balance cards
        const char* tokens[] = {"CPUNK", "CELL", "KEL"};
        const char* balances[] = {"1,234.56", "89.12", "456.78"};
        
        for (int i = 0; i < 3; i++) {
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.15f, 0.15f, 0.9f));
            
            float card_height = is_mobile ? 100.0f : 120.0f;
            ImGui::BeginChild(tokens[i], ImVec2(-1, card_height), true);
            
            ImGui::SetCursorPos(ImVec2(20, 15));
            ImGui::SetWindowFontScale(is_mobile ? 1.0f : 0.9f);
            ImGui::TextDisabled("%s", tokens[i]);
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::SetCursorPos(ImVec2(20, is_mobile ? 45 : 50));
            ImGui::SetWindowFontScale(is_mobile ? 1.8f : 2.0f);
            ImGui::Text("%s", balances[i]);
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::PopStyleVar();
            
            ImGui::Spacing();
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Action buttons
        float btn_height = is_mobile ? 50.0f : 45.0f;
        
        if (is_mobile) {
            // Mobile: Stacked full-width buttons
            if (ButtonDark(ICON_FA_PAPER_PLANE " Send Tokens", ImVec2(-1, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::Spacing();
            
            if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(-1, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::Spacing();
            
            if (ButtonDark(ICON_FA_RECEIPT " Transaction History", ImVec2(-1, btn_height))) {
                // TODO: Show transaction history
            }
        } else {
            // Desktop: Side-by-side buttons
            ImGuiStyle& style = ImGui::GetStyle();
            float available_width = ImGui::GetContentRegionAvail().x;
            float spacing = style.ItemSpacing.x;
            float btn_width = (available_width - spacing * 2) / 3.0f;
            
            if (ButtonDark(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::SameLine();
            
            if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(btn_width, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::SameLine();
            
            if (ButtonDark(ICON_FA_RECEIPT " History", ImVec2(btn_width, btn_height))) {
                // TODO: Show transaction history
            }
        }
        
        ImGui::EndChild();
    }
    
    void renderSettingsView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        float padding = is_mobile ? 15.0f : 20.0f;
        
        ImGui::SetCursorPos(ImVec2(padding, padding));
        ImGui::BeginChild("SettingsContent", ImVec2(-padding, -padding), false);
        
        // Header
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text(ICON_FA_COG " Settings");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Theme selection
        ImGui::Text("Theme");
        ImGui::Spacing();
        
        static int theme = 0;
        
        if (is_mobile) {
            // Mobile: Full-width radio buttons with larger touch targets
            if (ImGui::RadioButton("cpunk.io (Cyan)##theme", theme == 0)) theme = 0;
            ImGui::Spacing();
            if (ImGui::RadioButton("cpunk.club (Orange)##theme", theme == 1)) theme = 1;
            ImGui::Spacing();
            if (ImGui::RadioButton("Dark Mode##theme", theme == 2)) theme = 2;
        } else {
            ImGui::RadioButton("cpunk.io (Cyan)", &theme, 0);
            ImGui::RadioButton("cpunk.club (Orange)", &theme, 1);
            ImGui::RadioButton("Dark Mode", &theme, 2);
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Identity section
        ImGui::Text("Identity");
        ImGui::Spacing();
        ImGui::TextDisabled("Not loaded");
        ImGui::Spacing();
        
        float btn_height = is_mobile ? 50.0f : 40.0f;
        
        if (is_mobile) {
            if (ButtonDark("🆕 Create New Identity", ImVec2(-1, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::Spacing();
            
            if (ButtonDark("📥 Import Identity", ImVec2(-1, btn_height))) {
                // TODO: Import identity dialog
            }
        } else {
            if (ButtonDark("Create New Identity", ImVec2(200, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::SameLine();
            if (ButtonDark("Import Identity", ImVec2(200, btn_height))) {
                // TODO: Import identity dialog
            }
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // App info
        ImGui::TextDisabled("DNA Messenger v0.1");
        ImGui::TextDisabled("Post-Quantum Encrypted Messaging");
        
        ImGui::EndChild();
    }
};

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "DNA Messenger", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

        // Load embedded fonts
    #include "fonts/NotoSans-Regular.h"
    #include "fonts/fa-solid-900.h"
    
    ImFontConfig config;
    config.MergeMode = false;
    
    // Default font (1.1x scale = 19.8px for base 18px)
    float base_size = 18.0f * 1.1f;
    io.Fonts->AddFontFromMemoryTTF(NotoSans_Regular_ttf, sizeof(NotoSans_Regular_ttf), base_size, &config);
    
    // Merge Font Awesome icons
    config.MergeMode = true;
    config.GlyphMinAdvanceX = base_size;
    config.GlyphOffset = ImVec2(0, 2);
    static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    io.Fonts->AddFontFromMemoryTTF(fa_solid_900_ttf, sizeof(fa_solid_900_ttf), base_size * 0.9f, &config, icon_ranges);

    ImGui::StyleColorsDark();
    
    // DNA Messenger color scheme
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Colors
    ImVec4 bg_main = ImVec4(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f);  // #151719
    ImVec4 bg_popup = ImVec4(0x0f/255.0f, 0x11/255.0f, 0x13/255.0f, 1.0f); // Darker for popups
    ImVec4 text_primary = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 1.0f); // #00FFCC (cyan)
    ImVec4 text_secondary = ImVec4(0x80/255.0f, 0xff/255.0f, 0xe6/255.0f, 1.0f); // Lighter cyan
    ImVec4 text_button = ImVec4(0.05f, 0.05f, 0.05f, 1.0f); // Dark text for buttons
    ImVec4 accent = ImVec4(0x00/255.0f, 0xcc/255.0f, 0xa3/255.0f, 1.0f); // Darker cyan for buttons
    ImVec4 accent_hover = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 1.0f); // Bright cyan on hover
    
    // Main colors
    style.Colors[ImGuiCol_WindowBg] = bg_main;
    style.Colors[ImGuiCol_ChildBg] = bg_main;
    style.Colors[ImGuiCol_PopupBg] = bg_popup;
    style.Colors[ImGuiCol_Border] = ImVec4(0.2f, 0.2f, 0.2f, 0.5f);
    
    // Text
    style.Colors[ImGuiCol_Text] = text_primary;
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.3f);
    
    // Buttons - dark text for contrast on cyan background
    style.Colors[ImGuiCol_Button] = accent;
    style.Colors[ImGuiCol_ButtonHovered] = accent_hover;
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0x00/255.0f, 0xdd/255.0f, 0xaa/255.0f, 1.0f);
    // Note: Button text color is controlled by ImGuiCol_Text, we'll override per-button as needed
    
    // Headers (selectables, etc)
    style.Colors[ImGuiCol_Header] = ImVec4(0x00/255.0f, 0xcc/255.0f, 0xa3/255.0f, 0.3f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.4f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.5f);
    
    // Frames (inputs, etc)
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.1f, 0.1f, 0.1f, 0.9f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.2f, 0.2f, 0.2f, 0.9f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.15f, 0.15f, 0.15f, 0.9f);
    
    // Titles
    style.Colors[ImGuiCol_TitleBg] = bg_popup;
    style.Colors[ImGuiCol_TitleBgActive] = bg_popup;
    style.Colors[ImGuiCol_TitleBgCollapsed] = bg_popup;
    
    // Scrollbar
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.05f, 0.05f, 0.05f, 0.9f);
    style.Colors[ImGuiCol_ScrollbarGrab] = accent;
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = accent_hover;
    style.Colors[ImGuiCol_ScrollbarGrabActive] = accent_hover;
    
    // Checkboxes
    style.Colors[ImGuiCol_CheckMark] = text_primary;
    
    // Sliders
    style.Colors[ImGuiCol_SliderGrab] = accent;
    style.Colors[ImGuiCol_SliderGrabActive] = accent_hover;
    
    // Separators
    style.Colors[ImGuiCol_Separator] = ImVec4(0.3f, 0.3f, 0.3f, 0.5f);
    style.Colors[ImGuiCol_SeparatorHovered] = accent_hover;
    style.Colors[ImGuiCol_SeparatorActive] = accent_hover;
    
    // Resize grip
    style.Colors[ImGuiCol_ResizeGrip] = accent;
    style.Colors[ImGuiCol_ResizeGripHovered] = accent_hover;
    style.Colors[ImGuiCol_ResizeGripActive] = accent_hover;
    
    // Tabs
    style.Colors[ImGuiCol_Tab] = accent;
    style.Colors[ImGuiCol_TabHovered] = accent_hover;
    style.Colors[ImGuiCol_TabActive] = accent_hover;
    style.Colors[ImGuiCol_TabUnfocused] = ImVec4(0.1f, 0.1f, 0.1f, 0.9f);
    style.Colors[ImGuiCol_TabUnfocusedActive] = accent;
    
    // Rounding
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;
    style.ChildRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    DNAMessengerApp app;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f); // #151719
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
