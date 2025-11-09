#include "app.h"
#include "imgui.h"
#include "modal_helper.h"
#include "ui_helpers.h"
#include "font_awesome.h"
#include "theme_colors.h"
#include "settings_manager.h"
#include "helpers/identity_helpers.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>  // For _mkdir
#include "../win32/dirent.h"
// Undefine Windows status macros that conflict with our enum
#undef STATUS_PENDING
#else
#include <dirent.h>
#endif

// Backend includes
extern "C" {
    #include "../messenger.h"
    #include "../messenger_p2p.h"  // For messenger_p2p_check_offline_messages
    #include "../bip39.h"
    #include "../dht/dht_keyserver.h"
    #include "../dht/dht_singleton.h"
    #include "../dht/dna_message_wall.h"  // For message wall functions
    #include "../p2p/p2p_transport.h"  // For P2P transport DHT access
    #include "../qgp_types.h"  // For qgp_key_load, qgp_key_free
    #include "../qgp_platform.h"  // For qgp_platform_home_dir
    #include "../contacts_db.h"  // For contacts_db_add, contacts_db_exists
    #include "../wallet.h"  // For wallet functions
    #include "../cellframe_rpc.h"  // For RPC calls
    #include "../cellframe_tx_builder_minimal.h"  // Transaction builder
    #include "../cellframe_sign_minimal.h"  // Transaction signing
    #include "../cellframe_addr.h"  // Address utilities
    #include "../cellframe_json_minimal.h"  // JSON conversion
    #include "../cellframe_minimal.h"  // TSD types
    #include "../base58.h"  // Base58 encoding
    #include <time.h>
}

#include <json-c/json.h>  // For JSON parsing

#ifdef _WIN32
// Simple strptime implementation for Windows
static char* strptime(const char* s, const char* format, struct tm* tm) {
    // Simple RFC2822 parser: "Mon, 15 Oct 2024 14:30:00"
    const char* month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char day_name[4], month_name[4];
    int day, year, hour, min, sec;

    int parsed = sscanf(s, "%3s, %d %3s %d %d:%d:%d",
                        day_name, &day, month_name, &year, &hour, &min, &sec);

    if (parsed == 7) {
        tm->tm_mday = day;
        tm->tm_year = year - 1900;
        tm->tm_hour = hour;
        tm->tm_min = min;
        tm->tm_sec = sec;

        // Find month
        for (int i = 0; i < 12; i++) {
            if (strcmp(month_name, month_names[i]) == 0) {
                tm->tm_mon = i;
                break;
            }
        }
        return (char*)s + strlen(s);
    }
    return nullptr;
}
#endif

// Network fee constants
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  // 0.002 CELL

// UTXO structure for transaction building
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} utxo_t;

// Forward declaration for ApplyTheme (defined in main.cpp)
extern void ApplyTheme(int theme);
extern AppSettings g_app_settings;

// Method implementations will be moved here from app.h
// This file will contain all the inline method bodies

void DNAMessengerApp::render() {
    ImGuiIO& io = ImGui::GetIO();

    // First frame initialization (removed unnecessary loading spinner)
    if (state.is_first_frame) {
        state.is_first_frame = false;
    }

    // Periodic message polling (every 5 seconds)
    if (state.identity_loaded) {
        float current_time = (float)ImGui::GetTime();
        if (current_time - state.last_poll_time >= 5.0f) {
            checkForNewMessages();
            state.last_poll_time = current_time;
        }

        // Reload current conversation if new messages arrived
        if (state.new_messages_received && state.selected_contact >= 0) {
            loadMessagesForContact(state.selected_contact);
            state.new_messages_received = false;
        }
        
        // Reload contacts if DHT sync completed
        if (state.contacts_synced_from_dht) {
            printf("[Contacts] DHT sync completed, reloading contact list...\n");
            reloadContactsFromDatabase();
            state.contacts_synced_from_dht = false;
        }
    }

    // Show identity selection on first run (but not during spinner operations)
    if (state.show_identity_selection && !state.show_operation_spinner) {
        renderIdentitySelection();
    } else if (!state.show_operation_spinner) {
        // Main window only shows when identity is selected
        // Detect screen size for responsive layout
        bool is_mobile = io.DisplaySize.x < 600.0f;

        // Main window (fullscreen)
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        // Add global padding
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));

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
        ImGui::PopStyleVar(); // Pop WindowPadding
    }
    
    // Render operation spinner overlay (for async DHT operations)
    // This must be AFTER all other windows/modals so it's on top
    if (state.show_operation_spinner) {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        
        // Use themed background
        ImVec4 bg_color = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
        bg_color.w = 0.95f; // Slightly transparent
        ImGui::PushStyleColor(ImGuiCol_WindowBg, bg_color);
        
        ImGui::Begin("##operation_spinner", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoInputs);
        
        // Center spinner
        float spinner_size = 40.0f;
        ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_size, center.y - spinner_size * 2));
        ThemedSpinner("##op_spinner", spinner_size, 6.0f);
        
        // Show latest message from async task
        auto messages = dht_publish_task.getMessages();
        if (!messages.empty()) {
            const char* msg = messages.back().c_str();
            ImVec2 text_size = ImGui::CalcTextSize(msg);
            ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_size));
            ImGui::Text("%s", msg);
        } else {
            // Fallback to static message
            ImVec2 text_size = ImGui::CalcTextSize(state.operation_spinner_message);
            ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_size));
            ImGui::Text("%s", state.operation_spinner_message);
        }
        
        ImGui::End();
        ImGui::PopStyleColor();
        
        // Check if async task completed
        if (dht_publish_task.isCompleted() && !dht_publish_task.isRunning()) {
            state.show_operation_spinner = false;
            // Identity selection is already hidden when Create button was clicked
        }
    }

    // Add Contact dialog
    if (state.show_add_contact_dialog) {
        ImGui::OpenPopup("Add Contact");
        renderAddContactDialog();
    }

    // Receive dialog
    renderReceiveDialog();

    // Send dialog
    renderSendDialog();

    // Transaction History dialog
    renderTransactionHistoryDialog();

    // Message Wall dialog
    renderMessageWallDialog();

    // Profile Editor dialog
    renderProfileEditorDialog();

    // Register DNA Name dialog
    renderRegisterNameDialog();
}


void DNAMessengerApp::renderIdentitySelection() {
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

    // Title (centered)
    const char* title_text = "Welcome to DNA Messenger";
    float title_width = ImGui::CalcTextSize(title_text).x;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - title_width) * 0.5f);
    ImGui::Text("%s", title_text);
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();

    // Info text (centered)
    const char* info_text = "Select an existing identity or create a new one:";
    float info_width = ImGui::CalcTextSize(info_text).x;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - info_width) * 0.5f);
    ImGui::Text("%s", info_text);
    ImGui::Spacing();

    // Load identities on first render (async)
    if (!state.identities_scanned && !identity_scan_task.isRunning()) {
        DNAMessengerApp* app = this;
        
        identity_scan_task.start([app](AsyncTask* task) {
            // Scan for identity files
            app->scanIdentities();
            
            // Do DHT reverse lookups for names (in background)
            dht_context_t *dht_ctx = dht_singleton_get();
            if (dht_ctx) {
                for (const auto& fp : app->state.identities) {
                    if (fp.length() == 128 && app->state.identity_name_cache.find(fp) == app->state.identity_name_cache.end()) {
                        // Try DHT reverse lookup to get registered name
                        char *registered_name = nullptr;
                        int ret = dht_keyserver_reverse_lookup(dht_ctx, fp.c_str(), &registered_name);
                        
                        if (ret == 0 && registered_name != nullptr) {
                            // Found registered name, cache it
                            printf("[Identity] DHT lookup: %s → %s\n", fp.substr(0, 16).c_str(), registered_name);
                            app->state.identity_name_cache[fp] = std::string(registered_name);
                            free(registered_name);
                        } else {
                            // Not registered or lookup failed, use shortened fingerprint
                            app->state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                        }
                    }
                }
            } else {
                // No DHT available, use shortened fingerprints
                for (const auto& fp : app->state.identities) {
                    if (fp.length() == 128 && app->state.identity_name_cache.find(fp) == app->state.identity_name_cache.end()) {
                        app->state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                    }
                }
            }
            
            // Mark as complete
            app->state.identities_scanned = true;
        });
    }


    // Identity list (reduce reserved space for buttons to prevent scrollbar)
    ImGui::BeginChild("IdentityList", ImVec2(0, is_mobile ? -180 : -140), true);

    // Show spinner while scanning
    if (identity_scan_task.isRunning()) {
        float spinner_radius = 30.0f;
        float window_width = ImGui::GetWindowWidth();
        float window_height = ImGui::GetWindowHeight();
        ImVec2 center = ImVec2(window_width * 0.5f, window_height * 0.4f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
        ThemedSpinner("##identity_scan", spinner_radius, 6.0f);
        
        const char* loading_text = "Loading identities...";
        ImVec2 text_size = ImGui::CalcTextSize(loading_text);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_radius + 20));
        ImGui::Text("%s", loading_text);
    } else if (state.identities.empty()) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No identities found.");
        ImGui::TextWrapped("Create a new identity to get started.");
    } else {
        for (size_t i = 0; i < state.identities.size(); i++) {
            ImGui::PushID(i);
            bool selected = (state.selected_identity_idx == (int)i);

            float item_height = is_mobile ? 50 : 35;
            ImVec2 text_size = ImGui::CalcTextSize(state.identities[i].c_str());
            float text_offset_y = (item_height - text_size.y) * 0.5f;

            // Custom color handling for hover and selection
            ImVec4 text_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            ImVec4 bg_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();

            ImVec2 pos = ImGui::GetCursorScreenPos();
            ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, item_height);

            // Check hover
            bool hovered = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + size.x, pos.y + size.y));

            if (hovered) {
                bg_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                text_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            }

            if (selected) {
                bg_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                text_color = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            }

            // Draw background
            if (selected || hovered) {
                ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(bg_color));
            }

            // Draw text centered vertically with left padding
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + text_offset_y);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, text_color);
            
            // Get display name (use cache to avoid blocking DHT lookups)
            std::string fingerprint = state.identities[i];
            std::string display_name;
            
            // Check cache first
            auto cached = state.identity_name_cache.find(fingerprint);
            if (cached != state.identity_name_cache.end()) {
                // Use cached name
                display_name = cached->second;
            } else if (fingerprint.length() == 128) {
                // Not in cache and looks like a fingerprint - show shortened version for now
                // DHT lookup will happen async later
                display_name = fingerprint.substr(0, 10) + "..." + fingerprint.substr(fingerprint.length() - 10);
            } else {
                // Short name (legacy), use as-is
                display_name = fingerprint;
            }
            
            ImGui::Text("%s", display_name.c_str());
            ImGui::PopStyleColor();

            // Move cursor back and render invisible button for click detection
            ImGui::SetCursorScreenPos(pos);
            if (ImGui::InvisibleButton(state.identities[i].c_str(), size)) {
                if (state.selected_identity_idx == (int)i) {
                    state.selected_identity_idx = -1;
                } else {
                    state.selected_identity_idx = i;
                }
            }

            ImGui::PopID();
        }
    }

    ImGui::EndChild();

    ImGui::Spacing();

    // Buttons
    float btn_height = is_mobile ? 50.0f : 40.0f;

    // Select button (only if identity selected)
    ImGui::BeginDisabled(state.selected_identity_idx < 0);
    if (ButtonDark(ICON_FA_USER " Select Identity", ImVec2(-1, btn_height))) {
        if (state.selected_identity_idx >= 0 && state.selected_identity_idx < (int)state.identities.size()) {
            state.current_identity = state.identities[state.selected_identity_idx];
            loadIdentity(state.current_identity);
        }
    }
    ImGui::EndDisabled();

    // Create new button
    if (ButtonDark(ICON_FA_CIRCLE_PLUS " Create New Identity", ImVec2(-1, btn_height))) {
        state.create_identity_step = STEP_NAME;
        state.seed_confirmed = false;
        memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::OpenPopup("Create New Identity");
    }

    // Restore from seed button
    if (ButtonDark(ICON_FA_DOWNLOAD " Restore from Seed", ImVec2(-1, btn_height))) {
        state.restore_identity_step = RESTORE_STEP_SEED;
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::OpenPopup("Restore from Seed");
    }

    // Restore from seed popup - single step (just seed phrase, username not required)
    if (CenteredModal::Begin("Restore from Seed")) {
        renderRestoreStep2_Seed();
        CenteredModal::End();
    }

        // Create identity popup - multi-step wizard (using CenteredModal helper)
        if (CenteredModal::Begin("Create New Identity")) {
            if (state.create_identity_step == STEP_NAME) {
                renderCreateIdentityStep1();
            } else if (state.create_identity_step == STEP_SEED_PHRASE) {
                renderCreateIdentityStep2();
            }
            // STEP_CREATING is handled by spinner overlay, no modal content needed

            CenteredModal::End();
        }

        CenteredModal::End(); // End identity selection modal
    }
}


void DNAMessengerApp::scanIdentities() {
    state.identities.clear();

    // Scan ~/.dna for *.dsa files (Dilithium signature keys)
    const char* home = getenv("HOME");
    if (!home) {
        printf("[Identity] HOME environment variable not set\n");
        return;
    }

    std::string dna_dir = std::string(home) + "/.dna";

#ifdef _WIN32
    std::string search_path = dna_dir + "\\*.dsa";
    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path.c_str(), &find_data);

    if (handle != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = find_data.cFileName;
            // Remove ".dsa" suffix (4 chars)
            if (filename.length() > 4) {
                std::string fingerprint = filename.substr(0, filename.length() - 4);
                
                // Verify both key files exist (.dsa and .kem)
                std::string dsa_path = dna_dir + "\\" + fingerprint + ".dsa";
                std::string kem_path = dna_dir + "\\" + fingerprint + ".kem";
                
                struct stat dsa_stat, kem_stat;
                if (stat(dsa_path.c_str(), &dsa_stat) == 0 && stat(kem_path.c_str(), &kem_stat) == 0) {
                    state.identities.push_back(fingerprint);
                }
            }
        } while (FindNextFileA(handle, &find_data));
        FindClose(handle);
    }
#else
    DIR* dir = opendir(dna_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            // Check if filename ends with ".dsa"
            if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".dsa") {
                std::string fingerprint = filename.substr(0, filename.length() - 4);
                
                // Verify both key files exist (.dsa and .kem)
                std::string dsa_path = dna_dir + "/" + fingerprint + ".dsa";
                std::string kem_path = dna_dir + "/" + fingerprint + ".kem";
                
                struct stat dsa_stat, kem_stat;
                if (stat(dsa_path.c_str(), &dsa_stat) == 0 && stat(kem_path.c_str(), &kem_stat) == 0) {
                    state.identities.push_back(fingerprint);
                }
            }
        }
        closedir(dir);
    }
#endif

    printf("[Identity] Scanned ~/.dna: found %zu identities\n", state.identities.size());
}


void DNAMessengerApp::renderCreateIdentityStep1() {
    // Step 1: Enter identity name
    ImGui::Text("Step 1: Choose Your Identity Name");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextWrapped("Your identity name is your username in DNA Messenger.");
    ImGui::TextWrapped("Requirements: 3-20 characters, letters/numbers/underscore only");
    ImGui::Spacing();

    // Auto-focus input when step 1 is active
    if (state.create_identity_step == STEP_NAME && strlen(state.new_identity_name) == 0) {
        ImGui::SetKeyboardFocusHere();
    }

    // Style input like chat message input (recipient bubble color)
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)  // DNA: slightly lighter than bg
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f); // Club: slightly lighter
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));

    bool enter_pressed = ImGui::InputText("##IdentityName", state.new_identity_name, sizeof(state.new_identity_name),
                    ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_EnterReturnsTrue, IdentityNameInputFilter);

    ImGui::PopStyleColor(2);

    // Validate identity name
    size_t name_len = strlen(state.new_identity_name);
    bool name_valid = true;
    std::string error_msg;

    if (name_len > 0) {
        // First check for invalid characters (highest priority)
        char invalid_char = '\0';
        for (size_t i = 0; i < name_len; i++) {
            char c = state.new_identity_name[i];
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
        ImVec4 error_color = g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning();
        ImGui::PushStyleColor(ImGuiCol_Text, error_color);
        ImGui::TextWrapped("✗ %s", error_msg.c_str());
        ImGui::PopStyleColor();
    } else if (name_len > 0 && name_valid) {
        ImVec4 success_color = g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess();
        ImGui::PushStyleColor(ImGuiCol_Text, success_color);
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
        // Generate real BIP39 24-word seed phrase
        char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
        if (bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic)) != 0) {
            printf("[Identity] ERROR: Failed to generate BIP39 mnemonic\n");
            snprintf(state.generated_mnemonic, sizeof(state.generated_mnemonic), "ERROR: Failed to generate seed");
        } else {
            snprintf(state.generated_mnemonic, sizeof(state.generated_mnemonic), "%s", mnemonic);
            printf("[Identity] Generated 24-word BIP39 seed phrase\n");
            printf("[Identity] SEED PHRASE (copy from here if clipboard fails):\n%s\n", mnemonic);
        }
        state.create_identity_step = STEP_SEED_PHRASE;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
        // Reset wizard state and go back to identity selection
        state.create_identity_step = STEP_NAME;
        state.seed_confirmed = false;
        state.seed_copied = false;
        memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }
}


void DNAMessengerApp::renderCreateIdentityStep2() {
    // Step 2: Display and confirm seed phrase
    ImGui::Text("Step 2: Your Recovery Seed Phrase");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImVec4 warning_color = g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning();
    ImGui::PushStyleColor(ImGuiCol_Text, warning_color);
    ImGui::TextWrapped("IMPORTANT: Write down these 24 words in order!");
    ImGui::TextWrapped("This is the ONLY way to recover your identity.");
    ImGui::PopStyleColor();
    ImGui::Spacing();



    // Copy button - full width
    if (ButtonDark(ICON_FA_COPY " Copy All Words", ImVec2(-1, 40))) {
        ImGui::SetClipboardText(state.generated_mnemonic);
        state.seed_copied = true;
        state.seed_copied_timer = 3.0f; // Show message for 3 seconds

        // Fallback: Also print to console for manual copying (Wayland/clipboard issues)
        printf("\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  SEED PHRASE (24 words) - SELECT AND COPY FROM TERMINAL:\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("%s\n", state.generated_mnemonic);
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("\n");
    }

    ImGui::Spacing();

    // Display seed phrase in a bordered box with proper alignment
    ImGui::BeginChild("SeedPhraseDisplay", ImVec2(0, 250), true, ImGuiWindowFlags_NoScrollbar);

    // Split mnemonic into words
    char* mnemonic_copy = strdup(state.generated_mnemonic);
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
    ImGui::Checkbox("I have written down my 24-word seed phrase securely", &state.seed_confirmed);
    ImGui::Spacing();

    // Show success message if recently copied (centered above buttons)
    if (state.seed_copied && state.seed_copied_timer > 0.0f) {
        const char* msg = "✓ Words copied to clipboard!";
        ImVec2 text_size = ImGui::CalcTextSize(msg);
        float center_offset = (ImGui::GetContentRegionAvail().x - text_size.x) * 0.5f;
        if (center_offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + center_offset);
        
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
        ImGui::Text("%s", msg);
        ImGui::PopStyleColor();
        state.seed_copied_timer -= ImGui::GetIO().DeltaTime;
        if (state.seed_copied_timer <= 0.0f) {
            state.seed_copied = false;
        }
    }

    ImGui::Spacing();

    // Center buttons
    float button_width = 100.0f;
    float spacing = 10.0f;
    float total_width = button_width * 3 + spacing * 2;
    float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;

    if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);

    if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
        // Reset wizard state and go back to identity selection
        state.create_identity_step = STEP_NAME;
        state.seed_confirmed = false;
        state.seed_copied = false;
        memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    
    if (ButtonDark("Back", ImVec2(button_width, 40))) {
        state.create_identity_step = STEP_NAME;
    }
    ImGui::SameLine();

    ImGui::BeginDisabled(!state.seed_confirmed);
    if (ButtonDark("Create", ImVec2(button_width, 40))) {
        // Close all modals immediately
        ImGui::CloseCurrentPopup();
        state.show_identity_selection = false; // Hide identity list modal immediately
        state.create_identity_step = STEP_NAME; // Reset wizard
        
        // Show spinner overlay
        state.show_operation_spinner = true;
        snprintf(state.operation_spinner_message, sizeof(state.operation_spinner_message),
                 "Creating identity...");

        // Copy name and mnemonic to heap for async task
        std::string name_copy = std::string(state.new_identity_name);
        std::string mnemonic_copy = std::string(state.generated_mnemonic);

        // Start async DHT publishing task
        dht_publish_task.start([this, name_copy, mnemonic_copy](AsyncTask* task) {
            task->addMessage("Generating cryptographic keys...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Publishing keys to DHT network...");
            createIdentityWithSeed(name_copy.c_str(), mnemonic_copy.c_str());

            task->addMessage("Initializing messenger context...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Loading contacts database...");
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            task->addMessage("✓ Identity created successfully!");
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        });
    }
    ImGui::EndDisabled();
}


void DNAMessengerApp::renderCreateIdentityStep3() {
    // Step 3: This step is now handled by the spinner overlay
    // The modal will close and spinner will show until creation completes
    // This function should never actually render since we trigger async task immediately
}


void DNAMessengerApp::createIdentityWithSeed(const char* name, const char* mnemonic) {
    printf("[Identity] Creating identity: %s\n", name);
    
    // Derive cryptographic seeds from BIP39 mnemonic
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];
    
    if (qgp_derive_seeds_from_mnemonic(mnemonic, "", signing_seed, encryption_seed) != 0) {
        printf("[Identity] ERROR: Failed to derive seeds from mnemonic\n");
        return;
    }
    
    printf("[Identity] Derived seeds from mnemonic\n");
    
    // Ensure ~/.dna directory exists
    const char* home = getenv("HOME");
    if (!home) {
        printf("[Identity] ERROR: HOME environment variable not set\n");
        return;
    }
    
    std::string dna_dir = std::string(home) + "/.dna";
    
#ifdef _WIN32
    _mkdir(dna_dir.c_str());
#else
    mkdir(dna_dir.c_str(), 0700);
#endif
    
    // Create temporary messenger context for key generation
    messenger_context_t *ctx = messenger_init("temp");
    if (!ctx) {
        printf("[Identity] ERROR: Failed to initialize messenger context\n");
        return;
    }
    
    // Generate keys from seeds (returns fingerprint)
    char fingerprint[129];
    int result = messenger_generate_keys_from_seeds(ctx, signing_seed, encryption_seed, fingerprint);
    
    // Securely wipe seeds from memory
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));
    
    if (result != 0) {
        printf("[Identity] ERROR: Failed to generate keys\n");
        messenger_free(ctx);
        return;
    }
    
    printf("[Identity] Generated keys with fingerprint: %.20s...\n", fingerprint);
    
    // Publish to DHT keyserver with name
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx && strlen(name) > 0) {
        printf("[Identity] Publishing public keys to DHT with name: %s\n", name);
        
        // Load keys from disk
        std::string dsa_path = dna_dir + "/" + std::string(fingerprint) + ".dsa";
        std::string kem_path = dna_dir + "/" + std::string(fingerprint) + ".kem";
        
        qgp_key_t *sign_key = nullptr;
        qgp_key_t *enc_key = nullptr;
        
        if (qgp_key_load(dsa_path.c_str(), &sign_key) != 0 || !sign_key) {
            printf("[Identity] ERROR: Failed to load signing key from %s\n", dsa_path.c_str());
        } else if (qgp_key_load(kem_path.c_str(), &enc_key) != 0 || !enc_key) {
            printf("[Identity] ERROR: Failed to load encryption key from %s\n", kem_path.c_str());
            qgp_key_free(sign_key);
        } else {
            // Publish to DHT
            int ret = dht_keyserver_publish(
                dht_ctx,
                fingerprint,
                name,  // Display name
                sign_key->public_key,
                enc_key->public_key,
                sign_key->private_key
            );
            
            qgp_key_free(sign_key);
            qgp_key_free(enc_key);
            
            if (ret == 0) {
                printf("[Identity] ✓ Keys published to DHT successfully!\n");
                // Cache the name mapping
                state.identity_name_cache[std::string(fingerprint)] = name;
            } else {
                printf("[Identity] ERROR: Failed to publish keys to DHT\n");
            }
        }
    }
    
    // Identity created successfully
    state.identities.push_back(fingerprint);
    state.current_identity = fingerprint;
    state.identity_loaded = true;
    // DON'T set show_identity_selection here - it's set in render() when task completes
    
    // Load contacts for the new identity
    loadIdentity(fingerprint);
    
    // Reset wizard state
    memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
    state.seed_confirmed = false;
    // Modal will be closed when async task completes (in render())
    
    messenger_free(ctx);
    printf("[Identity] Identity created successfully\n");
}


void DNAMessengerApp::renderRestoreStep2_Seed() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    ImGui::Text("Restore Your Identity");
    ImGui::Spacing();
    ImGui::Spacing();

    ImGui::TextWrapped("Enter your 24-word seed phrase to restore your identity.");
    ImGui::Spacing();
    ImGui::TextWrapped("Your cryptographic keys will be regenerated from the seed phrase.");
    ImGui::Spacing();
    ImGui::Spacing();

    // Style input
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);

    ImGui::SetNextItemWidth(-1);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::InputTextMultiline("##RestoreSeedPhrase", state.generated_mnemonic, sizeof(state.generated_mnemonic),
                             ImVec2(-1, 200), ImGuiInputTextFlags_WordWrap);
    ImGui::PopStyleColor();

    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::TextWrapped("Paste or type your 24-word seed phrase (separated by spaces).");
    ImGui::Spacing();

    // Validate word count
    int word_count = 0;
    if (strlen(state.generated_mnemonic) > 0) {
        char* mnemonic_copy = strdup(state.generated_mnemonic);
        char* token = strtok(mnemonic_copy, " \n\r\t");
        while (token != nullptr) {
            word_count++;
            token = strtok(nullptr, " \n\r\t");
        }
        free(mnemonic_copy);

        if (word_count != 24) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
                              "Invalid: Found %d words, need exactly 24 words", word_count);
            ImGui::PopTextWrapPos();
        } else {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "✓ Valid: 24 words");
        }
    }

    ImGui::Spacing();

    float button_width = is_mobile ? -1 : 150.0f;

    if (ButtonDark("Cancel", ImVec2(button_width, 40)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        // Reset wizard state and go back to identity selection
        state.restore_identity_step = RESTORE_STEP_SEED;
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::CloseCurrentPopup();
    }

    if (!is_mobile) ImGui::SameLine();

    ImGui::BeginDisabled(word_count != 24);
    if (ButtonDark("Restore", ImVec2(button_width, 40))) {
        // Close all modals immediately
        ImGui::CloseCurrentPopup();
        state.show_identity_selection = false; // Hide identity list modal immediately
        state.restore_identity_step = RESTORE_STEP_SEED; // Reset wizard

        // Show spinner overlay
        state.show_operation_spinner = true;
        snprintf(state.operation_spinner_message, sizeof(state.operation_spinner_message),
                 "Restoring identity...");

        // Copy mnemonic to heap for async task
        std::string mnemonic_copy = std::string(state.generated_mnemonic);

        dht_publish_task.start([this, mnemonic_copy](AsyncTask* task) {
            task->addMessage("Validating seed phrase...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Deriving cryptographic keys...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Regenerating identity from seed...");
            restoreIdentityWithSeed(mnemonic_copy.c_str());

            task->addMessage("Initializing messenger context...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            task->addMessage("Loading contacts database...");
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            task->addMessage("✓ Identity restored successfully!");
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        });
    }
    ImGui::EndDisabled();
}


void DNAMessengerApp::restoreIdentityWithSeed(const char* mnemonic) {
    printf("[Identity] Restoring identity from seed phrase\n");

    // Clean up mnemonic: trim, lowercase, normalize spaces
    std::string cleaned_mnemonic = mnemonic;
    
    // Trim leading/trailing whitespace
    size_t start = cleaned_mnemonic.find_first_not_of(" \n\r\t");
    size_t end = cleaned_mnemonic.find_last_not_of(" \n\r\t");
    if (start == std::string::npos) {
        printf("[Identity] ERROR: Empty mnemonic\n");
        return;
    }
    cleaned_mnemonic = cleaned_mnemonic.substr(start, end - start + 1);
    
    // Convert to lowercase
    std::transform(cleaned_mnemonic.begin(), cleaned_mnemonic.end(), 
                   cleaned_mnemonic.begin(), ::tolower);
    
    // Normalize multiple spaces/newlines to single spaces
    std::string normalized;
    bool prev_space = false;
    for (char c : cleaned_mnemonic) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            if (!prev_space) {
                normalized += ' ';
                prev_space = true;
            }
        } else {
            normalized += c;
            prev_space = false;
        }
    }
    
    // Trim trailing space if added
    if (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }
    
    printf("[Identity] Cleaned mnemonic: '%s'\n", normalized.c_str());
    printf("[Identity] Mnemonic length: %zu bytes\n", normalized.length());
    
    // Count words for debug
    int word_count = 0;
    std::string temp = normalized;
    size_t pos = 0;
    while ((pos = temp.find(' ')) != std::string::npos) {
        word_count++;
        temp = temp.substr(pos + 1);
    }
    if (!temp.empty()) word_count++; // Last word
    printf("[Identity] Word count: %d\n", word_count);
    
    // Validate mnemonic using BIP39
    if (!bip39_validate_mnemonic(normalized.c_str())) {
        printf("[Identity] ERROR: Invalid BIP39 mnemonic\n");
        printf("[Identity] Please check that you have exactly 24 valid words\n");
        // TODO: Show error modal to user
        return;
    }
    
    printf("[Identity] Seed phrase validated\n");
    
    // Derive seeds from mnemonic (no passphrase)
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];
    
    if (qgp_derive_seeds_from_mnemonic(normalized.c_str(), "", signing_seed, encryption_seed) != 0) {
        printf("[Identity] ERROR: Failed to derive seeds from mnemonic\n");
        return;
    }
    
    printf("[Identity] Derived seeds from mnemonic\n");
    
    // Create temporary messenger context
    messenger_context_t *ctx = messenger_init("temp");
    if (!ctx) {
        printf("[Identity] ERROR: Failed to initialize messenger context\n");
        // Securely wipe seeds
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return;
    }
    
    printf("[Identity] Generating keys from seeds...\n");
    
    // Generate keys from seeds (fingerprint-first, no name required)
    char fingerprint[129];
    int result = messenger_generate_keys_from_seeds(ctx, signing_seed, encryption_seed, fingerprint);
    
    // Securely wipe seeds from memory
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));
    
    if (result != 0) {
        printf("[Identity] ERROR: Failed to generate keys from seeds\n");
        messenger_free(ctx);
        return;
    }
    
    printf("✓ Identity restored successfully!\n");
    printf("✓ Fingerprint: %s\n", fingerprint);
    printf("✓ Keys saved to: ~/.dna/%s.dsa and ~/.dna/%s.kem\n", fingerprint, fingerprint);

    // Try to fetch registered name via DHT reverse lookup
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        printf("[Identity] Looking up registered name from DHT...\n");
        char *registered_name = nullptr;
        int lookup_result = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &registered_name);

        if (lookup_result == 0 && registered_name && registered_name[0] != '\0') {
            printf("✓ Found registered name: %s\n", registered_name);
            state.identity_name_cache[fingerprint] = registered_name;
            free(registered_name);
        } else {
            printf("  No registered name found for this identity\n");
            printf("\n");
            printf("TIP: You can register a human-readable name for this identity\n");
            printf("     in Settings → Register Name\n");
            printf("\n");
        }
    }

    // Keys are saved to ~/.dna/<fingerprint>.{dsa,kem}
    // Add to identity list
    state.identities.push_back(fingerprint);
    state.current_identity = fingerprint;
    state.identity_loaded = true;

    // Load identity state (contacts, etc)
    loadIdentity(fingerprint);

    // Cleanup
    messenger_free(ctx);

    // Reset UI state
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));

    printf("[Identity] Identity restore complete\n");
}


void DNAMessengerApp::loadIdentity(const std::string& identity) {
    printf("[Identity] Loading identity: %s\n", identity.c_str());

    // Clear existing data
    state.contacts.clear();
    state.contact_messages.clear();

    // Initialize messenger context if not already done
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (ctx == nullptr) {
        ctx = messenger_init(identity.c_str());
        state.messenger_ctx = ctx;
        if (!ctx) {
            printf("[Identity] ERROR: Failed to initialize messenger context\n");
            return;
        }
        printf("[Identity] Messenger context initialized for: %s\n", identity.c_str());
        
        // Initialize P2P transport for DHT and messaging
        if (messenger_p2p_init(ctx) != 0) {
            printf("[Identity] ERROR: Failed to initialize P2P transport\n");
            messenger_free(ctx);
            state.messenger_ctx = nullptr;
            return;
        }
        printf("[Identity] P2P transport initialized\n");
    }

    // Load contacts from database using messenger API
    char **identities = nullptr;
    int contactCount = 0;

    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        printf("[Contacts] Loading %d contacts from database\n", contactCount);

        for (int i = 0; i < contactCount; i++) {
            std::string contact_identity = identities[i];

            // Get display name (registered name or shortened fingerprint)
            char displayName[256] = {0};
            if (messenger_get_display_name(ctx, identities[i], displayName) == 0) {
                // Success - use display name
            } else {
                // Fallback to raw identity
                strncpy(displayName, identities[i], sizeof(displayName) - 1);
            }

            // For now, set all contacts as offline (TODO: integrate presence system)
            bool is_online = false;

            // Add contact to list
            state.contacts.push_back({
                displayName,           // name
                contact_identity,      // address (fingerprint)
                is_online              // online status
            });

            free(identities[i]);
        }
        free(identities);

        // Sort contacts: online first, then alphabetically
        std::sort(state.contacts.begin(), state.contacts.end(), [](const Contact& a, const Contact& b) {
            if (a.is_online != b.is_online) {
                return a.is_online > b.is_online; // Online first
            }
            return strcmp(a.name.c_str(), b.name.c_str()) < 0; // Then alphabetically
        });

        printf("[Contacts] Loaded %d contacts\n", contactCount);
    } else {
        printf("[Contacts] No contacts found or error loading contacts\n");
    }

    state.identity_loaded = true;
    state.show_identity_selection = false; // Close identity selection modal
    state.current_identity = identity;

    // Fetch contacts from DHT in background (sync from other devices)
    DNAMessengerApp* app = this;
    state.contacts_synced_from_dht = false;
    
    contact_sync_task.start([app, ctx](AsyncTask* task) {
        printf("[Contacts] Syncing from DHT...\n");
        
        // First: Fetch contacts from DHT (merge with local)
        int result = messenger_sync_contacts_from_dht(ctx);
        if (result == 0) {
            printf("[Contacts] ✓ Synced from DHT successfully\n");
            app->state.contacts_synced_from_dht = true;
        } else {
            printf("[Contacts] DHT sync failed or no data found\n");
        }
        
        // Second: Push local contacts back to DHT (ensure DHT is up-to-date)
        printf("[Contacts] Publishing local contacts to DHT...\n");
        messenger_sync_contacts_to_dht(ctx);
        printf("[Contacts] ✓ Local contacts published to DHT\n");
    });

    // Preload messages for all contacts (improves UX - instant switching)
    printf("[Identity] Preloading messages for %zu contacts...\n", state.contacts.size());
    for (size_t i = 0; i < state.contacts.size(); i++) {
        loadMessagesForContact(i);
    }

    printf("[Identity] Identity loaded successfully: %s (%zu contacts)\n",
           identity.c_str(), state.contacts.size());
}

void DNAMessengerApp::reloadContactsFromDatabase() {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Contacts] ERROR: No messenger context\n");
        return;
    }

    char **identities = nullptr;
    int contactCount = 0;

    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        printf("[Contacts] Reloading %d contacts from database\n", contactCount);

        // Clear existing contacts
        state.contacts.clear();

        for (int i = 0; i < contactCount; i++) {
            std::string contact_identity = identities[i];

            // Get display name
            char displayName[256] = {0};
            if (messenger_get_display_name(ctx, identities[i], displayName) == 0) {
                // Success - use display name
            } else {
                // Fallback to raw identity
                strncpy(displayName, identities[i], sizeof(displayName) - 1);
            }

            bool is_online = false;

            // Add contact to list
            state.contacts.push_back({
                displayName,
                contact_identity,
                is_online
            });

            free(identities[i]);
        }
        free(identities);

        // Sort contacts: online first, then alphabetically
        std::sort(state.contacts.begin(), state.contacts.end(), [](const Contact& a, const Contact& b) {
            if (a.is_online != b.is_online) {
                return a.is_online > b.is_online;
            }
            return strcmp(a.name.c_str(), b.name.c_str()) < 0;
        });

        printf("[Contacts] ✓ Reloaded %d contacts\n", contactCount);
    } else {
        printf("[Contacts] Failed to reload contacts from database\n");
    }
}

void DNAMessengerApp::loadMessagesForContact(int contact_index) {
    if (contact_index < 0 || contact_index >= (int)state.contacts.size()) {
        return;
    }
    
    if (message_load_task.isRunning()) {
        return; // Already loading
    }

    const Contact& contact = state.contacts[contact_index];
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Messages] ERROR: No messenger context\n");
        return;
    }

    // Check if messages are already cached
    if (!state.contact_messages[contact_index].empty()) {
        printf("[Messages] Using cached messages for contact %d (%zu messages)\n", 
               contact_index, state.contact_messages[contact_index].size());
        return;  // Already loaded, use cache!
    }

    // Copy data for async task
    std::string contact_address = contact.address;
    std::string contact_name = contact.name;
    std::string current_identity = state.current_identity;
    DNAMessengerApp* app = this;

    // Load messages asynchronously
    message_load_task.start([app, ctx, contact_index, contact_address, contact_name, current_identity](AsyncTask* task) {
        printf("[Messages] Loading messages for contact: %s (%s)\n",
               contact_name.c_str(), contact_address.c_str());

        // Load conversation from database
        message_info_t *messages = nullptr;
        int count = 0;

        // Use contact.address which contains the fingerprint
        if (messenger_get_conversation(ctx, contact_address.c_str(), &messages, &count) == 0) {
            printf("[Messages] Loaded %d messages from database\n", count);

            // Build message vector in background thread (don't touch UI yet)
            std::vector<Message> loaded_messages;
            loaded_messages.reserve(count); // Pre-allocate for performance

            for (int i = 0; i < count; i++) {
                // Decrypt message if possible
                char *plaintext = nullptr;
                size_t plaintext_len = 0;

                std::string messageText = "[encrypted]";
                if (messenger_decrypt_message(ctx, messages[i].id, &plaintext, &plaintext_len) == 0) {
                    messageText = std::string(plaintext, plaintext_len);
                    free(plaintext);
                } else {
                    printf("[Messages] Warning: Could not decrypt message ID %d\n", messages[i].id);
                }

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                std::string timestamp = messages[i].timestamp ? messages[i].timestamp : "Unknown";
                if (timestamp.length() >= 16) {
                    // Extract "HH:MM" from "YYYY-MM-DD HH:MM:SS"
                    timestamp = timestamp.substr(11, 5);
                }

                // Determine if message is outgoing (sent by current user)
                bool is_outgoing = false;
                if (messages[i].sender && current_identity.length() > 0) {
                    // Compare fingerprints
                    is_outgoing = (strcmp(messages[i].sender, current_identity.c_str()) == 0);
                }

                // Get sender display name
                std::string sender = contact_name; // Default to contact name for incoming
                if (is_outgoing) {
                    sender = "You";
                } else if (messages[i].sender) {
                    // Try to get display name for sender
                    char displayName[256] = {0};
                    if (messenger_get_display_name(ctx, messages[i].sender, displayName) == 0) {
                        sender = displayName;
                    } else {
                        // Fallback to shortened fingerprint
                        std::string fingerprint = messages[i].sender;
                        if (fingerprint.length() > 32) {
                            sender = fingerprint.substr(0, 16) + "..." + fingerprint.substr(fingerprint.length() - 16);
                        } else {
                            sender = fingerprint;
                        }
                    }
                }

                // Initialize status from database (default to SENT for loaded messages)
                MessageStatus msg_status = STATUS_SENT;  // Default for historical messages
                if (messages[i].status) {
                    // Parse string status (old format compatibility)
                    if (strcmp(messages[i].status, "pending") == 0) {
                        msg_status = STATUS_PENDING;
                    } else if (strcmp(messages[i].status, "failed") == 0) {
                        msg_status = STATUS_FAILED;
                    }
                }

                // Add message to temporary vector (not UI yet)
                Message msg;
                msg.sender = sender;
                msg.content = messageText;
                msg.timestamp = timestamp;
                msg.is_outgoing = is_outgoing;
                msg.status = msg_status;

                loaded_messages.push_back(msg);
            }

            // Free messages array
            messenger_free_messages(messages, count);

            // Atomic swap: replace UI vector in one operation (FAST!)
            app->state.contact_messages[contact_index] = std::move(loaded_messages);

            printf("[Messages] Processed %d messages for display\n", count);
        } else {
            printf("[Messages] No messages found or error loading conversation\n");
        }
    });
}

void DNAMessengerApp::checkForNewMessages() {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !state.identity_loaded) {
        return;
    }

    // Don't start a new poll if one is already running
    if (message_poll_task.isRunning()) {
        return;
    }

    // Capture state by value for the worker thread
    DNAMessengerApp* app = this;

    // Start async poll task
    message_poll_task.start([app, ctx](AsyncTask* task) {
        size_t messages_received = 0;

        // Check DHT offline queue for new messages
        int result = messenger_p2p_check_offline_messages(ctx, &messages_received);

        if (result == 0 && messages_received > 0) {
            printf("[Poll] ✓ Received %zu new message(s) from DHT offline queue\n", messages_received);
            // Set flag for main thread to reload messages
            app->state.new_messages_received = true;
        } else if (result != 0) {
            printf("[Poll] Warning: Error checking offline messages\n");
        }
    });
}

void DNAMessengerApp::retryMessage(int contact_idx, int msg_idx) {
    if (contact_idx < 0 || contact_idx >= (int)state.contacts.size()) {
        printf("[Retry] ERROR: Invalid contact index\n");
        return;
    }

    // Check queue limit before retrying
    if (message_send_queue.size() >= 20) {
        printf("[Retry] ERROR: Queue full, cannot retry\n");
        return;
    }

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Retry] ERROR: No messenger context\n");
        return;
    }

    // Validate and copy message data (with mutex protection)
    std::string message_copy;
    std::string recipient;
    {
        std::lock_guard<std::mutex> lock(state.messages_mutex);
        std::vector<Message>& messages = state.contact_messages[contact_idx];

        if (msg_idx < 0 || msg_idx >= (int)messages.size()) {
            printf("[Retry] ERROR: Invalid message index\n");
            return;
        }

        Message& msg = messages[msg_idx];
        if (msg.status != STATUS_FAILED) {
            printf("[Retry] ERROR: Can only retry failed messages\n");
            return;
        }

        // Update status to pending
        msg.status = STATUS_PENDING;

        // Copy data for async task
        message_copy = msg.content;
        recipient = state.contacts[contact_idx].address;
    }

    DNAMessengerApp* app = this;
    printf("[Retry] Retrying message to %s...\n", recipient.c_str());

    // Enqueue retry task
    message_send_queue.enqueue([app, ctx, message_copy, recipient, contact_idx, msg_idx]() {
        const char* recipients[] = { recipient.c_str() };
        int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

        // Update status with mutex protection
        {
            std::lock_guard<std::mutex> lock(app->state.messages_mutex);
            if (msg_idx >= 0 && msg_idx < (int)app->state.contact_messages[contact_idx].size()) {
                app->state.contact_messages[contact_idx][msg_idx].status =
                    (result == 0) ? STATUS_SENT : STATUS_FAILED;
            }
        }

        if (result == 0) {
            printf("[Retry] ✓ Message retry successful to %s\n", recipient.c_str());
        } else {
            printf("[Retry] ERROR: Message retry failed to %s\n", recipient.c_str());
        }
    }, msg_idx);
}

void DNAMessengerApp::renderAddContactDialog() {
    if (!CenteredModal::Begin("Add Contact")) {
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    
    // Autofocus on input when dialog first opens
    static bool first_open = false;
    if (ImGui::IsWindowAppearing()) {
        first_open = true;
    }

    ImGui::Text("Enter contact fingerprint or name:");
    ImGui::Spacing();

    // Style input like other inputs (themed background)
    ImVec4 input_bg = g_app_settings.theme == 0 ? DNATheme::InputBackground() : ClubTheme::InputBackground();
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);

    // Input field for fingerprint/name
    ImGui::PushItemWidth(-1);
    if (first_open) {
        ImGui::SetKeyboardFocusHere();
        first_open = false;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    bool input_changed = ImGui::InputText("##contact_input", state.add_contact_input,
                                          sizeof(state.add_contact_input));
    ImGui::PopStyleColor();
    ImGui::PopItemWidth();

    ImGui::PopStyleColor(); // FrameBg
    ImGui::Spacing();

    // Auto-search as user types (debounced)
    std::string current_input = std::string(state.add_contact_input);
    size_t input_len = current_input.length();

    // Update timer when input changes
    if (input_changed) {
        state.add_contact_last_input_time = (float)ImGui::GetTime();
    }

    // Check if we should auto-trigger search
    float time_since_last_input = (float)ImGui::GetTime() - state.add_contact_last_input_time;
    bool should_auto_search = (
        input_len >= 3 &&  // Minimum 3 characters
        time_since_last_input >= 0.5f &&  // 500ms debounce
        current_input != state.add_contact_last_searched_input &&  // Haven't searched this yet
        !state.add_contact_lookup_in_progress  // Not already searching
    );

    if (should_auto_search) {
        // Auto-trigger lookup
        printf("[AddContact] Auto-searching: %s\n", state.add_contact_input);

        state.add_contact_lookup_in_progress = true;
        state.add_contact_error_message.clear();
        state.add_contact_found_name.clear();
        state.add_contact_found_fingerprint.clear();
        state.add_contact_last_searched_input = current_input;

        std::string input_copy = current_input;
        std::string current_identity = state.current_identity;
        messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;

        contact_lookup_task.start([this, input_copy, current_identity, ctx](AsyncTask* task) {
            task->addMessage("Looking up contact in DHT...");

            // Check if contact already exists
            if (contacts_db_exists(input_copy.c_str())) {
                state.add_contact_error_message = "Contact already exists in your list";
                state.add_contact_lookup_in_progress = false;
                return;
            }

            // Query DHT for public keys
            uint8_t *signing_pubkey = NULL;
            size_t signing_pubkey_len = 0;
            uint8_t *encryption_pubkey = NULL;
            size_t encryption_pubkey_len = 0;
            char fingerprint[129] = {0};

            int result = messenger_load_pubkey(
                ctx,
                input_copy.c_str(),
                &signing_pubkey,
                &signing_pubkey_len,
                &encryption_pubkey,
                &encryption_pubkey_len,
                fingerprint
            );

            if (result != 0) {
                state.add_contact_error_message = "Identity not found on DHT keyserver";
                state.add_contact_lookup_in_progress = false;
                task->addMessage("Not found");
                return;
            }

            // Free public keys (already cached)
            free(signing_pubkey);
            free(encryption_pubkey);

            // Check if user is trying to add themselves
            if (strcmp(fingerprint, current_identity.c_str()) == 0) {
                state.add_contact_error_message = "You cannot add yourself as a contact";
                state.add_contact_lookup_in_progress = false;
                state.add_contact_found_name.clear();
                state.add_contact_found_fingerprint.clear();
                task->addMessage("Cannot add self");
                return;
            }

            // Check if contact already exists by fingerprint
            if (contacts_db_exists(fingerprint)) {
                state.add_contact_error_message = "Contact already exists in your list";
                state.add_contact_lookup_in_progress = false;
                state.add_contact_found_name.clear();
                state.add_contact_found_fingerprint.clear();
                task->addMessage("Already exists");
                return;
            }

            // Success - store results
            state.add_contact_found_fingerprint = std::string(fingerprint);
            state.add_contact_found_name = input_copy;
            state.add_contact_lookup_in_progress = false;

            task->addMessage("Found!");
            printf("[AddContact] Found: %s (fingerprint: %s)\n", input_copy.c_str(), fingerprint);
        });
    }

    // Show error message if any
    if (!state.add_contact_error_message.empty()) {
        ImVec4 error_color = g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning();
        ImGui::PushStyleColor(ImGuiCol_Text, error_color);
        ImGui::TextWrapped("%s", state.add_contact_error_message.c_str());
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }

    // Show found contact info if lookup succeeded
    if (!state.add_contact_found_name.empty()) {
        ImVec4 success_color = g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess();
        ImGui::PushStyleColor(ImGuiCol_Text, success_color);
        ImGui::Text("Found: %s", state.add_contact_found_name.c_str());
        ImGui::PopStyleColor();
        
        // Display fingerprint with wrapping to prevent modal widening
        ImGui::PushTextWrapPos(ImGui::GetCursorPos().x + 420.0f); // Limit width
        ImGui::TextDisabled("Fingerprint:");
        ImGui::TextWrapped("%s", state.add_contact_found_fingerprint.c_str());
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
    }

    // Show spinner if lookup in progress (inline with search hint)
    if (state.add_contact_lookup_in_progress) {
        ImGui::SameLine();
        ThemedSpinner("##lookup_spinner", 15.0f, 3.0f);
        ImGui::SameLine();
        ImGui::TextDisabled("Searching...");
    } else if (input_len > 0 && input_len < 3) {
        ImGui::TextDisabled("Type at least 3 characters to search");
    }

    ImGui::Spacing();

    // Buttons
    float button_width = is_mobile ? -1 : 150.0f;

    if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
        state.show_add_contact_dialog = false;
        CenteredModal::End();
        return;
    }

    if (!is_mobile) ImGui::SameLine();

    // Save button (only enabled if contact found)
    ImGui::BeginDisabled(state.add_contact_found_fingerprint.empty());
    if (ButtonDark("Save", ImVec2(button_width, 40))) {
        // Save contact to database using FINGERPRINT
        const char* fingerprint = state.add_contact_found_fingerprint.c_str();
        int result = contacts_db_add(fingerprint, NULL);

        if (result == 0) {
            printf("[AddContact] Contact '%s' added successfully (fingerprint: %s)\n",
                   state.add_contact_found_name.c_str(), fingerprint);

            // Reload contacts from database (fast, no messenger reinit)
            reloadContactsFromDatabase();
            
            // Auto-publish contacts to DHT (async, non-blocking)
            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (ctx) {
                dht_publish_task.start([ctx](AsyncTask* task) {
                    printf("[AddContact] Publishing contacts to DHT...\n");
                    messenger_sync_contacts_to_dht(ctx);
                    printf("[AddContact] ✓ Published to DHT\n");
                });
            }

            // Close dialog
            state.show_add_contact_dialog = false;
        } else {
            printf("[AddContact] ERROR: Failed to save contact to database\n");
            state.add_contact_error_message = "Failed to save contact to database";
        }
    }
    ImGui::EndDisabled();

    CenteredModal::End();
}


void DNAMessengerApp::renderMobileLayout() {
    ImGuiIO& io = ImGui::GetIO();
    float screen_height = io.DisplaySize.y;
    float bottom_nav_height = 60.0f;

    // Track view changes to close emoji picker
    static View prev_view = VIEW_CONTACTS;
    static int prev_contact = -1;

    if (prev_view != state.current_view || prev_contact != state.selected_contact) {
        state.show_emoji_picker = false;
    }
    prev_view = state.current_view;
    prev_contact = state.selected_contact;

    // Content area (full screen minus bottom nav) - use full width
    ImGui::BeginChild("MobileContent", ImVec2(-1, -bottom_nav_height), false, ImGuiWindowFlags_NoScrollbar);

    switch(state.current_view) {
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


void DNAMessengerApp::renderDesktopLayout() {
    // Sidebar (state.contacts + navigation)
    renderSidebar();

    ImGui::SameLine();

    // Main content area
    ImGui::BeginChild("MainContent", ImVec2(0, 0), true);

    switch(state.current_view) {
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


void DNAMessengerApp::renderBottomNavBar() {
    ImGuiIO& io = ImGui::GetIO();
    float btn_width = io.DisplaySize.x / 4.0f;

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

    // Contacts button
    if (ThemedButton(ICON_FA_COMMENTS "\nChats", ImVec2(btn_width, 60), state.current_view == VIEW_CONTACTS)) {
        state.current_view = VIEW_CONTACTS;
    }

    ImGui::SameLine();

    // Wallet button
    if (ThemedButton(ICON_FA_WALLET "\nWallet", ImVec2(btn_width, 60), state.current_view == VIEW_WALLET)) {
        state.current_view = VIEW_WALLET;
        state.selected_contact = -1;
    }

    ImGui::SameLine();

    // Settings button
    if (ThemedButton(ICON_FA_GEAR "\nSettings", ImVec2(btn_width, 60), state.current_view == VIEW_SETTINGS)) {
        state.current_view = VIEW_SETTINGS;
        state.selected_contact = -1;
    }

    ImGui::SameLine();

    // Profile button (placeholder)
    if (ThemedButton(ICON_FA_USER "\nProfile", ImVec2(btn_width, 60), false)) {
        // TODO: Profile view
    }

    ImGui::PopStyleVar(2);
}


void DNAMessengerApp::renderContactsList() {
    ImGuiIO& io = ImGui::GetIO();

    // Get full available width before any child windows
    float full_width = ImGui::GetContentRegionAvail().x;

    // Top bar with title and add button
    ImGui::BeginChild("ContactsHeader", ImVec2(full_width, 60), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);

    ImGui::Text("  DNA Messenger");

    ImGui::SameLine(io.DisplaySize.x - 60);
    if (ButtonDark(ICON_FA_CIRCLE_PLUS, ImVec2(50, 40))) {
        // TODO: Add contact dialog
    }

    ImGui::EndChild();

    // Contact list (large touch targets)
    ImGui::BeginChild("ContactsScrollArea", ImVec2(full_width, 0), false);

    for (size_t i = 0; i < state.contacts.size(); i++) {
        ImGui::PushID(i);

        // Get button width
        float button_width = ImGui::GetContentRegionAvail().x;
        if (i == 0) {
        }

        // Large touch-friendly buttons (80px height)
        bool selected = (int)i == state.selected_contact;
        if (selected) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.3f));
        }

        if (ButtonDark("##contact", ImVec2(button_width, 80))) {
            state.selected_contact = i;
            state.current_view = VIEW_CHAT;
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
        ImU32 status_color = state.contacts[i].is_online ?
            IM_COL32(0, 255, 0, 255) : IM_COL32(128, 128, 128, 255);
        draw_list->AddCircleFilled(circle_center, 8.0f, status_color);

        // Contact name
        ImVec2 text_pos = ImVec2(button_min.x + 50, button_min.y + 20);
        draw_list->AddText(ImGui::GetFont(), 20.0f, text_pos,
            IM_COL32(255, 255, 255, 255), state.contacts[i].name.c_str());

        // Status text
        const char* status = state.contacts[i].is_online ? "Online" : "Offline";
        ImVec2 status_pos = ImVec2(button_min.x + 50, button_min.y + 45);
        draw_list->AddText(ImGui::GetFont(), 14.0f, status_pos,
            IM_COL32(180, 180, 180, 255), status);

        ImGui::PopID();
    }

    ImGui::EndChild();
}


void DNAMessengerApp::renderSidebar() {
    // Push border color before creating child
    ImVec4 border_col = (g_app_settings.theme == 0) ? DNATheme::Separator() : ClubTheme::Separator();
    ImGui::PushStyleColor(ImGuiCol_Border, border_col);

    ImGui::BeginChild("Sidebar", ImVec2(250, 0), true, ImGuiWindowFlags_NoScrollbar);

    // Navigation buttons (40px each)
    if (ThemedButton(ICON_FA_COMMENTS " Chat", ImVec2(-1, 40), state.current_view == VIEW_CONTACTS || state.current_view == VIEW_CHAT)) {
        state.current_view = VIEW_CONTACTS;
    }
    if (ThemedButton(ICON_FA_WALLET " Wallet", ImVec2(-1, 40), state.current_view == VIEW_WALLET)) {
        state.current_view = VIEW_WALLET;
    }
    if (ThemedButton(ICON_FA_GEAR " Settings", ImVec2(-1, 40), state.current_view == VIEW_SETTINGS)) {
        state.current_view = VIEW_SETTINGS;
    }

    ImGui::Spacing();
    ImGui::Text("Contacts");
    ImGui::Spacing();

    // Contact list - use remaining space minus 3 action buttons
    float add_button_height = 40.0f;
    float num_buttons = 3.0f;
    float spacing = ImGui::GetStyle().ItemSpacing.y;
    float available_height = ImGui::GetContentRegionAvail().y - (add_button_height * num_buttons) - (spacing * num_buttons);

    ImGui::BeginChild("ContactList", ImVec2(0, available_height), false);

    float list_width = ImGui::GetContentRegionAvail().x;
    for (size_t i = 0; i < state.contacts.size(); i++) {
        ImGui::PushID(i);

        float item_height = 30;
        bool selected = (state.selected_contact == (int)i);

        // Use invisible button for interaction
        ImVec2 cursor_screen_pos = ImGui::GetCursorScreenPos();
        bool clicked = ImGui::InvisibleButton("##contact", ImVec2(list_width, item_height));
        bool hovered = ImGui::IsItemHovered();

        if (clicked) {
            state.selected_contact = i;
            state.current_view = VIEW_CHAT;
            // Load messages for this contact from database
            loadMessagesForContact(i);
        }

        // Draw background
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 rect_min = cursor_screen_pos;
        ImVec2 rect_max = ImVec2(cursor_screen_pos.x + list_width, cursor_screen_pos.y + item_height);

        if (selected) {
            ImVec4 col = (g_app_settings.theme == 0) ? DNATheme::ButtonActive() : ClubTheme::ButtonActive();
            ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
            draw_list->AddRectFilled(rect_min, rect_max, bg_color);
        } else if (hovered) {
            ImVec4 col = (g_app_settings.theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
            ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
            draw_list->AddRectFilled(rect_min, rect_max, bg_color);
        }

        // Format: "✉ Name" with mail icon (theme-colored)
        const char* icon = ICON_FA_ENVELOPE;

        char display_text[256];
        snprintf(display_text, sizeof(display_text), "%s   %s", icon, state.contacts[i].name.c_str());

        // Center text vertically
        ImVec2 text_size = ImGui::CalcTextSize(display_text);
        float text_offset_y = (item_height - text_size.y) * 0.5f;
        ImVec2 text_pos = ImVec2(cursor_screen_pos.x + 8, cursor_screen_pos.y + text_offset_y);
        ImU32 text_color;
        if (selected || hovered) {
            // Use theme background color when selected or hovered
            ImVec4 bg_col = (g_app_settings.theme == 0) ? DNATheme::Background() : ClubTheme::Background();
            text_color = IM_COL32((int)(bg_col.x * 255), (int)(bg_col.y * 255), (int)(bg_col.z * 255), 255);
        } else {
            // Normal theme text color
            ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
        }
        draw_list->AddText(text_pos, text_color, display_text);

        ImGui::PopID();
    }

    ImGui::EndChild(); // ContactList

    // Action buttons at bottom (40px each to match main buttons)
    float button_width = ImGui::GetContentRegionAvail().x;
    if (ThemedButton(ICON_FA_CIRCLE_PLUS " Add Contact", ImVec2(button_width, add_button_height), false)) {
        state.show_add_contact_dialog = true;
        state.add_contact_lookup_in_progress = false;
        state.add_contact_error_message.clear();
        state.add_contact_found_name.clear();
        state.add_contact_found_fingerprint.clear();
        state.add_contact_last_searched_input.clear();
        memset(state.add_contact_input, 0, sizeof(state.add_contact_input));
        ImGui::OpenPopup("Add Contact");
    }

    if (ThemedButton(ICON_FA_USERS " Create Group", ImVec2(button_width, add_button_height), false)) {
        // TODO: Open create group dialog
    }

    if (ThemedButton(ICON_FA_ARROWS_ROTATE " Refresh", ImVec2(button_width, add_button_height), false)) {
        // TODO: Refresh contact list / sync from DHT
    }

    ImGui::EndChild(); // Sidebar

    ImGui::PopStyleColor(); // Border
}


void DNAMessengerApp::renderChatView() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    if (state.selected_contact < 0 || state.selected_contact >= (int)state.contacts.size()) {
        if (is_mobile) {
            // On mobile, show state.contacts list
            state.current_view = VIEW_CONTACTS;
            return;
        } else {
            ImGui::Text("Select a contact to start chatting");
            return;
        }
    }

    Contact& contact = state.contacts[state.selected_contact];

    // Top bar (mobile: with back button)
    float header_height = is_mobile ? 60.0f : 40.0f;
    ImGui::BeginChild("ChatHeader", ImVec2(0, header_height), true, ImGuiWindowFlags_NoScrollbar);

    if (is_mobile) {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        if (ButtonDark(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
            state.current_view = VIEW_CONTACTS;
            state.selected_contact = -1;
        }
        ImGui::SameLine();
    }

    // Style contact name same as in contact list
    // Use mail icon with theme colors
    const char* status_icon = ICON_FA_ENVELOPE;
    ImVec4 icon_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

    // Center text vertically in header
    float text_size_y = ImGui::CalcTextSize(contact.name.c_str()).y;
    float text_offset_y = (header_height - text_size_y) * 0.5f;
    ImGui::SetCursorPosY(text_offset_y);

    ImGui::TextColored(icon_color, "%s", status_icon);
    ImGui::SameLine();

    ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
    ImGui::TextColored(text_col, "%s", contact.name.c_str());

    // Message Wall button (right side of header)
    ImGui::SameLine();
    float wall_btn_width = is_mobile ? 120.0f : 140.0f;
    float wall_btn_height = is_mobile ? 40.0f : 30.0f;
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - wall_btn_width - 10);
    ImGui::SetCursorPosY((header_height - wall_btn_height) * 0.5f);

    if (ButtonDark(ICON_FA_NEWSPAPER " Wall", ImVec2(wall_btn_width, wall_btn_height))) {
        // Open message wall for this contact
        state.wall_fingerprint = contact.address;  // Use address as fingerprint
        state.wall_display_name = contact.name;
        state.wall_is_own = false;  // Viewing someone else's wall
        state.show_message_wall = true;
    }

    ImGui::EndChild();

    // Message area
    float input_height = is_mobile ? 100.0f : 80.0f;
    ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);

    // Show spinner while loading messages for the first time
    if (message_load_task.isRunning()) {
        float spinner_radius = 30.0f;
        float window_width = ImGui::GetWindowWidth();
        float window_height = ImGui::GetWindowHeight();
        ImVec2 center = ImVec2(window_width * 0.5f, window_height * 0.4f);
        ImGui::SetCursorPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
        ThemedSpinner("##message_load", spinner_radius, 6.0f);
        
        const char* loading_text = "Loading message history...";
        ImVec2 text_size = ImGui::CalcTextSize(loading_text);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_radius + 20));
        ImGui::Text("%s", loading_text);
        
        ImGui::EndChild();
        
        // Input area (disabled while loading)
        ImGui::BeginChild("InputArea", ImVec2(0, 0), true);
        ImGui::EndChild();
        return;
    }

    // Copy messages with mutex protection (minimal lock time)
    std::vector<Message> messages_copy;
    {
        std::lock_guard<std::mutex> lock(state.messages_mutex);
        messages_copy = state.contact_messages[state.selected_contact];
    }

    // Render all messages (no clipper for variable-height items)
    for (size_t i = 0; i < messages_copy.size(); i++) {
        const auto& msg = messages_copy[i];

            // Calculate bubble width based on current window size
            float available_width = ImGui::GetContentRegionAvail().x;
            float bubble_width = available_width;  // 100% of available width (padding inside bubble prevents overflow)

            // All bubbles aligned left (Telegram-style)

            // Draw bubble background with proper padding (theme-aware)
            ImVec4 base_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

            // Recipient bubble: much lighter (0.12 opacity)
            // Own bubble: normal opacity (0.25)
            ImVec4 bg_color;
            if (msg.is_outgoing) {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
            } else {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
            }

            ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0)); // No border
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f); // Square corners

        char bubble_id[32];
        snprintf(bubble_id, sizeof(bubble_id), "bubble%zu", i);

        // Calculate padding and dimensions
        float padding_horizontal = 15.0f;
        float padding_vertical = 12.0f;
        float content_width = bubble_width - (padding_horizontal * 2);

        ImVec2 text_size = ImGui::CalcTextSize(msg.content.c_str(), NULL, false, content_width);

        float bubble_height = text_size.y + (padding_vertical * 2);

        ImGui::BeginChild(bubble_id, ImVec2(bubble_width, bubble_height), false,
            ImGuiWindowFlags_NoScrollbar);

        // Right-click context menu - set compact style BEFORE opening
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.0f, 0.0f)); // No vertical padding
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, 0.0f)); // No vertical spacing

        if (ImGui::BeginPopupContextWindow()) {
            if (ImGui::MenuItem(ICON_FA_COPY " Copy")) {
                ImGui::SetClipboardText(msg.content.c_str());
            }
            ImGui::EndPopup();
        }

        ImGui::PopStyleVar(2);

        // Apply padding
        ImGui::SetCursorPos(ImVec2(padding_horizontal, padding_vertical));

        // Use TextWrapped for better text rendering
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + content_width);
        ImGui::TextWrapped("%s", msg.content.c_str());
        ImGui::PopTextWrapPos();

        // Status indicator (bottom-right corner) for outgoing messages
        if (msg.is_outgoing) {
            const char* status_icon;
            ImVec4 status_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

            switch (msg.status) {
                case STATUS_PENDING:
                    status_icon = ICON_FA_CLOCK;
                    break;
                case STATUS_SENT:
                    status_icon = ICON_FA_CHECK;
                    break;
                case STATUS_FAILED:
                    status_icon = ICON_FA_CIRCLE_EXCLAMATION;
                    break;
            }

            status_color.w = 0.6f; // Subtle opacity for all states
            float icon_size = 12.0f;
            ImVec2 status_pos = ImVec2(content_width - icon_size, bubble_height - padding_vertical - icon_size);

            ImGui::SetCursorPos(status_pos);
            ImGui::PushStyleColor(ImGuiCol_Text, status_color);
            ImGui::Text("%s", status_icon);
            ImGui::PopStyleColor();

            // Add retry hover tooltip and click handler for failed messages
            if (msg.status == STATUS_FAILED) {
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Send failed - click to retry");
                }
                if (ImGui::IsItemClicked()) {
                    retryMessage(state.selected_contact, i);
                }
            }
        }

        ImGui::EndChild();

        // Get bubble position for arrow (AFTER EndChild)
        ImVec2 bubble_min = ImGui::GetItemRectMin();
        ImVec2 bubble_max = ImGui::GetItemRectMax();

        ImGui::PopStyleVar(1); // ChildRounding
        ImGui::PopStyleColor(2); // ChildBg, Border

        // Draw triangle arrow pointing DOWN from bubble to username
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec4 arrow_color;
        if (msg.is_outgoing) {
            arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
        } else {
            arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
        }
        ImU32 arrow_col = ImGui::ColorConvertFloat4ToU32(arrow_color);

        // Triangle points: pointing DOWN from bubble to username
        float arrow_x = bubble_min.x + 20.0f; // 20px from left edge
        float arrow_top = bubble_max.y; // Bottom of bubble
        float arrow_bottom = bubble_max.y + 10.0f; // Point of arrow extends down

        ImVec2 p1(arrow_x, arrow_bottom);           // Bottom point (pointing down)
        ImVec2 p2(arrow_x - 8.0f, arrow_top);       // Top left (at bubble bottom)
        ImVec2 p3(arrow_x + 8.0f, arrow_top);       // Top right (at bubble bottom)

        draw_list->AddTriangleFilled(p1, p2, p3, arrow_col);

        // Sender name and timestamp BELOW the arrow (theme-aware)
        ImVec4 meta_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
        meta_color.w = 0.7f; // Slightly transparent

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f); // Space for arrow
        ImGui::PushStyleColor(ImGuiCol_Text, meta_color);
        const char* sender_label = msg.is_outgoing ? "You" : msg.sender.c_str();
        ImGui::Text("%s • %s", sender_label, msg.timestamp.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Spacing();
    }  // End message loop

    // Handle scroll logic BEFORE EndChild() (operates on MessageArea window)
    float current_scroll = ImGui::GetScrollY();
    float max_scroll = ImGui::GetScrollMaxY();
    bool is_at_bottom = (current_scroll >= max_scroll - 1.0f);

    // Check if user actively scrolled UP (not just hovering)
    bool user_scrolled_up = !is_at_bottom && ImGui::IsWindowFocused();

    if (user_scrolled_up && state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames = 0; // Cancel auto-scroll if user scrolled up
    }

    // Delayed scroll (wait 2 frames for message to fully render)
    if (state.scroll_to_bottom_frames > 0) {
        state.scroll_to_bottom_frames--;
        if (state.scroll_to_bottom_frames == 0) {
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        }
    } else if (state.should_scroll_to_bottom) {
        // Start delayed scroll
        state.scroll_to_bottom_frames = 2;
        state.should_scroll_to_bottom = false;
    }

    ImGui::EndChild();

    // Message input area - Multiline with recipient bubble color
    ImGui::Spacing();
    ImGui::Spacing();

    // Recipient bubble background color
    ImVec4 recipient_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)  // DNA: slightly lighter than bg
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f); // Club: slightly lighter

    ImGui::PushStyleColor(ImGuiCol_FrameBg, recipient_bg);

    // Check if we need to autofocus (contact changed or message sent)
    bool should_autofocus = (state.prev_selected_contact != state.selected_contact) || state.should_focus_input;
    if (state.prev_selected_contact != state.selected_contact) {
        state.prev_selected_contact = state.selected_contact;
        state.should_scroll_to_bottom = true;  // Scroll to bottom when switching contacts
    }
    state.should_focus_input = false; // Reset flag

    if (is_mobile) {
        // Mobile: stacked layout
        if (should_autofocus) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(-1, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine);
        ImGui::PopStyleColor();

        // Send button with paper plane icon
        if (ButtonDark(ICON_FA_PAPER_PLANE, ImVec2(-1, 40)) || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_contact >= 0) {
                // Check queue limit
                if (message_send_queue.size() >= 20) {
                    ImGui::OpenPopup("Queue Full");
                } else {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        // Copy data for async task
                        std::string message_copy = std::string(state.message_input);
                        std::string recipient = state.contacts[state.selected_contact].address;
                        int contact_idx = state.selected_contact;
                        DNAMessengerApp* app = this;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[contact_idx].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[contact_idx].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task
                        message_send_queue.enqueue([app, ctx, message_copy, recipient, contact_idx, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(app->state.messages_mutex);
                                if (msg_idx < (int)app->state.contact_messages[contact_idx].size()) {
                                    app->state.contact_messages[contact_idx][msg_idx].status =
                                        (result == 0) ? STATUS_SENT : STATUS_FAILED;
                                }
                            }

                            if (result == 0) {
                                printf("[Send] ✓ Message sent to %s (queue processed)\n", recipient.c_str());
                            } else {
                                printf("[Send] ERROR: Failed to send to %s (status=FAILED)\n", recipient.c_str());
                            }
                        }, msg_idx);
                    } else {
                        printf("[Send] ERROR: No messenger context\n");
                    }
                }
            }
        }
    } else {
        // Desktop: side-by-side
        float input_width = ImGui::GetContentRegionAvail().x - 70; // Reserve 70px for button

        ImVec2 input_pos = ImGui::GetCursorScreenPos();

        if (should_autofocus) {
            ImGui::SetKeyboardFocusHere();
        }
        ImGui::SetNextItemWidth(input_width);

        // Callback to set cursor position if needed
        auto input_callback = [](ImGuiInputTextCallbackData* data) -> int {
            DNAMessengerApp* app = (DNAMessengerApp*)data->UserData;
            if (app->state.input_cursor_pos >= 0) {
                data->CursorPos = app->state.input_cursor_pos;
                data->SelectionStart = data->SelectionEnd = data->CursorPos;
                app->state.input_cursor_pos = -1; // Reset
            }
            return 0;
        };

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(input_width, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_CallbackAlways,
            input_callback, this);
        ImGui::PopStyleColor();

        // Get input box position right after rendering it
        ImVec2 input_rect_min = ImGui::GetItemRectMin();

        // Check if ':' was just typed to trigger emoji picker
        static char prev_message[16384] = "";
        static bool already_triggered_for_current = false;
        static ImVec2 prev_window_size = ImVec2(0, 0);
        ImVec2 current_window_size = ImGui::GetIO().DisplaySize;
        size_t len = strlen(state.message_input);
        bool message_changed = (strcmp(state.message_input, prev_message) != 0);

        // Close emoji picker if window was resized
        if (state.show_emoji_picker && (prev_window_size.x != current_window_size.x || prev_window_size.y != current_window_size.y)) {
            state.show_emoji_picker = false;
        }
        prev_window_size = current_window_size;

        // Reset trigger flag if message changed
        if (message_changed) {
            already_triggered_for_current = false;
            strcpy(prev_message, state.message_input);
        }

        // Detect if ':' was just typed - calculate text cursor position
        if (!already_triggered_for_current && len > 0 && state.message_input[len-1] == ':' && ImGui::IsItemActive()) {
            state.show_emoji_picker = true;

            // Calculate approximate cursor position based on text
            ImFont* font = ImGui::GetFont();
            float font_size = ImGui::GetFontSize();

            // Count newlines to determine which line we're on
            int line_num = 0;
            int last_newline_pos = -1;
            for (size_t i = 0; i < len; i++) {
                if (state.message_input[i] == '\n') {
                    line_num++;
                    last_newline_pos = i;
                }
            }

            // Calculate text width from last newline (or start) to cursor
            const char* line_start = (last_newline_pos >= 0) ? &state.message_input[last_newline_pos + 1] : state.message_input;
            size_t chars_in_line = len - (last_newline_pos + 1);
            ImVec2 text_size = font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, line_start, line_start + chars_in_line);

            // Position picker at text cursor location
            float cursor_x = input_rect_min.x + text_size.x + 5.0f; // 5px padding
            float cursor_y = input_rect_min.y + (line_num * font_size * 1.2f); // 1.2 line height multiplier

            // Emoji picker size
            float picker_width = 400.0f;
            float picker_height = 200.0f;

            // Check if picker would go outside window bounds (right side)
            float window_right = ImGui::GetIO().DisplaySize.x;
            if (cursor_x + picker_width > window_right) {
                // Place on left side of cursor instead
                cursor_x = cursor_x - picker_width - 10.0f;
                // Make sure it doesn't go off left side
                if (cursor_x < 0) cursor_x = 10.0f;
            }

            state.emoji_picker_pos = ImVec2(cursor_x, cursor_y - 210);
            already_triggered_for_current = true;
        }

        // Emoji picker popup
        if (state.show_emoji_picker) {
            ImGui::SetNextWindowPos(state.emoji_picker_pos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(ImVec2(400, 200), ImGuiCond_Always);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10));

            if (ImGui::Begin("##EmojiPicker", &state.show_emoji_picker, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
                // ESC to close
                if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                    state.show_emoji_picker = false;
                    state.should_focus_input = true; // Refocus message input
                }

                // Close if clicked outside
                if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows)) {
                    state.show_emoji_picker = false;
                }

                // Font Awesome emoji icons in a single flat array
                static const char* emojis[] = {
                    // Smileys
                    ICON_FA_FACE_SMILE, ICON_FA_FACE_GRIN, ICON_FA_FACE_LAUGH, ICON_FA_FACE_GRIN_BEAM,
                    ICON_FA_FACE_GRIN_HEARTS, ICON_FA_FACE_KISS_WINK_HEART, ICON_FA_FACE_GRIN_WINK, ICON_FA_FACE_SMILE_WINK,
                    ICON_FA_FACE_GRIN_TONGUE, ICON_FA_FACE_SURPRISE, ICON_FA_FACE_FROWN, ICON_FA_FACE_SAD_TEAR,
                    ICON_FA_FACE_ANGRY, ICON_FA_FACE_TIRED, ICON_FA_FACE_MEH, ICON_FA_FACE_ROLLING_EYES,
                    // Hearts & Symbols
                    ICON_FA_HEART, ICON_FA_HEART_PULSE, ICON_FA_HEART_CRACK, ICON_FA_STAR,
                    ICON_FA_THUMBS_UP, ICON_FA_THUMBS_DOWN, ICON_FA_FIRE, ICON_FA_ROCKET,
                    ICON_FA_BOLT, ICON_FA_CROWN, ICON_FA_GEM, ICON_FA_TROPHY,
                    ICON_FA_GIFT, ICON_FA_CAKE_CANDLES, ICON_FA_BELL, ICON_FA_MUSIC,
                    // Objects
                    ICON_FA_CHECK, ICON_FA_XMARK, ICON_FA_CIRCLE_EXCLAMATION, ICON_FA_CIRCLE_QUESTION,
                    ICON_FA_LIGHTBULB, ICON_FA_COMMENT, ICON_FA_ENVELOPE, ICON_FA_PHONE,
                    ICON_FA_LOCATION_DOT, ICON_FA_CALENDAR, ICON_FA_CLOCK, ICON_FA_FLAG,
                    ICON_FA_SHIELD, ICON_FA_KEY, ICON_FA_LOCK, ICON_FA_EYE
                };
                static const int emoji_count = sizeof(emojis) / sizeof(emojis[0]);
                static const int emojis_per_row = 9;

                ImGui::BeginChild("EmojiGrid", ImVec2(0, 0), false);

                // Transparent button style
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.3f, 0.3f, 0.3f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.4f, 0.4f, 0.4f, 0.4f));
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 2));
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));

                // Display emojis in a grid (9 per row)
                for (int i = 0; i < emoji_count; i++) {
                    if (ImGui::Button(emojis[i], ImVec2(35, 35))) {
                        if (len > 0) state.message_input[len-1] = '\0'; // Remove the ':'
                        strcat(state.message_input, emojis[i]);
                        state.input_cursor_pos = strlen(state.message_input); // Set cursor to end
                        state.show_emoji_picker = false;
                        state.should_focus_input = true;
                    }
                    if ((i + 1) % emojis_per_row != 0 && i < emoji_count - 1) ImGui::SameLine();
                }

                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);
                ImGui::EndChild();
                ImGui::End();
            }
            ImGui::PopStyleVar();
        }

        ImGui::SameLine();

        // Send button - round button with paper plane icon
        ImVec4 btn_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(btn_color.x * 0.9f, btn_color.y * 0.9f, btn_color.z * 0.9f, btn_color.w));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(btn_color.x * 0.8f, btn_color.y * 0.8f, btn_color.z * 0.8f, btn_color.w));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.1f, 0.11f, 0.13f, 1.0f)); // Dark text on button
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 25.0f); // Round button

        // Center icon in button
        const char* icon = ICON_FA_PAPER_PLANE;
        ImVec2 icon_size = ImGui::CalcTextSize(icon);
        float button_size = 50.0f;
        ImVec2 padding((button_size - icon_size.x) * 0.5f, (button_size - icon_size.y) * 0.5f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, padding);

        bool icon_clicked = ImGui::Button(icon, ImVec2(button_size, button_size));

        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(4);

        if (icon_clicked || enter_pressed) {
            if (strlen(state.message_input) > 0 && state.selected_contact >= 0) {
                // Check queue limit
                if (message_send_queue.size() >= 20) {
                    ImGui::OpenPopup("Queue Full");
                } else {
                    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                    if (ctx) {
                        // Copy data for async task
                        std::string message_copy = std::string(state.message_input);
                        std::string recipient = state.contacts[state.selected_contact].address;
                        int contact_idx = state.selected_contact;
                        DNAMessengerApp* app = this;

                        // Get message index BEFORE appending (important for queue)
                        int msg_idx;
                        {
                            std::lock_guard<std::mutex> lock(state.messages_mutex);
                            msg_idx = state.contact_messages[contact_idx].size();

                            // Optimistic UI update: append pending message immediately
                            Message pending_msg;
                            pending_msg.sender = "You";
                            pending_msg.content = message_copy;
                            pending_msg.timestamp = "now";
                            pending_msg.is_outgoing = true;
                            pending_msg.status = STATUS_PENDING;
                            state.contact_messages[contact_idx].push_back(pending_msg);
                        }

                        // Clear input immediately for better UX
                        state.message_input[0] = '\0';
                        state.should_focus_input = true;
                        state.should_scroll_to_bottom = true;  // Force scroll to bottom after sending

                        // Enqueue message send task
                        message_send_queue.enqueue([app, ctx, message_copy, recipient, contact_idx, msg_idx]() {
                            const char* recipients[] = { recipient.c_str() };
                            int result = messenger_send_message(ctx, recipients, 1, message_copy.c_str());

                            // Update status with mutex protection
                            {
                                std::lock_guard<std::mutex> lock(app->state.messages_mutex);
                                if (msg_idx < (int)app->state.contact_messages[contact_idx].size()) {
                                    app->state.contact_messages[contact_idx][msg_idx].status =
                                        (result == 0) ? STATUS_SENT : STATUS_FAILED;
                                }
                            }

                            if (result == 0) {
                                printf("[Send] ✓ Message sent to %s (queue processed)\n", recipient.c_str());
                            } else {
                                printf("[Send] ERROR: Failed to send to %s (status=FAILED)\n", recipient.c_str());
                            }
                        }, msg_idx);
                    } else {
                        printf("[Send] ERROR: No messenger context\n");
                    }
                }
            }
        }
    }

    ImGui::PopStyleColor(); // FrameBg

    // Queue Full modal
    if (ImGui::BeginPopupModal("Queue Full", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Message queue is full (20 pending messages).");
        ImGui::Text("Please wait for messages to send before adding more.");
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}


void DNAMessengerApp::renderWalletView() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("WalletContent", ImVec2(-padding, -padding), false);

    // Load wallet on first render
    if (!state.wallet_loaded && !state.wallet_loading) {
        loadWallet();
    }

    // Show error if wallet failed to load
    if (!state.wallet_error.empty()) {
        ImVec2 available_size = ImGui::GetContentRegionAvail();
        ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);

        const char* error_icon = ICON_FA_TRIANGLE_EXCLAMATION " Wallet Error";
        ImVec2 text_size = ImGui::CalcTextSize(error_icon);
        ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y - 60));
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", error_icon);

        ImVec2 desc_size = ImGui::CalcTextSize(state.wallet_error.c_str());
        ImGui::SetCursorPos(ImVec2(center.x - desc_size.x * 0.5f, center.y - 20));
        ImGui::TextDisabled("%s", state.wallet_error.c_str());

        ImGui::EndChild();
        return;
    }

    // Show loading spinner while wallet is loading
    if (state.wallet_loading) {
        ImVec2 available_size = ImGui::GetContentRegionAvail();
        ImVec2 center = ImVec2(available_size.x * 0.5f, available_size.y * 0.5f);
        ImGui::SetCursorPos(ImVec2(center.x - 50, center.y - 50));
        ThemedSpinner("##wallet_loading", 20.0f, 4.0f);
        ImGui::SetCursorPos(ImVec2(center.x - 50, center.y));
        ImGui::TextDisabled("Loading wallet...");
        ImGui::EndChild();
        return;
    }

    // Header
    ImGui::Text(ICON_FA_WALLET " %s", state.wallet_name.c_str());
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Refresh button
    if (ImGui::Button(ICON_FA_ARROWS_ROTATE " Refresh")) {
        refreshBalances();
    }
    ImGui::Spacing();

    // Token balance cards
    const char* tokens[] = {"CPUNK", "CELL", "KEL"};
    const char* token_names[] = {"ChipPunk", "Cellframe", "KelVPN"};
    const char* token_icons[] = {ICON_FA_COINS, ICON_FA_BOLT, ICON_FA_GEM};

    for (int i = 0; i < 3; i++) {
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.15f, 0.15f, 0.9f));

        float card_height = is_mobile ? 100.0f : 120.0f;
        char card_id[32];
        snprintf(card_id, sizeof(card_id), "##card_%s", tokens[i]);
        ImGui::BeginChild(card_id, ImVec2(-1, card_height), true);

        // Token icon and name
        ImGui::SetCursorPos(ImVec2(20, 15));
        ImGui::Text("%s %s", token_icons[i], tokens[i]);

        ImGui::SetCursorPos(ImVec2(20, 35));
        ImGui::TextDisabled("%s", token_names[i]);

        // Balance
        ImGui::SetCursorPos(ImVec2(20, is_mobile ? 60 : 65));
        auto it = state.token_balances.find(tokens[i]);
        if (it != state.token_balances.end()) {
            std::string formatted = formatBalance(it->second);
            ImGui::Text("%s", formatted.c_str());
        } else {
            ImGui::TextDisabled("0.00");
        }

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
            state.show_send_dialog = true;
            state.send_status.clear();
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(-1, btn_height))) {
            state.show_receive_dialog = true;
            // Get wallet address for Backbone network
            wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
            if (wallets && state.current_wallet_index >= 0) {
                wallet_get_address(&wallets->wallets[state.current_wallet_index],
                                  "Backbone", state.wallet_address);
            }
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_RECEIPT " Transaction History", ImVec2(-1, btn_height))) {
            state.show_transaction_history = true;
            loadTransactionHistory();
        }
    } else {
        // Desktop: Side-by-side buttons
        ImGuiStyle& style = ImGui::GetStyle();
        float available_width = ImGui::GetContentRegionAvail().x;
        float spacing = style.ItemSpacing.x;
        float btn_width = (available_width - spacing * 2) / 3.0f;

        if (ButtonDark(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, btn_height))) {
            state.show_send_dialog = true;
            state.send_status.clear();
        }
        ImGui::SameLine();

        if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(btn_width, btn_height))) {
            state.show_receive_dialog = true;
            // Get wallet address for Backbone network
            wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
            if (wallets && state.current_wallet_index >= 0) {
                wallet_get_address(&wallets->wallets[state.current_wallet_index],
                                  "Backbone", state.wallet_address);
            }
        }
        ImGui::SameLine();

        if (ButtonDark(ICON_FA_RECEIPT " History", ImVec2(btn_width, btn_height))) {
            state.show_transaction_history = true;
            loadTransactionHistory();
        }
    }

    ImGui::EndChild();
}


void DNAMessengerApp::renderSettingsView() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("SettingsContent", ImVec2(-padding, -padding), false);

    // Header
    ImGui::Text(ICON_FA_GEAR " Settings");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Theme selection
    ImGui::Text("Theme");
    ImGui::Spacing();

    int prev_theme = g_app_settings.theme;

    if (is_mobile) {
        // Mobile: Full-width radio buttons with larger touch targets
        if (ImGui::RadioButton("cpunk.io (Cyan)##theme", g_app_settings.theme == 0)) {
            g_app_settings.theme = 0;
        }
        ImGui::Spacing();
        if (ImGui::RadioButton("cpunk.club (Orange)##theme", g_app_settings.theme == 1)) {
            g_app_settings.theme = 1;
        }
    } else {
        ImGui::RadioButton("cpunk.io (Cyan)", &g_app_settings.theme, 0);
        ImGui::RadioButton("cpunk.club (Orange)", &g_app_settings.theme, 1);
    }

    // Apply theme if changed
    if (prev_theme != g_app_settings.theme) {
        ApplyTheme(g_app_settings.theme);
        SettingsManager::Save(g_app_settings);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // UI Scale selection
    ImGui::Text("UI Scale (Accessibility)");
    ImGui::Spacing();

    float prev_scale = g_app_settings.ui_scale;
    int scale_index = 0;
    // Use tolerance for float comparison
    if (g_app_settings.ui_scale < 1.25f) scale_index = 0;          // 100% (1.1)
    else scale_index = 1;                                           // 125% (1.375)

    if (is_mobile) {
        if (ImGui::RadioButton("Normal (100%)##scale", scale_index == 0)) {
            g_app_settings.ui_scale = 1.1f;
        }
        ImGui::Spacing();
        if (ImGui::RadioButton("Large (125%)##scale", scale_index == 1)) {
            g_app_settings.ui_scale = 1.375f;
        }
    } else {
        if (ImGui::RadioButton("Normal (100%)", scale_index == 0)) {
            g_app_settings.ui_scale = 1.1f;
        }
        if (ImGui::RadioButton("Large (125%)", scale_index == 1)) {
            g_app_settings.ui_scale = 1.375f;
        }
    }

    // Apply scale if changed (requires app restart)
    if (prev_scale != g_app_settings.ui_scale) {
        SettingsManager::Save(g_app_settings);
    }

    // Show persistent warning if scale was changed (compare to current ImGui scale)
    ImGuiStyle& current_style = ImGui::GetStyle();
    if (fabs(g_app_settings.ui_scale - current_style.FontScaleMain) > 0.01f) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "⚠ Restart app to apply scale changes");
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
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_USER " Edit DNA Profile", ImVec2(-1, btn_height))) {
            state.show_profile_editor = true;
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_TAG " Register DNA Name", ImVec2(-1, btn_height))) {
            state.show_register_name = true;
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_NEWSPAPER " My Message Wall", ImVec2(-1, btn_height))) {
            // Open own message wall
            state.wall_fingerprint = state.current_identity;  // Use current identity fingerprint
            state.wall_display_name = "My Wall";
            state.wall_is_own = true;  // Can post to own wall
            state.show_message_wall = true;
        }
    } else {
        if (ButtonDark("Create New Identity", ImVec2(200, btn_height))) {
            // TODO: Create identity dialog
        }
        ImGui::SameLine();
        if (ButtonDark("Import Identity", ImVec2(200, btn_height))) {
            // TODO: Import identity dialog
        }

        ImGui::Spacing();

        if (ButtonDark(ICON_FA_USER " Edit Profile", ImVec2(200, btn_height))) {
            state.show_profile_editor = true;
        }
        ImGui::SameLine();
        if (ButtonDark(ICON_FA_TAG " Register Name", ImVec2(200, btn_height))) {
            state.show_register_name = true;
        }

        ImGui::Spacing();

        if (ButtonDark(ICON_FA_NEWSPAPER " My Message Wall", ImVec2(-1, btn_height))) {
            // Open own message wall
            state.wall_fingerprint = state.current_identity;  // Use current identity fingerprint
            state.wall_display_name = "My Wall";
            state.wall_is_own = true;  // Can post to own wall
            state.show_message_wall = true;
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

// ===== WALLET FUNCTIONS =====

void DNAMessengerApp::loadWallet() {
    if (state.wallet_loading) return;  // Already loading

    state.wallet_loading = true;
    state.wallet_error.clear();

    wallet_list_t *wallets = nullptr;
    int ret = wallet_list_cellframe(&wallets);

    if (ret != 0 || !wallets || wallets->count == 0) {
        state.wallet_error = "No wallets found. Create one with cellframe-node-cli.";
        state.wallet_loaded = false;
        state.wallet_loading = false;
        return;
    }

    // Store wallet list and use first wallet
    state.wallet_list = wallets;
    state.current_wallet_index = 0;
    state.wallet_name = std::string(wallets->wallets[0].name);
    state.wallet_loaded = true;
    state.wallet_loading = false;

    printf("[Wallet] Loaded wallet: %s\n", state.wallet_name.c_str());

    // Automatically refresh balances
    refreshBalances();
}

void DNAMessengerApp::refreshBalances() {
    if (!state.wallet_loaded || state.current_wallet_index < 0) {
        return;
    }

    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets) return;

    cellframe_wallet_t *wallet = &wallets->wallets[state.current_wallet_index];

    // Get wallet address for Backbone network
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        state.wallet_error = "Failed to get wallet address";
        return;
    }

    printf("[Wallet] Querying balances for address: %s\n", address);

    // Query balance for CPUNK token
    cellframe_rpc_response_t *response = nullptr;
    if (cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response) == 0 && response->result) {
        json_object *jresult = response->result;

        if (json_object_is_type(jresult, json_type_array) && json_object_array_length(jresult) > 0) {
            json_object *first = json_object_array_get_idx(jresult, 0);
            if (json_object_is_type(first, json_type_array) && json_object_array_length(first) > 0) {
                json_object *wallet_obj = json_object_array_get_idx(first, 0);
                json_object *tokens_obj = nullptr;

                if (json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                    int token_count = json_object_array_length(tokens_obj);

                    for (int i = 0; i < token_count; i++) {
                        json_object *token_entry = json_object_array_get_idx(tokens_obj, i);
                        json_object *token_info_obj = nullptr;
                        json_object *coins_obj = nullptr;

                        // Get coins from top level
                        if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                            printf("[Wallet] Token %d: No 'coins' field, skipping\n", i);
                            continue;
                        }

                        // Get ticker from nested "token" object
                        if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                            printf("[Wallet] Token %d: No 'token' object, skipping\n", i);
                            continue;
                        }

                        json_object *ticker_obj = nullptr;
                        if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                            const char *ticker = json_object_get_string(ticker_obj);
                            const char *coins = json_object_get_string(coins_obj);

                            state.token_balances[ticker] = coins;
                            printf("[Wallet] %s: %s\n", ticker, coins);
                        } else {
                            printf("[Wallet] Token %d: No 'ticker' field in token object\n", i);
                        }
                    }
                }
            }
        }

        if (response) {
            cellframe_rpc_response_free(response);
        }
    }

    // Also query CELL and KEL (on different networks if needed)
    // For now, assume they're all on Backbone network
}

std::string DNAMessengerApp::formatBalance(const std::string& coins) {
    if (coins.empty() || coins == "0") {
        return "0.00";
    }

    // Try to parse as double
    try {
        double value = std::stod(coins);

        // Format with 2 decimals for large amounts, 8 for small amounts
        if (value >= 0.01) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%.2f", value);
            return std::string(buf);
        } else if (value > 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%.8f", value);
            return std::string(buf);
        }
        return "0.00";
    } catch (...) {
        return coins;  // Return as-is if parsing fails
    }
}

void DNAMessengerApp::buildAndSendTransaction() {
    state.send_status = "Checking wallet...";

    // Get wallet
    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets || state.current_wallet_index < 0) {
        state.send_status = "ERROR: No wallet loaded";
        return;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[state.current_wallet_index];

    // Check if address is available
    if (wallet->address[0] == '\0') {
        if (wallet->status == WALLET_STATUS_PROTECTED) {
            state.send_status = "ERROR: Wallet is password-protected. Cannot send from protected wallet.";
        } else {
            state.send_status = "ERROR: Could not generate wallet address. Wallet may be corrupted.";
        }
        return;
    }

    char address[WALLET_ADDRESS_MAX];
    strncpy(address, wallet->address, WALLET_ADDRESS_MAX - 1);
    address[WALLET_ADDRESS_MAX - 1] = '\0';

    state.send_status = "Querying UTXOs...";

    // Get parameters
    const char *amount_str = state.send_amount;
    const char *fee_str = state.send_fee;
    const char *recipient = state.send_recipient;

    // Parse amounts
    uint256_t amount, fee;
    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        state.send_status = "ERROR: Failed to parse amount";
        return;
    }

    if (cellframe_uint256_from_str(fee_str, &fee) != 0) {
        state.send_status = "ERROR: Failed to parse fee";
        return;
    }

    // STEP 1: Query UTXOs
    utxo_t *selected_utxos = NULL;
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;

    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    cellframe_rpc_response_t *utxo_resp = NULL;
    if (cellframe_rpc_get_utxo("Backbone", address, "CELL", &utxo_resp) == 0 && utxo_resp) {
        if (utxo_resp->result) {
            // Parse UTXO response: result[0][0]["outs"][]
            if (json_object_is_type(utxo_resp->result, json_type_array) &&
                json_object_array_length(utxo_resp->result) > 0) {

                json_object *first_array = json_object_array_get_idx(utxo_resp->result, 0);
                if (first_array && json_object_is_type(first_array, json_type_array) &&
                    json_object_array_length(first_array) > 0) {

                    json_object *first_item = json_object_array_get_idx(first_array, 0);
                    json_object *outs_obj = NULL;

                    if (first_item && json_object_object_get_ex(first_item, "outs", &outs_obj) &&
                        json_object_is_type(outs_obj, json_type_array)) {

                        int num_utxos = json_object_array_length(outs_obj);
                        if (num_utxos == 0) {
                            state.send_status = "ERROR: No UTXOs available";
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        // Parse all UTXOs
                        utxo_t *all_utxos = (utxo_t*)malloc(sizeof(utxo_t) * num_utxos);
                        int valid_utxos = 0;

                        for (int i = 0; i < num_utxos; i++) {
                            json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
                            json_object *jhash = NULL, *jidx = NULL, *jvalue = NULL;

                            if (utxo_obj &&
                                json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
                                json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
                                json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

                                const char *hash_str = json_object_get_string(jhash);
                                const char *value_str = json_object_get_string(jvalue);

                                // Parse hash
                                if (hash_str && strlen(hash_str) >= 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
                                    for (int j = 0; j < 32; j++) {
                                        sscanf(hash_str + 2 + (j * 2), "%2hhx", &all_utxos[valid_utxos].hash.raw[j]);
                                    }
                                    all_utxos[valid_utxos].idx = json_object_get_int(jidx);
                                    cellframe_uint256_from_str(value_str, &all_utxos[valid_utxos].value);
                                    valid_utxos++;
                                }
                            }
                        }

                        if (valid_utxos == 0) {
                            state.send_status = "ERROR: No valid UTXOs";
                            free(all_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                        // Select UTXOs (greedy selection)
                        selected_utxos = (utxo_t*)malloc(sizeof(utxo_t) * valid_utxos);
                        for (int i = 0; i < valid_utxos; i++) {
                            selected_utxos[num_selected_utxos++] = all_utxos[i];
                            total_input_u64 += all_utxos[i].value.lo.lo;

                            if (total_input_u64 >= required_u64) {
                                break;
                            }
                        }

                        free(all_utxos);

                        // Check if we have enough
                        if (total_input_u64 < required_u64) {
                            char error_msg[256];
                            snprintf(error_msg, sizeof(error_msg),
                                    "ERROR: Insufficient funds. Need: %.6f CELL, Have: %.6f CELL",
                                    (double)required_u64 / 1e18, (double)total_input_u64 / 1e18);
                            state.send_status = std::string(error_msg);
                            free(selected_utxos);
                            cellframe_rpc_response_free(utxo_resp);
                            return;
                        }

                    } else {
                        state.send_status = "ERROR: Invalid UTXO response";
                        cellframe_rpc_response_free(utxo_resp);
                        return;
                    }
                } else {
                    state.send_status = "ERROR: Invalid UTXO response";
                    cellframe_rpc_response_free(utxo_resp);
                    return;
                }
            } else {
                state.send_status = "ERROR: Invalid UTXO response";
                cellframe_rpc_response_free(utxo_resp);
                return;
            }
        }
        cellframe_rpc_response_free(utxo_resp);
    } else {
        state.send_status = "ERROR: Failed to query UTXOs from RPC";
        return;
    }

    // STEP 2: Build transaction
    state.send_status = "Building transaction...";

    cellframe_tx_builder_t *builder = cellframe_tx_builder_new();
    if (!builder) {
        state.send_status = "ERROR: Failed to create builder";
        free(selected_utxos);
        return;
    }

    // Set timestamp
    uint64_t ts = (uint64_t)time(NULL);
    cellframe_tx_set_timestamp(builder, ts);

    // Parse recipient address from Base58
    cellframe_addr_t recipient_addr;
    size_t decoded_size = base58_decode(recipient, &recipient_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid recipient address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse network collector address
    cellframe_addr_t network_collector_addr;
    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, &network_collector_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid network collector address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Parse sender address (for change)
    cellframe_addr_t sender_addr;
    decoded_size = base58_decode(address, &sender_addr);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        state.send_status = "ERROR: Invalid sender address";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Calculate network fee
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    // Calculate change
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;

    // Add all IN items
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            state.send_status = "ERROR: Failed to add IN item";
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT item (recipient)
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        state.send_status = "ERROR: Failed to add recipient OUT";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (network fee collector)
    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        state.send_status = "ERROR: Failed to add network fee OUT";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Add OUT item (change) - only if change > 0
    if (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            state.send_status = "ERROR: Failed to add change OUT";
            free(selected_utxos);
            cellframe_tx_builder_free(builder);
            return;
        }
    }

    // Add OUT_COND item (validator fee)
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        state.send_status = "ERROR: Failed to add validator fee";
        free(selected_utxos);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Free selected UTXOs
    free(selected_utxos);

    // STEP 3: Sign transaction
    state.send_status = "Signing transaction...";


    // Get signing data
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        state.send_status = "ERROR: Failed to get transaction data";
        cellframe_tx_builder_free(builder);
        return;
    }


    // Sign transaction
    uint8_t *dap_sign = NULL;
    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                    wallet->private_key, wallet->private_key_size,
                                    wallet->public_key, wallet->public_key_size,
                                    &dap_sign, &dap_sign_size) != 0) {
        state.send_status = "ERROR: Failed to sign transaction";
        free((void*)tx_data);
        cellframe_tx_builder_free(builder);
        return;
    }

    // Free temporary signing data
    free((void*)tx_data);


    // Add signature to transaction
    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        state.send_status = "ERROR: Failed to add signature";
        free(dap_sign);
        cellframe_tx_builder_free(builder);
        return;
    }
    free(dap_sign);

    // STEP 4: Convert to JSON
    state.send_status = "Converting to JSON...";


    // Get complete signed transaction
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        state.send_status = "ERROR: Failed to get signed transaction";
        cellframe_tx_builder_free(builder);
        return;
    }

    // Convert to JSON
    char *json = NULL;
    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        state.send_status = "ERROR: Failed to convert to JSON";
        cellframe_tx_builder_free(builder);
        return;
    }


    // STEP 5: Submit to RPC
    state.send_status = "Submitting to RPC...";


    cellframe_rpc_response_t *submit_resp = NULL;
    if (cellframe_rpc_submit_tx("Backbone", "main", json, &submit_resp) == 0 && submit_resp) {
        printf("      Transaction submitted successfully!\n\n");

        std::string txHash = "N/A";
        bool txCreated = false;

        if (submit_resp->result) {
            const char *result_str = json_object_to_json_string_ext(submit_resp->result, JSON_C_TO_STRING_PRETTY);
            printf("=== RPC RESPONSE ===\n%s\n====================\n\n", result_str);

            // Response format: [ { "tx_create": true, "hash": "0x...", "total_items": 7 } ]
            if (json_object_is_type(submit_resp->result, json_type_array) &&
                json_object_array_length(submit_resp->result) > 0) {

                json_object *first_elem = json_object_array_get_idx(submit_resp->result, 0);
                if (first_elem) {
                    // Check tx_create status
                    json_object *jtx_create = NULL;
                    if (json_object_object_get_ex(first_elem, "tx_create", &jtx_create)) {
                        txCreated = json_object_get_boolean(jtx_create);
                    }

                    // Extract hash
                    json_object *jhash = NULL;
                    if (json_object_object_get_ex(first_elem, "hash", &jhash)) {
                        const char *tx_hash = json_object_get_string(jhash);
                        if (tx_hash) {
                            txHash = std::string(tx_hash);
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(submit_resp);

        // Check if transaction was actually created
        if (!txCreated) {
            state.send_status = "ERROR: Transaction failed to create. May indicate insufficient balance or network issues.";
            free(json);
            cellframe_tx_builder_free(builder);
            return;
        }

        // Success!
        char success_msg[512];
        snprintf(success_msg, sizeof(success_msg),
                "SUCCESS! Transaction submitted!\nHash: %s\nAmount: %s CELL\nExplorer: https://scan.cellframe.net/datum-details/%s?net=Backbone",
                txHash.c_str(), amount_str, txHash.c_str());
        state.send_status = std::string(success_msg);

    } else {
        state.send_status = "ERROR: Failed to submit transaction to RPC";
        free(json);
        cellframe_tx_builder_free(builder);
        return;
    }

    free(json);
    cellframe_tx_builder_free(builder);

}

void DNAMessengerApp::renderSendDialog() {
    if (!state.show_send_dialog) return;

    // Center the modal
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(550, 500), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Send Tokens", &state.show_send_dialog, ImGuiWindowFlags_NoResize)) {
        // Wallet name
        ImGui::Text(ICON_FA_WALLET " From: %s", state.wallet_name.c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Show balance
        auto it = state.token_balances.find("CELL");
        if (it != state.token_balances.end()) {
            std::string formatted = formatBalance(it->second);
            ImGui::TextDisabled("Available: %s CELL", formatted.c_str());
        } else {
            ImGui::TextDisabled("Available: 0.00 CELL");
        }
        ImGui::Spacing();

        // Recipient address
        ImGui::Text("To Address:");
        ImGui::PushItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        ImGui::InputText("##recipient", state.send_recipient, sizeof(state.send_recipient));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::Spacing();

        // Amount
        ImGui::Text("Amount:");
        ImGui::PushItemWidth(-120);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        ImGui::InputText("##amount", state.send_amount, sizeof(state.send_amount));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextDisabled("CELL");
        ImGui::SameLine();
        if (ImGui::Button("MAX", ImVec2(60, 0))) {
            // Calculate max amount (balance - fees)
            auto balance_it = state.token_balances.find("CELL");
            if (balance_it != state.token_balances.end()) {
                try {
                    double balance = std::stod(balance_it->second);
                    double fee = std::stod(state.send_fee);
                    double network_fee = 0.002;
                    double max_amount = balance - fee - network_fee;
                    if (max_amount > 0) {
                        snprintf(state.send_amount, sizeof(state.send_amount), "%.6f", max_amount);
                    }
                } catch (...) {}
            }
        }
        ImGui::Spacing();

        // Validator fee
        ImGui::Text("Validator Fee:");
        ImGui::PushItemWidth(-80);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        ImGui::InputText("##fee", state.send_fee, sizeof(state.send_fee));
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextDisabled("CELL");
        ImGui::Spacing();

        // Network fee (fixed, read-only)
        ImGui::TextDisabled("Network Fee: 0.002 CELL (fixed)");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Total
        try {
            double amount = std::stod(state.send_amount);
            double fee = std::stod(state.send_fee);
            double network_fee = 0.002;
            double total = amount + fee + network_fee;
            ImGui::Text("Total: %.6f CELL", total);
        } catch (...) {
            ImGui::TextDisabled("Total: (invalid amount)");
        }
        ImGui::Spacing();
        ImGui::Spacing();

        // Status message
        if (!state.send_status.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.3f, 1.0f));
            ImGui::TextWrapped("%s", state.send_status.c_str());
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }

        // Buttons
        float btn_width = 120.0f;
        float btn_spacing = (ImGui::GetContentRegionAvail().x - (btn_width * 2)) / 3.0f;

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + btn_spacing);
        if (ButtonDark(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, 40))) {
            buildAndSendTransaction();
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(btn_width, 40))) {
            state.show_send_dialog = false;
            state.send_status.clear();
        }

        ImGui::EndPopup();
    }

    // Open the modal if flag is set
    if (state.show_send_dialog && !ImGui::IsPopupOpen("Send Tokens")) {
        ImGui::OpenPopup("Send Tokens");
    }
}

void DNAMessengerApp::renderReceiveDialog() {
    if (!state.show_receive_dialog) return;

    // Center the modal
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Receive Tokens", &state.show_receive_dialog, ImGuiWindowFlags_NoResize)) {
        // Wallet name
        ImGui::Text(ICON_FA_WALLET " %s", state.wallet_name.c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Network (Backbone is the default)
        ImGui::TextDisabled("Network: Backbone");
        ImGui::Spacing();

        // Address label
        ImGui::Text("Your Wallet Address:");
        ImGui::Spacing();

        // Address input (read-only, monospace font)
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);  // Use default font (monospace would be better)
        ImGui::PushItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        ImGui::InputText("##address", state.wallet_address, sizeof(state.wallet_address),
                        ImGuiInputTextFlags_ReadOnly);
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::PopFont();

        ImGui::Spacing();

        // Copy button
        float btn_width = 200.0f;
        float btn_x = (ImGui::GetContentRegionAvail().x - btn_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + btn_x);

        if (state.address_copied) {
            // Show "Copied!" feedback
            if (ButtonDark(ICON_FA_CHECK " Copied!", ImVec2(btn_width, 40))) {
                // Button disabled
            }

            // Reset after 2 seconds
            state.address_copied_timer += io.DeltaTime;
            if (state.address_copied_timer >= 2.0f) {
                state.address_copied = false;
                state.address_copied_timer = 0.0f;
            }
        } else {
            if (ButtonDark(ICON_FA_CLIPBOARD " Copy Address", ImVec2(btn_width, 40))) {
                ImGui::SetClipboardText(state.wallet_address);
                state.address_copied = true;
                state.address_copied_timer = 0.0f;
            }
        }

        ImGui::Spacing();
        ImGui::Spacing();

        // QR Code placeholder
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - 200) * 0.5f);
        ImGui::BeginChild("##qr_placeholder", ImVec2(200, 200), true);
        ImGui::SetCursorPos(ImVec2(70, 90));
        ImGui::TextDisabled("QR Code");
        ImGui::SetCursorPos(ImVec2(50, 105));
        ImGui::TextDisabled("(Coming Soon)");
        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::Spacing();

        // Close button
        float close_btn_width = 150.0f;
        float close_btn_x = (ImGui::GetContentRegionAvail().x - close_btn_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + close_btn_x);

        if (ImGui::Button("Close", ImVec2(close_btn_width, 40))) {
            state.show_receive_dialog = false;
            state.address_copied = false;
        }

        ImGui::EndPopup();
    }

    // Open the modal if flag is set
    if (state.show_receive_dialog && !ImGui::IsPopupOpen("Receive Tokens")) {
        ImGui::OpenPopup("Receive Tokens");
    }
}


// Load transaction history from Cellframe RPC
void DNAMessengerApp::loadTransactionHistory() {
    state.transaction_list.clear();
    state.transaction_history_loading = true;
    state.transaction_history_error.clear();

    wallet_list_t *wallets = (wallet_list_t*)state.wallet_list;
    if (!wallets || state.current_wallet_index < 0) {
        state.transaction_history_error = "No wallet loaded";
        state.transaction_history_loading = false;
        return;
    }

    // Get wallet address
    char address[WALLET_ADDRESS_MAX];
    if (wallet_get_address(&wallets->wallets[state.current_wallet_index], "Backbone", address) != 0) {
        state.transaction_history_error = "Failed to get wallet address";
        state.transaction_history_loading = false;
        return;
    }

    // Query transaction history via RPC
    json_object *args = json_object_new_object();
    json_object_object_add(args, "net", json_object_new_string("Backbone"));
    json_object_object_add(args, "addr", json_object_new_string(address));
    json_object_object_add(args, "chain", json_object_new_string("main"));

    cellframe_rpc_request_t req = {
        .method = "tx_history",
        .subcommand = "",
        .arguments = args,
        .id = 1
    };

    cellframe_rpc_response_t *response = nullptr;
    int ret = cellframe_rpc_call(&req, &response);
    json_object_put(args);

    if (ret == 0 && response && response->result) {
        json_object *jresult = response->result;

        // DEBUG: Print full RPC response
        const char *json_str = json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY);

        if (json_object_is_type(jresult, json_type_array)) {
            int result_len = json_object_array_length(jresult);

            if (result_len > 0) {
                json_object *tx_array = json_object_array_get_idx(jresult, 0);

                if (json_object_is_type(tx_array, json_type_array)) {
                    int array_len = json_object_array_length(tx_array);

                    // Skip first 2 items (query parameters), show ALL transactions
                    for (int i = 2; i < array_len; i++) {
                        json_object *tx_obj = json_object_array_get_idx(tx_array, i);

                        // DEBUG: Print each transaction object
                        const char *tx_json = json_object_to_json_string_ext(tx_obj, JSON_C_TO_STRING_PRETTY);

                        json_object *status_obj = nullptr;
                        if (!json_object_object_get_ex(tx_obj, "status", &status_obj)) {
                            continue;
                        }

                        json_object *hash_obj = nullptr, *timestamp_obj = nullptr, *data_obj = nullptr;
                        json_object_object_get_ex(tx_obj, "hash", &hash_obj);
                        json_object_object_get_ex(tx_obj, "tx_created", &timestamp_obj);
                        json_object_object_get_ex(tx_obj, "data", &data_obj);

                        std::string hash = hash_obj ? json_object_get_string(hash_obj) : "N/A";
                        std::string shortHash = hash.substr(0, 12) + "...";
                        std::string status = json_object_get_string(status_obj);

                        // Parse timestamp (smart formatting from Qt lines 143-154)
                        std::string timeStr = "Unknown";
                        if (timestamp_obj) {
                            const char *ts_str = json_object_get_string(timestamp_obj);
                            // Parse RFC2822 format timestamp (e.g., "Mon, 15 Oct 2024 14:30:00 GMT")
                            struct tm tm_time = {};
                            if (strptime(ts_str, "%a, %d %b %Y %H:%M:%S", &tm_time) != nullptr) {
                                time_t tx_time = mktime(&tm_time);
                                time_t now = time(nullptr);
                                int64_t diff = now - tx_time;

                                if (diff < 60) {
                                    timeStr = "Just now";
                                } else if (diff < 3600) {
                                    timeStr = std::to_string(diff / 60) + "m ago";
                                } else if (diff < 86400) {
                                    timeStr = std::to_string(diff / 3600) + "h ago";
                                } else if (diff < 86400 * 30) {
                                    timeStr = std::to_string(diff / 86400) + "d ago";
                                } else {
                                    char date_buf[64];
                                    strftime(date_buf, sizeof(date_buf), "%b %d, %Y", &tm_time);
                                    timeStr = date_buf;
                                }
                            }
                        }

                        // Parse transaction data (from Qt lines 158-217)
                        std::string direction = "received";
                        std::string amount = "0.00";
                        std::string token = "UNKNOWN";
                        std::string otherAddress = shortHash;

                        if (data_obj && json_object_is_type(data_obj, json_type_array)) {
                            int data_count = json_object_array_length(data_obj);
                            if (data_count > 0) {
                                json_object *first_data = json_object_array_get_idx(data_obj, 0);

                                json_object *tx_type_obj = nullptr, *token_obj = nullptr;
                                json_object *coins_obj = nullptr, *addr_obj = nullptr;

                                if (json_object_object_get_ex(first_data, "tx_type", &tx_type_obj)) {
                                    const char *tx_type_str = json_object_get_string(tx_type_obj);

                                    if (strcmp(tx_type_str, "recv") == 0) {
                                        direction = "received";
                                        if (json_object_object_get_ex(first_data, "recv_coins", &coins_obj)) {
                                            amount = json_object_get_string(coins_obj);
                                            // Smart decimal formatting (Qt lines 177-188)
                                            double amt = std::stod(amount);
                                            char formatted[64];
                                            if (amt < 0.01) {
                                                snprintf(formatted, sizeof(formatted), "%.8f", amt);
                                            } else if (amt < 1.0) {
                                                snprintf(formatted, sizeof(formatted), "%.4f", amt);
                                            } else {
                                                snprintf(formatted, sizeof(formatted), "%.2f", amt);
                                            }
                                            amount = formatted;
                                            // Remove trailing zeros
                                            while (amount.back() == '0') amount.pop_back();
                                            if (amount.back() == '.') amount.pop_back();
                                        }
                                        if (json_object_object_get_ex(first_data, "source_address", &addr_obj)) {
                                            std::string full_addr = json_object_get_string(addr_obj);
                                            otherAddress = full_addr.substr(0, 12) + "...";
                                        }
                                    } else if (strcmp(tx_type_str, "send") == 0) {
                                        direction = "sent";
                                        if (json_object_object_get_ex(first_data, "send_coins", &coins_obj)) {
                                            amount = json_object_get_string(coins_obj);
                                            // Smart decimal formatting (Qt lines 194-206)
                                            double amt = std::stod(amount);
                                            char formatted[64];
                                            if (amt < 0.01) {
                                                snprintf(formatted, sizeof(formatted), "%.8f", amt);
                                            } else if (amt < 1.0) {
                                                snprintf(formatted, sizeof(formatted), "%.4f", amt);
                                            } else {
                                                snprintf(formatted, sizeof(formatted), "%.2f", amt);
                                            }
                                            amount = formatted;
                                            // Remove trailing zeros
                                            while (amount.back() == '0') amount.pop_back();
                                            if (amount.back() == '.') amount.pop_back();
                                        }
                                        if (json_object_object_get_ex(first_data, "destination_address", &addr_obj)) {
                                            std::string full_addr = json_object_get_string(addr_obj);
                                            otherAddress = full_addr.substr(0, 12) + "...";
                                        }
                                    }

                                    if (json_object_object_get_ex(first_data, "token", &token_obj)) {
                                        token = json_object_get_string(token_obj);
                                    } else {
                                    }
                                } else {
                                }
                            }
                        } else {
                        }

                        // Add transaction to list
                        AppState::Transaction tx;
                        tx.direction = direction;
                        tx.amount = amount;
                        tx.token = token;
                        tx.address = otherAddress;
                        tx.time = timeStr;
                        tx.status = status;
                        tx.is_declined = (status.find("DECLINED") != std::string::npos);

                               i-2, direction.c_str(), amount.c_str(), token.c_str(),
                               otherAddress.c_str(), status.c_str(), timeStr.c_str());

                        state.transaction_list.push_back(tx);
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    } else {
        state.transaction_history_error = "Failed to load transaction history";
    }

    state.transaction_history_loading = false;
}

// Render transaction history dialog
void DNAMessengerApp::renderTransactionHistoryDialog() {
    if (!state.show_transaction_history) return;

    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Transaction History")) {
        ImGui::OpenPopup("Transaction History");
        loadTransactionHistory();
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = (io.DisplaySize.x < 600);

    ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x : 700, is_mobile ? io.DisplaySize.y : 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Transaction History", &state.show_transaction_history, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(io.Fonts->Fonts[2]); // Title font
        ImGui::Text("Transaction History - %s", state.wallet_name.c_str());
        ImGui::PopFont();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable transaction list
        ImGui::BeginChild("TransactionList", ImVec2(0, -50), true);

        if (state.transaction_history_loading) {
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Loading transactions...");
        } else if (!state.transaction_history_error.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", state.transaction_history_error.c_str());
        } else if (state.transaction_list.empty()) {
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "No transactions found");
        } else {
            // Display all transactions
            for (size_t i = 0; i < state.transaction_list.size(); i++) {
                const auto& tx = state.transaction_list[i];

                ImGui::PushID(i);
                ImGui::BeginGroup();

                // Transaction item (similar to Qt createTransactionItem)
                float item_height = 60.0f;
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();

                // Background
                ImU32 bg_color = IM_COL32(30, 30, 35, 255);
                draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + item_height), bg_color, 4.0f);

                ImGui::Dummy(ImVec2(0, 5));
                ImGui::Indent(10);

                // Direction icon (Qt lines 252-259)
                ImGui::PushFont(io.Fonts->Fonts[2]); // Large font for icon
                if (tx.direction == "sent") {
                    ImGui::TextColored(ImVec4(1.0f, 0.27f, 0.27f, 1.0f), ICON_FA_ARROW_UP); // Red arrow up
                } else {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), ICON_FA_ARROW_DOWN); // Green arrow down
                }
                ImGui::PopFont();
                ImGui::SameLine();

                // Transaction info
                ImGui::BeginGroup();
                ImGui::PushFont(io.Fonts->Fonts[1]); // Bold font
                ImGui::Text("%s %s", tx.amount.c_str(), tx.token.c_str());
                ImGui::PopFont();
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", tx.address.c_str());
                ImGui::EndGroup();

                // Time and status (right-aligned)
                ImGui::SameLine(ImGui::GetContentRegionAvail().x - 120);
                ImGui::BeginGroup();
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", tx.time.c_str());
                if (tx.is_declined) {
                    ImGui::TextColored(ImVec4(1.0f, 0.27f, 0.27f, 1.0f), "%s", tx.status.c_str()); // Red for DECLINED
                } else {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", tx.status.c_str()); // Green for ACCEPTED
                }
                ImGui::EndGroup();

                ImGui::Unindent(10);
                ImGui::Dummy(ImVec2(0, 5));

                ImGui::EndGroup();
                ImGui::PopID();

                if (i < state.transaction_list.size() - 1) {
                    ImGui::Spacing();
                }
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Close button
        if (ButtonDark("Close", ImVec2(-1, 40))) {
            state.show_transaction_history = false;
        }

        ImGui::EndPopup();
    }
}


// ===== MESSAGE WALL DIALOG =====

// Format wall timestamp (from Qt MessageWallDialog.cpp lines 418-438)
std::string DNAMessengerApp::formatWallTimestamp(uint64_t timestamp) {
    time_t now = time(nullptr);
    int64_t secondsAgo = now - (time_t)timestamp;

    if (secondsAgo < 60) {
        return "Just now";
    } else if (secondsAgo < 3600) {
        int minutes = secondsAgo / 60;
        return std::to_string(minutes) + " min" + (minutes > 1 ? "s" : "") + " ago";
    } else if (secondsAgo < 86400) {
        int hours = secondsAgo / 3600;
        return std::to_string(hours) + " hour" + (hours > 1 ? "s" : "") + " ago";
    } else if (secondsAgo < 604800) {
        int days = secondsAgo / 86400;
        return std::to_string(days) + " day" + (days > 1 ? "s" : "") + " ago";
    } else {
        char buf[64];
        struct tm *tm_info = localtime((time_t*)&timestamp);
        strftime(buf, sizeof(buf), "%b %d, %Y", tm_info);
        return std::string(buf);
    }
}

// Load message wall from DHT (from Qt MessageWallDialog.cpp lines 129-174)
void DNAMessengerApp::loadMessageWall() {
    state.wall_status = "Loading wall from DHT...";
    state.wall_loading = true;
    state.wall_messages.clear();

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.wall_status = "Error: DHT not available";
        state.wall_loading = false;
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.wall_status = "Error: DHT not available";
        state.wall_loading = false;
        return;
    }

    // Load wall from DHT
    dna_message_wall_t *wall = nullptr;
    int ret = dna_load_wall(dht_ctx, state.wall_fingerprint.c_str(), &wall);

    if (ret == -2) {
        state.wall_status = "No messages yet. Be the first to post!";
        state.wall_loading = false;
        return;
    } else if (ret != 0) {
        state.wall_status = "Error loading wall from DHT";
        state.wall_loading = false;
        return;
    }

    // Display messages
    if (wall && wall->message_count > 0) {
        for (size_t i = 0; i < wall->message_count; i++) {
            const dna_wall_message_t *msg = &wall->messages[i];
            AppState::WallMessage wall_msg;
            wall_msg.timestamp = msg->timestamp;
            wall_msg.text = msg->text;
            wall_msg.verified = true;  // TODO: Implement signature verification
            state.wall_messages.push_back(wall_msg);
        }
        state.wall_status = "Loaded " + std::to_string(wall->message_count) + " messages";
    } else {
        state.wall_status = "No messages yet. Be the first to post!";
    }

    if (wall) {
        dna_message_wall_free(wall);
    }

    state.wall_loading = false;
}

// Post to message wall (from Qt MessageWallDialog.cpp lines 242-315)
void DNAMessengerApp::postToMessageWall() {
    std::string messageText = std::string(state.wall_message_input);

    // Trim whitespace
    while (!messageText.empty() && isspace(messageText.front())) messageText.erase(0, 1);
    while (!messageText.empty() && isspace(messageText.back())) messageText.pop_back();

    if (messageText.empty()) {
        state.wall_status = "Error: Message is empty";
        return;
    }

    if (messageText.length() > 1024) {
        state.wall_status = "Error: Message exceeds 1024 characters";
        return;
    }

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.wall_status = "Error: DHT not available";
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.wall_status = "Error: DHT not available";
        return;
    }

    // Load private key for signing
    const char *home_dir = qgp_platform_home_dir();
    if (!home_dir) {
        state.wall_status = "Error: Failed to get home directory";
        return;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home_dir, ctx->identity);

    qgp_key_t *key = nullptr;
    int ret = qgp_key_load(key_path, &key);
    if (ret != 0 || !key) {
        state.wall_status = "Error: Failed to load private key for signing";
        return;
    }

    // Post message to DHT
    state.wall_status = "Posting message...";

    ret = dna_post_to_wall(dht_ctx, state.wall_fingerprint.c_str(),
                           messageText.c_str(), key->private_key);

    qgp_key_free(key);

    if (ret != 0) {
        state.wall_status = "Error: Failed to post message to DHT";
        return;
    }

    // Success
    state.wall_status = "Message posted successfully!";
    memset(state.wall_message_input, 0, sizeof(state.wall_message_input));

    // Reload wall after 500ms
    // (In real implementation, would use async task)
    loadMessageWall();
}

// Render message wall dialog
void DNAMessengerApp::renderMessageWallDialog() {
    if (!state.show_message_wall) return;


    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Message Wall")) {
        ImGui::OpenPopup("Message Wall");
        loadMessageWall();
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = (io.DisplaySize.x < 600);

    ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x : 700, is_mobile ? io.DisplaySize.y : 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Message Wall", &state.show_message_wall, ImGuiWindowFlags_NoResize)) {
        // Title
        ImGui::PushFont(io.Fonts->Fonts[2]);
        ImGui::Text(ICON_FA_CLIPBOARD " Message Wall: %s", state.wall_display_name.c_str());
        ImGui::PopFont();

        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100);
        if (ButtonDark(ICON_FA_ROTATE " Refresh", ImVec2(100, 30))) {
            loadMessageWall();
        }

        ImGui::Spacing();

        // Status label
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", state.wall_status.c_str());

        ImGui::Separator();
        ImGui::Spacing();

        // Message list
        ImGui::BeginChild("WallMessages", ImVec2(0, state.wall_is_own ? -200 : -50), true);

        if (state.wall_loading) {
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Loading messages...");
        } else if (state.wall_messages.empty()) {
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "No messages yet. Be the first to post!");
        } else {
            for (size_t i = 0; i < state.wall_messages.size(); i++) {
                const auto& msg = state.wall_messages[i];

                ImGui::PushID(i);
                ImGui::BeginGroup();

                // Background
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();
                float item_height = 80.0f;
                ImU32 bg_color = IM_COL32(30, 30, 35, 255);
                draw_list->AddRectFilled(cursor_pos, ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + item_height), bg_color, 4.0f);

                ImGui::Dummy(ImVec2(0, 5));
                ImGui::Indent(10);

                // Header: timestamp + verification
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", formatWallTimestamp(msg.timestamp).c_str());
                ImGui::SameLine();
                if (msg.verified) {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), ICON_FA_CHECK " Signed");
                }

                ImGui::Spacing();

                // Message text
                ImGui::TextWrapped("%s", msg.text.c_str());

                ImGui::Unindent(10);
                ImGui::Dummy(ImVec2(0, 5));

                ImGui::EndGroup();
                ImGui::PopID();

                if (i < state.wall_messages.size() - 1) {
                    ImGui::Spacing();
                }
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Post section (only if own wall)
        if (state.wall_is_own) {
            ImGui::Text(ICON_FA_PEN " Post New Message");
            ImGui::Spacing();

            // Message input (white text for visibility)
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputTextMultiline("##WallInput", state.wall_message_input, sizeof(state.wall_message_input),
                                     ImVec2(-1, 80), ImGuiInputTextFlags_None);
            ImGui::PopStyleColor();

            // Character counter
            int len = strlen(state.wall_message_input);
            ImGui::Text("%d / 1024", len);
            ImGui::SameLine();

            // Post button
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 150);
            if (ButtonDark(ICON_FA_PAPER_PLANE " Post Message", ImVec2(150, 35))) {
                postToMessageWall();
            }
        } else {
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), ICON_FA_CIRCLE_INFO " This is %s's public message wall (read-only)", state.wall_display_name.c_str());
        }

        ImGui::Spacing();

        // Close button
        if (ButtonDark("Close", ImVec2(-1, 40))) {
            state.show_message_wall = false;
        }

        ImGui::EndPopup();
    }
}


// ===== PROFILE EDITOR DIALOG =====

// Load profile from DHT (from Qt ProfileEditorDialog.cpp lines 289-381)
void DNAMessengerApp::loadProfile() {
    state.profile_status = "Loading profile from DHT...";
    state.profile_loading = true;

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.profile_status = "P2P transport not initialized";
        state.profile_registered_name = "N/A (DHT not connected)";
        state.profile_loading = false;
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.profile_status = "DHT not connected";
        state.profile_registered_name = "N/A (DHT not connected)";
        state.profile_loading = false;
        return;
    }

    // Load profile from DHT
    dna_unified_identity_t *profile = nullptr;
    int ret = dna_load_identity(dht_ctx, ctx->fingerprint, &profile);

    if (ret == 0 && profile) {
        // Display registered name
        if (profile->registered_name && strlen(profile->registered_name) > 0) {
            state.profile_registered_name = std::string(profile->registered_name);
        } else {
            state.profile_registered_name = "Not registered";
        }

        // Load wallet addresses
        if (profile->wallets.backbone[0] != '\0') strncpy(state.profile_backbone, profile->wallets.backbone, sizeof(state.profile_backbone) - 1);
        if (profile->wallets.kelvpn[0] != '\0') strncpy(state.profile_kelvpn, profile->wallets.kelvpn, sizeof(state.profile_kelvpn) - 1);
        if (profile->wallets.subzero[0] != '\0') strncpy(state.profile_subzero, profile->wallets.subzero, sizeof(state.profile_subzero) - 1);
        if (profile->wallets.cpunk_testnet[0] != '\0') strncpy(state.profile_testnet, profile->wallets.cpunk_testnet, sizeof(state.profile_testnet) - 1);
        if (profile->wallets.btc[0] != '\0') strncpy(state.profile_btc, profile->wallets.btc, sizeof(state.profile_btc) - 1);
        if (profile->wallets.eth[0] != '\0') strncpy(state.profile_eth, profile->wallets.eth, sizeof(state.profile_eth) - 1);
        if (profile->wallets.sol[0] != '\0') strncpy(state.profile_sol, profile->wallets.sol, sizeof(state.profile_sol) - 1);

        // Load social links
        if (profile->socials.telegram[0] != '\0') strncpy(state.profile_telegram, profile->socials.telegram, sizeof(state.profile_telegram) - 1);
        if (profile->socials.x[0] != '\0') strncpy(state.profile_twitter, profile->socials.x, sizeof(state.profile_twitter) - 1);
        if (profile->socials.github[0] != '\0') strncpy(state.profile_github, profile->socials.github, sizeof(state.profile_github) - 1);

        // Load profile picture CID
        if (profile->profile_picture_ipfs[0] != '\0') strncpy(state.profile_pic_cid, profile->profile_picture_ipfs, sizeof(state.profile_pic_cid) - 1);

        // Load bio
        if (profile->bio[0] != '\0') strncpy(state.profile_bio, profile->bio, sizeof(state.profile_bio) - 1);

        state.profile_status = "Profile loaded from DHT";
        dna_identity_free(profile);
    } else if (ret == -2) {
        state.profile_registered_name = "Not registered";
        state.profile_status = "No profile found. Create your first profile!";
    } else {
        state.profile_status = "Failed to load profile from DHT";
        state.profile_registered_name = "Error loading";
    }

    state.profile_loading = false;
}

// Save profile to DHT (from Qt ProfileEditorDialog.cpp lines 420-557)
void DNAMessengerApp::saveProfile() {
    state.profile_status = "Saving profile to DHT...";

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.profile_status = "P2P transport not initialized";
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.profile_status = "DHT not connected";
        return;
    }

    // Build profile data structure
    dna_profile_data_t profile_data = {0};

    // Wallet addresses
    if (state.profile_backbone[0]) strncpy(profile_data.wallets.backbone, state.profile_backbone, sizeof(profile_data.wallets.backbone) - 1);
    if (state.profile_kelvpn[0]) strncpy(profile_data.wallets.kelvpn, state.profile_kelvpn, sizeof(profile_data.wallets.kelvpn) - 1);
    if (state.profile_subzero[0]) strncpy(profile_data.wallets.subzero, state.profile_subzero, sizeof(profile_data.wallets.subzero) - 1);
    if (state.profile_testnet[0]) strncpy(profile_data.wallets.cpunk_testnet, state.profile_testnet, sizeof(profile_data.wallets.cpunk_testnet) - 1);
    if (state.profile_btc[0]) strncpy(profile_data.wallets.btc, state.profile_btc, sizeof(profile_data.wallets.btc) - 1);
    if (state.profile_eth[0]) strncpy(profile_data.wallets.eth, state.profile_eth, sizeof(profile_data.wallets.eth) - 1);
    if (state.profile_sol[0]) strncpy(profile_data.wallets.sol, state.profile_sol, sizeof(profile_data.wallets.sol) - 1);

    // Social links
    if (state.profile_telegram[0]) strncpy(profile_data.socials.telegram, state.profile_telegram, sizeof(profile_data.socials.telegram) - 1);
    if (state.profile_twitter[0]) strncpy(profile_data.socials.x, state.profile_twitter, sizeof(profile_data.socials.x) - 1);
    if (state.profile_github[0]) strncpy(profile_data.socials.github, state.profile_github, sizeof(profile_data.socials.github) - 1);

    // Profile picture CID
    if (state.profile_pic_cid[0]) strncpy(profile_data.profile_picture_ipfs, state.profile_pic_cid, sizeof(profile_data.profile_picture_ipfs) - 1);

    // Bio
    if (state.profile_bio[0]) strncpy(profile_data.bio, state.profile_bio, sizeof(profile_data.bio) - 1);

    // Load private key for signing
    const char *home = qgp_platform_home_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, ctx->identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        state.profile_status = "Failed to load private key for signing";
        return;
    }

    // Update profile in DHT
    int ret = dna_update_profile(dht_ctx, ctx->fingerprint, &profile_data, key->private_key);

    qgp_key_free(key);

    if (ret == 0) {
        state.profile_status = "Profile saved to DHT successfully!";
        state.show_profile_editor = false;
    } else {
        state.profile_status = "Failed to save profile to DHT";
    }
}

// Render profile editor dialog
void DNAMessengerApp::renderProfileEditorDialog() {
    if (!state.show_profile_editor) return;


    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Edit DNA Profile")) {
        ImGui::OpenPopup("Edit DNA Profile");
        loadProfile();
    }

    ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowSize(ImVec2(800, 700), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Edit DNA Profile", &state.show_profile_editor, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(io.Fonts->Fonts[2]);
        ImGui::Text("DNA Profile Editor");
        ImGui::PopFont();

        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Edit your public DNA profile. All changes are stored in the DHT.");
        ImGui::Spacing();

        ImGui::Text("Registered Name: %s", state.profile_registered_name.c_str());
        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable form
        ImGui::BeginChild("ProfileForm", ImVec2(0, -80), true);

        // Cellframe Network Addresses
        if (ImGui::CollapsingHeader("Cellframe Network Addresses", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputText("Backbone", state.profile_backbone, sizeof(state.profile_backbone));
            ImGui::InputText("KelVPN", state.profile_kelvpn, sizeof(state.profile_kelvpn));
            ImGui::InputText("Subzero", state.profile_subzero, sizeof(state.profile_subzero));
            ImGui::InputText("Millixt", state.profile_millixt, sizeof(state.profile_millixt));
            ImGui::InputText("Testnet", state.profile_testnet, sizeof(state.profile_testnet));
            ImGui::PopStyleColor();
        }

        // External Wallet Addresses
        if (ImGui::CollapsingHeader("External Wallet Addresses")) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputText("Bitcoin (BTC)", state.profile_btc, sizeof(state.profile_btc));
            ImGui::InputText("Ethereum (ETH)", state.profile_eth, sizeof(state.profile_eth));
            ImGui::InputText("Solana (SOL)", state.profile_sol, sizeof(state.profile_sol));
            ImGui::InputText("Litecoin (LTC)", state.profile_ltc, sizeof(state.profile_ltc));
            ImGui::InputText("Dogecoin (DOGE)", state.profile_doge, sizeof(state.profile_doge));
            ImGui::PopStyleColor();
        }

        // Social Media Links
        if (ImGui::CollapsingHeader("Social Media Links")) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputText("Telegram", state.profile_telegram, sizeof(state.profile_telegram));
            ImGui::InputText("X (Twitter)", state.profile_twitter, sizeof(state.profile_twitter));
            ImGui::InputText("GitHub", state.profile_github, sizeof(state.profile_github));
            ImGui::InputText("Discord", state.profile_discord, sizeof(state.profile_discord));
            ImGui::InputText("Website", state.profile_website, sizeof(state.profile_website));
            ImGui::PopStyleColor();
        }

        // Profile Picture
        if (ImGui::CollapsingHeader("Profile Picture")) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputText("IPFS CID", state.profile_pic_cid, sizeof(state.profile_pic_cid));
            ImGui::PopStyleColor();
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Upload your profile picture to IPFS and paste the CID here.");
        }

        // Bio
        if (ImGui::CollapsingHeader("Bio", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            ImGui::InputTextMultiline("##Bio", state.profile_bio, sizeof(state.profile_bio), ImVec2(-1, 100));
            ImGui::PopStyleColor();
            ImGui::Text("%zu / 512", strlen(state.profile_bio));
        }

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", state.profile_status.c_str());
        ImGui::Spacing();

        // Buttons
        if (ButtonDark("Cancel", ImVec2(100, 40))) {
            state.show_profile_editor = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        if (ButtonDark(ICON_FA_FLOPPY_DISK " Save Profile to DHT", ImVec2(200, 40))) {
            saveProfile();
        }

        ImGui::EndPopup();
    }
}


// ===== REGISTER DNA NAME DIALOG =====

// Check name availability (from Qt RegisterDNANameDialog.cpp lines 212-249)
void DNAMessengerApp::checkNameAvailability() {
    std::string name = std::string(state.register_name_input);

    // Trim
    while (!name.empty() && isspace(name.front())) name.erase(0, 1);
    while (!name.empty() && isspace(name.back())) name.pop_back();

    // Convert to lowercase
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    if (name.empty() || name.length() < 3 || name.length() > 20) {
        state.register_name_availability = "Invalid name (3-20 chars, alphanumeric + underscore only)";
        state.register_name_available = false;
        return;
    }

    // Validate characters
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            state.register_name_availability = "Invalid name (3-20 chars, alphanumeric + underscore only)";
            state.register_name_available = false;
            return;
        }
    }

    state.register_name_checking = true;

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.register_name_availability = "P2P transport not initialized";
        state.register_name_available = false;
        state.register_name_checking = false;
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.register_name_availability = "DHT not connected";
        state.register_name_available = false;
        state.register_name_checking = false;
        return;
    }

    // Query DHT for name
    dht_pubkey_entry_t *entry = NULL;
    int result = dht_keyserver_lookup(dht_ctx, name.c_str(), &entry);

    if (result == 0 && entry) {
        state.register_name_availability = "Name already registered";
        state.register_name_available = false;
        dht_keyserver_free_entry(entry);
    } else {
        state.register_name_availability = "Name available!";
        state.register_name_available = true;
    }

    state.register_name_checking = false;
}

// Register name (from Qt RegisterDNANameDialog.cpp lines 251-282)
void DNAMessengerApp::registerName() {
    std::string name = std::string(state.register_name_input);

    if (!state.register_name_available || name.empty()) {
        state.register_name_status = "Please enter a valid, available name.";
        return;
    }

    state.register_name_status = "Registering name...";

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    int result = messenger_register_name(ctx, ctx->fingerprint, name.c_str());

    if (result == 0) {
        state.register_name_status = "Name registered successfully!";
        state.show_register_name = false;
    } else {
        state.register_name_status = "Registration failed. Please try again.";
    }
}

// Render register name dialog
void DNAMessengerApp::renderRegisterNameDialog() {
    if (!state.show_register_name) return;


    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Register DNA Name")) {
        ImGui::OpenPopup("Register DNA Name");
    }

    ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowSize(ImVec2(600, 450), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Register DNA Name", &state.show_register_name, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(io.Fonts->Fonts[2]);
        ImGui::Text("Register DNA Name");
        ImGui::PopFont();

        ImGui::Spacing();
        ImGui::TextWrapped("Register a human-readable name for your identity. Others can find you by searching for this name.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Desired Name:");
        ImGui::SetNextItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        if (ImGui::InputText("##NameInput", state.register_name_input, sizeof(state.register_name_input))) {
            // Trigger availability check on text change
            checkNameAvailability();
        }
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // Availability status
        if (state.register_name_checking) {
            ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.0f, 1.0f), ICON_FA_SPINNER " Checking availability...");
        } else if (!state.register_name_availability.empty()) {
            if (state.register_name_available) {
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), ICON_FA_CHECK " %s", state.register_name_availability.c_str());
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), ICON_FA_XMARK " %s", state.register_name_availability.c_str());
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushFont(io.Fonts->Fonts[1]);
        ImGui::Text(ICON_FA_COINS " Cost: 1 CPUNK");
        ImGui::PopFont();
        ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.0f, 1.0f), ICON_FA_EXCLAMATION " Payment: Free for now (not yet implemented)");

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "%s", state.register_name_status.c_str());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Buttons
        if (ButtonDark("Cancel", ImVec2(100, 40))) {
            state.show_register_name = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        bool can_register = state.register_name_available && !state.register_name_checking && strlen(state.register_name_input) > 0;
        if (!can_register) {
            ImGui::BeginDisabled();
        }
        if (ButtonDark(ICON_FA_CHECK " Register Name (Free)", ImVec2(200, 40))) {
            registerName();
        }
        if (!can_register) {
            ImGui::EndDisabled();
        }

        ImGui::EndPopup();
    }
}


// Static method: Input filter callback for identity name
int DNAMessengerApp::IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
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
