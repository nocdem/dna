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
#include <dirent.h>

// Backend includes
extern "C" {
    #include "../messenger.h"
    #include "../bip39.h"
    #include "../dht/dht_keyserver.h"
    #include "../dht/dht_singleton.h"
    #include "../qgp_types.h"  // For qgp_key_load, qgp_key_free
}

// Forward declaration for ApplyTheme (defined in main.cpp)
extern void ApplyTheme(int theme);
extern AppSettings g_app_settings;

// Method implementations will be moved here from app.h
// This file will contain all the inline method bodies

void DNAMessengerApp::render() {
    ImGuiIO& io = ImGui::GetIO();

    // Show loading spinner for 2 seconds on first launch
    if (state.is_first_frame) {
        if (state.loading_start_time == 0.0f) {
            state.loading_start_time = (float)ImGui::GetTime();
        }

        float elapsed = (float)ImGui::GetTime() - state.loading_start_time;

        if (elapsed < 2.0f) {
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("Loading", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse);

            // Center spinner (same size as DHT loading spinner for consistency)
            float spinner_size = 40.0f;
            ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
            ImGui::SetCursorPos(ImVec2(center.x - spinner_size, center.y - spinner_size));
            ThemedSpinner("##loading", spinner_size, 6.0f);

            // Loading text below spinner
            const char* loading_text = "Loading DNA Messenger...";
            ImVec2 text_size = ImGui::CalcTextSize(loading_text);
            ImGui::SetCursorPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_size + 20));
            ImGui::Text("%s", loading_text);

            ImGui::End();
            return;
        } else {
            // 2 seconds elapsed, mark as done
            state.is_first_frame = false;
        }
    }

    // Show identity selection on first run
    if (state.show_identity_selection) {
        renderIdentitySelection();
        return;
    }

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
    
    // Render operation spinner overlay (for async DHT operations)
    // This must be AFTER all other windows/modals so it's on top
    if (state.show_operation_spinner) {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0.7f)); // Semi-transparent background
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
        }
    }
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

    // Load identities on first render
    if (!state.identities_scanned) {
        scanIdentities();
        state.identities_scanned = true;  // Mark as scanned
        
        // Do DHT reverse lookups for names (synchronous for now, async in future)
        static bool lookups_done = false;
        if (!lookups_done) {
            lookups_done = true;
            
            dht_context_t *dht_ctx = dht_singleton_get();
            if (dht_ctx) {
                for (const auto& fp : state.identities) {
                    if (fp.length() == 128 && state.identity_name_cache.find(fp) == state.identity_name_cache.end()) {
                        // Try DHT reverse lookup to get registered name
                        char *registered_name = nullptr;
                        int ret = dht_keyserver_reverse_lookup(dht_ctx, fp.c_str(), &registered_name);
                        
                        if (ret == 0 && registered_name != nullptr) {
                            // Found registered name, cache it
                            printf("[Identity] DHT lookup: %s → %s\n", fp.substr(0, 16).c_str(), registered_name);
                            state.identity_name_cache[fp] = std::string(registered_name);
                            free(registered_name);
                        } else {
                            // Not registered or lookup failed, use shortened fingerprint
                            state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                        }
                    }
                }
            } else {
                // No DHT available, use shortened fingerprints
                for (const auto& fp : state.identities) {
                    if (fp.length() == 128 && state.identity_name_cache.find(fp) == state.identity_name_cache.end()) {
                        state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                    }
                }
            }
        }
    }

    // Identity list (reduce reserved space for buttons to prevent scrollbar)
    ImGui::BeginChild("IdentityList", ImVec2(0, is_mobile ? -180 : -140), true);

    if (state.identities.empty()) {
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
        state.restore_identity_step = RESTORE_STEP_NAME;
        memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
        memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
        ImGui::OpenPopup("Restore from Seed");
    }

    // Restore from seed popup
    if (CenteredModal::Begin("Restore from Seed")) {
        if (state.restore_identity_step == RESTORE_STEP_NAME) {
            renderRestoreStep1_Name();
        } else if (state.restore_identity_step == RESTORE_STEP_SEED) {
            renderRestoreStep2_Seed();
        }
        CenteredModal::End();
    }

        // Create identity popup - multi-step wizard (using CenteredModal helper)
        if (CenteredModal::Begin("Create New Identity")) {
            if (state.create_identity_step == STEP_NAME) {
                renderCreateIdentityStep1();
            } else if (state.create_identity_step == STEP_SEED_PHRASE) {
                renderCreateIdentityStep2();
            } else if (state.create_identity_step == STEP_CREATING) {
                renderCreateIdentityStep3();
            }

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

    bool enter_pressed = ImGui::InputText("##IdentityName", state.new_identity_name, sizeof(state.new_identity_name),
                    ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_EnterReturnsTrue, IdentityNameInputFilter);

    ImGui::PopStyleColor();

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
    float button_width = 120.0f;
    float spacing = 10.0f;
    float total_width = button_width * 2 + spacing;
    float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;

    if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);

    if (ButtonDark("Back", ImVec2(button_width, 40))) {
        state.create_identity_step = STEP_NAME;
    }
    ImGui::SameLine();

    ImGui::BeginDisabled(!state.seed_confirmed);
    if (ButtonDark("Create", ImVec2(button_width, 40))) {
        // Close ALL modals immediately
        ImGui::CloseCurrentPopup();
        
        // Hide identity selection so we proceed to main window (where spinner renders)
        state.show_identity_selection = false;
        
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
    state.show_identity_selection = false;
    
    // Load contacts for the new identity
    loadIdentity(fingerprint);
    
    // Reset wizard state
    memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
    state.seed_confirmed = false;
    // Modal already closed before async task started
    
    messenger_free(ctx);
    printf("[Identity] Identity created successfully\n");
    
    // Hide spinner (async task will finish)
    state.show_operation_spinner = false;
}


void DNAMessengerApp::renderRestoreStep1_Name() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    ImGui::Text("Restore Your Identity");
    ImGui::Spacing();
    ImGui::Spacing();

    ImGui::TextWrapped("Enter the identity name you used when creating this identity.");
    ImGui::Spacing();
    ImGui::TextWrapped("This should be the same name you used originally.");
    ImGui::Spacing();
    ImGui::Spacing();

    ImGui::Text("Identity Name:");
    ImGui::Spacing();

    // Style input like chat message input
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);

    ImGui::SetNextItemWidth(-1);
    bool enter_pressed = ImGui::InputText("##RestoreIdentityName", state.new_identity_name, sizeof(state.new_identity_name),
                    ImGuiInputTextFlags_EnterReturnsTrue);

    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::Spacing();

    float button_width = is_mobile ? -1 : 150.0f;

    if (ButtonDark("Cancel", ImVec2(button_width, 40)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        ImGui::CloseCurrentPopup();
    }

    if (!is_mobile) ImGui::SameLine();

    ImGui::BeginDisabled(strlen(state.new_identity_name) == 0);
    if (ButtonDark("Next", ImVec2(button_width, 40)) || enter_pressed) {
        state.restore_identity_step = RESTORE_STEP_SEED;
    }
    ImGui::EndDisabled();
}


void DNAMessengerApp::renderRestoreStep2_Seed() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;

    ImGui::TextWrapped("Enter Your 24-Word Seed Phrase");
    ImGui::Spacing();

    // Style input
    ImVec4 input_bg = g_app_settings.theme == 0
        ? ImVec4(0.12f, 0.14f, 0.16f, 1.0f)
        : ImVec4(0.15f, 0.14f, 0.13f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, input_bg);

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextMultiline("##RestoreSeedPhrase", state.generated_mnemonic, sizeof(state.generated_mnemonic),
                             ImVec2(-1, 200), ImGuiInputTextFlags_WordWrap);

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

    if (ButtonDark("Back", ImVec2(button_width, 40))) {
        state.restore_identity_step = RESTORE_STEP_NAME;
    }

    if (!is_mobile) ImGui::SameLine();

    ImGui::BeginDisabled(word_count != 24);
    if (ButtonDark("Restore", ImVec2(button_width, 40))) {
        restoreIdentityWithSeed(state.new_identity_name, state.generated_mnemonic);
    }
    ImGui::EndDisabled();
}


void DNAMessengerApp::restoreIdentityWithSeed(const char* name, const char* mnemonic) {
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
    if (bip39_validate_mnemonic(normalized.c_str()) != 0) {
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
    
    // Publish to DHT keyserver with name (if DHT is available)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx && strlen(name) > 0) {
        printf("[Identity] Publishing restored identity to DHT with name: %s\n", name);
        
        const char* home = getenv("HOME");
        if (home) {
            std::string dna_dir = std::string(home) + "/.dna";
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
                    printf("[Identity] ✓ Restored identity published to DHT successfully!\n");
                    // Cache the name mapping
                    state.identity_name_cache[std::string(fingerprint)] = name;
                } else {
                    printf("[Identity] ERROR: Failed to publish restored identity to DHT\n");
                }
            }
        }
    }
    
    // Keys are saved to ~/.dna/<fingerprint>.{dsa,kem}
    // Add to identity list
    state.identities.push_back(fingerprint);
    state.current_identity = fingerprint;
    state.identity_loaded = true;
    state.show_identity_selection = false;
    
    // Load identity state (contacts, etc)
    loadIdentity(fingerprint);
    
    // Cleanup
    messenger_free(ctx);
    
    // Reset UI state
    memset(state.new_identity_name, 0, sizeof(state.new_identity_name));
    memset(state.generated_mnemonic, 0, sizeof(state.generated_mnemonic));
    ImGui::CloseCurrentPopup();
    
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

    // TODO: Load message history for contacts from SQLite database
    // For now, message history will be empty

    state.identity_loaded = true;
    state.show_identity_selection = false;
    state.current_identity = identity;

    printf("[Identity] Identity loaded successfully: %s (%zu contacts)\n",
           identity.c_str(), state.contacts.size());
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
    printf("[DEBUG] ContactsList available width: %.1f, screen width: %.1f\n", full_width, io.DisplaySize.x);

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
            printf("[DEBUG] Contact button width: %.1f\n", button_width);
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

        // Format: "✓ Name" or "✗ Name" with colored icons
        const char* icon = state.contacts[i].is_online ? ICON_FA_CIRCLE_CHECK : ICON_FA_CIRCLE_XMARK;

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
            // Normal colors when not selected - use theme colors
            if (state.contacts[i].is_online) {
                ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
            } else {
                text_color = IM_COL32(100, 100, 100, 255);
            }
        }
        draw_list->AddText(text_pos, text_color, display_text);

        ImGui::PopID();
    }

    ImGui::EndChild(); // ContactList

    // Action buttons at bottom (40px each to match main buttons)
    float button_width = ImGui::GetContentRegionAvail().x;
    if (ThemedButton(ICON_FA_CIRCLE_PLUS " Add Contact", ImVec2(button_width, add_button_height), false)) {
        // TODO: Open add contact dialog
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
    const char* status_icon = contact.is_online ? ICON_FA_CHECK : ICON_FA_XMARK;
    ImVec4 icon_color;
    if (contact.is_online) {
        icon_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
    } else {
        icon_color = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
    }

    // Center text vertically in header
    float text_size_y = ImGui::CalcTextSize(contact.name.c_str()).y;
    float text_offset_y = (header_height - text_size_y) * 0.5f;
    ImGui::SetCursorPosY(text_offset_y);

    ImGui::TextColored(icon_color, "%s", status_icon);
    ImGui::SameLine();

    ImVec4 text_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
    if (!contact.is_online) {
        text_col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
    }
    ImGui::TextColored(text_col, "%s", contact.name.c_str());

    ImGui::EndChild();

    // Message area
    float input_height = is_mobile ? 100.0f : 80.0f;
    ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);

    // Get messages for current contact
    std::vector<Message>& messages = state.contact_messages[state.selected_contact];

    for (size_t i = 0; i < messages.size(); i++) {
        const auto& msg = messages[i];

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
    }

    // Auto-scroll to bottom
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);

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
    }
    state.should_focus_input = false; // Reset flag

    if (is_mobile) {
        // Mobile: stacked layout
        if (should_autofocus) {
            ImGui::SetKeyboardFocusHere();
        }
        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(-1, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine);

        // Send button with paper plane icon
        if (ButtonDark(ICON_FA_PAPER_PLANE, ImVec2(-1, 40)) || enter_pressed) {
            if (strlen(state.message_input) > 0) {
                Message msg;
                msg.content = state.message_input;
                msg.is_outgoing = true;
                msg.timestamp = "Now";
                messages.push_back(msg);
                state.message_input[0] = '\0';
                state.should_focus_input = true; // Set flag to refocus next frame
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

        bool enter_pressed = ImGui::InputTextMultiline("##MessageInput", state.message_input,
            sizeof(state.message_input), ImVec2(input_width, 60),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_CallbackAlways,
            input_callback, this);

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
            if (strlen(state.message_input) > 0) {
                Message msg;
                msg.content = state.message_input;
                msg.is_outgoing = true;
                msg.timestamp = "Now";
                messages.push_back(msg);
                state.message_input[0] = '\0';
                state.should_focus_input = true; // Set flag to refocus next frame
            }
        }
    }

    ImGui::PopStyleColor(); // FrameBg
}


void DNAMessengerApp::renderWalletView() {
    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600.0f;
    float padding = is_mobile ? 15.0f : 20.0f;

    ImGui::SetCursorPos(ImVec2(padding, padding));
    ImGui::BeginChild("WalletContent", ImVec2(-padding, -padding), false);

    // Header
    ImGui::Text(ICON_FA_WALLET " cpunk Wallet");
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
        ImGui::TextDisabled("%s", tokens[i]);

        ImGui::SetCursorPos(ImVec2(20, is_mobile ? 45 : 50));

        // Show spinner while loading (mockup - always show spinner)
        float spinner_size = is_mobile ? 10.0f : 12.0f;
        ThemedSpinner("##spinner", spinner_size, 2.0f);

        ImGui::SameLine();
        ImGui::Text("%s", balances[i]);

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
