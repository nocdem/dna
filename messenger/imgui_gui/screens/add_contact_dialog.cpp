#include "add_contact_dialog.h"
#include "../imgui.h"
#include "../modal_helper.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../../messenger.h"
#include "../../database/contacts_db.h"
#include "../../database/profile_manager.h"

#include <cstring>
#include <cstdio>

// External settings variable
extern AppSettings g_app_settings;

namespace AddContactDialog {

void render(AppState& state, std::function<void()> reload_contacts_callback) {
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
    ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
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

        state.contact_lookup_task.start([&state, input_copy, current_identity, ctx](AsyncTask* task) {
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
            reload_contacts_callback();

            // Auto-publish contacts to DHT (async, non-blocking)
            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (ctx) {
                state.dht_publish_task.start([ctx, fingerprint](AsyncTask* task) {
                    printf("[AddContact] Publishing contacts to DHT...\n");
                    messenger_sync_contacts_to_dht(ctx);
                    printf("[AddContact] [OK] Published to DHT\n");

                    // Fetch profile for new contact (cache for future use)
                    printf("[AddContact] Fetching profile for new contact...\n");
                    dht_profile_t profile;
                    int result = profile_manager_get_profile(fingerprint, &profile);
                    if (result == 0) {
                        printf("[AddContact] [OK] Profile cached: %s\n", profile.display_name);
                    } else if (result == -2) {
                        printf("[AddContact] No profile found in DHT (user hasn't published yet)\n");
                    } else {
                        printf("[AddContact] Warning: Failed to fetch profile\n");
                    }
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

} // namespace AddContactDialog
