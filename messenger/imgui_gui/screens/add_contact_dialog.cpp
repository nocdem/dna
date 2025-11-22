#include "add_contact_dialog.h"
#include "../imgui.h"
#include "../modal_helper.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../texture_manager.h"
#include "../../messenger.h"
#include "../../database/contacts_db.h"
#include "../../database/profile_manager.h"
#include "../../dht/core/dht_keyserver.h"
#include "../../p2p/p2p_transport.h"

#include <cstring>
#include <cstdio>
#include <GLFW/glfw3.h>  // For GLuint

// External settings variable
extern AppSettings g_app_settings;

namespace AddContactDialog {

// Helper to clean up profile when closing dialog
static void cleanupProfile(AppState& state) {
    if (state.add_contact_profile) {
        dna_identity_free(state.add_contact_profile);
        state.add_contact_profile = nullptr;
    }
    state.add_contact_profile_loaded = false;
    state.add_contact_profile_loading = false;
}

void render(AppState& state, std::function<void()> reload_contacts_callback) {
    if (!CenteredModal::Begin("Add Contact", &state.show_add_contact_dialog, ImGuiWindowFlags_NoResize, true, false, 450, 590)) {
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();

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
        state.add_contact_profile_loaded = false;
        state.add_contact_profile_loading = false;
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
                state.add_contact_profile_loaded = false;
                state.add_contact_profile_loading = false;
                task->addMessage("Cannot add self");
                return;
            }

            // Check if contact already exists by fingerprint
            if (contacts_db_exists(fingerprint)) {
                state.add_contact_error_message = "Contact already exists in your list";
                state.add_contact_lookup_in_progress = false;
                state.add_contact_found_name.clear();
                state.add_contact_found_fingerprint.clear();
                state.add_contact_profile_loaded = false;
                state.add_contact_profile_loading = false;
                task->addMessage("Already exists");
                return;
            }

            // Success - store results
            state.add_contact_found_fingerprint = std::string(fingerprint);
            state.add_contact_found_name = input_copy;
            state.add_contact_lookup_in_progress = false;

            // Fetch profile for found contact using dna_load_identity
            state.add_contact_profile_loading = true;
            state.add_contact_profile_loaded = false;
            
            // Free previous profile if exists
            if (state.add_contact_profile) {
                dna_identity_free(state.add_contact_profile);
                state.add_contact_profile = nullptr;
            }
            
            // Get DHT context
            messenger_context_t *msg_ctx = (messenger_context_t*)state.messenger_ctx;
            dht_context_t *dht_ctx = nullptr;
            if (msg_ctx && msg_ctx->p2p_transport) {
                dht_ctx = p2p_transport_get_dht_context(msg_ctx->p2p_transport);
            }
            
            if (dht_ctx) {
                int profile_result = dna_load_identity(dht_ctx, fingerprint, &state.add_contact_profile);
                if (profile_result == 0 && state.add_contact_profile) {
                    state.add_contact_profile_loaded = true;
                    printf("[AddContact] Profile loaded for %s\n", fingerprint);
                    if (state.add_contact_profile->bio[0] != '\0') {
                        printf("[AddContact] Bio: %s\n", state.add_contact_profile->bio);
                    }
                } else if (profile_result == -2) {
                    printf("[AddContact] No profile found for this user\n");
                } else {
                    printf("[AddContact] Failed to load profile (error %d)\n", profile_result);
                }
            } else {
                printf("[AddContact] DHT context not available\n");
            }
            state.add_contact_profile_loading = false;

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
        ImGui::Text("%s %s", ICON_FA_CIRCLE_CHECK, state.add_contact_found_name.c_str());
        ImGui::PopStyleColor();
        ImGui::Spacing();

        // Show profile loading or loaded state
        if (state.add_contact_profile_loading) {
            ImGui::AlignTextToFramePadding();
            ThemedSpinner("##profile_spinner", 15.0f, 3.0f);
            ImGui::SameLine();
            ImGui::TextDisabled("Loading profile...");
            ImGui::Spacing();
        } else if (state.add_contact_profile_loaded && state.add_contact_profile) {
            // Display profile information with avatar and bio
            ImGui::Separator();
            ImGui::Spacing();
            
            // Show avatar if available (centered above bio)
            if (state.add_contact_profile->avatar_base64[0] != '\0') {
                float avatar_size = 96.0f;  // Match profile sidebar size
                float available_width = ImGui::GetContentRegionAvail().x;
                float avatar_center_x = (available_width - avatar_size) * 0.5f;
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avatar_center_x);
                
                // Load avatar texture
                int avatar_width = 0, avatar_height = 0;
                GLuint texture_id = TextureManager::getInstance().loadAvatar(
                    state.add_contact_found_fingerprint,
                    state.add_contact_profile->avatar_base64,
                    &avatar_width,
                    &avatar_height
                );
                
                if (texture_id != 0) {
                    // Draw the avatar as a simple image (no interaction needed)
                    ImVec2 avatar_pos = ImGui::GetCursorScreenPos();
                    ImDrawList* draw_list = ImGui::GetWindowDrawList();
                    
                    // Calculate center position for circular avatar
                    ImVec2 center = ImVec2(avatar_pos.x + avatar_size * 0.5f, avatar_pos.y + avatar_size * 0.5f);
                    float radius = avatar_size * 0.5f;
                    
                    // Draw circular avatar
                    draw_list->AddImageRounded((ImTextureID)(intptr_t)texture_id, avatar_pos, 
                                             ImVec2(avatar_pos.x + avatar_size, avatar_pos.y + avatar_size), 
                                             ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, radius);
                    
                    // Add subtle border
                    ImVec4 border_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                    ImU32 border_color = IM_COL32((int)(border_col.x * 255), (int)(border_col.y * 255), (int)(border_col.z * 255), 128);
                    draw_list->AddCircle(center, radius, border_color, 0, 1.0f);
                    
                    // Move cursor down past the avatar
                    ImGui::SetCursorScreenPos(ImVec2(avatar_pos.x, avatar_pos.y + avatar_size));
                    ImGui::Spacing();
                    ImGui::Spacing();
                } else {
                    // Avatar failed to load, show placeholder icon
                    ImVec4 placeholder_color = (g_app_settings.theme == 0) ? DNATheme::TextDisabled() : ClubTheme::TextDisabled();
                    ImGui::PushStyleColor(ImGuiCol_Text, placeholder_color);
                    ImGui::SetWindowFontScale(3.0f);  // Large icon
                    
                    // Center the placeholder icon
                    ImVec2 icon_size = ImGui::CalcTextSize(ICON_FA_USER);
                    float icon_center_x = (available_width - icon_size.x) * 0.5f;
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + icon_center_x);
                    ImGui::Text("%s", ICON_FA_USER);
                    
                    ImGui::SetWindowFontScale(1.0f);
                    ImGui::PopStyleColor();
                    ImGui::Spacing();
                }
            }
            
            // Show bio if available
            if (state.add_contact_profile->bio[0] != '\0') {
                ImGui::TextDisabled("Bio:");
                ImGui::PushTextWrapPos(0.0f);
                ImGui::TextWrapped("%s", state.add_contact_profile->bio);
                ImGui::PopTextWrapPos();
            } else {
                ImGui::TextDisabled("No bio available");
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
        } else {
            // No profile found
            ImGui::TextDisabled("No public profile available");
            ImGui::Spacing();
        }
    }

    // Show spinner if lookup in progress (inline with search hint)
    if (state.add_contact_lookup_in_progress) {
        ImGui::AlignTextToFramePadding();
        ThemedSpinner("##lookup_spinner", 15.0f, 3.0f);
        ImGui::SameLine();
        ImGui::TextDisabled("Searching...");
    } else if (input_len > 0 && input_len < 3) {
        ImGui::TextDisabled("Type at least 3 characters to search");
    }

    // Position buttons at bottom
    CenteredModal::BottomSection();

    // Buttons - properly aligned with equal spacing from edges
    float button_width_left = 100.0f;
    float button_width_right = 100.0f;
    float content_width = ImGui::GetContentRegionAvail().x;
    
    // Left button - starts at current cursor position
    if (ThemedButton("Cancel", ImVec2(button_width_left, 40))) {
        cleanupProfile(state);
        state.show_add_contact_dialog = false;
        CenteredModal::End();
        return;
    }
    
    // Right button - position to align with right edge of content region
    ImGui::SameLine(0.0f, content_width - button_width_left - button_width_right);
    
    // Save button (only enabled if contact found)
    ImGui::BeginDisabled(state.add_contact_found_fingerprint.empty());
    if (ThemedButton("Save", ImVec2(button_width_right, 40))) {
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
                    dna_unified_identity_t *identity = NULL;
                    int result = profile_manager_get_profile(fingerprint, &identity);
                    if (result == 0 && identity) {
                        printf("[AddContact] [OK] Profile cached: %s\n",
                               identity->display_name[0] ? identity->display_name : fingerprint);
                        dna_identity_free(identity);
                    } else if (result == -2) {
                        printf("[AddContact] No profile found in DHT (user hasn't published yet)\n");
                    } else {
                        printf("[AddContact] Warning: Failed to fetch profile\n");
                    }
                });
            }

            // Close dialog
            cleanupProfile(state);
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
