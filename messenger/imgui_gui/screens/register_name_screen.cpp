#include "register_name_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../helpers/data_loader.h"
#include "../helpers/async_helpers.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/core/dht_keyserver.h"
    #include "../../p2p/p2p_transport.h"
}
#include <algorithm>
#include <cctype>

namespace RegisterNameScreen {

// Check name availability asynchronously (from Qt RegisterDNANameDialog.cpp lines 212-249)
void checkNameAvailability(AppState& state) {
    std::string name = std::string(state.register_name_input);

    // Trim
    while (!name.empty() && isspace(name.front())) name.erase(0, 1);
    while (!name.empty() && isspace(name.back())) name.pop_back();

    // Convert to lowercase
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    // Early validation (synchronous)
    if (name.empty() || name.length() < 3 || name.length() > 20) {
        state.register_name_availability = "Invalid name (3-20 chars, alphanumeric + underscore only)";
        state.register_name_available = false;
        state.register_name_checking = false;
        return;
    }

    // Validate characters
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            state.register_name_availability = "Invalid name (3-20 chars, alphanumeric + underscore only)";
            state.register_name_available = false;
            state.register_name_checking = false;
            return;
        }
    }

    // Start async DHT lookup
    state.register_name_checking = true;
    state.register_name_availability = "";
    
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    std::string name_copy = name;

    state.register_name_check_task.start([&state, ctx, name_copy](AsyncTask* task) {
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
        int result = dht_keyserver_lookup(dht_ctx, name_copy.c_str(), &entry);

        if (result == 0 && entry) {
            state.register_name_availability = "Name already registered";
            state.register_name_available = false;
            dht_keyserver_free_entry(entry);
        } else {
            state.register_name_availability = "Name available!";
            state.register_name_available = true;
        }

        state.register_name_checking = false;
    });
}

// Register name (from Qt RegisterDNANameDialog.cpp lines 251-282)
void registerName(AppState& state) {
    std::string name = std::string(state.register_name_input);

    if (!state.register_name_available || name.empty()) {
        state.register_name_status = "Please enter a valid, available name.";
        return;
    }

    // Start async registration task
    state.register_name_task.start([&state, name](AsyncTask* task) {
        messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
        
        task->addMessage("Registering name...");
        
        int result = messenger_register_name(ctx, ctx->fingerprint, name.c_str());
        
        if (result == 0) {
            task->addMessage("Name registered successfully!");
            
            // Update the registered name in app state
            state.profile_registered_name = name;
            
            // Update identity name cache so sidebar displays the new name immediately
            state.identity_name_cache[state.current_identity] = name;
            
            // Refresh the registered name from DHT to ensure consistency
            DataLoader::fetchRegisteredName(state);
            
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        } else {
            task->addMessage("Registration failed. Please try again.");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
}

// Render register name dialog
void render(AppState& state) {
    if (!state.show_register_name) return;

    // Clear state when opening modal
    static bool was_shown = false;
    static bool focus_set = false;
    if (!was_shown) {
        state.register_name_availability = "";
        state.register_name_available = false;
        state.register_name_checking = false;
        state.register_name_last_checked_input = "";
        state.register_name_status = "";
        memset(state.register_name_input, 0, sizeof(state.register_name_input));
        was_shown = true;
        focus_set = false;  // Reset focus flag when opening
    }

    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Register DNA")) {
        ImGui::OpenPopup("Register DNA");
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Register DNA", &state.show_register_name, ImGuiWindowFlags_NoResize, true, false, 500, 590)) {
        
        // Check if registration task completed
        if (state.register_name_task.isCompleted() && !state.register_name_task.isRunning()) {
            auto messages = state.register_name_task.getMessages();
            if (!messages.empty()) {
                if (messages.back().find("successfully") != std::string::npos) {
                    // Success - close after a moment
                    state.show_register_name = false;
                } else if (messages.back().find("failed") != std::string::npos) {
                    // Error occurred - show error message and allow retry
                    ImGui::Spacing();
                    ImGui::Spacing();
                    
                    // Center error icon and message
                    const char* error_msg = messages.back().c_str();
                    float text_width = ImGui::CalcTextSize(error_msg).x;
                    ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - text_width) * 0.5f);
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), 
                                      ICON_FA_CIRCLE_XMARK " %s", error_msg);
                    
                    ImGui::Spacing();
                    ImGui::Spacing();
                    
                    // Close button
                    float btn_width = 120.0f;
                    ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - btn_width) * 0.5f);
                    if (ThemedButton("Close", ImVec2(btn_width, 40))) {
                        state.show_register_name = false;
                    }
                    
                    CenteredModal::End();
                    return;
                }
            }
        }
        
        // Show spinner if task is running
        if (state.register_name_task.isRunning()) {
            ImGui::Spacing();
            ImGui::Spacing();
            
            // Center spinner using absolute positioning
            float window_width = ImGui::GetWindowWidth();
            float window_padding = ImGui::GetStyle().WindowPadding.x;
            float spinner_size = 50.0f;
            ImGui::SetCursorPosX((window_width - spinner_size) * 0.5f);
            ThemedSpinner("##regspinner", 25.0f, 4.0f);
            
            ImGui::Spacing();
            ImGui::Spacing();
            
            // Center status message
            auto messages = state.register_name_task.getMessages();
            if (!messages.empty()) {
                float text_width = ImGui::CalcTextSize(messages.back().c_str()).x;
                ImGui::SetCursorPosX((window_width - text_width) * 0.5f);
                ImGui::Text("%s", messages.back().c_str());
            }
            
            ImGui::Spacing();
            ImGui::Spacing();
            
            CenteredModal::End();
            return;
        }

        ImGui::Spacing();
        ImGui::TextWrapped("Register a human-readable name for your identity. Others can find you by searching for this name.");
        ImGui::Spacing();
        ImGui::Spacing();

        ImGui::Text("Desired Name:");
        ImGui::SetNextItemWidth(-1);
        
        // Autofocus on first render
        if (!focus_set) {
            ImGui::SetKeyboardFocusHere();
            focus_set = true;
        }
        
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        bool input_changed = ImGui::InputText("##NameInput", state.register_name_input, sizeof(state.register_name_input));
        ImGui::PopStyleColor();

        // Update timer when input changes
        if (input_changed) {
            state.register_name_last_input_time = (float)ImGui::GetTime();
            
            // Clear availability text if input is too short or empty
            std::string current_input = std::string(state.register_name_input);
            if (current_input.length() < 3) {
                state.register_name_availability = "";
                state.register_name_available = false;
                state.register_name_last_checked_input = "";
            }
        }

        // Check if we should auto-trigger availability check (debounced)
        std::string current_input = std::string(state.register_name_input);
        float time_since_last_input = (float)ImGui::GetTime() - state.register_name_last_input_time;
        bool should_auto_check = (
            current_input.length() >= 3 &&  // Minimum 3 characters
            time_since_last_input >= 0.5f &&  // 500ms debounce
            current_input != state.register_name_last_checked_input &&  // Haven't checked this yet
            !state.register_name_checking  // Not already checking
        );

        if (should_auto_check) {
            state.register_name_last_checked_input = current_input;
            checkNameAvailability(state);
        }

        ImGui::Spacing();

        // Availability status
        if (state.register_name_checking) {
            ImGui::AlignTextToFramePadding();
            ThemedSpinner("##check_spinner", 15.0f, 3.0f);
            ImGui::SameLine();
            ImGui::TextDisabled("Checking availability...");
        } else if (!state.register_name_availability.empty()) {
            if (state.register_name_available) {
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), ICON_FA_CIRCLE_CHECK " %s", state.register_name_availability.c_str());
            } else {
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), ICON_FA_CIRCLE_XMARK " %s", state.register_name_availability.c_str());
            }
        } else if (strlen(state.register_name_input) > 0 && strlen(state.register_name_input) < 3) {
            ImGui::TextDisabled("Type at least 3 characters");
        }

        ImGui::Spacing();
        ImGui::Spacing();

        ImGui::Text(ICON_FA_COINS " Cost: 1 CPUNK");
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextInfo() : ClubTheme::TextInfo(), ICON_FA_CIRCLE_INFO " Payment: Free for now (not yet implemented)");

        ImGui::Spacing();
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", state.register_name_status.c_str());

        ImGui::Spacing();
        ImGui::Spacing();

        // Buttons - properly aligned with equal spacing from edges
        float button_width_left = 100.0f;
        float button_width_right = 220.0f;
        float cursor_start_x = ImGui::GetCursorPosX();  // Get current cursor X (includes left padding)
        float available_width = ImGui::GetContentRegionAvail().x;
        
        // Left button starts at current cursor position (already has left padding)
        if (ThemedButton("Cancel", ImVec2(button_width_left, 40))) {
            state.show_register_name = false;
        }
        
        // Right button - position relative to cursor start, so it has same right padding as left padding
        ImGui::SameLine(cursor_start_x + available_width - button_width_right);
        bool can_register = state.register_name_available && !state.register_name_checking && strlen(state.register_name_input) > 0;
        if (!can_register) {
            ImGui::BeginDisabled();
        }
        if (ThemedButton(ICON_FA_CIRCLE_CHECK " Register DNA (Free)", ImVec2(button_width_right, 40))) {
            registerName(state);
        }
        if (!can_register) {
            ImGui::EndDisabled();
        }

        CenteredModal::End();
    } else {
        // Modal was closed, reset the flag
        was_shown = false;
    }
}

} // namespace RegisterNameScreen
