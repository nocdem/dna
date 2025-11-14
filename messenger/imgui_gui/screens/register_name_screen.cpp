#include "register_name_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../helpers/data_loader.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/dht_keyserver.h"
    #include "../../p2p/p2p_transport.h"
}
#include <algorithm>
#include <cctype>

namespace RegisterNameScreen {

// Check name availability (from Qt RegisterDNANameDialog.cpp lines 212-249)
void checkNameAvailability(AppState& state) {
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
void registerName(AppState& state) {
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

        // Update the registered name in app state
        state.profile_registered_name = name;

        // Refresh the registered name from DHT to ensure consistency
        DataLoader::fetchRegisteredName(state);

        state.show_register_name = false;
    } else {
        state.register_name_status = "Registration failed. Please try again.";
    }
}

// Render register name dialog
void render(AppState& state) {
    if (!state.show_register_name) return;

    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Register DNA")) {
        ImGui::OpenPopup("Register DNA");
    }

    ImGuiIO& io = ImGui::GetIO();


    if (CenteredModal::Begin("Register DNA", &state.show_register_name, ImGuiWindowFlags_NoResize)) {

        ImGui::Spacing();
        ImGui::TextWrapped("Register a human-readable name for your identity. Others can find you by searching for this name.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Desired Name:");
        ImGui::SetNextItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        if (ImGui::InputText("##NameInput", state.register_name_input, sizeof(state.register_name_input))) {
            // Trigger availability check on text change
            checkNameAvailability(state);
        }
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // Availability status
        if (state.register_name_checking) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextInfo() : ClubTheme::TextInfo(), ICON_FA_SPINNER " Checking availability...");
        } else if (!state.register_name_availability.empty()) {
            if (state.register_name_available) {
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), ICON_FA_CHECK " %s", state.register_name_availability.c_str());
            } else {
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), ICON_FA_XMARK " %s", state.register_name_availability.c_str());
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text(ICON_FA_COINS " Cost: 1 CPUNK");
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextInfo() : ClubTheme::TextInfo(), ICON_FA_EXCLAMATION " Payment: Free for now (not yet implemented)");

        ImGui::Spacing();
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", state.register_name_status.c_str());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Buttons
        if (ThemedButton("Cancel", ImVec2(100, 40))) {
            state.show_register_name = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        bool can_register = state.register_name_available && !state.register_name_checking && strlen(state.register_name_input) > 0;
        if (!can_register) {
            ImGui::BeginDisabled();
        }
        if (ThemedButton(ICON_FA_CHECK " Register DNA (Free)", ImVec2(200, 40))) {
            registerName(state);
        }
        if (!can_register) {
            ImGui::EndDisabled();
        }

        CenteredModal::End();
    }
}

} // namespace RegisterNameScreen
