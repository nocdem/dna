#include "contact_profile_viewer.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/dht_keyserver.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
}

#include <cstring>

namespace ContactProfileViewer {

// Load contact's profile from DHT
static void loadContactProfile(AppState& state) {
    state.profile_status = "Loading profile...";
    state.profile_loading = true;

    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !ctx->p2p_transport) {
        state.profile_status = "P2P transport not initialized";
        state.profile_loading = false;
        return;
    }

    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        state.profile_status = "DHT not connected";
        state.profile_loading = false;
        return;
    }

    // Load profile from DHT using contact's fingerprint
    dna_unified_identity_t *profile = nullptr;
    int ret = dna_load_identity(dht_ctx, state.viewed_profile_fingerprint.c_str(), &profile);

    if (ret == 0 && profile) {
        // Load registered name
        if (profile->registered_name && strlen(profile->registered_name) > 0) {
            state.profile_registered_name = std::string(profile->registered_name);
        } else {
            state.profile_registered_name = "";
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

        // Load bio
        if (profile->bio[0] != '\0') strncpy(state.profile_bio, profile->bio, sizeof(state.profile_bio) - 1);

        state.profile_status = "Profile loaded";
        dna_identity_free(profile);
    } else if (ret == -2) {
        state.profile_status = "No profile found";
    } else {
        state.profile_status = "Failed to load profile";
    }

    state.profile_loading = false;
}

void render(AppState& state) {
    if (!state.show_contact_profile) return;

    // Load profile on first show
    static std::string last_loaded_fingerprint = "";
    if (last_loaded_fingerprint != state.viewed_profile_fingerprint) {
        last_loaded_fingerprint = state.viewed_profile_fingerprint;

        // Clear previous profile data
        state.profile_registered_name = "";
        memset(state.profile_backbone, 0, sizeof(state.profile_backbone));
        memset(state.profile_kelvpn, 0, sizeof(state.profile_kelvpn));
        memset(state.profile_subzero, 0, sizeof(state.profile_subzero));
        memset(state.profile_testnet, 0, sizeof(state.profile_testnet));
        memset(state.profile_btc, 0, sizeof(state.profile_btc));
        memset(state.profile_eth, 0, sizeof(state.profile_eth));
        memset(state.profile_sol, 0, sizeof(state.profile_sol));
        memset(state.profile_telegram, 0, sizeof(state.profile_telegram));
        memset(state.profile_twitter, 0, sizeof(state.profile_twitter));
        memset(state.profile_github, 0, sizeof(state.profile_github));
        memset(state.profile_bio, 0, sizeof(state.profile_bio));

        loadContactProfile(state);
    }

    // Open popup
    if (!ImGui::IsPopupOpen("Contact Profile")) {
        ImGui::OpenPopup("Contact Profile");
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Contact Profile", &state.show_contact_profile, ImGuiWindowFlags_NoResize, true, false, 600)) {
        // Header

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Show loading spinner or content
        if (state.profile_loading) {
            ThemedSpinner("##profile_loading", 30.0f, 6.0f);
            ImGui::SameLine();
            ImGui::Text("Loading profile...");
        } else {
            ImGui::BeginChild("ProfileContent", ImVec2(0, -50), false);

            // Identity section
            ImGui::Text(ICON_FA_FINGERPRINT " Identity");
            ImGui::Separator();
            ImGui::Spacing();

            // DNA Name
            if (!state.profile_registered_name.empty()) {
                ImGui::Text("DNA Name:");
                ImGui::SameLine();
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(), "%s", state.profile_registered_name.c_str());
            }

            // Fingerprint
            ImGui::Text("Fingerprint:");
            ImGui::SameLine();
            std::string fp = state.viewed_profile_fingerprint;
            if (fp.length() > 23) {
                std::string shortened = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), "%s", shortened.c_str());
            } else {
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess(), "%s", fp.c_str());
            }

            ImGui::Spacing();
            ImGui::Spacing();

            // Bio section
            if (strlen(state.profile_bio) > 0) {
                ImGui::Text(ICON_FA_COMMENT " Bio");
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextWrapped("%s", state.profile_bio);
                ImGui::Spacing();
                ImGui::Spacing();
            }

            // Social Links section
            bool has_social = strlen(state.profile_telegram) > 0 || strlen(state.profile_twitter) > 0 ||
                            strlen(state.profile_github) > 0;

            if (has_social) {
                ImGui::Text(ICON_FA_LINK " Social Links");
                ImGui::Separator();
                ImGui::Spacing();

                if (strlen(state.profile_telegram) > 0) {
                    ImGui::BulletText("Telegram: %s", state.profile_telegram);
                }
                if (strlen(state.profile_twitter) > 0) {
                    ImGui::BulletText("Twitter/X: %s", state.profile_twitter);
                }
                if (strlen(state.profile_github) > 0) {
                    ImGui::BulletText("GitHub: %s", state.profile_github);
                }

                ImGui::Spacing();
                ImGui::Spacing();
            }

            // Crypto Addresses section
            bool has_addresses = strlen(state.profile_backbone) > 0 || strlen(state.profile_kelvpn) > 0 ||
                                strlen(state.profile_subzero) > 0 ||
                                strlen(state.profile_testnet) > 0 || strlen(state.profile_btc) > 0 ||
                                strlen(state.profile_eth) > 0 || strlen(state.profile_sol) > 0;

            if (has_addresses) {
                ImGui::Text(ICON_FA_WALLET " Crypto Addresses");
                ImGui::Separator();
                ImGui::Spacing();

                if (strlen(state.profile_backbone) > 0) {
                    ImGui::BulletText("CPUNK (Backbone): %s", state.profile_backbone);
                }
                if (strlen(state.profile_kelvpn) > 0) {
                    ImGui::BulletText("KEL (KelVPN): %s", state.profile_kelvpn);
                }
                if (strlen(state.profile_subzero) > 0) {
                    ImGui::BulletText("CELL (SubZero): %s", state.profile_subzero);
                }
                if (strlen(state.profile_testnet) > 0) {
                    ImGui::BulletText("CPUNK (Testnet): %s", state.profile_testnet);
                }
                if (strlen(state.profile_btc) > 0) {
                    ImGui::BulletText("BTC: %s", state.profile_btc);
                }
                if (strlen(state.profile_eth) > 0) {
                    ImGui::BulletText("ETH: %s", state.profile_eth);
                }
                if (strlen(state.profile_sol) > 0) {
                    ImGui::BulletText("SOL: %s", state.profile_sol);
                }

                ImGui::Spacing();
            }

            // Status message
            if (!state.profile_status.empty()) {
                ImGui::Spacing();
                ImGui::TextDisabled("%s", state.profile_status.c_str());
            }

            ImGui::EndChild();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Close button
        if (ThemedButton("Close", ImVec2(120, 40))) {
            state.show_contact_profile = false;
        }

        CenteredModal::End();
    }
}

} // namespace ContactProfileViewer
