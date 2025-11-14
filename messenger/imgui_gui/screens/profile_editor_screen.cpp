#include "profile_editor_screen.h"
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
    #include "../../crypto/utils/qgp_platform.h"
}

#include <cstring>

namespace ProfileEditorScreen {

// Load profile from DHT (from Qt ProfileEditorDialog.cpp lines 289-381)
void loadProfile(AppState& state) {
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
void saveProfile(AppState& state) {
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
void render(AppState& state) {
    if (!state.show_profile_editor) return;


    // Open popup on first show (MUST be before BeginPopupModal!)
    if (!ImGui::IsPopupOpen("Edit DNA Profile")) {
        ImGui::OpenPopup("Edit DNA Profile");
        loadProfile(state);
    }

    ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowSize(ImVec2(800, 700), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Edit DNA Profile", &state.show_profile_editor, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(io.Fonts->Fonts[2]);
        ImGui::Text("DNA Profile Editor");
        ImGui::PopFont();

        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "Edit your public DNA profile. All changes are stored in the DHT.");
        ImGui::Spacing();

        ImGui::Text("Registered Name: %s", state.profile_registered_name.c_str());
        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable form
        ImGui::BeginChild("ProfileForm", ImVec2(0, -80), true);

        // Cellframe Network Addresses
        if (ImGui::CollapsingHeader("Cellframe Network Addresses", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputText("Backbone", state.profile_backbone, sizeof(state.profile_backbone));
            ImGui::InputText("KelVPN", state.profile_kelvpn, sizeof(state.profile_kelvpn));
            ImGui::InputText("Subzero", state.profile_subzero, sizeof(state.profile_subzero));
            ImGui::InputText("Millixt", state.profile_millixt, sizeof(state.profile_millixt));
            ImGui::InputText("Testnet", state.profile_testnet, sizeof(state.profile_testnet));
            ImGui::PopStyleColor();
        }

        // External Wallet Addresses
        if (ImGui::CollapsingHeader("External Wallet Addresses")) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputText("Bitcoin (BTC)", state.profile_btc, sizeof(state.profile_btc));
            ImGui::InputText("Ethereum (ETH)", state.profile_eth, sizeof(state.profile_eth));
            ImGui::InputText("Solana (SOL)", state.profile_sol, sizeof(state.profile_sol));
            ImGui::InputText("Litecoin (LTC)", state.profile_ltc, sizeof(state.profile_ltc));
            ImGui::InputText("Dogecoin (DOGE)", state.profile_doge, sizeof(state.profile_doge));
            ImGui::PopStyleColor();
        }

        // Social Media Links
        if (ImGui::CollapsingHeader("Social Media Links")) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputText("Telegram", state.profile_telegram, sizeof(state.profile_telegram));
            ImGui::InputText("X (Twitter)", state.profile_twitter, sizeof(state.profile_twitter));
            ImGui::InputText("GitHub", state.profile_github, sizeof(state.profile_github));
            ImGui::InputText("Discord", state.profile_discord, sizeof(state.profile_discord));
            ImGui::InputText("Website", state.profile_website, sizeof(state.profile_website));
            ImGui::PopStyleColor();
        }

        // Profile Picture
        if (ImGui::CollapsingHeader("Profile Picture")) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputText("IPFS CID", state.profile_pic_cid, sizeof(state.profile_pic_cid));
            ImGui::PopStyleColor();
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "Upload your profile picture to IPFS and paste the CID here.");
        }

        // Bio
        if (ImGui::CollapsingHeader("Bio", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputTextMultiline("##Bio", state.profile_bio, sizeof(state.profile_bio), ImVec2(-1, 100));
            ImGui::PopStyleColor();
            ImGui::Text("%zu / 512", strlen(state.profile_bio));
        }

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", state.profile_status.c_str());
        ImGui::Spacing();

        // Buttons
        if (ButtonDark("Cancel", ImVec2(100, 40))) {
            state.show_profile_editor = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        if (ButtonDark(ICON_FA_FLOPPY_DISK " Save Profile to DHT", ImVec2(200, 40))) {
            saveProfile(state);
        }

        ImGui::EndPopup();
    }
}

} // namespace ProfileEditorScreen
