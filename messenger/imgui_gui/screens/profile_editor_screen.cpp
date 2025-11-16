#include "profile_editor_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../texture_manager.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/core/dht_keyserver.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
    #include "../../crypto/utils/qgp_platform.h"
    #include "../../crypto/utils/avatar_utils.h"
}

#include <cstring>

namespace ProfileEditorScreen {

// Load profile from DHT (from Qt ProfileEditorDialog.cpp lines 289-381)
void loadProfile(AppState& state, bool force_reload) {
    // Skip if already cached and not forcing reload
    if (state.profile_cached && !force_reload) {
        return;
    }
    
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

        // Load bio
        if (profile->bio[0] != '\0') strncpy(state.profile_bio, profile->bio, sizeof(state.profile_bio) - 1);

        // Load avatar
        if (profile->avatar_base64[0] != '\0') {
            state.profile_avatar_base64 = std::string(profile->avatar_base64);
            state.profile_avatar_loaded = true;
        } else {
            state.profile_avatar_base64.clear();
            state.profile_avatar_loaded = false;
        }

        state.profile_status = "Profile loaded from DHT";
        state.profile_cached = true;  // Mark as cached
        dna_identity_free(profile);
    } else if (ret == -2) {
        state.profile_registered_name = "Not registered";
        state.profile_status = "No profile found. Create your first profile!";
        state.profile_cached = true;  // Cache the "not found" state too
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

    // Bio
    if (state.profile_bio[0]) strncpy(profile_data.bio, state.profile_bio, sizeof(profile_data.bio) - 1);

    // Avatar
    if (!state.profile_avatar_base64.empty()) {
        strncpy(profile_data.avatar_base64, state.profile_avatar_base64.c_str(), sizeof(profile_data.avatar_base64) - 1);
        printf("[ProfileEditor] Saving profile with avatar: %zu bytes base64\n",
               state.profile_avatar_base64.length());
    } else {
        printf("[ProfileEditor] Saving profile without avatar\n");
    }

    // Load private key for signing
    const char *home = qgp_platform_home_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, ctx->identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        state.profile_status = "Failed to load private key for signing";
        printf("[ProfileEditor] ✗ Failed to load signing key from: %s\n", key_path);
        return;
    }

    // Update profile in DHT
    printf("[ProfileEditor] Publishing profile to DHT for: %s\n", ctx->fingerprint);
    int ret = dna_update_profile(dht_ctx, ctx->fingerprint, &profile_data, key->private_key);

    qgp_key_free(key);

    if (ret == 0) {
        state.profile_status = "Profile saved to DHT successfully!";
        state.profile_cached = false;  // Invalidate cache to force reload next time
        state.show_profile_editor = false;
        printf("[ProfileEditor] ✓ Profile published to DHT successfully\n");
    } else {
        state.profile_status = "Failed to save profile to DHT";
        printf("[ProfileEditor] ✗ Failed to publish profile to DHT (error code: %d)\n", ret);
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
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Edit DNA Profile", &state.show_profile_editor, ImGuiWindowFlags_NoResize, true, false, 600, 500)) {  // 600x500 with scrolling

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

        // Avatar Upload (NEW in Phase 4.3)
        if (ImGui::CollapsingHeader("Avatar Upload (64x64)", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());

            // File path input
            ImGui::InputText("Avatar File Path", state.profile_avatar_path, sizeof(state.profile_avatar_path));
            ImGui::PopStyleColor();

            // Browse button (opens file picker)
            if (ThemedButton(ICON_FA_FOLDER_OPEN " Browse", ImVec2(100, 25), false)) {
                #ifdef __linux__
                // Try zenity first (GNOME), fallback to kdialog (KDE)
                FILE *fp = popen("which zenity 2>/dev/null", "r");
                if (fp) {
                    char result[16];
                    bool has_zenity = (fgets(result, sizeof(result), fp) != NULL);
                    pclose(fp);

                    if (has_zenity) {
                        fp = popen("zenity --file-selection --title='Select Avatar Image' --file-filter='Images | *.png *.jpg *.jpeg *.bmp *.gif' 2>/dev/null", "r");
                    } else {
                        fp = popen("kdialog --getopenfilename . 'Images (*.png *.jpg *.jpeg *.bmp *.gif)' 2>/dev/null", "r");
                    }

                    if (fp) {
                        char selected_path[512] = {0};
                        if (fgets(selected_path, sizeof(selected_path), fp) != NULL) {
                            // Remove trailing newline
                            size_t len = strlen(selected_path);
                            if (len > 0 && selected_path[len-1] == '\n') {
                                selected_path[len-1] = '\0';
                            }
                            strncpy(state.profile_avatar_path, selected_path, sizeof(state.profile_avatar_path) - 1);
                            printf("[ProfileEditor] Selected avatar file: %s\n", selected_path);
                        }
                        pclose(fp);
                    }
                }
                #endif
            }

            ImGui::SameLine();
            if (ThemedButton(ICON_FA_UPLOAD " Upload", ImVec2(100, 25), false)) {
                printf("[ProfileEditor] ========== UPLOAD BUTTON CLICKED ==========\n");
                fflush(stdout);

                // Process avatar file
                if (strlen(state.profile_avatar_path) > 0) {
                    printf("[ProfileEditor] Uploading avatar from: '%s'\n", state.profile_avatar_path);
                    printf("[ProfileEditor] Path length: %zu bytes\n", strlen(state.profile_avatar_path));

                    char base64_out[12288] = {0};
                    printf("[ProfileEditor] Calling avatar_load_and_encode...\n");
                    int ret = avatar_load_and_encode(state.profile_avatar_path, base64_out, sizeof(base64_out));
                    printf("[ProfileEditor] avatar_load_and_encode returned: %d\n", ret);

                    if (ret == 0) {
                        state.profile_avatar_base64 = std::string(base64_out);
                        state.profile_avatar_loaded = true;
                        state.profile_status = "Avatar uploaded successfully! (64x64)";
                        printf("[ProfileEditor] ✓ Avatar encoded successfully: %zu bytes base64\n",
                               state.profile_avatar_base64.length());
                    } else {
                        state.profile_status = "Failed to load/encode avatar image";
                        printf("[ProfileEditor] ✗ Failed to encode avatar (error code: %d)\n", ret);
                    }
                } else {
                    state.profile_status = "Please enter a file path first";
                    printf("[ProfileEditor] ✗ No file path provided (path='%s', len=%zu)\n",
                           state.profile_avatar_path, strlen(state.profile_avatar_path));
                }
                printf("[ProfileEditor] ========== UPLOAD COMPLETE ==========\n");
            }

            // Avatar preview and controls
            if (state.profile_avatar_loaded && !state.profile_avatar_base64.empty()) {
                // Load and display avatar texture
                messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                std::string cache_key = ctx ? std::string(ctx->identity) : "preview";

                int avatar_width = 0, avatar_height = 0;
                GLuint texture_id = TextureManager::getInstance().loadAvatar(
                    cache_key,
                    state.profile_avatar_base64,
                    &avatar_width,
                    &avatar_height
                );

                if (texture_id != 0) {
                    // Center the avatar preview
                    float avatar_display_size = 64.0f;
                    float center_x = (ImGui::GetContentRegionAvail().x - avatar_display_size) * 0.5f;
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + center_x);

                    // Display avatar image
                    ImGui::Image((void*)(intptr_t)texture_id, ImVec2(avatar_display_size, avatar_display_size));

                    // Remove button (centered below avatar)
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + center_x);
                    if (ThemedButton(ICON_FA_TRASH " Remove", ImVec2(100, 25), false)) {
                        state.profile_avatar_base64.clear();
                        state.profile_avatar_loaded = false;
                        memset(state.profile_avatar_path, 0, sizeof(state.profile_avatar_path));
                        state.profile_status = "Avatar removed";
                        TextureManager::getInstance().removeTexture(cache_key);
                    }
                } else {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(),
                                     ICON_FA_IMAGE " Avatar failed to load");
                }
            }

            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                             "Supported: PNG, JPEG, BMP, GIF. Image will be resized to 64x64.");
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
        if (ThemedButton("Cancel", ImVec2(100, 40))) {
            state.show_profile_editor = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        if (ThemedButton(ICON_FA_FLOPPY_DISK " Save Profile to DHT", ImVec2(200, 40))) {
            saveProfile(state);
        }

        CenteredModal::End();
    }
}

} // namespace ProfileEditorScreen
