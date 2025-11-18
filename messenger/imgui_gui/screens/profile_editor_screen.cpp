#include "profile_editor_screen.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../texture_manager.h"
#include "../helpers/avatar_helpers.h"
#include <nfd.h>

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/core/dht_keyserver.h"
    #include "../../p2p/p2p_transport.h"
    #include "../../crypto/utils/qgp_types.h"
    #include "../../crypto/utils/qgp_platform.h"
    #include "../../crypto/utils/avatar_utils.h"
}

#include <cstring>
#include <algorithm>

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
            // Validate base64 string length (must be multiple of 4)
            size_t len = strlen(profile->avatar_base64);
            
            // Base64 must be a multiple of 4. If not, the data was truncated and is invalid.
            if (len % 4 == 0 && len > 0) {
                state.profile_avatar_base64 = std::string(profile->avatar_base64);
                state.profile_avatar_loaded = true;
                printf("[ProfileEditor] Loaded avatar from DHT (%zu bytes)\n", len);
            } else {
                printf("[ProfileEditor] Avatar corrupted in DHT (invalid length: %zu, not multiple of 4)\n", len);
                printf("[ProfileEditor] Please re-upload your avatar\n");
                state.profile_avatar_base64.clear();
                state.profile_avatar_loaded = false;
            }
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
        size_t avatar_len = state.profile_avatar_base64.length();
        printf("[ProfileEditor] Saving avatar: %zu bytes\n", avatar_len);
        
        if (avatar_len >= sizeof(profile_data.avatar_base64)) {
            printf("[ProfileEditor] WARNING: Avatar too large (%zu bytes), truncating to %zu\n", 
                   avatar_len, sizeof(profile_data.avatar_base64) - 1);
        }
        
        strncpy(profile_data.avatar_base64, state.profile_avatar_base64.c_str(), sizeof(profile_data.avatar_base64) - 1);
        profile_data.avatar_base64[sizeof(profile_data.avatar_base64) - 1] = '\0';  // Ensure null termination
    }

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
        // Keep cache valid since we already have the current data in memory
        // state.profile_cached is already true, no need to invalidate
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
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Edit DNA Profile", &state.show_profile_editor, ImGuiWindowFlags_NoResize, true, false, 600, 500)) {  // 600x500 with scrolling

        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(), "Edit your public DNA profile. All changes are stored in the DHT.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable form
        ImGui::BeginChild("ProfileForm", ImVec2(0, -80), true);

        // Cellframe Network Addresses
        if (ImGui::CollapsingHeader("Cellframe Network Addresses")) {
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
        if (ImGui::CollapsingHeader("Avatar Upload (64x64)")) {
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

                    // Render circular avatar with border
                    ImVec4 border_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                    AvatarHelpers::renderCircularAvatar(texture_id, avatar_display_size, border_col, 0.5f);

                    // Remove button (centered below avatar) - round icon button
                    ImGui::Spacing();
                    float remove_button_size = 32.0f;
                    float button_center_x = (ImGui::GetContentRegionAvail().x - remove_button_size) * 0.5f;
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + button_center_x);
                    if (ThemedRoundButton(ICON_FA_TRASH, remove_button_size, false)) {
                        state.profile_avatar_base64.clear();
                        state.profile_avatar_loaded = false;
                        state.profile_status = "Avatar removed";
                        // Remove from texture cache
                        TextureManager::getInstance().removeTexture(cache_key);
                    }
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                        ImGui::SetTooltip("Remove avatar");
                    }
                } else {
                    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning(),
                                     "Failed to load avatar preview");
                }
            } else {
                // No avatar uploaded - show browse button
                ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                                 "No avatar uploaded");
                ImGui::Spacing();
                
                if (ThemedButton(ICON_FA_FOLDER_OPEN " Browse Image File", ImVec2(200, 30), false)) {
                    // Use NFD to select image file (GTK workaround applied in main.cpp)
                    nfdchar_t *outPath = nullptr;
                    nfdfilteritem_t filters[1] = { { "Image Files", "png,jpg,jpeg,bmp,gif" } };
                    nfdresult_t result = NFD_OpenDialog(&outPath, filters, 1, nullptr);

                    if (result == NFD_ERROR) {
                        state.profile_status = std::string("File dialog error: ") + NFD_GetError();
                        printf("[ProfileEditor] NFD error: %s\n", NFD_GetError());
                    }
                    else if (result == NFD_OKAY) {
                        // Process avatar file immediately (larger buffer for safety)
                        char *base64_out = (char*)malloc(65536); // 64KB buffer for base64
                        if (!base64_out) {
                            state.profile_status = "Failed to allocate memory";
                            NFD_FreePath(outPath);
                            return;
                        }
                        
                        int ret = avatar_load_and_encode(outPath, base64_out, 65536);

                        if (ret == 0) {
                            // Remove old texture from cache before loading new one
                            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
                            std::string cache_key = ctx ? std::string(ctx->identity) : "preview";
                            TextureManager::getInstance().removeTexture(cache_key);
                            
                            state.profile_avatar_base64 = std::string(base64_out);
                            state.profile_avatar_loaded = true;
                            state.profile_status = "Avatar uploaded successfully! (64x64)";
                            printf("[ProfileEditor] Avatar loaded from: %s\n", outPath);
                        } else {
                            state.profile_status = "Failed to load/resize avatar image";
                        }
                        
                        free(base64_out);
                        NFD_FreePath(outPath);
                    } else if (result == NFD_CANCEL) {
                        printf("[ProfileEditor] User cancelled file selection\n");
                    } else {
                        printf("[ProfileEditor] NFD Error: %s\n", NFD_GetError());
                        state.profile_status = "Error opening file dialog";
                    }
                }
            }
        }

        // Bio
        if (ImGui::CollapsingHeader("Bio")) {
            ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
            ImGui::InputTextMultiline("##Bio", state.profile_bio, sizeof(state.profile_bio), ImVec2(-1, 100));
            ImGui::PopStyleColor();
            ImGui::Text("%zu / 512", strlen(state.profile_bio));
        }

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(), "%s", state.profile_status.c_str());
        ImGui::Spacing();

        // Buttons - left and right aligned with equal padding
        float cancel_width = 100.0f;
        float save_width = 200.0f;
        
        // Get the left padding by checking cursor X position
        float left_padding = ImGui::GetCursorPosX();
        
        // Draw Cancel button (it will use the natural left padding)
        if (ThemedButton("Cancel", ImVec2(cancel_width, 40))) {
            state.show_profile_editor = false;
        }
        
        // Position Save button from the right with same padding as left
        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - save_width - left_padding);
        
        if (ThemedButton(ICON_FA_FLOPPY_DISK " Save Profile to DHT", ImVec2(save_width, 40))) {
            saveProfile(state);
        }

        CenteredModal::End();
    }
}

} // namespace ProfileEditorScreen
