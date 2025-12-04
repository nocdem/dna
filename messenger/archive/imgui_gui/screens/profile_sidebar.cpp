#include "profile_sidebar.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../texture_manager.h"
#include "../helpers/avatar_helpers.h"

#include <GLFW/glfw3.h>  // For GLuint

// External settings variable
extern AppSettings g_app_settings;

namespace ProfileSidebar {

void renderSidebar(AppState& state) {
    // Remove background and border - make it transparent
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0)); // Transparent background
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));  // Transparent border

    ImGui::BeginChild("ProfileSidebar", ImVec2(0, 200), false, ImGuiWindowFlags_NoScrollbar);

    // Show current identity name centered at top
    if (!state.current_identity.empty()) {
        ImGui::Spacing();
        
        // Get display name from cache, or use shortened fingerprint
        std::string display_name = state.current_identity.substr(0, 10) + "...";
        auto it = state.identity_name_cache.find(state.current_identity);
        if (it != state.identity_name_cache.end()) {
            display_name = it->second;
        }
        
        // Show avatar or placeholder - 96x96 size
        float avatar_size = 96.0f;
        float available_width = ImGui::GetContentRegionAvail().x;
        float avatar_center_x = (available_width - avatar_size) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avatar_center_x);
        
        if (state.profile_avatar_loaded && !state.profile_avatar_base64.empty()) {
            int avatar_width = 0, avatar_height = 0;
            GLuint texture_id = TextureManager::getInstance().loadAvatar(
                state.current_identity,
                state.profile_avatar_base64,
                &avatar_width,
                &avatar_height
            );
            
            if (texture_id != 0) {
                // Check registration status before making avatar clickable
                bool has_registered_name = !state.profile_registered_name.empty() &&
                                           state.profile_registered_name != "Loading..." &&
                                           state.profile_registered_name != "N/A (DHT not connected)" &&
                                           state.profile_registered_name != "Not registered" &&
                                           state.profile_registered_name != "Error loading";
                
                // Make avatar clickable only if user is registered
                if (has_registered_name && ImGui::InvisibleButton("avatar_click", ImVec2(avatar_size, avatar_size))) {
                    state.show_profile_editor = true;
                }
                
                // Draw the avatar over the invisible button (or just draw it if not registered)
                ImVec2 button_min = has_registered_name ? ImGui::GetItemRectMin() : ImGui::GetCursorScreenPos();
                if (!has_registered_name) {
                    ImGui::SetCursorScreenPos(ImVec2(button_min.x, button_min.y + avatar_size)); // Move cursor down
                }
                ImDrawList* draw_list = ImGui::GetWindowDrawList();
                
                // Calculate center position for circular avatar
                ImVec2 center = ImVec2(button_min.x + avatar_size * 0.5f, button_min.y + avatar_size * 0.5f);
                float radius = avatar_size * 0.5f;
                
                // Draw circular avatar
                draw_list->AddImageRounded((ImTextureID)(intptr_t)texture_id, button_min, 
                                         ImVec2(button_min.x + avatar_size, button_min.y + avatar_size), 
                                         ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, radius);
                
                // Add border
                ImVec4 border_col = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                ImU32 border_color = IM_COL32((int)(border_col.x * 255), (int)(border_col.y * 255), (int)(border_col.z * 255), 255);
                draw_list->AddCircle(center, radius, border_color, 0, 2.0f);
                
                if (has_registered_name && ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Click to edit your profile picture");
                }
                
                ImGui::Spacing();
            } else {
                // Show placeholder if texture failed to load - custom large icon
                ImGui::PushID("avatar_placeholder_failed");
                
                // Create custom round button with larger icon
                ImVec4 btn_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                ImVec4 hover_color = (g_app_settings.theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
                ImVec4 text_color = (g_app_settings.theme == 0) ? DNATheme::SelectedText() : ClubTheme::SelectedText();
                
                ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, hover_color);
                ImGui::PushStyleColor(ImGuiCol_Text, text_color);
                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, avatar_size * 0.5f);
                
                // Scale the font for larger icon
                ImGui::SetWindowFontScale(2.0f);
                bool clicked = ImGui::Button(ICON_FA_USER, ImVec2(avatar_size, avatar_size));
                ImGui::SetWindowFontScale(1.0f);
                
                ImGui::PopStyleVar(1);
                ImGui::PopStyleColor(4);
                
                // Check registration status before handling click
                bool has_registered_name = !state.profile_registered_name.empty() &&
                                           state.profile_registered_name != "Loading..." &&
                                           state.profile_registered_name != "N/A (DHT not connected)" &&
                                           state.profile_registered_name != "Not registered" &&
                                           state.profile_registered_name != "Error loading";
                
                if (clicked && has_registered_name) {
                    state.show_profile_editor = true;
                }
                
                ImGui::PopID();
                if (ImGui::IsItemHovered()) {
                    if (has_registered_name) {
                        ImGui::SetTooltip("Click to add a profile picture");
                    } else {
                        ImGui::SetTooltip("Register a DNA name to add a profile picture");
                    }
                }
                ImGui::Spacing();
            }
        } else {
            // Show FontAwesome user icon as placeholder - custom large icon
            ImGui::PushID("avatar_placeholder_none");
            
            // Create custom round button with larger icon
            ImVec4 btn_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            ImVec4 hover_color = (g_app_settings.theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
            ImVec4 text_color = (g_app_settings.theme == 0) ? DNATheme::SelectedText() : ClubTheme::SelectedText();
            
            ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, hover_color);
            ImGui::PushStyleColor(ImGuiCol_Text, text_color);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, avatar_size * 0.5f);
            
            // Scale the font for larger icon
            ImGui::SetWindowFontScale(2.0f);
            bool clicked = ImGui::Button(ICON_FA_USER, ImVec2(avatar_size, avatar_size));
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::PopStyleVar(1);
            ImGui::PopStyleColor(4);
            
            // Check registration status before handling click
            bool has_registered_name = !state.profile_registered_name.empty() &&
                                       state.profile_registered_name != "Loading..." &&
                                       state.profile_registered_name != "N/A (DHT not connected)" &&
                                       state.profile_registered_name != "Not registered" &&
                                       state.profile_registered_name != "Error loading";
            
            if (clicked && has_registered_name) {
                state.show_profile_editor = true;
            }
            
            ImGui::PopID();
            if (ImGui::IsItemHovered()) {
                if (has_registered_name) {
                    ImGui::SetTooltip("Click to add a profile picture");
                } else {
                    ImGui::SetTooltip("Register a DNA name to add a profile picture");
                }
            }
            ImGui::Spacing();
        }
        
        // Center the identity name
        float text_width = ImGui::CalcTextSize(display_name.c_str()).x;
        float text_available_width = ImGui::GetContentRegionAvail().x;
        float text_center_x = (text_available_width - text_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + text_center_x);
        ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(), "%s", display_name.c_str());
        
        ImGui::Spacing();
        
        // Show Register DNA or Edit Profile button based on registration status
        bool has_registered_name = !state.profile_registered_name.empty() &&
                                   state.profile_registered_name != "Loading..." &&
                                   state.profile_registered_name != "N/A (DHT not connected)" &&
                                   state.profile_registered_name != "Not registered" &&
                                   state.profile_registered_name != "Error loading";
        
        if (has_registered_name) {
            // User is registered - show all 5 round icon buttons in a single row
            // Edit Profile, Post to Wall, Feed, Wallet, Settings
            float button_spacing = 8.0f;
            float total_width = (32.0f * 5) + (button_spacing * 4);  // 5 buttons, 4 spaces
            float start_x = (250 - total_width) * 0.5f;

            ImGui::SetCursorPosX(start_x);
            if (ThemedRoundButton(ICON_FA_USER)) {
                state.show_profile_editor = true;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Edit your profile information");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_COMMENT)) {
                state.wall_fingerprint = state.current_identity;
                state.wall_display_name = "My Wall";
                state.wall_is_own = true;
                state.show_message_wall = true;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Post messages to your public wall");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_NEWSPAPER)) {
                state.current_view = VIEW_FEED;
                state.selected_contact = -1;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Browse public feed channels");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_CREDIT_CARD)) {
                state.current_view = VIEW_WALLET;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Manage your cryptocurrency wallet");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_GEAR)) {
                state.current_view = VIEW_SETTINGS;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Configure application settings");
            }
        } else {
            // User not registered - show Register DNA, Feed, Wallet and Settings buttons in a row
            float button_spacing = 8.0f;
            float total_width = (32.0f * 4) + (button_spacing * 3);  // 4 buttons, 3 spaces
            float available_width = ImGui::GetContentRegionAvail().x;
            float start_x = (available_width - total_width) * 0.5f;

            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + start_x);
            if (ThemedRoundButton(ICON_FA_ID_CARD)) {
                state.show_register_name = true;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Register a human-readable DNA name");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_NEWSPAPER)) {
                state.current_view = VIEW_FEED;
                state.selected_contact = -1;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Browse public feed channels");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_CREDIT_CARD)) {
                state.current_view = VIEW_WALLET;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Manage your cryptocurrency wallet");
            }

            ImGui::SameLine(0, button_spacing);
            if (ThemedRoundButton(ICON_FA_GEAR)) {
                state.current_view = VIEW_SETTINGS;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_NoSharedDelay)) {
                ImGui::SetTooltip("Configure application settings");
            }
        }
    }

    // Add separator at the bottom
    ImGui::Spacing();
    ImGui::Separator();

    ImGui::EndChild();

    // Pop style colors
    ImGui::PopStyleColor(2);
}

} // namespace ProfileSidebar