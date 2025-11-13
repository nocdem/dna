#include "settings_screen.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../settings_manager.h"
#include "../theme_colors.h"

#include <cmath>

// External theme function
extern void ApplyTheme(int theme);

// External settings variable
extern AppSettings g_app_settings;

namespace SettingsScreen {

void render(AppState& state) {
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
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_USER " Edit DNA Profile", ImVec2(-1, btn_height))) {
            state.show_profile_editor = true;
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_TAG " Register DNA Name", ImVec2(-1, btn_height))) {
            state.show_register_name = true;
        }
        ImGui::Spacing();

        if (ButtonDark(ICON_FA_NEWSPAPER " My Message Wall", ImVec2(-1, btn_height))) {
            // Open own message wall
            state.wall_fingerprint = state.current_identity;  // Use current identity fingerprint
            state.wall_display_name = "My Wall";
            state.wall_is_own = true;  // Can post to own wall
            state.show_message_wall = true;
        }
    } else {
        if (ButtonDark("Create New Identity", ImVec2(200, btn_height))) {
            // TODO: Create identity dialog
        }
        ImGui::SameLine();
        if (ButtonDark("Import Identity", ImVec2(200, btn_height))) {
            // TODO: Import identity dialog
        }

        ImGui::Spacing();

        if (ButtonDark(ICON_FA_USER " Edit Profile", ImVec2(200, btn_height))) {
            state.show_profile_editor = true;
        }
        ImGui::SameLine();
        if (ButtonDark(ICON_FA_TAG " Register Name", ImVec2(200, btn_height))) {
            state.show_register_name = true;
        }

        ImGui::Spacing();

        if (ButtonDark(ICON_FA_NEWSPAPER " My Message Wall", ImVec2(-1, btn_height))) {
            // Open own message wall
            state.wall_fingerprint = state.current_identity;  // Use current identity fingerprint
            state.wall_display_name = "My Wall";
            state.wall_is_own = true;  // Can post to own wall
            state.show_message_wall = true;
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

} // namespace SettingsScreen
