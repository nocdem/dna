#ifndef UI_HELPERS_H
#define UI_HELPERS_H

#include "imgui.h"
#include "settings_manager.h"
#include "theme_colors.h"

// Global settings (defined in main.cpp)
extern AppSettings g_app_settings;

// UI Helper Functions
// Helper function for themed main buttons
bool ThemedButton(const char* label, const ImVec2& size = ImVec2(0, 0), bool is_active = false);

// Helper function for themed round icon buttons (32x32 by default)
bool ThemedRoundButton(const char* icon, float size = 32.0f, bool is_active = false);

// Global themed spinner utility
void ThemedSpinner(const char* label, float radius = 16.0f, float thickness = 3.0f);

// Check if mobile layout should be used
inline bool IsMobileLayout() {
    return ImGui::GetIO().DisplaySize.x < 600;
}

// Get modal width based on mobile/desktop
inline float GetModalWidth(float desktop_width) {
    ImGuiIO& io = ImGui::GetIO();
    return IsMobileLayout() ? io.DisplaySize.x * 0.9f : desktop_width;
}

#endif // UI_HELPERS_H
