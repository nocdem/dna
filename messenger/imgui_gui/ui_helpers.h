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

// Global themed spinner utility
void ThemedSpinner(const char* label, float radius = 16.0f, float thickness = 3.0f);

#endif // UI_HELPERS_H
