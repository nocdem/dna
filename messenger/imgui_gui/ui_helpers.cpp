#include "ui_helpers.h"
#include <cmath>

// Helper function for themed main buttons
bool ThemedButton(const char* label, const ImVec2& size, bool is_active) {
    ImVec4 btn_color, hover_color, active_color, text_color, text_bg;

    if (g_app_settings.theme == 0) { // DNA Theme
        btn_color = DNATheme::Text();
        hover_color = DNATheme::ButtonHover();
        active_color = DNATheme::ButtonActive();
        text_color = DNATheme::SelectedText();
        text_bg = DNATheme::Background();
    } else { // Club Theme
        btn_color = ClubTheme::Text();
        hover_color = ClubTheme::ButtonHover();
        active_color = ClubTheme::ButtonActive();
        text_color = ClubTheme::SelectedText();
        text_bg = ClubTheme::Background();
    }

    if (is_active) {
        // Active state: same as ButtonActive (slightly darker than hover)
        ImGui::PushStyleColor(ImGuiCol_Button, active_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, active_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    }

    ImGui::PushStyleColor(ImGuiCol_Text, text_color);
    bool result = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return result;
}

// Global themed spinner utility (beautiful arc design)
void ThemedSpinner(const char* label, float radius, float thickness) {
    ImGui::BeginGroup();
    
    // Get theme color
    ImVec4 color;
    if (g_app_settings.theme == 0) { // DNA Theme
        color = DNATheme::Text();
    } else { // Club Theme
        color = ClubTheme::Text();
    }

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 center = ImVec2(pos.x + radius, pos.y + radius);

    // Animated smooth arc
    const float t = (float)ImGui::GetTime();
    const float rotation = t * 3.5f; // Rotation speed
    const float arc_length = 3.14159265f * 1.5f; // 270 degrees
    
    // Draw background circle (subtle)
    draw_list->AddCircle(center, radius, 
        ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.1f)), 32, thickness * 0.5f);
    
    // Draw animated arc with gradient effect
    const int segments = 32;
    for (int i = 0; i < segments; i++) {
        float a1 = rotation + (i / (float)segments) * arc_length;
        float a2 = rotation + ((i + 1) / (float)segments) * arc_length;
        
        // Gradient alpha from start to end of arc
        float alpha1 = 0.2f + (i / (float)segments) * 0.8f;
        float alpha2 = 0.2f + ((i + 1) / (float)segments) * 0.8f;
        
        ImVec2 p1 = ImVec2(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius);
        ImVec2 p2 = ImVec2(center.x + cosf(a2) * radius, center.y + sinf(a2) * radius);
        
        ImU32 col1 = ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, alpha1));
        ImU32 col2 = ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, alpha2));
        
        // Draw thick line segment with gradient
        draw_list->AddLine(p1, p2, col2, thickness);
    }
    
    // Add glowing endpoint
    float end_angle = rotation + arc_length;
    ImVec2 end_point = ImVec2(center.x + cosf(end_angle) * radius, center.y + sinf(end_angle) * radius);
    draw_list->AddCircleFilled(end_point, thickness * 0.8f, ImGui::GetColorU32(color));
    
    // Outer glow effect
    draw_list->AddCircleFilled(end_point, thickness * 1.3f, 
        ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.3f)));
    
    ImGui::Dummy(ImVec2(radius * 2, radius * 2));
    ImGui::EndGroup();
}
