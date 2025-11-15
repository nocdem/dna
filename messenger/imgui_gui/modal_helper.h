#ifndef MODAL_HELPER_H
#define MODAL_HELPER_H

#include "imgui.h"
#include "theme_colors.h"
#include "settings_manager.h"

// Forward declare settings
extern AppSettings g_app_settings;

// Helper to create centered modal windows that stay centered on resize
class CenteredModal {
private:
    static inline bool* s_esc_close_target = nullptr;  // Store pointer for ESC handling
    
public:
    static bool Begin(const char* name, bool* p_open = nullptr, ImGuiWindowFlags flags = 0, bool allow_esc_close = true, bool show_close_button = true, float desktop_width = 500.0f, float desktop_height = 0.0f) {
        // Center modal before opening
        ImGuiIO& io = ImGui::GetIO();
        ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
        ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        
        // Set fixed width (and optionally height) based on mobile/desktop
        bool is_mobile = io.DisplaySize.x < 600;
        float modal_width = is_mobile ? io.DisplaySize.x * 0.9f : desktop_width;
        float modal_height = desktop_height > 0 ? (is_mobile ? io.DisplaySize.y * 0.9f : desktop_height) : 0.0f;
        ImGui::SetNextWindowSize(ImVec2(modal_width, modal_height), ImGuiCond_Always);
        
        // Apply standard modal styling with border
        ImVec4 border_color = (g_app_settings.theme == 0) ? DNATheme::Text() : ClubTheme::Text();
        border_color.w = 0.3f;  // Very transparent border
        ImGui::PushStyleColor(ImGuiCol_Border, border_color);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.5f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowTitleAlign, ImVec2(0.5f, 0.5f));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 12));
        
        // Use theme colors for modal background
        ImVec4 bg = g_app_settings.theme == 0 ? DNATheme::Background() : ClubTheme::Background();
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(bg.x * 0.9f, bg.y * 0.9f, bg.z * 0.9f, 0.8f));
        
        // Only add AlwaysAutoResize if NoResize is not specified
        if (!(flags & ImGuiWindowFlags_NoResize)) {
            flags |= ImGuiWindowFlags_AlwaysAutoResize;
        }
        
        // Store the close target for ESC handling, but pass nullptr to BeginPopupModal if no X button wanted
        s_esc_close_target = p_open;
        bool result = ImGui::BeginPopupModal(name, show_close_button ? p_open : nullptr, flags);
        
        if (result) {
            // Pop styles inside the modal
            ImGui::PopStyleVar(4);  // WindowBorderSize, WindowPadding, WindowTitleAlign, FramePadding
            ImGui::PopStyleColor(2); // Border, ModalWindowDimBg
            ImGui::Spacing();
            
            // Handle ESC key to close modal (only if allowed and p_open is provided)
            if (allow_esc_close && s_esc_close_target && ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                *s_esc_close_target = false;
                ImGui::CloseCurrentPopup();
            }
        } else {
            // Pop styles if modal didn't open
            ImGui::PopStyleVar(4);  // WindowBorderSize, WindowPadding, WindowTitleAlign, FramePadding
            ImGui::PopStyleColor(2); // Border, ModalWindowDimBg
        }
        
        return result;
    }
    
    static void End() {
        ImGui::EndPopup();
        s_esc_close_target = nullptr;
    }
};

#endif // MODAL_HELPER_H
