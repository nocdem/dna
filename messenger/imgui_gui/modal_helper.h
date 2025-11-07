#ifndef MODAL_HELPER_H
#define MODAL_HELPER_H

#include "imgui.h"
#include "theme_colors.h"
#include "settings_manager.h"

// Forward declare settings
extern AppSettings g_app_settings;

// Helper to create centered modal windows that stay centered on resize
class CenteredModal {
public:
    static bool Begin(const char* name, bool* p_open = nullptr, ImGuiWindowFlags flags = 0) {
        // Center modal before opening
        ImGuiIO& io = ImGui::GetIO();
        ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
        ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        
        // Apply standard modal styling
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
        
        bool result = ImGui::BeginPopupModal(name, p_open, flags);
        
        if (result) {
            // Pop styles inside the modal
            ImGui::PopStyleVar(3);
            ImGui::PopStyleColor();
            ImGui::Spacing();
        } else {
            // Pop styles if modal didn't open
            ImGui::PopStyleVar(3);
            ImGui::PopStyleColor();
        }
        
        return result;
    }
    
    static void End() {
        ImGui::EndPopup();
    }
};

#endif // MODAL_HELPER_H
