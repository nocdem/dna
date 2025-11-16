#include "wallet_receive_dialog.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "qrcodegen.hpp"
#include <string>

using qrcodegen::QrCode;

namespace WalletReceiveDialog {

static void RenderQRCode(const char* text, float size) {
    if (!text || text[0] == '\0') return;
    
    try {
        // Generate QR code
        const QrCode qr = QrCode::encodeText(text, QrCode::Ecc::MEDIUM);
        int qr_size = qr.getSize();
        
        // Calculate module size (each QR "pixel")
        float module_size = size / (qr_size + 2);  // +2 for border
        
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 pos = ImGui::GetCursorScreenPos();
        
        // White background
        ImVec4 bg_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        draw_list->AddRectFilled(pos, ImVec2(pos.x + size, pos.y + size), ImGui::ColorConvertFloat4ToU32(bg_color));
        
        // Draw QR modules (black squares)
        ImVec4 fg_color = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        for (int y = 0; y < qr_size; y++) {
            for (int x = 0; x < qr_size; x++) {
                if (qr.getModule(x, y)) {
                    ImVec2 module_pos = ImVec2(
                        pos.x + (x + 1) * module_size,
                        pos.y + (y + 1) * module_size
                    );
                    draw_list->AddRectFilled(
                        module_pos,
                        ImVec2(module_pos.x + module_size, module_pos.y + module_size),
                        ImGui::ColorConvertFloat4ToU32(fg_color)
                    );
                }
            }
        }
        
        // Move cursor
        ImGui::Dummy(ImVec2(size, size));
        
    } catch (const std::exception& e) {
        // Fallback if QR generation fails
        ImGui::BeginChild("##qr_error", ImVec2(size, size), true);
        ImGui::SetCursorPos(ImVec2(size * 0.5f - 30, size * 0.5f - 10));
        ImGui::TextDisabled("QR Error");
        ImGui::EndChild();
    }
}

void render(AppState& state) {
    if (!state.show_receive_dialog) return;

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();


    if (CenteredModal::Begin("Receive Tokens", &state.show_receive_dialog, ImGuiWindowFlags_NoResize, true, false, 500)) {
        // Wallet name
        ImGui::Text(ICON_FA_WALLET " %s", state.wallet_name.c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Network (Backbone is the default)
        ImGui::TextDisabled("Network: Backbone");
        ImGui::Spacing();

        // Address label
        ImGui::Text("Your Wallet Address:");
        ImGui::Spacing();

        // Address input (read-only, monospace font)
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);  // Use default font (monospace would be better)
        ImGui::PushItemWidth(-1);
        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::InputText("##address", state.wallet_address, sizeof(state.wallet_address),
                        ImGuiInputTextFlags_ReadOnly);
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();
        ImGui::PopFont();

        ImGui::Spacing();

        // Copy button
        float btn_width = 200.0f;
        float btn_x = (ImGui::GetContentRegionAvail().x - btn_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + btn_x);

        if (state.address_copied) {
            // Show "Copied!" feedback
            if (ThemedButton(ICON_FA_CIRCLE_CHECK " Copied!", ImVec2(btn_width, 40))) {
                // Button disabled
            }

            // Reset after 2 seconds
            state.address_copied_timer += io.DeltaTime;
            if (state.address_copied_timer >= 2.0f) {
                state.address_copied = false;
                state.address_copied_timer = 0.0f;
            }
        } else {
            if (ThemedButton(ICON_FA_CLIPBOARD " Copy Address", ImVec2(btn_width, 40))) {
                ImGui::SetClipboardText(state.wallet_address);
                state.address_copied = true;
                state.address_copied_timer = 0.0f;
            }
        }

        ImGui::Spacing();
        ImGui::Spacing();

        // QR Code
        float qr_size = 200.0f;
        float available_width = ImGui::GetContentRegionAvail().x;
        float qr_x = (available_width - qr_size) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + qr_x);
        RenderQRCode(state.wallet_address, qr_size);

        ImGui::Spacing();
        ImGui::Spacing();

        // Close button
        float close_btn_width = 150.0f;
        float close_btn_x = (ImGui::GetContentRegionAvail().x - close_btn_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + close_btn_x);

        if (ThemedButton("Close", ImVec2(close_btn_width, 40))) {
            state.show_receive_dialog = false;
            state.address_copied = false;
        }

        CenteredModal::End();
    }

    // Open the modal if flag is set
    if (state.show_receive_dialog && !ImGui::IsPopupOpen("Receive Tokens")) {
        ImGui::OpenPopup("Receive Tokens");
    }
}

} // namespace WalletReceiveDialog
