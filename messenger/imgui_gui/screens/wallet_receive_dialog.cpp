#include "wallet_receive_dialog.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"

namespace WalletReceiveDialog {

void render(AppState& state) {
    if (!state.show_receive_dialog) return;

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = io.DisplaySize.x < 600;

    // Set fixed width like other modals
    ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x * 0.9f : 500, 0), ImGuiCond_Always);

    if (CenteredModal::Begin("Receive Tokens", &state.show_receive_dialog, ImGuiWindowFlags_NoResize, true, false)) {
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

        // QR Code placeholder
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - 200) * 0.5f);
        ImGui::BeginChild("##qr_placeholder", ImVec2(200, 200), true);
        ImGui::SetCursorPos(ImVec2(70, 90));
        ImGui::TextDisabled("QR Code");
        ImGui::SetCursorPos(ImVec2(50, 105));
        ImGui::TextDisabled("(Coming Soon)");
        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::Spacing();

        // Close button
        float close_btn_width = 150.0f;
        float close_btn_x = (ImGui::GetContentRegionAvail().x - close_btn_width) * 0.5f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + close_btn_x);

        if (ImGui::Button("Close", ImVec2(close_btn_width, 40))) {
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
